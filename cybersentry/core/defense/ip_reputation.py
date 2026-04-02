"""
CyberSentry IP Reputation Engine.
Blocks Tor exit nodes, known abusive ranges, datacenter IPs,
and manages temporary bans from other defence layers.
"""
from __future__ import annotations

import ipaddress
import threading
import time
import urllib.request
from dataclasses import dataclass
from enum import Enum


class IPVerdict(str, Enum):
    ALLOW     = "allow"
    BLOCK     = "block"
    CHALLENGE = "challenge"
    TARPIT    = "tarpit"


@dataclass
class IPCheckResult:
    ip: str
    verdict: IPVerdict
    reason: str
    score: int
    is_tor: bool = False
    is_datacenter: bool = False


# Known abusive / scanning ranges
ABUSIVE_RANGES = [
    "185.220.0.0/16",   # Tor / abuse hosting
    "89.248.160.0/19",  # ShadowServer scanning
    "80.82.77.0/24",    # Shodan scanning
    "198.20.0.0/24",    # Shodan scanning
    "45.155.205.0/24",
    "185.129.60.0/22",
]

# Cloud/datacenter ranges (challenge, don't hard block)
DATACENTER_RANGES = [
    "3.0.0.0/8", "13.32.0.0/15", "52.0.0.0/11", "54.0.0.0/11",
    "18.0.0.0/8", "34.0.0.0/9", "35.184.0.0/13", "104.154.0.0/15",
    "13.64.0.0/11", "20.0.0.0/11", "40.64.0.0/10", "52.224.0.0/11",
    "104.131.0.0/18", "159.203.0.0/16", "165.232.0.0/16",
    "45.33.0.0/17", "45.56.0.0/21", "45.79.0.0/16",
    "45.32.0.0/16", "66.42.0.0/16",
]

PRIVATE_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128",
]

TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"


def _parse_nets(cidrs):
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets


class IPReputationEngine:
    def __init__(
        self,
        block_tor: bool = True,
        block_abusive: bool = True,
        challenge_datacenters: bool = True,
        blocked_countries: set[str] | None = None,
        allowlist: set[str] | None = None,
        blocklist: set[str] | None = None,
        tor_refresh_interval: int = 3600,
    ):
        self.block_tor = block_tor
        self.block_abusive = block_abusive
        self.challenge_datacenters = challenge_datacenters
        self._allowlist: set[str] = allowlist or set()
        self._blocklist: set[str] = blocklist or set()
        self._abusive_nets = _parse_nets(ABUSIVE_RANGES)
        self._datacenter_nets = _parse_nets(DATACENTER_RANGES)
        self._private_nets = _parse_nets(PRIVATE_RANGES)
        self._tor_exits: set[str] = set()
        self._bans: dict[str, float] = {}
        self._lock = threading.RLock()
        self._start_tor_refresh(tor_refresh_interval)

    def check(self, ip: str) -> IPCheckResult:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IPCheckResult(ip=ip, verdict=IPVerdict.BLOCK, reason="invalid_ip", score=100)

        ip_str = str(addr)

        if ip_str in self._allowlist:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW, reason="allowlisted", score=0)

        if ip_str in self._blocklist:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK, reason="blocklisted", score=100)

        with self._lock:
            ban_exp = self._bans.get(ip_str)
        if ban_exp and time.time() < ban_exp:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK, reason="temp_banned", score=95)

        for net in self._private_nets:
            if addr in net:
                return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW, reason="private", score=0)

        if self.block_abusive:
            for net in self._abusive_nets:
                if addr in net:
                    return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK, reason=f"abusive_range:{net}", score=90)

        if self.block_tor and ip_str in self._tor_exits:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK, reason="tor_exit", score=85, is_tor=True)

        if self.challenge_datacenters:
            for net in self._datacenter_nets:
                if addr in net:
                    return IPCheckResult(ip=ip_str, verdict=IPVerdict.CHALLENGE, reason=f"datacenter:{net}", score=40, is_datacenter=True)

        return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW, reason="clean", score=0)

    def ban(self, ip: str, duration_seconds: int = 3600) -> None:
        with self._lock:
            self._bans[ip] = time.time() + duration_seconds

    def add_to_blocklist(self, ip: str) -> None:
        self._blocklist.add(ip)

    def add_to_allowlist(self, ip: str) -> None:
        self._allowlist.add(ip)

    def get_stats(self) -> dict:
        with self._lock:
            active_bans = sum(1 for e in self._bans.values() if time.time() < e)
        return {
            "blocklist": len(self._blocklist),
            "allowlist": len(self._allowlist),
            "tor_exits": len(self._tor_exits),
            "active_bans": active_bans,
        }

    def _fetch_tor_exits(self) -> set[str]:
        try:
            with urllib.request.urlopen(TOR_EXIT_URL, timeout=10) as r:
                data = r.read().decode("utf-8", errors="replace")
            result = set()
            for line in data.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_address(line)
                        result.add(line)
                    except ValueError:
                        pass
            return result
        except Exception:
            return set()

    def _start_tor_refresh(self, interval: int) -> None:
        def _loop():
            exits = self._fetch_tor_exits()
            with self._lock:
                self._tor_exits = exits
            while True:
                time.sleep(interval)
                exits = self._fetch_tor_exits()
                if exits:
                    with self._lock:
                        self._tor_exits = exits

        t = threading.Thread(target=_loop, daemon=True, name="cs-tor-refresh")
        t.start()
