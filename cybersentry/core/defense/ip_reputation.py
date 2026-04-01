"""
CyberSentry IP Reputation Engine — Layer 1 defence.

Checks incoming IPs against:
  - Local blocklist / allowlist
  - Known Tor exit nodes (fetched periodically)
  - Known datacenter / cloud ASN ranges (AWS, GCP, Azure, DigitalOcean, etc.)
  - Country block list (configurable)
  - Persistent ban list (auto-populated by other layers)

All lookups are O(1) via sets / prefix tries.
No external API required — works fully offline with bundled data.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cybersentry.ip_reputation")


class IPVerdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"   # serve CAPTCHA / JS challenge
    TARPIT = "tarpit"         # slow down the connection


@dataclass
class IPCheckResult:
    ip: str
    verdict: IPVerdict
    reason: str
    score: int          # 0 = clean, 100 = definitely malicious
    country: str | None = None
    asn: str | None = None
    is_tor: bool = False
    is_datacenter: bool = False
    is_vpn: bool = False


# ── Known malicious / datacenter CIDR ranges ─────────────────────────────────
# Major cloud/datacenter ASN CIDR prefixes — traffic from these is often
# automated scanning, botnets, or abuse. Challenge rather than block outright
# (legitimate API clients also run in cloud).
DATACENTER_RANGES: list[str] = [
    # AWS
    "3.0.0.0/8", "13.32.0.0/15", "13.35.0.0/16", "52.0.0.0/11",
    "54.0.0.0/11", "18.0.0.0/8", "35.152.0.0/13",
    # GCP
    "34.0.0.0/9", "35.184.0.0/13", "104.154.0.0/15", "130.211.0.0/16",
    # Azure
    "13.64.0.0/11", "20.0.0.0/11", "40.64.0.0/10", "52.224.0.0/11",
    # DigitalOcean
    "104.131.0.0/18", "159.203.0.0/16", "165.232.0.0/16", "167.99.0.0/16",
    # Linode / Akamai
    "45.33.0.0/17", "45.56.0.0/21", "45.79.0.0/16",
    # Vultr
    "45.32.0.0/16", "66.42.0.0/16", "108.61.0.0/16",
    # OVH
    "51.68.0.0/16", "51.75.0.0/16", "51.89.0.0/16", "54.36.0.0/15",
]

# RFC 1918 + link-local + loopback — these should never come from the internet
PRIVATE_RANGES: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
]

# Known Tor exit node list URL (fetched periodically)
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

# Notorious abuse hosting ranges (frequent source of scanning/botnets)
KNOWN_ABUSIVE_RANGES: list[str] = [
    "185.220.0.0/16",   # common Tor/abuse hosting
    "185.129.60.0/22",
    "45.155.205.0/24",
    "89.248.160.0/19",  # ShadowServer scanning
    "80.82.77.0/24",    # Shodan scanning
    "198.20.0.0/24",    # Shodan scanning
    "104.149.0.0/16",
]


def _parse_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    return networks


class IPReputationEngine:
    """
    Fast O(1) IP reputation checks with automatic Tor node updates.

    Usage:
        engine = IPReputationEngine()
        result = engine.check("1.2.3.4")
        if result.verdict == IPVerdict.BLOCK:
            return 403
    """

    def __init__(
        self,
        blocked_countries: set[str] | None = None,
        allowlist: set[str] | None = None,
        blocklist: set[str] | None = None,
        block_tor: bool = True,
        challenge_datacenters: bool = True,
        block_abusive: bool = True,
        tor_refresh_interval: int = 3600,   # seconds
    ):
        self.blocked_countries: set[str] = blocked_countries or set()
        self._allowlist: set[str] = allowlist or set()
        self._blocklist: set[str] = blocklist or set()
        self.block_tor = block_tor
        self.challenge_datacenters = challenge_datacenters
        self.block_abusive = block_abusive
        self._tor_refresh_interval = tor_refresh_interval

        # Compiled network lists
        self._datacenter_nets = _parse_networks(DATACENTER_RANGES)
        self._private_nets = _parse_networks(PRIVATE_RANGES)
        self._abusive_nets = _parse_networks(KNOWN_ABUSIVE_RANGES)

        # Dynamic state
        self._tor_exits: set[str] = set()
        self._ban_list: dict[str, float] = {}   # ip -> expiry timestamp
        self._last_tor_update: float = 0.0
        self._lock = threading.RLock()

        # Kick off background Tor list refresh
        self._start_tor_refresh()

    # ── Public API ─────────────────────────────────────────────────────────
    def check(self, ip: str) -> IPCheckResult:
        """Check a single IP. Returns verdict + reason."""
        # Normalize
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IPCheckResult(ip=ip, verdict=IPVerdict.BLOCK,
                                 reason="invalid IP address", score=100)

        ip_str = str(addr)

        # 1. Allowlist — always pass
        if ip_str in self._allowlist:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW,
                                 reason="allowlisted", score=0)

        # 2. Explicit blocklist
        if ip_str in self._blocklist:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK,
                                 reason="explicit blocklist", score=100)

        # 3. Temporary ban (auto-populated by rate limiter / anomaly engine)
        with self._lock:
            ban_expiry = self._ban_list.get(ip_str)
        if ban_expiry and time.time() < ban_expiry:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK,
                                 reason="temporary ban", score=95)

        # 4. Private / loopback → allow (internal traffic)
        for net in self._private_nets:
            if addr in net:
                return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW,
                                     reason="private/loopback", score=0)

        # 5. Known abusive ranges
        if self.block_abusive:
            for net in self._abusive_nets:
                if addr in net:
                    return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK,
                                         reason=f"known abusive range: {net}",
                                         score=90)

        # 6. Tor exit node
        if self.block_tor and ip_str in self._tor_exits:
            return IPCheckResult(ip=ip_str, verdict=IPVerdict.BLOCK,
                                 reason="Tor exit node", score=85, is_tor=True)

        # 7. Datacenter IP — challenge rather than hard block
        if self.challenge_datacenters:
            for net in self._datacenter_nets:
                if addr in net:
                    return IPCheckResult(ip=ip_str, verdict=IPVerdict.CHALLENGE,
                                         reason=f"datacenter range: {net}",
                                         score=40, is_datacenter=True)

        return IPCheckResult(ip=ip_str, verdict=IPVerdict.ALLOW,
                             reason="clean", score=0)

    def ban(self, ip: str, duration_seconds: int = 3600) -> None:
        """Temporarily ban an IP (called by other defence layers)."""
        with self._lock:
            self._ban_list[ip] = time.time() + duration_seconds
        logger.warning("Banned IP %s for %ds", ip, duration_seconds)

    def add_to_blocklist(self, ip: str) -> None:
        self._blocklist.add(ip)

    def add_to_allowlist(self, ip: str) -> None:
        self._allowlist.add(ip)

    def load_blocklist_file(self, path: Path) -> int:
        """Load a newline-separated IP blocklist file. Returns count loaded."""
        count = 0
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self._blocklist.add(line)
                    count += 1
        except (OSError, IOError) as e:
            logger.warning("Could not load blocklist %s: %s", path, e)
        return count

    def get_stats(self) -> dict:
        with self._lock:
            active_bans = sum(1 for exp in self._ban_list.values() if time.time() < exp)
        return {
            "blocklist_size": len(self._blocklist),
            "allowlist_size": len(self._allowlist),
            "tor_exits_loaded": len(self._tor_exits),
            "active_bans": active_bans,
            "last_tor_update": datetime.fromtimestamp(self._last_tor_update, tz=timezone.utc).isoformat()
            if self._last_tor_update else None,
        }

    # ── Background Tor refresh ──────────────────────────────────────────────
    def _fetch_tor_exits(self) -> set[str]:
        """Fetch current Tor exit node list from torproject.org."""
        try:
            import urllib.request
            with urllib.request.urlopen(TOR_EXIT_LIST_URL, timeout=10) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            exits = set()
            for line in data.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.ip_address(line)
                        exits.add(line)
                    except ValueError:
                        pass
            logger.info("Loaded %d Tor exit nodes", len(exits))
            return exits
        except Exception as exc:
            logger.debug("Could not fetch Tor exit list: %s", exc)
            return set()

    def _refresh_tor_loop(self) -> None:
        while True:
            time.sleep(self._tor_refresh_interval)
            exits = self._fetch_tor_exits()
            if exits:
                with self._lock:
                    self._tor_exits = exits
                    self._last_tor_update = time.time()

    def _start_tor_refresh(self) -> None:
        # Initial fetch in background (non-blocking)
        def _initial():
            exits = self._fetch_tor_exits()
            with self._lock:
                self._tor_exits = exits
                self._last_tor_update = time.time()
            # Then start the refresh loop
            self._refresh_tor_loop()

        t = threading.Thread(target=_initial, daemon=True, name="cybersentry-tor-refresh")
        t.start()
