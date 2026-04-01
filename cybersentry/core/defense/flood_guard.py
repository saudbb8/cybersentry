"""
CyberSentry Flood Guard — Layer 2 defence.

Protects against:
  - HTTP flood (high volume from single IP or distributed)
  - Slow loris (connection held open with trickle of data)
  - Header-overflow attacks (oversized headers)
  - Payload-bomb attacks (huge request bodies)
  - Connection rate limiting (too many new connections/sec)

Works at the application layer (ASGI/WSGI level).
For full volumetric DDoS mitigation, pair with Cloudflare / AWS Shield.
"""
from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FloodEvent:
    ip: str
    attack_type: str    # flood | slow_loris | header_overflow | body_bomb | conn_rate
    requests_per_min: float
    threshold: float
    action: str         # block | tarpit | log
    timestamp: float = field(default_factory=time.time)


class SlidingWindowCounter:
    """Thread-safe sliding window counter for request rates."""

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def add(self) -> int:
        """Record a hit. Returns current count in window."""
        now = time.monotonic()
        with self._lock:
            self._timestamps.append(now)
            cutoff = now - self.window
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            return len(self._timestamps)

    def count(self) -> int:
        now = time.monotonic()
        with self._lock:
            cutoff = now - self.window
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            return len(self._timestamps)


class FloodGuard:
    """
    Application-layer flood and slow-loris protection.

    Thresholds (all configurable):
      - http_flood_rpm: max requests/min per IP before block
      - slow_loris_timeout: max seconds to receive headers
      - max_header_size: max total header size in bytes
      - max_body_size: max request body size in bytes
      - conn_rate_per_sec: max new connections/sec per IP
      - global_rpm: max total requests/min across all IPs
    """

    def __init__(
        self,
        http_flood_rpm: int = 300,           # per IP
        http_flood_burst: int = 50,           # per 10s burst
        slow_loris_header_timeout: float = 10.0,  # seconds to finish headers
        max_header_size: int = 8192,          # 8 KB
        max_body_size: int = 10 * 1024 * 1024,  # 10 MB
        conn_rate_per_sec: int = 20,          # new connections/sec per IP
        global_rpm: int = 10000,              # total across all IPs
        tarpit_enabled: bool = True,
        ban_threshold_rpm: int = 1000,        # above this → hard ban
        ban_duration_seconds: int = 3600,
    ):
        self.http_flood_rpm = http_flood_rpm
        self.http_flood_burst = http_flood_burst
        self.slow_loris_timeout = slow_loris_header_timeout
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.conn_rate_per_sec = conn_rate_per_sec
        self.global_rpm = global_rpm
        self.tarpit_enabled = tarpit_enabled
        self.ban_threshold_rpm = ban_threshold_rpm
        self.ban_duration_seconds = ban_duration_seconds

        # Per-IP minute counters
        self._ip_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(60)
        )
        # Per-IP 10-second burst counters
        self._ip_burst_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(10)
        )
        # Per-IP connection-rate counters (1 second window)
        self._conn_counters: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(1)
        )
        # Global counter
        self._global_counter = SlidingWindowCounter(60)

        # Active slow-loris connections: ip -> {conn_id: start_time}
        self._slow_loris_tracking: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = threading.RLock()

        # Temporary bans from flood guard
        self._bans: dict[str, float] = {}   # ip -> expiry

        self._events: deque[FloodEvent] = deque(maxlen=1000)

    def is_banned(self, ip: str) -> bool:
        expiry = self._bans.get(ip)
        if expiry and time.time() < expiry:
            return True
        if expiry:
            del self._bans[ip]
        return False

    def ban_ip(self, ip: str, duration: int | None = None) -> None:
        self._bans[ip] = time.time() + (duration or self.ban_duration_seconds)

    def check_request(
        self,
        ip: str,
        method: str,
        path: str,
        header_size: int = 0,
        content_length: int = 0,
        user_agent: str = "",
    ) -> tuple[bool, str]:
        """
        Check whether to allow a request.
        Returns (allowed, reason).
        Call this at the START of request processing.
        """
        # Hard ban check
        if self.is_banned(ip):
            return False, "ip_banned"

        # Header size check
        if header_size > self.max_header_size:
            self._record_event(ip, "header_overflow", 0, 0, "block")
            self.ban_ip(ip, 300)
            return False, f"header_too_large:{header_size}"

        # Content-Length check (reject before reading body)
        if content_length > self.max_body_size:
            self._record_event(ip, "body_bomb", 0, 0, "block")
            return False, f"body_too_large:{content_length}"

        # Connection rate (new connections per second)
        conn_count = self._conn_counters[ip].add()
        if conn_count > self.conn_rate_per_sec:
            self._record_event(ip, "conn_rate", conn_count, self.conn_rate_per_sec, "block")
            self.ban_ip(ip, 60)
            return False, f"conn_rate_exceeded:{conn_count}/s"

        # HTTP flood — burst check (50 req / 10s)
        burst_count = self._ip_burst_counters[ip].add()
        if burst_count > self.http_flood_burst:
            self._record_event(ip, "flood_burst", burst_count, self.http_flood_burst, "tarpit")
            if burst_count > self.http_flood_burst * 3:
                self.ban_ip(ip, 300)
                return False, f"flood_burst_banned:{burst_count}"
            return False, f"flood_burst:{burst_count}"

        # HTTP flood — per-minute check
        rpm = self._ip_counters[ip].add()
        if rpm > self.ban_threshold_rpm:
            self._record_event(ip, "flood", rpm, self.ban_threshold_rpm, "ban")
            self.ban_ip(ip)
            return False, f"flood_banned:{rpm}rpm"
        if rpm > self.http_flood_rpm:
            self._record_event(ip, "flood", rpm, self.http_flood_rpm, "block")
            return False, f"flood:{rpm}rpm"

        # Global rate check
        global_count = self._global_counter.add()
        if global_count > self.global_rpm:
            return False, f"global_rpm_exceeded:{global_count}"

        return True, "ok"

    def check_body_size(self, ip: str, actual_size: int) -> tuple[bool, str]:
        """
        Check actual body size after reading.
        Call this AFTER reading the body.
        """
        if actual_size > self.max_body_size:
            self._record_event(ip, "body_bomb", actual_size, self.max_body_size, "block")
            self.ban_ip(ip, 600)
            return False, f"body_bomb:{actual_size}b"
        return True, "ok"

    def track_connection(self, ip: str, conn_id: str) -> None:
        """Register a new connection for slow-loris tracking."""
        with self._lock:
            self._slow_loris_tracking[ip][conn_id] = time.monotonic()

    def complete_connection(self, ip: str, conn_id: str) -> None:
        """Mark connection as completed (headers fully received)."""
        with self._lock:
            self._slow_loris_tracking[ip].pop(conn_id, None)

    def sweep_slow_loris(self) -> list[tuple[str, str]]:
        """
        Identify and evict connections that are taking too long to send headers.
        Returns list of (ip, conn_id) to forcibly close.
        Should be called periodically (e.g. every 5 seconds).
        """
        now = time.monotonic()
        evict = []
        with self._lock:
            for ip, conns in list(self._slow_loris_tracking.items()):
                for conn_id, start in list(conns.items()):
                    if now - start > self.slow_loris_timeout:
                        evict.append((ip, conn_id))
                        del conns[conn_id]
                        self._record_event(ip, "slow_loris", 0, 0, "block")
        # Auto-ban IPs with multiple slow-loris attempts
        slow_ips: dict[str, int] = {}
        for ip, _ in evict:
            slow_ips[ip] = slow_ips.get(ip, 0) + 1
        for ip, count in slow_ips.items():
            if count >= 3:
                self.ban_ip(ip, 1800)
        return evict

    def get_ip_stats(self, ip: str) -> dict:
        return {
            "rpm": self._ip_counters[ip].count(),
            "burst_10s": self._ip_burst_counters[ip].count(),
            "banned": self.is_banned(ip),
        }

    def get_stats(self) -> dict:
        active_bans = sum(1 for e in self._bans.values() if time.time() < e)
        return {
            "global_rpm": self._global_counter.count(),
            "active_bans": active_bans,
            "recent_events": len(self._events),
        }

    def recent_events(self, limit: int = 50) -> list[FloodEvent]:
        return list(self._events)[-limit:]

    def _record_event(self, ip: str, attack_type: str, rpm: float,
                      threshold: float, action: str) -> None:
        self._events.append(FloodEvent(
            ip=ip, attack_type=attack_type,
            requests_per_min=rpm, threshold=threshold, action=action,
        ))
