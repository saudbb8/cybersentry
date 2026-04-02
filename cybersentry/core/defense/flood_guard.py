"""
CyberSentry Flood Guard.
Protects against HTTP floods, slow loris, header overflow,
body bombs, and connection rate attacks.
"""
from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class FloodEvent:
    ip: str
    attack_type: str
    value: float
    threshold: float
    action: str
    timestamp: float = field(default_factory=time.time)


class SlidingWindowCounter:
    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def add(self) -> int:
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
    def __init__(
        self,
        http_flood_rpm: int = 300,
        http_flood_burst: int = 50,
        slow_loris_timeout: float = 10.0,
        max_header_size: int = 8192,
        max_body_size: int = 10 * 1024 * 1024,
        conn_rate_per_sec: int = 20,
        global_rpm: int = 10000,
        ban_threshold_rpm: int = 1000,
        ban_duration_seconds: int = 3600,
    ):
        self.flood_rpm = http_flood_rpm
        self.burst_limit = http_flood_burst
        self.loris_timeout = slow_loris_timeout
        self.max_header = max_header_size
        self.max_body = max_body_size
        self.conn_rate = conn_rate_per_sec
        self.global_rpm = global_rpm
        self.ban_threshold = ban_threshold_rpm
        self.ban_duration = ban_duration_seconds

        self._ip_rpm: dict[str, SlidingWindowCounter] = defaultdict(lambda: SlidingWindowCounter(60))
        self._ip_burst: dict[str, SlidingWindowCounter] = defaultdict(lambda: SlidingWindowCounter(10))
        self._ip_conn: dict[str, SlidingWindowCounter] = defaultdict(lambda: SlidingWindowCounter(1))
        self._global = SlidingWindowCounter(60)
        self._bans: dict[str, float] = {}
        self._events: deque[FloodEvent] = deque(maxlen=1000)

    def is_banned(self, ip: str) -> bool:
        exp = self._bans.get(ip)
        if exp and time.time() < exp:
            return True
        if exp:
            del self._bans[ip]
        return False

    def ban_ip(self, ip: str, duration: int | None = None) -> None:
        self._bans[ip] = time.time() + (duration or self.ban_duration)

    def check_request(
        self,
        ip: str,
        method: str = "GET",
        path: str = "/",
        header_size: int = 0,
        content_length: int = 0,
        user_agent: str = "",
    ) -> tuple[bool, str]:
        if self.is_banned(ip):
            return False, "ip_banned"

        if header_size > self.max_header:
            self._log(ip, "header_overflow", header_size, self.max_header, "block")
            self.ban_ip(ip, 300)
            return False, f"header_too_large:{header_size}"

        if content_length > self.max_body:
            self._log(ip, "body_bomb", content_length, self.max_body, "block")
            return False, f"body_too_large:{content_length}"

        conn_count = self._ip_conn[ip].add()
        if conn_count > self.conn_rate:
            self._log(ip, "conn_rate", conn_count, self.conn_rate, "block")
            self.ban_ip(ip, 60)
            return False, f"conn_rate_exceeded:{conn_count}/s"

        burst = self._ip_burst[ip].add()
        if burst > self.burst_limit:
            self._log(ip, "flood_burst", burst, self.burst_limit, "block")
            if burst > self.burst_limit * 3:
                self.ban_ip(ip, 300)
                return False, f"flood_burst_banned:{burst}"
            return False, f"flood_burst:{burst}"

        rpm = self._ip_rpm[ip].add()
        if rpm > self.ban_threshold:
            self._log(ip, "flood", rpm, self.ban_threshold, "ban")
            self.ban_ip(ip)
            return False, f"flood_banned:{rpm}rpm"
        if rpm > self.flood_rpm:
            self._log(ip, "flood", rpm, self.flood_rpm, "block")
            return False, f"flood:{rpm}rpm"

        global_count = self._global.add()
        if global_count > self.global_rpm:
            return False, f"global_rpm:{global_count}"

        return True, "ok"

    def get_stats(self) -> dict:
        active_bans = sum(1 for e in self._bans.values() if time.time() < e)
        return {
            "global_rpm": self._global.count(),
            "active_bans": active_bans,
            "recent_events": len(self._events),
        }

    def recent_events(self, limit: int = 50) -> list[FloodEvent]:
        return list(self._events)[-limit:]

    def _log(self, ip, attack_type, value, threshold, action):
        self._events.append(FloodEvent(ip=ip, attack_type=attack_type, value=value, threshold=threshold, action=action))
