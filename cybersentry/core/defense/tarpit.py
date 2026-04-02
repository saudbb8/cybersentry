"""
CyberSentry Tarpit + Honeypot.
Wastes attacker time and auto-bans honeypot triggers.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class HoneypotHit:
    ip: str
    path: str
    method: str
    user_agent: str
    timestamp: float = field(default_factory=time.time)


class TarpitEngine:
    def __init__(self, delay_seconds: float = 30.0, max_concurrent: int = 500):
        self.delay = delay_seconds
        self.max_concurrent = max_concurrent
        self._active = 0
        self._total = 0
        self._wasted_seconds = 0.0

    async def slow_response(self) -> bytes:
        if self._active >= self.max_concurrent:
            await asyncio.sleep(2.0)
            return b"HTTP/1.1 503 Service Unavailable\r\n\r\n"
        self._active += 1
        self._total += 1
        start = time.monotonic()
        try:
            await asyncio.sleep(self.delay)
            self._wasted_seconds += time.monotonic() - start
            return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        finally:
            self._active -= 1

    def get_stats(self) -> dict:
        return {
            "active": self._active,
            "total_tarpitted": self._total,
            "wasted_minutes": round(self._wasted_seconds / 60, 1),
        }


class HoneypotManager:
    DEFAULT_PATHS = {
        "/.env", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/wp-admin", "/wp-login.php", "/wp-config.php",
        "/phpmyadmin", "/adminer.php",
        "/server-status", "/server-info",
        "/actuator", "/actuator/env", "/actuator/health",
        "/config.php", "/.DS_Store",
        "/backup.zip", "/backup.sql", "/dump.sql",
        "/xmlrpc.php", "/shell.php", "/c99.php",
        "/aws.yml", "/.aws/credentials",
        "/etc/passwd", "/proc/self/environ",
    }

    SAFE_PATHS = {"/health", "/healthz", "/ping", "/metrics", "/docs", "/openapi.json", "/robots.txt"}

    def __init__(
        self,
        extra_paths: set[str] | None = None,
        auto_ban_callback: Callable[[str, int], None] | None = None,
        ban_duration: int = 86400,
    ):
        self._paths = self.DEFAULT_PATHS.copy()
        if extra_paths:
            self._paths.update(extra_paths)
        self._ban_cb = auto_ban_callback
        self._ban_duration = ban_duration
        self._hits: list[HoneypotHit] = []
        self._offenders: dict[str, int] = defaultdict(int)

    def is_honeypot(self, path: str) -> bool:
        if path in self.SAFE_PATHS:
            return False
        return path in self._paths

    def record_hit(self, ip: str, path: str, method: str, ua: str) -> HoneypotHit:
        hit = HoneypotHit(ip=ip, path=path, method=method, user_agent=ua)
        self._hits.append(hit)
        self._offenders[ip] += 1
        if self._ban_cb:
            self._ban_cb(ip, self._ban_duration)
        return hit

    def get_fake_response(self, path: str) -> tuple[int, str]:
        fakes = {
            "/.env":        (200, "APP_ENV=production\nDB_PASSWORD=secret123\nAPP_KEY=base64:fake"),
            "/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:company/app.git"),
            "/wp-login.php":(200, "<html><body>WordPress Login</body></html>"),
            "/actuator/env":(200, '{"activeProfiles":["production"]}'),
        }
        return fakes.get(path, (404, "Not Found"))

    def get_stats(self) -> dict:
        return {
            "honeypot_paths": len(self._paths),
            "total_hits": len(self._hits),
            "unique_offenders": len(self._offenders),
            "top_offenders": sorted(self._offenders.items(), key=lambda x: x[1], reverse=True)[:5],
        }
