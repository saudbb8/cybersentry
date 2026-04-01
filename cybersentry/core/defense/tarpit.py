"""
CyberSentry Tarpit + Honeypot Engine — Layer 5 defence.

Tarpit: deliberately slows down bad bots and attackers, wasting
their time and resources instead of simply blocking them.

Honeypot: exposes fake endpoints (robots.txt excluded, admin paths, etc.)
that no legitimate user would ever visit. Anyone who hits them gets
auto-banned.

Why tarpit instead of block?
  - Blocked connections are retried immediately → still loads server
  - Tarpitted connections stay open, tying up attacker threads
  - Attackers can't distinguish tarpit from a slow server
  - Buys time for anomaly detection to gather evidence
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("cybersentry.tarpit")


@dataclass
class HoneypotHit:
    ip: str
    path: str
    method: str
    user_agent: str
    timestamp: float = field(default_factory=time.time)


class TarpitEngine:
    """
    Async tarpit: holds attacker connections open for a configurable delay,
    sending drip responses to simulate a slow-but-alive server.
    """

    def __init__(
        self,
        delay_seconds: float = 30.0,
        drip_interval: float = 1.0,     # send 1 byte every N seconds
        max_concurrent_tarpits: int = 500,
    ):
        self.delay = delay_seconds
        self.drip_interval = drip_interval
        self.max_concurrent = max_concurrent_tarpits
        self._active: int = 0
        self._total_tarpitted: int = 0
        self._wasted_seconds: float = 0.0

    async def tarpit_response(self) -> bytes:
        """
        Async generator that drips HTTP bytes slowly.
        Call this from your ASGI handler for tarpitted requests.
        Returns a slow HTTP 200 response that wastes attacker time.
        """
        if self._active >= self.max_concurrent:
            # At capacity — just delay and close
            await asyncio.sleep(2.0)
            return b"HTTP/1.1 503 Service Unavailable\r\n\r\n"

        self._active += 1
        self._total_tarpitted += 1
        start = time.monotonic()

        try:
            # Start HTTP response (valid headers, open body)
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"X-Server: nginx/1.18.0\r\n"  # fake server header
                b"\r\n"
            )
            elapsed = 0.0
            while elapsed < self.delay:
                await asyncio.sleep(self.drip_interval)
                elapsed += self.drip_interval
                # Drip one chunk byte to keep connection alive
                response += b"1\r\n \r\n"

            response += b"0\r\n\r\n"
            self._wasted_seconds += time.monotonic() - start
            return response
        finally:
            self._active -= 1

    def get_stats(self) -> dict:
        return {
            "active_tarpits": self._active,
            "total_tarpitted": self._total_tarpitted,
            "total_wasted_seconds": round(self._wasted_seconds, 1),
            "wasted_minutes": round(self._wasted_seconds / 60, 1),
        }


class HoneypotManager:
    """
    Manages honeypot trap endpoints.

    Any request to a honeypot path is immediately suspicious —
    real users never visit these paths. We auto-ban the IP.

    Built-in honeypot paths (customizable):
      - /admin, /.env, /.git/config, /wp-admin, /phpmyadmin
      - /config.php, /server-status, /actuator
      - Custom paths you define
    """

    # Default honeypot paths — no legitimate user should ever hit these
    DEFAULT_HONEYPOT_PATHS: set[str] = {
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.git/config",
        "/.git/HEAD",
        "/wp-admin",
        "/wp-login.php",
        "/wp-config.php",
        "/phpmyadmin",
        "/phpMyAdmin",
        "/adminer.php",
        "/admin/config",
        "/server-status",
        "/server-info",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/config.php",
        "/configuration.php",
        "/.DS_Store",
        "/backup.zip",
        "/backup.sql",
        "/dump.sql",
        "/db.sql",
        "/xmlrpc.php",
        "/cgi-bin/",
        "/shell.php",
        "/c99.php",
        "/r57.php",
        "/eval-stdin.php",
        "/aws.yml",
        "/credentials",
        "/.aws/credentials",
        "/etc/passwd",
    }

    # Paths that look like honeypots but are legitimate (exclusions)
    LEGITIMATE_EXCLUSIONS: set[str] = {
        "/health",
        "/healthz",
        "/ping",
        "/status",
        "/metrics",
        "/robots.txt",
        "/favicon.ico",
    }

    def __init__(
        self,
        extra_paths: set[str] | None = None,
        auto_ban_callback: Callable[[str, int], None] | None = None,
        ban_duration_seconds: int = 86400,  # 24 hours
    ):
        self._paths = self.DEFAULT_HONEYPOT_PATHS.copy()
        if extra_paths:
            self._paths.update(extra_paths)
        self._auto_ban_callback = auto_ban_callback
        self._ban_duration = ban_duration_seconds
        self._hits: list[HoneypotHit] = []
        self._offenders: dict[str, int] = defaultdict(int)  # ip -> hit count

    def add_path(self, path: str) -> None:
        self._paths.add(path)

    def remove_path(self, path: str) -> None:
        self._paths.discard(path)

    def is_honeypot(self, path: str) -> bool:
        """Return True if path is a honeypot trap."""
        if path in self.LEGITIMATE_EXCLUSIONS:
            return False
        if path in self._paths:
            return True
        # Check prefix patterns
        for trap in self._paths:
            if trap.endswith("/") and path.startswith(trap):
                return True
        return False

    def record_hit(
        self,
        ip: str,
        path: str,
        method: str,
        user_agent: str,
    ) -> HoneypotHit:
        """Record a honeypot hit and trigger auto-ban."""
        hit = HoneypotHit(ip=ip, path=path, method=method, user_agent=user_agent)
        self._hits.append(hit)
        self._offenders[ip] += 1

        logger.warning(
            "Honeypot triggered: %s %s from %s (UA: %s)",
            method, path, ip, user_agent[:80]
        )

        if self._auto_ban_callback:
            self._auto_ban_callback(ip, self._ban_duration)

        return hit

    def get_fake_response(self, path: str) -> tuple[int, str]:
        """
        Return a convincing fake response for honeypot paths.
        This makes scanners think they found something and dig deeper
        (wasting more time) or think the server is vulnerable.
        """
        # Mimic what a vulnerable server might return
        fake_responses = {
            "/.env": (200, "APP_ENV=production\nDB_PASSWORD=password123\nAPP_KEY=base64:fake"),
            "/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:fake/repo.git"),
            "/wp-login.php": (200, "<html><body>WordPress Login</body></html>"),
            "/phpmyadmin": (200, "<html><body>phpMyAdmin 5.0.0</body></html>"),
            "/actuator/env": (200, '{"activeProfiles":["production"],"propertySources":[]}'),
        }
        if path in fake_responses:
            return fake_responses[path]
        return (404, "Not Found")

    def get_offenders(self) -> dict[str, int]:
        return dict(self._offenders)

    def get_recent_hits(self, limit: int = 50) -> list[HoneypotHit]:
        return self._hits[-limit:]

    def get_stats(self) -> dict:
        return {
            "honeypot_paths": len(self._paths),
            "total_hits": len(self._hits),
            "unique_offenders": len(self._offenders),
            "top_offenders": sorted(
                self._offenders.items(), key=lambda x: x[1], reverse=True
            )[:10],
        }


# ── Challenge / CAPTCHA token engine ─────────────────────────────────────────
class ChallengeEngine:
    """
    Issues and validates challenge tokens for suspicious requests.
    Instead of a CAPTCHA (requires external service), we use a
    proof-of-work challenge: client must solve a simple hash puzzle.

    This stops most bots without user friction for humans
    (modern browsers solve it in <100ms via JS).
    """

    def __init__(self, difficulty: int = 4, token_ttl: int = 300):
        self.difficulty = difficulty   # leading zeros required in hash
        self.token_ttl = token_ttl
        self._issued: dict[str, float] = {}   # token -> issued_at
        self._solved: set[str] = set()

    def issue_challenge(self, ip: str) -> dict:
        """Issue a proof-of-work challenge."""
        import secrets
        nonce = secrets.token_hex(16)
        target = "0" * self.difficulty
        token = hashlib.sha256(f"{ip}:{nonce}:{time.time()}".encode()).hexdigest()[:16]
        self._issued[token] = time.time()
        return {
            "challenge_token": token,
            "nonce": nonce,
            "target": target,
            "difficulty": self.difficulty,
            "message": (
                f"Find a number X such that sha256('{nonce}:X') starts with '{target}'. "
                "Submit X as 'solution' header."
            ),
        }

    def verify_solution(self, token: str, solution: str) -> bool:
        """Verify a proof-of-work solution."""
        issued_at = self._issued.get(token)
        if not issued_at:
            return False
        if time.time() - issued_at > self.token_ttl:
            del self._issued[token]
            return False
        if token in self._solved:
            return False   # prevent replay

        # Verify the hash
        challenge_hash = hashlib.sha256(f"{token}:{solution}".encode()).hexdigest()
        if challenge_hash.startswith("0" * self.difficulty):
            self._solved.add(token)
            return True
        return False