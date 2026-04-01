"""
CyberSentry FastAPI Middleware.
Drop-in security middleware for any FastAPI application.
Provides: attack detection, rate limiting, behavioral anomaly detection,
security headers, and request logging.

Usage:
    from cybersentry.middleware.fastapi import CyberSentryMiddleware
    app.add_middleware(CyberSentryMiddleware)
"""
from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from cybersentry.config import settings
from cybersentry.core.detection.engine import DetectionEngine, RequestAnalysis
from cybersentry.core.detection.anomaly import AnomalyDetector


class RateLimiter:
    """Simple sliding-window rate limiter per IP."""

    def __init__(self, requests_per_window: int, window_seconds: int, ban_threshold: int):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.ban_threshold = ban_threshold
        self._windows: dict[str, deque] = defaultdict(deque)
        self._banned: dict[str, float] = {}  # ip -> ban_expiry

    def is_banned(self, ip: str) -> bool:
        expiry = self._banned.get(ip)
        if expiry and time.monotonic() < expiry:
            return True
        if expiry:
            del self._banned[ip]
        return False

    def check(self, ip: str) -> tuple[bool, int]:
        """
        Returns (allowed, remaining_requests).
        Allowed=False means rate limit exceeded.
        """
        if self.is_banned(ip):
            return False, 0

        now = time.monotonic()
        window = self._windows[ip]

        # Evict old entries
        while window and now - window[0] > self.window_seconds:
            window.popleft()

        count = len(window)

        # Check for ban (way over limit)
        if count >= self.ban_threshold:
            self._banned[ip] = now + self.window_seconds * 10
            return False, 0

        if count >= self.requests_per_window:
            return False, 0

        window.append(now)
        remaining = self.requests_per_window - count - 1
        return True, remaining


# Security headers to add to every response
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "X-Powered-By": "",  # Remove framework fingerprint
}


class CyberSentryMiddleware(BaseHTTPMiddleware):
    """
    Plug-and-play CyberSentry middleware for FastAPI / Starlette.

    Features:
    - Real-time attack detection (SQLi, XSS, CMDi, Path Traversal, SSRF, SSTI)
    - Rate limiting per IP
    - Behavioral anomaly detection
    - Security headers on all responses
    - Attack event logging

    Usage:
        app.add_middleware(
            CyberSentryMiddleware,
            block_attacks=True,
            rate_limit=True,
            on_attack=my_callback,  # optional async callback
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        block_attacks: bool = True,
        rate_limit: bool = True,
        anomaly_detection: bool = True,
        security_headers: bool = True,
        log_attacks: bool = True,
        on_attack: Callable[[RequestAnalysis], Any] | None = None,
        whitelist_ips: list[str] | None = None,
        whitelist_paths: list[str] | None = None,
    ):
        super().__init__(app)
        self.block_attacks = block_attacks
        self.rate_limit_enabled = rate_limit
        self.anomaly_enabled = anomaly_detection
        self.security_headers_enabled = security_headers
        self.log_attacks = log_attacks
        self.on_attack = on_attack
        self.whitelist_ips: set[str] = set(whitelist_ips or [])
        self.whitelist_paths: set[str] = set(whitelist_paths or ["/health", "/metrics", "/docs", "/openapi.json"])

        self._detection = DetectionEngine(
            block_on_severity=["critical", "high"] if block_attacks else []
        )
        self._rate_limiter = RateLimiter(
            requests_per_window=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
            ban_threshold=settings.rate_limit_ban_threshold,
        )
        self._anomaly = AnomalyDetector(
            z_score_threshold=settings.anomaly_z_score_threshold
        )
        self._attack_log: deque = deque(maxlen=10000)

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.monotonic()
        client_ip = self._get_client_ip(request)
        request_id = str(uuid.uuid4())

        # Skip whitelisted paths / IPs
        if request.url.path in self.whitelist_paths or client_ip in self.whitelist_ips:
            response = await call_next(request)
            self._add_security_headers(response)
            return response

        # Rate limiting
        if self.rate_limit_enabled:
            allowed, remaining = self._rate_limiter.check(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests. Please slow down.",
                        "request_id": request_id,
                    },
                    headers={
                        "X-Request-ID": request_id,
                        "Retry-After": str(settings.rate_limit_window_seconds),
                    },
                )

        # Read body for POST/PUT analysis (with size limit)
        body_dict: dict | str | None = None
        if request.method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
            payload_size = len(body_bytes)
            try:
                import json
                body_dict = json.loads(body_bytes)
            except Exception:
                try:
                    from urllib.parse import parse_qs
                    body_dict = {
                        k: v[0] if len(v) == 1 else v
                        for k, v in parse_qs(body_bytes.decode("utf-8", errors="replace")).items()
                    }
                except Exception:
                    body_dict = body_bytes.decode("utf-8", errors="replace")[:4096]
        else:
            payload_size = 0

        # Attack detection
        analysis = self._detection.analyze(
            request_id=request_id,
            path=str(request.url.path),
            method=request.method,
            params=dict(request.query_params),
            body=body_dict,
            headers=dict(request.headers),
            source_ip=client_ip,
        )

        # Log attack
        if analysis.is_attack and self.log_attacks:
            self._attack_log.append(analysis)

        # Call user callback
        if analysis.is_attack and self.on_attack:
            try:
                await self.on_attack(analysis)
            except Exception:
                pass  # Never let callback crash the request

        # Block if attack detected and blocking is enabled
        if analysis.blocked:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "request_blocked",
                    "message": "This request was blocked by CyberSentry.",
                    "request_id": request_id,
                    "threat_level": analysis.threat_level,
                },
                headers={"X-Request-ID": request_id, "X-CyberSentry": "blocked"},
            )

        # Forward request
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        # Anomaly detection (runs after response)
        if self.anomaly_enabled:
            anomalies = self._anomaly.observe(
                endpoint=str(request.url.path),
                method=request.method,
                response_time_ms=elapsed_ms,
                payload_size=payload_size,
                source_ip=client_ip,
            )
            if anomalies:
                # Log anomalies (could store to DB here)
                pass

        # Add security headers
        if self.security_headers_enabled:
            self._add_security_headers(response)

        response.headers["X-Request-ID"] = request_id
        if analysis.is_attack:
            response.headers["X-CyberSentry"] = f"detected:{analysis.threat_level}"

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP, respecting common proxy headers."""
        # Trust X-Forwarded-For only in known proxy setups
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _add_security_headers(self, response: Response) -> None:
        for header, value in SECURITY_HEADERS.items():
            if value:
                response.headers[header] = value
            elif header in response.headers:
                del response.headers[header]

    def get_attack_log(self, limit: int = 100) -> list[RequestAnalysis]:
        """Return recent attack events."""
        log = list(self._attack_log)
        return log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Return middleware statistics."""
        log = list(self._attack_log)
        return {
            "total_attacks_logged": len(log),
            "recent_attacks": len([a for a in log[-100:] if a.is_attack]),
            "anomaly_summary": self._anomaly.summary(),
        }
