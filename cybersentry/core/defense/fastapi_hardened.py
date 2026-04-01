"""
CyberSentry Hardened Middleware — all 5 defence layers in one.

Replaces the basic CyberSentryMiddleware with a production-hardened version:

Layer 1 — IP reputation (Tor, datacenter, known abusive ranges, geo block)
Layer 2 — Flood guard (DDoS, slow loris, header/body bomb, conn rate)
Layer 3 — Smart fingerprinting (bot detection, scanner detection, honeypot)
Layer 4 — OWASP attack detection (SQLi, XSS, CMDi, Path Traversal, SSRF, SSTI)
Layer 5 — Tarpit + honeypot traps (waste attacker time, auto-ban)

Usage:
    from cybersentry.middleware.fastapi_hardened import HardenedMiddleware

    app.add_middleware(
        HardenedMiddleware,
        # Optional overrides:
        block_tor=True,
        flood_rpm=300,
        honeypot_paths={"/secret-admin", "/debug"},
        on_threat=my_async_callback,
    )
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from typing import Any, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp

from cybersentry.core.defense.ip_reputation import IPReputationEngine, IPVerdict
from cybersentry.core.defense.flood_guard import FloodGuard
from cybersentry.core.defense.fingerprint import FingerprintEngine
from cybersentry.core.defense.tarpit import TarpitEngine, HoneypotManager, ChallengeEngine
from cybersentry.core.detection.engine import DetectionEngine
from cybersentry.config import settings

import logging
logger = logging.getLogger("cybersentry.hardened")


# Security headers added to every response
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cache-Control": "no-store",   # prevent sensitive data caching
}
# Headers to remove (fingerprinting)
_REMOVE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


class ThreatEvent:
    """A detected threat event for logging and callbacks."""
    def __init__(
        self,
        request_id: str,
        ip: str,
        path: str,
        method: str,
        layer: str,
        threat_type: str,
        severity: str,
        action: str,
        details: str,
    ):
        self.request_id = request_id
        self.ip = ip
        self.path = path
        self.method = method
        self.layer = layer
        self.threat_type = threat_type
        self.severity = severity
        self.action = action
        self.details = details
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return self.__dict__


class HardenedMiddleware(BaseHTTPMiddleware):
    """
    Production-hardened CyberSentry middleware.
    Stacks all 5 defence layers with minimal overhead (all in-memory, no I/O).

    Typical overhead: < 1ms per request on clean traffic.
    """

    def __init__(
        self,
        app: ASGIApp,
        # Layer 1: IP reputation
        block_tor: bool = True,
        block_abusive_ranges: bool = True,
        challenge_datacenters: bool = True,
        blocked_countries: set[str] | None = None,
        ip_allowlist: set[str] | None = None,
        ip_blocklist: set[str] | None = None,
        # Layer 2: Flood guard
        flood_rpm: int = 300,
        flood_burst: int = 50,
        max_header_size: int = 8192,
        max_body_mb: float = 10.0,
        global_rpm: int = 10000,
        slow_loris_timeout: float = 10.0,
        # Layer 3: Fingerprinting
        bot_challenge_score: int = 50,
        bot_block_score: int = 80,
        honeypot_fields: set[str] | None = None,
        # Layer 4: Attack detection
        block_on_severity: list[str] | None = None,
        # Layer 5: Honeypot + tarpit
        honeypot_paths: set[str] | None = None,
        tarpit_delay: float = 30.0,
        tarpit_bad_bots: bool = True,
        # General
        on_threat: Callable[[ThreatEvent], Any] | None = None,
        skip_paths: set[str] | None = None,
        mode: str = "block",   # block | monitor | tarpit
    ):
        super().__init__(app)
        self.mode = mode
        self.on_threat = on_threat
        self.skip_paths: set[str] = skip_paths or {"/health", "/healthz", "/ping", "/metrics", "/docs", "/openapi.json", "/redoc"}

        # Layer 1
        self._ip_rep = IPReputationEngine(
            blocked_countries=blocked_countries,
            allowlist=ip_allowlist,
            blocklist=ip_blocklist,
            block_tor=block_tor,
            challenge_datacenters=challenge_datacenters,
            block_abusive=block_abusive_ranges,
        )

        # Layer 2
        self._flood = FloodGuard(
            http_flood_rpm=flood_rpm,
            http_flood_burst=flood_burst,
            max_header_size=max_header_size,
            max_body_size=int(max_body_mb * 1024 * 1024),
            global_rpm=global_rpm,
            slow_loris_header_timeout=slow_loris_timeout,
        )

        # Layer 3
        self._fingerprint = FingerprintEngine(
            bot_score_challenge_threshold=bot_challenge_score,
            bot_score_block_threshold=bot_block_score,
        )
        self._honeypot_fields: set[str] = honeypot_fields or {"_email", "website", "url_field", "phone_number_confirm"}

        # Layer 4
        self._detection = DetectionEngine(
            block_on_severity=block_on_severity or (["critical", "high"] if mode == "block" else [])
        )

        # Layer 5
        self._tarpit = TarpitEngine(delay_seconds=tarpit_delay)
        self._honeypot = HoneypotManager(
            extra_paths=honeypot_paths,
            auto_ban_callback=lambda ip, dur: self._ip_rep.ban(ip, dur),
        )
        self._challenge = ChallengeEngine()
        self._tarpit_bad_bots = tarpit_bad_bots

        # Event log
        self._events: deque[ThreatEvent] = deque(maxlen=5000)

        # Counters
        self._stats = {
            "total_requests": 0,
            "blocked": 0,
            "tarpitted": 0,
            "challenged": 0,
            "attacks_detected": 0,
            "honeypot_hits": 0,
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.monotonic()
        req_id = str(uuid.uuid4())[:8]
        ip = self._get_ip(request)
        path = request.url.path
        method = request.method
        headers = dict(request.headers)

        self._stats["total_requests"] += 1

        # ── Skip whitelisted paths ─────────────────────────────────────────
        if path in self.skip_paths:
            resp = await call_next(request)
            self._apply_security_headers(resp)
            return resp

        # ── LAYER 1: IP Reputation ─────────────────────────────────────────
        ip_result = self._ip_rep.check(ip)
        if ip_result.verdict == IPVerdict.BLOCK:
            return self._threat_response(
                req_id, ip, path, method, "layer1", "ip_reputation",
                "high", ip_result.reason, 403,
                {"X-Block-Reason": "ip_reputation"},
            )
        if ip_result.verdict == IPVerdict.TARPIT:
            return await self._tarpit_response(req_id, ip, path, method, "layer1", ip_result.reason)

        # ── LAYER 2: Flood / connection guard ─────────────────────────────
        header_size = sum(len(k) + len(v) for k, v in headers.items())
        content_length = int(headers.get("content-length", 0) or 0)

        flood_ok, flood_reason = self._flood.check_request(
            ip=ip,
            method=method,
            path=path,
            header_size=header_size,
            content_length=content_length,
            user_agent=headers.get("user-agent", ""),
        )
        if not flood_ok:
            severity = "critical" if "banned" in flood_reason else "high"
            return self._threat_response(
                req_id, ip, path, method, "layer2", "flood",
                severity, flood_reason, 429,
                {"Retry-After": "60"},
            )

        # ── LAYER 3: Bot fingerprinting ───────────────────────────────────
        form_data: dict | None = None
        body_bytes = b""
        body_str: str | None = None

        if method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                body_str = body_bytes.decode("utf-8", errors="replace")
                ct = headers.get("content-type", "")
                if "application/json" in ct:
                    form_data = json.loads(body_bytes) if body_bytes else {}
                elif "application/x-www-form-urlencoded" in ct or "multipart" in ct:
                    from urllib.parse import parse_qs
                    form_data = {k: v[0] for k, v in parse_qs(body_str).items()}
            except Exception:
                pass

        fp_result = self._fingerprint.fingerprint(
            ip=ip,
            method=method,
            path=path,
            headers=headers,
            form_data=form_data,
            honeypot_fields=self._honeypot_fields,
        )

        if fp_result.recommended_action == "block" and not fp_result.is_known_good_bot:
            if self._tarpit_bad_bots and self.mode != "block":
                return await self._tarpit_response(req_id, ip, path, method, "layer3", "bad_bot")
            return self._threat_response(
                req_id, ip, path, method, "layer3", "bot",
                "high", f"bot_score:{fp_result.bot_score}", 403,
            )

        if fp_result.recommended_action == "challenge":
            # Issue challenge (in a real deployment, redirect to JS challenge page)
            self._record_event(ThreatEvent(
                request_id=req_id, ip=ip, path=path, method=method,
                layer="layer3", threat_type="challenge",
                severity="medium", action="challenge",
                details=f"bot_score:{fp_result.bot_score} signals:{','.join(fp_result.signals[:3])}",
            ))

        # ── LAYER 5A: Honeypot path check ─────────────────────────────────
        if self._honeypot.is_honeypot(path):
            self._stats["honeypot_hits"] += 1
            self._record_event(ThreatEvent(
                request_id=req_id, ip=ip, path=path, method=method,
                layer="layer5", threat_type="honeypot",
                severity="high", action="ban",
                details=f"honeypot_path:{path}",
            ))
            # Ban the IP via reputation engine
            self._ip_rep.ban(ip, 86400)
            # Return fake response to waste scanner time
            status, body = self._honeypot.get_fake_response(path)
            resp = PlainTextResponse(body, status_code=status)
            self._apply_security_headers(resp)
            return resp

        # ── LAYER 4: OWASP attack detection ──────────────────────────────
        body_dict = form_data or (json.loads(body_bytes) if body_bytes else None)
        analysis = self._detection.analyze(
            request_id=req_id,
            path=path,
            method=method,
            params=dict(request.query_params),
            body=body_dict,
            headers=headers,
            source_ip=ip,
        )

        if analysis.is_attack:
            self._stats["attacks_detected"] += 1
            for detection in analysis.detections:
                self._record_event(ThreatEvent(
                    request_id=req_id, ip=ip, path=path, method=method,
                    layer="layer4", threat_type=detection.rule_id,
                    severity=detection.severity, action="block" if analysis.blocked else "log",
                    details=f"matched_in:{detection.matched_in}",
                ))

        if analysis.blocked and self.mode == "block":
            self._stats["blocked"] += 1
            return self._threat_response(
                req_id, ip, path, method, "layer4", analysis.threat_level,
                analysis.threat_level, "attack_blocked", 403,
            )

        # ── Forward to application ─────────────────────────────────────────
        resp = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        self._apply_security_headers(resp)
        resp.headers["X-Request-ID"] = req_id

        if analysis.is_attack:
            resp.headers["X-CyberSentry-Threat"] = analysis.threat_level

        return resp

    # ── Helpers ───────────────────────────────────────────────────────────

    def _threat_response(
        self,
        req_id: str,
        ip: str,
        path: str,
        method: str,
        layer: str,
        threat_type: str,
        severity: str,
        reason: str,
        status: int,
        extra_headers: dict | None = None,
    ) -> JSONResponse:
        self._stats["blocked"] += 1
        event = ThreatEvent(
            request_id=req_id, ip=ip, path=path, method=method,
            layer=layer, threat_type=threat_type,
            severity=severity, action="block", details=reason,
        )
        self._record_event(event)

        headers = {
            "X-Request-ID": req_id,
            "X-CyberSentry": "blocked",
            **(extra_headers or {}),
        }
        # Add security headers to error responses too
        headers.update(_SECURITY_HEADERS)

        return JSONResponse(
            status_code=status,
            content={
                "error": "request_blocked",
                "request_id": req_id,
                "message": "This request was blocked by CyberSentry.",
            },
            headers=headers,
        )

    async def _tarpit_response(
        self, req_id: str, ip: str, path: str, method: str, layer: str, reason: str
    ) -> Response:
        self._stats["tarpitted"] += 1
        self._record_event(ThreatEvent(
            request_id=req_id, ip=ip, path=path, method=method,
            layer=layer, threat_type="tarpit",
            severity="medium", action="tarpit", details=reason,
        ))
        # Slow delay — wastes attacker threads
        await asyncio.sleep(self._tarpit.delay)
        return JSONResponse(
            status_code=200,
            content={"status": "ok"},
            headers={"X-Request-ID": req_id},
        )

    def _apply_security_headers(self, response: Response) -> None:
        for k, v in _SECURITY_HEADERS.items():
            response.headers[k] = v
        for k in _REMOVE_HEADERS:
            response.headers.pop(k, None)

    def _record_event(self, event: ThreatEvent) -> None:
        self._events.append(event)
        if self.on_threat:
            try:
                asyncio.create_task(self.on_threat(event)) if asyncio.get_event_loop().is_running() \
                    else None
            except Exception:
                pass

    def _get_ip(self, request: Request) -> str:
        for header in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
            val = request.headers.get(header)
            if val:
                return val.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    # ── Public API ────────────────────────────────────────────────────────

    def ban_ip(self, ip: str, duration_seconds: int = 3600) -> None:
        """Manually ban an IP from all layers."""
        self._ip_rep.ban(ip, duration_seconds)
        self._flood.ban_ip(ip, duration_seconds)

    def allow_ip(self, ip: str) -> None:
        """Add IP to allowlist (bypass all checks)."""
        self._ip_rep.add_to_allowlist(ip)

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "ip_reputation": self._ip_rep.get_stats(),
            "flood_guard": self._flood.get_stats(),
            "honeypot": self._honeypot.get_stats(),
            "tarpit": self._tarpit.get_stats(),
        }

    def get_recent_threats(self, limit: int = 100) -> list[dict]:
        return [e.to_dict() for e in list(self._events)[-limit:]]