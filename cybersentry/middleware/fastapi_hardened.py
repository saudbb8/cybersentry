"""
CyberSentry Hardened Middleware.
All 6 defence layers in one drop-in middleware.

Usage:
    from cybersentry.middleware.fastapi_hardened import HardenedMiddleware
    app.add_middleware(HardenedMiddleware)
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import deque
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from cybersentry.core.defense.ip_reputation import IPReputationEngine, IPVerdict
from cybersentry.core.defense.flood_guard import FloodGuard
from cybersentry.core.defense.fingerprint import FingerprintEngine
from cybersentry.core.defense.tarpit import TarpitEngine, HoneypotManager
from cybersentry.core.detection.engine import DetectionEngine
from cybersentry.config import settings

import logging
logger = logging.getLogger("cybersentry.hardened")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


class ThreatEvent:
    def __init__(self, request_id, ip, path, method, layer, threat_type, severity, action, details):
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

    def to_dict(self):
        return self.__dict__


class HardenedMiddleware(BaseHTTPMiddleware):
    """
    Production-hardened CyberSentry middleware.

    Layer 1 — IP reputation (Tor, abusive ranges, datacenter)
    Layer 2 — Flood guard (DDoS, slow loris, body bomb, conn rate)
    Layer 3 — Bot fingerprinting (UA, timing, honeypot fields)
    Layer 4 — OWASP attack detection (SQLi, XSS, CMDi, etc.)
    Layer 5 — Honeypot traps (auto-ban on /.env, /.git, etc.)
    Layer 6 — Security headers on all responses
    """

    def __init__(
        self,
        app: ASGIApp,
        # Layer 1
        block_tor: bool = True,
        block_abusive: bool = True,
        challenge_datacenters: bool = True,
        ip_allowlist: set[str] | None = None,
        ip_blocklist: set[str] | None = None,
        # Layer 2
        flood_rpm: int = 300,
        flood_burst: int = 50,
        max_header_kb: int = 8,
        max_body_mb: float = 10.0,
        global_rpm: int = 10000,
        # Layer 3
        bot_challenge_score: int = 50,
        bot_block_score: int = 80,
        honeypot_fields: set[str] | None = None,
        # Layer 4
        block_on_severity: list[str] | None = None,
        # Layer 5
        honeypot_paths: set[str] | None = None,
        tarpit_delay: float = 30.0,
        # General
        on_threat: Callable[[ThreatEvent], Any] | None = None,
        skip_paths: set[str] | None = None,
        mode: str = "block",
    ):
        super().__init__(app)
        self.mode = mode
        self.on_threat = on_threat
        self.skip_paths = skip_paths or {
            "/health", "/healthz", "/ping", "/metrics",
            "/docs", "/openapi.json", "/redoc",
        }

        # Layer 1
        self._ip_rep = IPReputationEngine(
            block_tor=block_tor,
            block_abusive=block_abusive,
            challenge_datacenters=challenge_datacenters,
            allowlist=ip_allowlist,
            blocklist=ip_blocklist,
        )

        # Layer 2
        self._flood = FloodGuard(
            http_flood_rpm=flood_rpm,
            http_flood_burst=flood_burst,
            max_header_size=max_header_kb * 1024,
            max_body_size=int(max_body_mb * 1024 * 1024),
            global_rpm=global_rpm,
        )

        # Layer 3
        self._fp = FingerprintEngine(
            challenge_threshold=bot_challenge_score,
            block_threshold=bot_block_score,
        )
        self._honeypot_fields = honeypot_fields or {"_email", "website", "url_field"}

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

        self._events: deque[ThreatEvent] = deque(maxlen=5000)
        self._stats = {
            "total_requests": 0, "blocked": 0,
            "tarpitted": 0, "honeypot_hits": 0,
            "attacks_detected": 0,
        }

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = str(uuid.uuid4())[:8]
        ip = self._get_ip(request)
        path = request.url.path
        method = request.method
        headers = dict(request.headers)

        self._stats["total_requests"] += 1

        if path in self.skip_paths:
            resp = await call_next(request)
            self._add_headers(resp)
            return resp

        # ── Layer 1: IP reputation ────────────────────────────────────────
        ip_result = self._ip_rep.check(ip)
        if ip_result.verdict == IPVerdict.BLOCK:
            return self._block(req_id, ip, path, method, "layer1", "ip_reputation",
                               "high", ip_result.reason, 403)
        if ip_result.verdict == IPVerdict.TARPIT:
            return await self._tarpit_resp(req_id, ip, path, method, "layer1", ip_result.reason)

        # ── Layer 2: Flood guard ──────────────────────────────────────────
        header_size = sum(len(k) + len(v) for k, v in headers.items())
        content_length = int(headers.get("content-length", 0) or 0)
        flood_ok, flood_reason = self._flood.check_request(
            ip=ip, method=method, path=path,
            header_size=header_size, content_length=content_length,
            user_agent=headers.get("user-agent", ""),
        )
        if not flood_ok:
            sev = "critical" if "banned" in flood_reason else "high"
            return self._block(req_id, ip, path, method, "layer2", "flood",
                               sev, flood_reason, 429,
                               extra_headers={"Retry-After": "60"})

        # ── Read body ─────────────────────────────────────────────────────
        body_dict = None
        body_str = None
        if method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                body_str = body_bytes.decode("utf-8", errors="replace")
                ct = headers.get("content-type", "")
                if "application/json" in ct:
                    body_dict = json.loads(body_bytes) if body_bytes else {}
                elif "application/x-www-form-urlencoded" in ct:
                    from urllib.parse import parse_qs
                    body_dict = {k: v[0] for k, v in parse_qs(body_str).items()}
            except Exception:
                pass

        # ── Layer 3: Bot fingerprinting ───────────────────────────────────
        fp_result = self._fp.fingerprint(
            ip=ip, method=method, path=path, headers=headers,
            form_data=body_dict if isinstance(body_dict, dict) else None,
            honeypot_fields=self._honeypot_fields,
        )
        if fp_result.recommended_action == "block" and not fp_result.is_known_good_bot:
            return self._block(req_id, ip, path, method, "layer3", "bot",
                               "high", f"bot_score:{fp_result.bot_score}", 403)

        # ── Layer 5: Honeypot paths ───────────────────────────────────────
        if self._honeypot.is_honeypot(path):
            self._stats["honeypot_hits"] += 1
            self._honeypot.record_hit(ip, path, method, headers.get("user-agent", ""))
            self._record(ThreatEvent(req_id, ip, path, method, "layer5",
                                     "honeypot", "high", "ban", f"honeypot:{path}"))
            status, body = self._honeypot.get_fake_response(path)
            from starlette.responses import PlainTextResponse
            resp = PlainTextResponse(body, status_code=status)
            self._add_headers(resp)
            return resp

        # ── Layer 4: OWASP attack detection ──────────────────────────────
        analysis = self._detection.analyze(
            request_id=req_id, path=path, method=method,
            params=dict(request.query_params),
            body=body_dict, headers=headers, source_ip=ip,
        )

        if analysis.is_attack:
            self._stats["attacks_detected"] += 1
            for d in analysis.detections:
                self._record(ThreatEvent(req_id, ip, path, method, "layer4",
                                         d.rule_id, d.severity,
                                         "block" if analysis.blocked else "log",
                                         f"matched:{d.matched_in}"))

        if analysis.blocked and self.mode == "block":
            self._stats["blocked"] += 1
            return self._block(req_id, ip, path, method, "layer4",
                               analysis.threat_level, analysis.threat_level,
                               "attack_blocked", 403)

        # ── Forward to app ────────────────────────────────────────────────
        resp = await call_next(request)
        self._add_headers(resp)
        resp.headers["X-Request-ID"] = req_id
        if analysis.is_attack:
            resp.headers["X-CyberSentry-Threat"] = analysis.threat_level
        return resp

    def _block(self, req_id, ip, path, method, layer, threat_type,
               severity, reason, status, extra_headers=None) -> JSONResponse:
        self._stats["blocked"] += 1
        self._record(ThreatEvent(req_id, ip, path, method, layer,
                                 threat_type, severity, "block", reason))
        h = {"X-Request-ID": req_id, "X-CyberSentry": "blocked", **_SECURITY_HEADERS}
        if extra_headers:
            h.update(extra_headers)
        return JSONResponse(status_code=status, content={
            "error": "request_blocked",
            "request_id": req_id,
            "message": "Blocked by CyberSentry.",
        }, headers=h)

    async def _tarpit_resp(self, req_id, ip, path, method, layer, reason) -> Response:
        self._stats["tarpitted"] += 1
        self._record(ThreatEvent(req_id, ip, path, method, layer,
                                 "tarpit", "medium", "tarpit", reason))
        await asyncio.sleep(self._tarpit.delay)
        return JSONResponse(status_code=200, content={"status": "ok"},
                            headers={"X-Request-ID": req_id})

    def _add_headers(self, response: Response) -> None:
        for k, v in _SECURITY_HEADERS.items():
            response.headers[k] = v

    def _record(self, event: ThreatEvent) -> None:
        self._events.append(event)
        if self.on_threat:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.on_threat(event))
            except Exception:
                pass

    def _get_ip(self, request: Request) -> str:
        for h in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
            val = request.headers.get(h)
            if val:
                return val.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def ban_ip(self, ip: str, duration: int = 3600) -> None:
        self._ip_rep.ban(ip, duration)
        self._flood.ban_ip(ip, duration)

    def allow_ip(self, ip: str) -> None:
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
