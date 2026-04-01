"""
CyberSentry Attack Simulator.
Sends attack payloads against target URLs and evaluates responses
to determine vulnerability. Used ONLY on apps you own or have
explicit written permission to test.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import httpx

from cybersentry.core.attack.payloads import (
    ALL_PAYLOADS,
    BRUTE_FORCE_PASSWORDS,
    BRUTE_FORCE_USERNAMES,
    Payload,
    get_payloads,
)
from cybersentry.utils.validators import validate_url


@dataclass
class AttackResult:
    payload: Payload
    target_url: str
    target_param: str
    response_status: int | None = None
    response_body: str | None = None
    response_time_ms: float | None = None
    vulnerable: bool = False
    confidence: str = "low"          # low / medium / high
    evidence: str = ""
    error: str | None = None


@dataclass
class SimulationReport:
    target: str
    attack_types: list[str]
    total_tests: int = 0
    vulnerable_count: int = 0
    results: list[AttackResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def vulnerability_rate(self) -> float:
        return self.vulnerable_count / self.total_tests if self.total_tests else 0.0

    @property
    def critical_findings(self) -> list[AttackResult]:
        return [r for r in self.results if r.vulnerable and r.payload.severity == "critical"]


# ── Vulnerability indicators ─────────────────────────────────────────────────
# Strings in response body that indicate the attack was successful
VULN_INDICATORS: dict[str, list[str]] = {
    "sqli": [
        "SQL syntax", "mysql_fetch", "Warning: mysql", "ORA-01756",
        "PostgreSQL", "SQLSTATE", "unterminated quoted string",
        "quoted string not properly terminated", "syntax error",
        "You have an error in your SQL syntax",
        # Time-based indicator handled separately
    ],
    "xss": [
        '<script>alert("XSS")</script>',
        'alert(document.cookie)',
        'onerror=alert',
        'onload=fetch',
        "javascript:alert",
    ],
    "cmdi": [
        "uid=", "root:", "daemon:", "/bin/bash",
        "www-data", "[extensions]",   # win.ini
        "for 16-bit app support",     # win.ini
    ],
    "path_traversal": [
        "root:x:0:0", "daemon:", "bin:", "sys:",   # /etc/passwd
        "for 16-bit app support",                   # win.ini
        "HOME=", "USER=", "PATH=",                  # /proc/environ
    ],
    "ssrf": [
        "ami-id", "instance-id", "security-credentials",
        "iam/", "meta-data", "computeMetadata",
        "+PONG", "-ERR",   # Redis
    ],
    "ssti": [
        "49",    # {{7*7}}
        "config.items", "SECRET_KEY",
        "__subclasses__",
    ],
    "lfi": [
        "root:x:0:0", "[extensions]",
    ],
}

# Strings that indicate the response is an error page (unreliable indicator)
ERROR_INDICATORS = [
    "500 Internal Server Error", "An error occurred", "Exception",
    "Traceback", "Stack trace",
]


class AttackSimulator:
    """
    HTTP-based attack simulator.
    Sends payloads as GET params, POST body fields, and headers.
    """

    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        delay_between_requests: float = 0.2,
        max_concurrent: int = 5,
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ):
        self.target = validate_url(target)
        self.timeout = timeout
        self.delay = delay_between_requests
        self.max_concurrent = max_concurrent
        self._default_headers = {
            "User-Agent": "CyberSentry/0.1 Security Scanner (authorized testing)",
            **(headers or {}),
        }
        self._cookies = cookies or {}
        self._follow_redirects = follow_redirects

    # ── Core HTTP helpers ─────────────────────────────────────────────────────
    async def _get(self, url: str, params: dict[str, str] | None = None) -> tuple[int, str, float]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self._follow_redirects,
        ) as client:
            start = time.monotonic()
            response = await client.get(
                url,
                params=params,
                headers=self._default_headers,
                cookies=self._cookies,
            )
            elapsed = (time.monotonic() - start) * 1000
            return response.status_code, response.text, elapsed

    async def _post(self, url: str, data: dict[str, str]) -> tuple[int, str, float]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self._follow_redirects,
        ) as client:
            start = time.monotonic()
            response = await client.post(
                url,
                data=data,
                headers=self._default_headers,
                cookies=self._cookies,
            )
            elapsed = (time.monotonic() - start) * 1000
            return response.status_code, response.text, elapsed

    # ── Vulnerability detection ───────────────────────────────────────────────
    def _check_vulnerable(
        self,
        attack_type: str,
        body: str,
        status: int,
        elapsed_ms: float,
        baseline_ms: float | None = None,
    ) -> tuple[bool, str, str]:
        """
        Returns (vulnerable, confidence, evidence).
        """
        indicators = VULN_INDICATORS.get(attack_type, [])
        for indicator in indicators:
            if indicator.lower() in body.lower():
                return True, "high", f"Response contains: {indicator!r}"

        # Time-based detection (≥ 4.5 second delay vs baseline)
        if attack_type in ("sqli", "cmdi") and elapsed_ms > 4500:
            if baseline_ms is None or elapsed_ms > baseline_ms + 4500:
                return True, "medium", f"Response delayed {elapsed_ms:.0f}ms (time-based injection)"

        # Error leakage (lower confidence)
        for err in ERROR_INDICATORS:
            if err in body:
                return True, "low", f"Server error may indicate injection: {err!r}"

        return False, "low", ""

    # ── Individual attack runners ─────────────────────────────────────────────
    async def _test_get_param(
        self, payload: Payload, param: str, baseline_ms: float | None = None
    ) -> AttackResult:
        """Inject payload as a GET query parameter."""
        url = self.target
        try:
            status, body, elapsed = await self._get(url, params={param: payload.value})
            vulnerable, confidence, evidence = self._check_vulnerable(
                payload.attack_type, body, status, elapsed, baseline_ms
            )
            return AttackResult(
                payload=payload,
                target_url=url,
                target_param=param,
                response_status=status,
                response_body=body[:2000],   # truncate
                response_time_ms=elapsed,
                vulnerable=vulnerable,
                confidence=confidence,
                evidence=evidence,
            )
        except Exception as exc:
            return AttackResult(
                payload=payload,
                target_url=url,
                target_param=param,
                error=str(exc),
            )

    async def _test_post_field(
        self, payload: Payload, field_name: str, baseline_ms: float | None = None
    ) -> AttackResult:
        """Inject payload as a POST body field."""
        try:
            status, body, elapsed = await self._post(
                self.target, data={field_name: payload.value}
            )
            vulnerable, confidence, evidence = self._check_vulnerable(
                payload.attack_type, body, status, elapsed, baseline_ms
            )
            return AttackResult(
                payload=payload,
                target_url=self.target,
                target_param=field_name,
                response_status=status,
                response_body=body[:2000],
                response_time_ms=elapsed,
                vulnerable=vulnerable,
                confidence=confidence,
                evidence=evidence,
            )
        except Exception as exc:
            return AttackResult(
                payload=payload,
                target_url=self.target,
                target_param=field_name,
                error=str(exc),
            )

    # ── Brute force simulation ────────────────────────────────────────────────
    async def brute_force(
        self,
        login_url: str,
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: str = "dashboard",
        max_attempts: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Simulate a credential brute-force attack.
        Returns list of attempts with results.
        """
        results = []
        validate_url(login_url)

        attempts = [
            (u, p)
            for u in BRUTE_FORCE_USERNAMES
            for p in BRUTE_FORCE_PASSWORDS
        ][:max_attempts]

        sem = asyncio.Semaphore(self.max_concurrent)

        async def _try(username: str, password: str) -> dict[str, Any]:
            async with sem:
                try:
                    status, body, elapsed = await self._post(
                        login_url,
                        data={username_field: username, password_field: password},
                    )
                    success = success_indicator.lower() in body.lower() or status == 302
                    return {
                        "username": username,
                        "password": password,
                        "status": status,
                        "success": success,
                        "elapsed_ms": elapsed,
                    }
                except Exception as exc:
                    return {
                        "username": username,
                        "password": password,
                        "error": str(exc),
                        "success": False,
                    }
                finally:
                    await asyncio.sleep(self.delay)

        tasks = [_try(u, p) for u, p in attempts]
        results = await asyncio.gather(*tasks)
        return list(results)

    # ── Full simulation ───────────────────────────────────────────────────────
    async def simulate(
        self,
        attack_types: list[str] | None = None,
        params: list[str] | None = None,
        method: str = "GET",
        progress_callback=None,
    ) -> SimulationReport:
        """
        Run a full simulation against the target.

        Args:
            attack_types: List of attack types to test. None = all.
            params: Query/form param names to inject into. None = ['q','id','search','name'].
            method: HTTP method to use (GET or POST).
            progress_callback: Optional async callable(completed, total).
        """
        types = attack_types or list(ALL_PAYLOADS.keys())
        test_params = params or ["q", "id", "search", "name", "input", "query", "file", "url"]

        all_payloads = []
        for t in types:
            if t != "brute_force":
                all_payloads.extend(get_payloads(t))

        start = time.monotonic()
        report = SimulationReport(
            target=self.target,
            attack_types=types,
            total_tests=len(all_payloads) * len(test_params),
        )

        # Get baseline response time
        baseline_ms: float | None = None
        try:
            _, _, baseline_ms = await self._get(self.target)
        except Exception:
            pass

        sem = asyncio.Semaphore(self.max_concurrent)
        completed = 0

        async def run_test(payload: Payload, param: str) -> AttackResult:
            nonlocal completed
            async with sem:
                if method.upper() == "POST":
                    result = await self._test_post_field(payload, param, baseline_ms)
                else:
                    result = await self._test_get_param(payload, param, baseline_ms)
                await asyncio.sleep(self.delay)
                completed += 1
                if progress_callback:
                    await progress_callback(completed, report.total_tests)
                return result

        tasks = [
            run_test(payload, param)
            for payload in all_payloads
            for param in test_params
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            report.results.append(result)
            if result.vulnerable:
                report.vulnerable_count += 1

        report.duration_seconds = time.monotonic() - start
        return report
