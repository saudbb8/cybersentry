"""
CyberSentry Detection Engine.
Rule-based real-time detection for HTTP requests.
Used by the FastAPI middleware and CLI scan commands.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timezone

from cybersentry.core.detection.rules import ALL_RULES, Rule, get_rules_for_location


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    severity: str
    owasp_category: str
    cwe_id: str | None
    matched_in: str           # where the match was found (param name, header, etc.)
    matched_value: str        # the value that triggered the rule (truncated)
    pattern: str | None       # the regex that matched
    remediation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RequestAnalysis:
    """Result of analysing a single HTTP request."""
    request_id: str
    path: str
    method: str
    source_ip: str | None
    detections: list[DetectionResult] = field(default_factory=list)
    blocked: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def threat_level(self) -> str:
        """Highest severity among all detections."""
        if not self.detections:
            return "none"
        priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return min(self.detections, key=lambda d: priority.get(d.severity, 99)).severity

    @property
    def is_attack(self) -> bool:
        return len(self.detections) > 0


class DetectionEngine:
    """
    Stateless rule-based detection engine.
    Inspect HTTP request components against the rule set.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        max_value_length: int = 4096,
        block_on_severity: list[str] | None = None,
    ):
        self.rules = rules or ALL_RULES
        self.max_value_length = max_value_length
        # Automatically block if these severities are detected
        self.block_on_severity: set[str] = set(block_on_severity or ["critical"])

    def _truncate(self, value: str) -> str:
        if len(value) > self.max_value_length:
            return value[: self.max_value_length] + "...[truncated]"
        return value

    def _check_value(
        self,
        value: str,
        location: str,
        location_name: str,
        results: list[DetectionResult],
    ) -> None:
        """Run all applicable rules against a single value."""
        if not value or not isinstance(value, str):
            return

        applicable_rules = [r for r in self.rules if location in r.check_in]

        for rule in applicable_rules:
            matched, pattern = rule.matches(value)
            if matched:
                results.append(
                    DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        owasp_category=rule.owasp_category,
                        cwe_id=rule.cwe_id,
                        matched_in=location_name,
                        matched_value=self._truncate(value)[:200],
                        pattern=pattern,
                        remediation=rule.remediation,
                    )
                )

    def analyze(
        self,
        request_id: str,
        path: str,
        method: str,
        params: dict[str, str | list[str]] | None = None,
        body: dict[str, Any] | str | None = None,
        headers: dict[str, str] | None = None,
        source_ip: str | None = None,
    ) -> RequestAnalysis:
        """
        Analyse an incoming HTTP request for attack patterns.

        Args:
            request_id: Unique ID for this request (for correlation).
            path: URL path.
            method: HTTP method.
            params: Query string parameters.
            body: Request body (dict for form data, str for raw body).
            headers: HTTP request headers.
            source_ip: Client IP address.

        Returns:
            RequestAnalysis with all detections found.
        """
        detections: list[DetectionResult] = []

        # Check URL path
        self._check_value(path, "url", "URL path", detections)

        # Check query params
        if params:
            for param_name, param_value in params.items():
                if isinstance(param_value, list):
                    for v in param_value:
                        self._check_value(v, "params", f"param:{param_name}", detections)
                else:
                    self._check_value(param_value, "params", f"param:{param_name}", detections)

        # Check body
        if body:
            if isinstance(body, dict):
                for field_name, field_value in body.items():
                    if isinstance(field_value, str):
                        self._check_value(field_value, "body", f"body:{field_name}", detections)
                    elif isinstance(field_value, list):
                        for v in field_value:
                            if isinstance(v, str):
                                self._check_value(v, "body", f"body:{field_name}[]", detections)
            elif isinstance(body, str):
                self._check_value(body, "body", "raw body", detections)

        # Check headers (skip boring/binary ones)
        _SKIP_HEADERS = {
            "accept", "accept-encoding", "accept-language", "content-length",
            "content-type", "connection", "host", "cache-control",
        }
        if headers:
            for header_name, header_value in headers.items():
                if header_name.lower() not in _SKIP_HEADERS:
                    self._check_value(
                        header_value, "headers", f"header:{header_name}", detections
                    )

        # De-duplicate by rule_id (keep first match)
        seen_rules: set[str] = set()
        unique_detections: list[DetectionResult] = []
        for d in detections:
            if d.rule_id not in seen_rules:
                seen_rules.add(d.rule_id)
                unique_detections.append(d)

        # Decide if request should be blocked
        blocked = any(
            d.severity in self.block_on_severity for d in unique_detections
        )

        return RequestAnalysis(
            request_id=request_id,
            path=path,
            method=method,
            source_ip=source_ip,
            detections=unique_detections,
            blocked=blocked,
        )

    def analyze_from_starlette_request(self, request, request_id: str) -> RequestAnalysis:
        """
        Convenience method to analyze a Starlette/FastAPI Request object.
        Note: body must be read separately (async).
        """
        params = dict(request.query_params)
        headers = dict(request.headers)
        source_ip = request.client.host if request.client else None

        return self.analyze(
            request_id=request_id,
            path=str(request.url.path),
            method=request.method,
            params=params,
            headers=headers,
            source_ip=source_ip,
        )