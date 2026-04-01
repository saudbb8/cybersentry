"""
CyberSentry Behavioral Anomaly Detection.
Learns normal traffic patterns and flags deviations.
Uses a simple online statistics approach (Welford's algorithm) for
memory-efficient streaming mean + variance computation.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EndpointStats:
    """Running statistics for a single endpoint."""
    endpoint: str
    method: str
    sample_count: int = 0
    # Welford's online algorithm state
    _mean: float = 0.0
    _M2: float = 0.0   # sum of squared deviations

    # Rate tracking (requests per minute) — sliding window
    _timestamps: deque = field(default_factory=lambda: deque(maxlen=300))

    # Payload size stats
    _size_mean: float = 0.0
    _size_M2: float = 0.0

    def update(self, response_time_ms: float, payload_size: int = 0) -> None:
        """Update stats with a new observation (Welford's algorithm)."""
        self.sample_count += 1
        self._timestamps.append(time.monotonic())

        # Response time
        delta = response_time_ms - self._mean
        self._mean += delta / self.sample_count
        delta2 = response_time_ms - self._mean
        self._M2 += delta * delta2

        # Payload size
        delta_s = payload_size - self._size_mean
        self._size_mean += delta_s / self.sample_count
        delta_s2 = payload_size - self._size_mean
        self._size_M2 += delta_s * delta_s2

    @property
    def mean_response_time(self) -> float:
        return self._mean

    @property
    def stddev_response_time(self) -> float:
        if self.sample_count < 2:
            return 0.0
        return math.sqrt(self._M2 / (self.sample_count - 1))

    @property
    def mean_payload_size(self) -> float:
        return self._size_mean

    @property
    def current_rate(self) -> float:
        """Requests per minute over the last 60 seconds."""
        now = time.monotonic()
        recent = [t for t in self._timestamps if now - t <= 60]
        return len(recent)

    @property
    def is_established(self) -> bool:
        """True when we have enough samples to trust the baseline."""
        return self.sample_count >= 50

    def z_score_response_time(self, value: float) -> float:
        """How many standard deviations from the mean is this value?"""
        stddev = self.stddev_response_time
        if stddev < 1:
            return 0.0
        return abs(value - self._mean) / stddev

    def z_score_rate(self, current_rate: float) -> float:
        """
        Simple rate anomaly: flag if rate is more than N * established_rate.
        Returns a pseudo-z-score (0 = normal, > threshold = anomalous).
        """
        if not self.is_established or self.current_rate < 1:
            return 0.0
        baseline_rate = self.current_rate
        if baseline_rate < 1:
            return 0.0
        return current_rate / baseline_rate


@dataclass
class AnomalyDetection:
    endpoint: str
    source_ip: str | None
    anomaly_type: str
    z_score: float
    observed_value: float
    expected_value: float
    severity: str
    action: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AnomalyDetector:
    """
    Streaming behavioral anomaly detector.
    Maintains per-endpoint baselines and detects:
    - Unusual response time spikes
    - Request rate anomalies (DDoS / scanning patterns)
    - Payload size anomalies
    """

    def __init__(
        self,
        z_score_threshold: float = 3.0,
        rate_spike_threshold: float = 5.0,   # 5x normal rate
        min_samples: int = 50,
    ):
        self.z_score_threshold = z_score_threshold
        self.rate_spike_threshold = rate_spike_threshold
        self.min_samples = min_samples
        self._stats: dict[str, EndpointStats] = {}
        # Per-IP request tracking for rate limiting
        self._ip_requests: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def _key(self, endpoint: str, method: str) -> str:
        return f"{method.upper()}:{endpoint}"

    def get_or_create_stats(self, endpoint: str, method: str) -> EndpointStats:
        key = self._key(endpoint, method)
        if key not in self._stats:
            self._stats[key] = EndpointStats(endpoint=endpoint, method=method)
        return self._stats[key]

    def observe(
        self,
        endpoint: str,
        method: str,
        response_time_ms: float,
        payload_size: int = 0,
        source_ip: str | None = None,
    ) -> list[AnomalyDetection]:
        """
        Record an observation and return any anomalies detected.
        Call this AFTER processing each request.
        """
        stats = self.get_or_create_stats(endpoint, method)
        anomalies: list[AnomalyDetection] = []

        # Track per-IP
        if source_ip:
            self._ip_requests[source_ip].append(time.monotonic())

        # Only check anomalies once baseline is established
        if stats.is_established:
            # Response time anomaly
            rt_z = stats.z_score_response_time(response_time_ms)
            if rt_z >= self.z_score_threshold:
                severity = "high" if rt_z >= 5 else "medium"
                anomalies.append(AnomalyDetection(
                    endpoint=endpoint,
                    source_ip=source_ip,
                    anomaly_type="response_time_spike",
                    z_score=rt_z,
                    observed_value=response_time_ms,
                    expected_value=stats.mean_response_time,
                    severity=severity,
                    action="logged",
                ))

            # Request rate anomaly per IP
            if source_ip:
                ip_reqs = self._ip_requests[source_ip]
                now = time.monotonic()
                recent_count = sum(1 for t in ip_reqs if now - t <= 60)
                # Compare against endpoint's established rate
                if stats.current_rate > 0:
                    rate_ratio = recent_count / max(stats.current_rate, 1)
                    if rate_ratio >= self.rate_spike_threshold:
                        severity = "critical" if rate_ratio >= 10 else "high"
                        anomalies.append(AnomalyDetection(
                            endpoint=endpoint,
                            source_ip=source_ip,
                            anomaly_type="rate_spike",
                            z_score=rate_ratio,
                            observed_value=float(recent_count),
                            expected_value=stats.current_rate,
                            severity=severity,
                            action="rate_limited",
                        ))

            # Payload size anomaly
            if payload_size > 0 and stats.mean_payload_size > 0:
                size_ratio = payload_size / stats.mean_payload_size
                if size_ratio >= 10:   # 10x larger than normal
                    anomalies.append(AnomalyDetection(
                        endpoint=endpoint,
                        source_ip=source_ip,
                        anomaly_type="payload_size_spike",
                        z_score=size_ratio,
                        observed_value=float(payload_size),
                        expected_value=stats.mean_payload_size,
                        severity="medium",
                        action="logged",
                    ))

        # Update stats after checking (so current request doesn't skew baseline check)
        stats.update(response_time_ms, payload_size)

        return anomalies

    def get_ip_rate(self, ip: str, window_seconds: int = 60) -> int:
        """Return the number of requests from an IP in the last N seconds."""
        now = time.monotonic()
        reqs = self._ip_requests.get(ip, deque())
        return sum(1 for t in reqs if now - t <= window_seconds)

    def summary(self) -> dict[str, Any]:
        """Return a summary of all tracked endpoints."""
        return {
            key: {
                "samples": s.sample_count,
                "mean_response_ms": round(s.mean_response_time, 2),
                "stddev_response_ms": round(s.stddev_response_time, 2),
                "current_rate_rpm": s.current_rate,
                "baseline_established": s.is_established,
            }
            for key, s in self._stats.items()
        }
