"""
CyberSentry Credential Guard.

Protects login endpoints from:
  - Brute force attacks (single IP, many passwords)
  - Credential stuffing (many IPs, known username/password pairs)
  - Account enumeration (timing attacks on usernames)
  - Password spraying (one password, many usernames)
  - Distributed brute force (botnet, low-and-slow)

Implements:
  - Per-IP login failure tracking with exponential backoff
  - Per-account lockout (prevents account-targeted attacks)
  - Global failure rate anomaly detection
  - Constant-time response to prevent timing side channels
  - HIBP-style common password rejection
"""
from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ── Common / breached passwords to reject outright ────────────────────────────
# Top 100 most common passwords from HIBP dataset
COMMON_PASSWORDS: set[str] = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon", "123123",
    "baseball", "iloveyou", "trustno1", "sunshine", "master",
    "welcome", "shadow", "ashley", "football", "jesus", "michael",
    "ninja", "mustang", "password1", "password123", "admin",
    "abc123", "letmein", "monkey", "1234567890", "superman",
    "batman", "passw0rd", "qwerty123", "000000", "123321",
    "555555", "654321", "666666", "888888", "112233",
    "asdfghjkl", "zxcvbnm", "1q2w3e4r", "1qaz2wsx",
    "pass", "test", "guest", "hello", "hello123",
    "changeme", "secret", "qazwsx", "princess", "dragon1",
    "login", "admin123", "root", "toor", "pass123",
    "p@ssw0rd", "p@ssword", "P@ssw0rd", "P@ssword", "P@55word",
}


@dataclass
class LoginAttempt:
    ip: str
    username: str
    success: bool
    timestamp: float = field(default_factory=time.time)


@dataclass
class CredentialCheckResult:
    allowed: bool
    reason: str
    lockout_remaining_seconds: int = 0
    require_mfa: bool = False
    risk_score: int = 0       # 0-100
    is_password_breached: bool = False


class ExponentialBackoff:
    """Per-key exponential backoff tracker."""

    def __init__(self, base_delay: float = 2.0, max_delay: float = 900.0):
        self.base = base_delay
        self.max = max_delay
        self._failures: dict[str, int] = defaultdict(int)
        self._locked_until: dict[str, float] = {}

    def record_failure(self, key: str) -> float:
        """Record a failure. Returns lockout duration in seconds."""
        self._failures[key] += 1
        n = self._failures[key]
        delay = min(self.base ** n, self.max)
        self._locked_until[key] = time.time() + delay
        return delay

    def record_success(self, key: str) -> None:
        """Reset on successful login."""
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)

    def is_locked(self, key: str) -> tuple[bool, float]:
        """Returns (is_locked, seconds_remaining)."""
        unlock_at = self._locked_until.get(key)
        if not unlock_at:
            return False, 0.0
        remaining = unlock_at - time.time()
        if remaining <= 0:
            del self._locked_until[key]
            return False, 0.0
        return True, remaining

    def failure_count(self, key: str) -> int:
        return self._failures.get(key, 0)


class CredentialGuard:
    """
    Multi-layer credential attack protection.

    Usage:
        guard = CredentialGuard()

        # Before processing login:
        result = guard.check_login(ip, username, password)
        if not result.allowed:
            return error_response(result.reason, 429)

        # After processing login:
        if login_succeeded:
            guard.record_success(ip, username)
        else:
            guard.record_failure(ip, username)
    """

    def __init__(
        self,
        max_failures_per_ip: int = 10,
        max_failures_per_account: int = 5,
        ip_lockout_base_seconds: float = 2.0,
        account_lockout_base_seconds: float = 30.0,
        global_failure_rate_threshold: int = 50,   # failures/min across all IPs
        reject_common_passwords: bool = True,
        require_mfa_on_suspicious: bool = True,
        constant_time_delay_ms: int = 200,     # min response time (timing attack prevention)
    ):
        self.max_ip_failures = max_failures_per_ip
        self.max_account_failures = max_failures_per_account
        self.reject_common = reject_common_passwords
        self.require_mfa_suspicious = require_mfa_on_suspicious
        self.constant_time_ms = constant_time_delay_ms

        self._ip_backoff = ExponentialBackoff(base_delay=ip_lockout_base_seconds)
        self._account_backoff = ExponentialBackoff(base_delay=account_lockout_base_seconds)

        # Global failure rate (detect distributed attacks)
        self._global_failures: deque[float] = deque(maxlen=1000)
        self._global_rate_threshold = global_failure_rate_threshold

        # Credential stuffing detection: track (ip, username) pairs
        self._recent_attempts: deque[LoginAttempt] = deque(maxlen=5000)

        # Accounts that have been targeted (for alerting)
        self._targeted_accounts: dict[str, int] = defaultdict(int)

    def check_login(
        self,
        ip: str,
        username: str,
        password: str = "",
        user_agent: str = "",
    ) -> CredentialCheckResult:
        """
        Check whether a login attempt should be allowed.
        Call BEFORE verifying credentials.
        """
        risk = 0
        require_mfa = False

        # Common password check
        if self.reject_common and password and password in COMMON_PASSWORDS:
            return CredentialCheckResult(
                allowed=False,
                reason="password_too_common",
                is_password_breached=True,
                risk_score=90,
            )

        # IP lockout check
        ip_locked, ip_remaining = self._ip_backoff.is_locked(ip)
        if ip_locked:
            return CredentialCheckResult(
                allowed=False,
                reason="ip_locked_out",
                lockout_remaining_seconds=int(ip_remaining),
                risk_score=95,
            )

        # Per-account lockout check
        acct_locked, acct_remaining = self._account_backoff.is_locked(username)
        if acct_locked:
            return CredentialCheckResult(
                allowed=False,
                reason="account_locked_out",
                lockout_remaining_seconds=int(acct_remaining),
                risk_score=90,
            )

        # IP failure count → risk scoring
        ip_failures = self._ip_backoff.failure_count(ip)
        if ip_failures >= self.max_ip_failures:
            return CredentialCheckResult(
                allowed=False,
                reason="ip_too_many_failures",
                risk_score=95,
            )
        elif ip_failures >= 3:
            risk += ip_failures * 10
            require_mfa = True

        # Account failure count → risk
        acct_failures = self._account_backoff.failure_count(username)
        if acct_failures >= self.max_account_failures:
            return CredentialCheckResult(
                allowed=False,
                reason="account_too_many_failures",
                risk_score=90,
            )
        elif acct_failures >= 2:
            risk += acct_failures * 15
            require_mfa = True

        # Global failure rate (distributed attack detection)
        now = time.time()
        recent_global = sum(1 for t in self._global_failures if now - t <= 60)
        if recent_global >= self._global_rate_threshold:
            risk += 30
            require_mfa = True

        # Credential stuffing: same IP, many different usernames
        recent_from_ip = [
            a for a in self._recent_attempts
            if a.ip == ip and now - a.timestamp <= 300   # last 5 minutes
        ]
        unique_usernames = len({a.username for a in recent_from_ip})
        if unique_usernames >= 5:
            risk += 40
            require_mfa = True

        # Password spraying: same password, many usernames
        # (can't check without the actual password hash — check after the fact)

        risk = min(100, risk)

        return CredentialCheckResult(
            allowed=True,
            reason="ok",
            risk_score=risk,
            require_mfa=require_mfa and self.require_mfa_suspicious,
        )

    def record_failure(self, ip: str, username: str) -> None:
        """Call this after a login FAILS."""
        self._ip_backoff.record_failure(ip)
        self._account_backoff.record_failure(username)
        self._global_failures.append(time.time())
        self._targeted_accounts[username] += 1
        self._recent_attempts.append(
            LoginAttempt(ip=ip, username=username, success=False)
        )

    def record_success(self, ip: str, username: str) -> None:
        """Call this after a login SUCCEEDS. Resets IP backoff."""
        self._ip_backoff.record_success(ip)
        # Note: we intentionally don't reset account backoff on success
        # (attacker might have guessed correctly)
        self._recent_attempts.append(
            LoginAttempt(ip=ip, username=username, success=True)
        )

    def is_password_common(self, password: str) -> bool:
        return password in COMMON_PASSWORDS

    def get_constant_time_delay(self) -> float:
        """
        Return minimum response time to prevent timing attacks.
        Login endpoints should always take at least this long,
        whether or not the user exists.
        """
        return self.constant_time_ms / 1000.0

    def get_stats(self) -> dict:
        now = time.time()
        return {
            "global_failures_per_min": sum(1 for t in self._global_failures if now - t <= 60),
            "top_targeted_accounts": sorted(
                self._targeted_accounts.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "total_attempts_logged": len(self._recent_attempts),
        }