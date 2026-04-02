"""
CyberSentry Credential Guard.
Protects login endpoints from brute force, credential stuffing,
password spraying, and account enumeration.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "dragon", "123123", "baseball",
    "iloveyou", "trustno1", "sunshine", "master", "welcome",
    "shadow", "football", "monkey", "qwerty123", "000000",
    "letmein", "abc123", "admin", "admin123", "password1",
    "password123", "P@ssw0rd", "p@ssword", "changeme", "secret",
}


@dataclass
class CredentialCheckResult:
    allowed: bool
    reason: str
    lockout_remaining_seconds: int = 0
    require_mfa: bool = False
    risk_score: int = 0
    is_password_breached: bool = False


class ExponentialBackoff:
    def __init__(self, base: float = 2.0, max_delay: float = 900.0):
        self.base = base
        self.max = max_delay
        self._failures: dict[str, int] = defaultdict(int)
        self._locked_until: dict[str, float] = {}

    def record_failure(self, key: str) -> float:
        self._failures[key] += 1
        delay = min(self.base ** self._failures[key], self.max)
        self._locked_until[key] = time.time() + delay
        return delay

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)

    def is_locked(self, key: str) -> tuple[bool, float]:
        unlock = self._locked_until.get(key)
        if not unlock:
            return False, 0.0
        remaining = unlock - time.time()
        if remaining <= 0:
            del self._locked_until[key]
            return False, 0.0
        return True, remaining

    def failure_count(self, key: str) -> int:
        return self._failures.get(key, 0)


@dataclass
class LoginAttempt:
    ip: str
    username: str
    success: bool
    timestamp: float = field(default_factory=time.time)


class CredentialGuard:
    def __init__(
        self,
        max_ip_failures: int = 10,
        max_account_failures: int = 5,
        reject_common_passwords: bool = True,
        global_failure_threshold: int = 50,
        require_mfa_on_suspicious: bool = True,
    ):
        self.max_ip_failures = max_ip_failures
        self.max_account_failures = max_account_failures
        self.reject_common = reject_common_passwords
        self.global_threshold = global_failure_threshold
        self.require_mfa = require_mfa_on_suspicious

        self._ip_backoff = ExponentialBackoff()
        self._account_backoff = ExponentialBackoff(base=30.0)
        self._global_failures: deque[float] = deque(maxlen=1000)
        self._attempts: deque[LoginAttempt] = deque(maxlen=5000)
        self._targeted: dict[str, int] = defaultdict(int)

    def check_login(
        self,
        ip: str,
        username: str,
        password: str = "",
    ) -> CredentialCheckResult:
        risk = 0
        require_mfa = False

        if self.reject_common and password in COMMON_PASSWORDS:
            return CredentialCheckResult(
                allowed=False,
                reason="password_too_common",
                is_password_breached=True,
                risk_score=90,
            )

        ip_locked, ip_remaining = self._ip_backoff.is_locked(ip)
        if ip_locked:
            return CredentialCheckResult(
                allowed=False,
                reason="ip_locked",
                lockout_remaining_seconds=int(ip_remaining),
                risk_score=95,
            )

        acct_locked, acct_remaining = self._account_backoff.is_locked(username)
        if acct_locked:
            return CredentialCheckResult(
                allowed=False,
                reason="account_locked",
                lockout_remaining_seconds=int(acct_remaining),
                risk_score=90,
            )

        ip_failures = self._ip_backoff.failure_count(ip)
        if ip_failures >= self.max_ip_failures:
            return CredentialCheckResult(allowed=False, reason="ip_too_many_failures", risk_score=95)
        elif ip_failures >= 3:
            risk += ip_failures * 10
            require_mfa = True

        acct_failures = self._account_backoff.failure_count(username)
        if acct_failures >= self.max_account_failures:
            return CredentialCheckResult(allowed=False, reason="account_too_many_failures", risk_score=90)
        elif acct_failures >= 2:
            risk += acct_failures * 15
            require_mfa = True

        now = time.time()
        global_recent = sum(1 for t in self._global_failures if now - t <= 60)
        if global_recent >= self.global_threshold:
            risk += 30
            require_mfa = True

        recent_from_ip = [a for a in self._attempts if a.ip == ip and now - a.timestamp <= 300]
        unique_usernames = len({a.username for a in recent_from_ip})
        if unique_usernames >= 5:
            risk += 40
            require_mfa = True

        return CredentialCheckResult(
            allowed=True,
            reason="ok",
            risk_score=min(100, risk),
            require_mfa=require_mfa and self.require_mfa,
        )

    def record_failure(self, ip: str, username: str) -> None:
        self._ip_backoff.record_failure(ip)
        self._account_backoff.record_failure(username)
        self._global_failures.append(time.time())
        self._targeted[username] += 1
        self._attempts.append(LoginAttempt(ip=ip, username=username, success=False))

    def record_success(self, ip: str, username: str) -> None:
        self._ip_backoff.record_success(ip)
        self._attempts.append(LoginAttempt(ip=ip, username=username, success=True))

    def is_password_common(self, password: str) -> bool:
        return password in COMMON_PASSWORDS

    def get_stats(self) -> dict:
        now = time.time()
        return {
            "global_failures_per_min": sum(1 for t in self._global_failures if now - t <= 60),
            "top_targeted": sorted(self._targeted.items(), key=lambda x: x[1], reverse=True)[:5],
            "total_attempts": len(self._attempts),
        }
