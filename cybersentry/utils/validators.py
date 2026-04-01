"""
CyberSentry input validation + sanitization helpers.
These are used internally to ensure CyberSentry itself is secure.
Following OWASP A03:2021 Injection prevention.
"""
from __future__ import annotations

import html
import re
import urllib.parse
from pathlib import Path
from typing import Any


# ── Path traversal prevention ────────────────────────────────────────────────
def safe_path(base: str | Path, user_input: str) -> Path:
    """
    Resolve a user-supplied path relative to base, rejecting traversal attempts.
    Raises ValueError if the resolved path escapes base.
    """
    base = Path(base).resolve()
    target = (base / user_input).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError(f"Path traversal detected: {user_input!r}")
    return target


# ── URL validation ────────────────────────────────────────────────────────────
_SAFE_SCHEMES = {"http", "https"}

def validate_url(url: str) -> str:
    """
    Validate a URL is http/https and properly formed.
    Raises ValueError on invalid input.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise ValueError(f"Invalid URL: {url!r}") from exc

    if parsed.scheme.lower() not in _SAFE_SCHEMES:
        raise ValueError(
            f"Only http/https URLs are allowed, got scheme: {parsed.scheme!r}"
        )
    if not parsed.netloc:
        raise ValueError(f"URL must have a host: {url!r}")

    return url


# ── HTML / XSS sanitization ───────────────────────────────────────────────────
def sanitize_html(value: str) -> str:
    """Escape HTML entities to prevent XSS when rendering in HTML contexts."""
    return html.escape(value, quote=True)


# ── SQLi detection helpers (for rule engine) ─────────────────────────────────
_SQLI_PATTERNS = [
    r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|EXEC|EXECUTE)\b)",
    r"'.*?--",
    r";\s*(DROP|DELETE|UPDATE|INSERT)",
    r"(?i)(OR\s+1\s*=\s*1|AND\s+1\s*=\s*1)",
    r"(?i)(OR\s+'[^']*'\s*=\s*'[^']*')",
    r"(?i)(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
    r"(?i)(INFORMATION_SCHEMA|SYS\.TABLES|ALL_TABLES)",
    r"(?i)(xp_cmdshell|sp_executesql)",
    r"(?i)(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
    r"(?i)(CHAR\s*\(|CHR\s*\(|NCHAR\s*\()",
]
_SQLI_COMPILED = [re.compile(p) for p in _SQLI_PATTERNS]


def looks_like_sqli(value: str) -> tuple[bool, str | None]:
    """Return (True, matched_pattern) if value looks like a SQL injection attempt."""
    for compiled, pattern in zip(_SQLI_COMPILED, _SQLI_PATTERNS):
        if compiled.search(value):
            return True, pattern
    return False, None


# ── XSS detection helpers ─────────────────────────────────────────────────────
_XSS_PATTERNS = [
    r"(?i)<script[^>]*>",
    r"(?i)</script>",
    r"(?i)javascript\s*:",
    r"(?i)on\w+\s*=",            # onclick=, onerror=, etc.
    r"(?i)<iframe",
    r"(?i)<img[^>]+onerror",
    r"(?i)eval\s*\(",
    r"(?i)document\s*\.\s*cookie",
    r"(?i)document\s*\.\s*write",
    r"(?i)window\s*\.\s*location",
    r"(?i)fetch\s*\(",
    r"(?i)XMLHttpRequest",
    r"(?i)data:\s*text/html",
    r"(?i)<svg[^>]+on\w+",
    r"(?i)expression\s*\(",
]
_XSS_COMPILED = [re.compile(p) for p in _XSS_PATTERNS]


def looks_like_xss(value: str) -> tuple[bool, str | None]:
    for compiled, pattern in zip(_XSS_COMPILED, _XSS_PATTERNS):
        if compiled.search(value):
            return True, pattern
    return False, None


# ── Command injection detection ───────────────────────────────────────────────
_CMDI_PATTERNS = [
    r"[;&|`$]",
    r"\$\(",
    r"(?i)(&&|\|\|)",
    r"(?i)(nc\s+-|netcat|/bin/sh|/bin/bash|cmd\.exe)",
    r"(?i)(wget\s+http|curl\s+http)",
    r"(?i)(chmod|chown|sudo|su\s+root)",
    r"(?i)\brm\s+-rf\b",
    r"(?i)(cat\s+/etc/passwd|cat\s+/etc/shadow)",
    r"\.\./",
]
_CMDI_COMPILED = [re.compile(p) for p in _CMDI_PATTERNS]


def looks_like_cmdi(value: str) -> tuple[bool, str | None]:
    for compiled, pattern in zip(_CMDI_COMPILED, _CMDI_PATTERNS):
        if compiled.search(value):
            return True, pattern
    return False, None


# ── Path traversal detection ───────────────────────────────────────────────────
_PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"(?i)%252e%252e%252f",
    r"(?i)/etc/passwd",
    r"(?i)/etc/shadow",
    r"(?i)/proc/self",
    r"(?i)c:\\windows",
]
_PATH_COMPILED = [re.compile(p, re.IGNORECASE) for p in _PATH_TRAVERSAL_PATTERNS]


def looks_like_path_traversal(value: str) -> tuple[bool, str | None]:
    for compiled, pattern in zip(_PATH_COMPILED, _PATH_TRAVERSAL_PATTERNS):
        if compiled.search(value):
            return True, pattern
    return False, None


# ── General parameter entropy (secret detection helper) ──────────────────────
import math
import string


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. High entropy → likely secret/key."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy_string(value: str, threshold: float = 3.5) -> bool:
    """Return True if value has suspiciously high entropy (likely a secret)."""
    # Only check strings that look like they could be tokens (no spaces, right length)
    if " " in value or len(value) < 16:
        return False
    return shannon_entropy(value) >= threshold


# ── Redaction ─────────────────────────────────────────────────────────────────
def redact_secret(value: str, keep_chars: int = 4) -> str:
    """Redact a secret value showing only first/last N chars."""
    if len(value) <= keep_chars * 2:
        return "*" * len(value)
    return value[:keep_chars] + "..." + value[-keep_chars:]
