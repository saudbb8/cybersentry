"""
CyberSentry detection rule definitions.
Rules are aligned with OWASP Top 10 2021.
Each rule specifies patterns, severity, and remediation pointers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str               # critical / high / medium / low
    owasp_category: str
    cwe_id: str | None
    patterns: list[str]         # regex patterns to match against input
    check_in: list[str]         # where to check: body, headers, url, params
    remediation: str
    false_positive_notes: str = ""
    _compiled: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.patterns]

    def matches(self, value: str) -> tuple[bool, str | None]:
        """Return (True, pattern) if value matches any rule pattern."""
        for compiled, pattern in zip(self._compiled, self.patterns):
            if compiled.search(value):
                return True, pattern
        return False, None


# ── SQL Injection Rules ───────────────────────────────────────────────────────
SQLI_RULES = [
    Rule(
        id="SQLI-001",
        name="SQL tautology injection",
        description="Classic OR 1=1 authentication bypass pattern",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"'\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d",
            r"'\s*(OR|AND)\s+'[^']*'\s*=\s*'[^']*'",
            r"(?i)\bOR\b\s+1\s*=\s*1",
            r"(?i)\bAND\b\s+1\s*=\s*1",
        ],
        check_in=["params", "body", "headers"],
        remediation=(
            "Use parameterized queries (prepared statements) instead of string concatenation. "
            "Example (Python): cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        ),
    ),
    Rule(
        id="SQLI-002",
        name="SQL UNION-based injection",
        description="UNION SELECT used to extract data from other tables",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)\bUNION\b.*\bSELECT\b",
            r"(?i)\bUNION\b\s+ALL\s+\bSELECT\b",
        ],
        check_in=["params", "body", "url"],
        remediation="Use parameterized queries. Validate and whitelist column names if used in ORDER BY.",
    ),
    Rule(
        id="SQLI-003",
        name="SQL comment injection",
        description="SQL comment sequences used to truncate queries",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"'.*--",
            r"'.*#",
            r"/\*.*\*/",
            r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\b",
        ],
        check_in=["params", "body"],
        remediation="Use parameterized queries. Never concatenate user input into SQL strings.",
    ),
    Rule(
        id="SQLI-004",
        name="Time-based blind SQL injection",
        description="SLEEP/WAITFOR used for timing-based data extraction",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)SLEEP\s*\(",
            r"(?i)BENCHMARK\s*\(",
            r"(?i)WAITFOR\s+DELAY",
            r"(?i)pg_sleep\s*\(",
        ],
        check_in=["params", "body"],
        remediation="Use parameterized queries and implement query timeouts at the DB level.",
    ),
    Rule(
        id="SQLI-005",
        name="SQL schema enumeration",
        description="Queries against INFORMATION_SCHEMA or system tables",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)INFORMATION_SCHEMA",
            r"(?i)SYS\.TABLES",
            r"(?i)ALL_TABLES",
            r"(?i)USER_TABLES",
            r"(?i)sysobjects",
            r"(?i)pg_catalog",
        ],
        check_in=["params", "body"],
        remediation="Use parameterized queries. Apply least-privilege DB accounts — no access to system tables.",
    ),
]

# ── XSS Rules ─────────────────────────────────────────────────────────────────
XSS_RULES = [
    Rule(
        id="XSS-001",
        name="Script tag injection",
        description="Raw <script> tags in user input",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)<script[^>]*>",
            r"(?i)</script>",
        ],
        check_in=["params", "body", "headers"],
        remediation=(
            "HTML-encode all user input before rendering. "
            "Use a Content Security Policy (CSP) header. "
            "Use framework templating (e.g. Jinja2 autoescaping)."
        ),
    ),
    Rule(
        id="XSS-002",
        name="Event handler injection",
        description="JavaScript event handlers injected via HTML attributes",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)\bon\w+\s*=",   # onclick= onload= onerror= etc.
            r"(?i)<img[^>]+onerror",
            r"(?i)<svg[^>]+on\w+",
        ],
        check_in=["params", "body"],
        remediation="HTML-encode user input. Never concatenate input into HTML attribute values.",
    ),
    Rule(
        id="XSS-003",
        name="JavaScript protocol injection",
        description="javascript: protocol used to execute code via URLs",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)data:\s*text/html",
        ],
        check_in=["params", "body", "headers", "url"],
        remediation="Validate and whitelist URL schemes. Only allow http/https in user-supplied URLs.",
    ),
    Rule(
        id="XSS-004",
        name="Cookie theft via XSS",
        description="Attempt to exfiltrate cookies via XSS payload",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)document\.cookie",
            r"(?i)fetch\s*\(",
            r"(?i)XMLHttpRequest",
            r"(?i)window\.location\s*=",
        ],
        check_in=["params", "body"],
        remediation=(
            "Set HttpOnly and Secure flags on session cookies. "
            "Implement CSP. Use SameSite=Strict cookie attribute."
        ),
    ),
]

# ── Command Injection Rules ───────────────────────────────────────────────────
CMDI_RULES = [
    Rule(
        id="CMDI-001",
        name="Shell metacharacter injection",
        description="Shell special characters used to chain commands",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-78",
        patterns=[
            r"[;&|`]",
            r"\$\(",
            r"\$\{",
        ],
        check_in=["params", "body"],
        remediation=(
            "Never pass user input to shell commands. "
            "Use subprocess with a list (not shell=True). "
            "If shell commands are needed, use a strict allowlist of permitted values."
        ),
        false_positive_notes="Semicolons appear in legitimate URLs and base64. Check context.",
    ),
    Rule(
        id="CMDI-002",
        name="Dangerous system commands",
        description="Known dangerous system commands in input",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-78",
        patterns=[
            r"(?i)\brm\s+-rf\b",
            r"(?i)\bwhoami\b",
            r"(?i)/bin/(sh|bash|zsh|dash)",
            r"(?i)cmd\.exe",
            r"(?i)\bnetcat\b|\bnc\s+-",
            r"(?i)\bwget\b|\bcurl\b.*http",
            r"(?i)cat\s+/etc/(passwd|shadow)",
        ],
        check_in=["params", "body"],
        remediation="Do not pass user input to system commands. Use application-level APIs instead.",
    ),
]

# ── Path Traversal Rules ──────────────────────────────────────────────────────
PATH_RULES = [
    Rule(
        id="PATH-001",
        name="Directory traversal sequence",
        description="../ sequences used to escape intended directory",
        severity="critical",
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-22",
        patterns=[
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"\.\.%2f",
            r"\.\.%5c",
        ],
        check_in=["params", "url", "headers"],
        remediation=(
            "Use Path.resolve() and verify the resolved path starts with the intended base dir. "
            "Never concatenate user input into file paths. "
            "Use an allowlist of permitted file names."
        ),
    ),
    Rule(
        id="PATH-002",
        name="Sensitive file access",
        description="Attempts to access known sensitive system files",
        severity="critical",
        owasp_category="A01:2021 - Broken Access Control",
        cwe_id="CWE-22",
        patterns=[
            r"(?i)/etc/passwd",
            r"(?i)/etc/shadow",
            r"(?i)/proc/self",
            r"(?i)c:\\windows\\system32",
            r"(?i)/proc/\d+/environ",
            r"(?i)\.env\b",
            r"(?i)\.git/",
        ],
        check_in=["params", "url", "body"],
        remediation="Implement path canonicalization and directory jailing. Check resolved path before file operations.",
    ),
]

# ── SSRF Rules ────────────────────────────────────────────────────────────────
SSRF_RULES = [
    Rule(
        id="SSRF-001",
        name="Cloud metadata endpoint access",
        description="Attempts to access cloud provider instance metadata",
        severity="critical",
        owasp_category="A10:2021 - Server-Side Request Forgery",
        cwe_id="CWE-918",
        patterns=[
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"169\.254\.170\.2",  # ECS metadata
            r"fd00:ec2::254",     # IPv6 AWS IMDS
        ],
        check_in=["params", "body"],
        remediation=(
            "Use IMDSv2 (require session tokens). "
            "Validate and restrict URLs server-side using allowlists. "
            "Block outbound requests to 169.254.0.0/16 at the network layer."
        ),
    ),
    Rule(
        id="SSRF-002",
        name="Internal network probe via SSRF",
        description="Attempts to probe internal services via user-supplied URL",
        severity="high",
        owasp_category="A10:2021 - Server-Side Request Forgery",
        cwe_id="CWE-918",
        patterns=[
            r"(?i)http://localhost",
            r"(?i)http://127\.\d+\.\d+\.\d+",
            r"(?i)http://0\.0\.0\.0",
            r"(?i)file://",
            r"(?i)gopher://",
            r"(?i)dict://",
        ],
        check_in=["params", "body"],
        remediation=(
            "Parse and validate all user-supplied URLs. "
            "Resolve DNS and block RFC1918 addresses. "
            "Use an allowlist of permitted external domains."
        ),
    ),
]

# ── SSTI Rules ────────────────────────────────────────────────────────────────
SSTI_RULES = [
    Rule(
        id="SSTI-001",
        name="Template expression injection",
        description="Template engine expression syntax in user input",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-1336",
        patterns=[
            r"\{\{.*\}\}",         # Jinja2, Handlebars, Twig, Pebble
            r"\$\{.*\}",           # Freemarker, Thymeleaf, Spring EL
            r"#\{.*\}",            # Velocity, Spring EL
            r"\[%.*%\]",           # EJS-like
        ],
        check_in=["params", "body"],
        remediation=(
            "Never render user input directly as a template. "
            "Use sandboxed template rendering. "
            "Pass user data as context variables, not as the template string."
        ),
    ),
]

# ── Header injection rules ────────────────────────────────────────────────────
HEADER_RULES = [
    Rule(
        id="HDR-001",
        name="HTTP response splitting",
        description="CRLF injection in HTTP headers",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-113",
        patterns=[
            r"\r\n",
            r"%0d%0a",
            r"%0D%0A",
        ],
        check_in=["params", "headers"],
        remediation="Strip or reject CR/LF characters from all header values. Use framework-level header setting APIs.",
    ),
]

# ── Aggregated rule set ───────────────────────────────────────────────────────
ALL_RULES: list[Rule] = (
    SQLI_RULES
    + XSS_RULES
    + CMDI_RULES
    + PATH_RULES
    + SSRF_RULES
    + SSTI_RULES
    + HEADER_RULES
)

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}


def get_rules_for_location(location: str) -> list[Rule]:
    """Return rules that check a given request location."""
    return [r for r in ALL_RULES if location in r.check_in]
