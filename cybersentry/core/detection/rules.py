"""
CyberSentry detection rule definitions.
Rules are aligned with OWASP Top 10 2021.
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
    severity: str
    owasp_category: str
    cwe_id: str | None
    patterns: list[str]
    check_in: list[str]
    remediation: str
    false_positive_notes: str = ""
    _compiled: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.patterns]

    def matches(self, value: str) -> tuple[bool, str | None]:
        for compiled, pattern in zip(self._compiled, self.patterns):
            if compiled.search(value):
                return True, pattern
        return False, None


# ── SQL Injection ─────────────────────────────────────────────────────────────
SQLI_RULES = [
    Rule(
        id="SQLI-001",
        name="SQL tautology injection",
        description="Classic OR 1=1 and boolean blind patterns",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"'\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d",
            r"'\s*(OR|AND)\s+'[^']*'\s*=\s*'[^']*'",
            r"(?i)\bOR\b\s+1\s*=\s*1",
            r"(?i)\bAND\b\s+1\s*=\s*1",
            # FIX 1: Boolean blind with parentheses
            r"(?i)\bAND\b\s*\(\s*\d+\s*=\s*\d+\s*\)",
            r"(?i)\bOR\b\s*\(\s*\d+\s*=\s*\d+\s*\)",
            r"(?i)\bAND\b\s*\(\s*SELECT\s+",
            r"(?i)\bOR\b\s*\(\s*SELECT\s+",
        ],
        check_in=["params", "body", "headers"],
        remediation="Use parameterized queries instead of string concatenation.",
    ),
    Rule(
        id="SQLI-002",
        name="SQL UNION-based injection",
        description="UNION SELECT used to extract data",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)\bUNION\b.*\bSELECT\b",
            r"(?i)\bUNION\b\s+ALL\s+\bSELECT\b",
        ],
        check_in=["params", "body", "url"],
        remediation="Use parameterized queries.",
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
        remediation="Use parameterized queries.",
    ),
    Rule(
        id="SQLI-004",
        name="Time-based blind SQL injection",
        description="SLEEP/WAITFOR used for timing-based extraction",
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
        remediation="Use parameterized queries and implement query timeouts.",
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
        remediation="Use parameterized queries. Apply least-privilege DB accounts.",
    ),
    # FIX 2: New rule for error-based and hex-encoded SQLi
    Rule(
        id="SQLI-006",
        name="SQL error-based and hex injection",
        description="Error-based extraction and hex-encoded SQL injection",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)EXTRACTVALUE\s*\(",
            r"(?i)UPDATEXML\s*\(",
            r"(?i)FLOOR\s*\(RAND\s*\(",
            r"(?i)EXP\s*\(~",
            r"(?i)GEOMETRYCOLLECTION\s*\(",
            r"0x[0-9a-fA-F]{4,}",   # hex encoding like 0x7e
            r"(?i)CHAR\s*\(\s*\d+",
            r"(?i)CONCAT\s*\(.*SELECT",
            r"(?i)GROUP_CONCAT\s*\(",
            r"(?i)xp_cmdshell",
            r"(?i)sp_executesql",
        ],
        check_in=["params", "body"],
        remediation="Use parameterized queries. Never concatenate user input into SQL.",
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
        remediation="HTML-encode all user input before rendering.",
    ),
    Rule(
        id="XSS-002",
        name="Event handler injection",
        description="JavaScript event handlers via HTML attributes",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)\bon\w+\s*=",
            r"(?i)<img[^>]+onerror",
            r"(?i)<svg[^>]+on\w+",
            r"(?i)<details[^>]+on\w+",
            r"(?i)<body[^>]+on\w+",
        ],
        check_in=["params", "body"],
        remediation="HTML-encode user input. Never concatenate into HTML attributes.",
    ),
    Rule(
        id="XSS-003",
        name="JavaScript protocol injection",
        description="javascript: protocol used to execute code",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)data:\s*text/html",
        ],
        check_in=["params", "body", "headers", "url"],
        remediation="Validate URL schemes. Only allow http/https.",
    ),
    Rule(
        id="XSS-004",
        name="Cookie theft via XSS",
        description="Attempt to exfiltrate cookies via XSS",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-79",
        patterns=[
            r"(?i)document\.cookie",
            r"(?i)document\.write",
            r"(?i)window\.location\s*=",
            r"(?i)fetch\s*\(",
            r"(?i)XMLHttpRequest",
        ],
        check_in=["params", "body"],
        remediation="Set HttpOnly and Secure flags on cookies. Implement CSP.",
    ),
]

# ── Command Injection ─────────────────────────────────────────────────────────
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
            r"(?i)(&&|\|\|)",
        ],
        check_in=["params", "body"],
        remediation="Never pass user input to shell. Use subprocess list args.",
        false_positive_notes="Semicolons appear in URLs. Check context.",
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
        remediation="Do not pass user input to system commands.",
    ),
]

# ── Path Traversal ────────────────────────────────────────────────────────────
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
            r"\.\.%c0%af",
            r"\.\.%c1%9c",
        ],
        check_in=["params", "url", "headers"],
        remediation="Use Path.resolve() and verify path stays within base dir.",
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
            r"(?i)win\.ini",
            r"(?i)boot\.ini",
        ],
        check_in=["params", "url", "body"],
        remediation="Implement path canonicalization and directory jailing.",
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
            r"169\.254\.170\.2",
            r"fd00:ec2::254",
        ],
        check_in=["params", "body"],
        remediation="Use IMDSv2. Validate and restrict URLs using allowlists.",
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
            r"(?i)ftp://localhost",
        ],
        check_in=["params", "body"],
        remediation="Parse and validate all user-supplied URLs. Block RFC1918.",
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
            r"\{\{.*\}\}",
            r"\$\{.*\}",
            r"#\{.*\}",
            r"\[%.*%\]",
            r"<%.*%>",
        ],
        check_in=["params", "body"],
        remediation="Never render user input as a template string.",
    ),
]

# ── Header Injection ──────────────────────────────────────────────────────────
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
            # FIX 3: Single LF bypass
            r"%0a",
            r"%0A",
            r"\n",
            r"\\n",
        ],
        check_in=["params", "headers"],
        remediation="Strip or reject CR/LF from all header values.",
    ),
]

# ── Aggregated ────────────────────────────────────────────────────────────────
ALL_RULES: list[Rule] = (
    SQLI_RULES + XSS_RULES + CMDI_RULES +
    PATH_RULES + SSRF_RULES + SSTI_RULES + HEADER_RULES
)

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}


def get_rules_for_location(location: str) -> list[Rule]:
    return [r for r in ALL_RULES if location in r.check_in]


# ── XXE Rules ─────────────────────────────────────────────────────────────────
XXE_RULES = [
    Rule(
        id="XXE-001",
        name="XML external entity injection",
        description="DOCTYPE with SYSTEM or PUBLIC entity declaration",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-611",
        patterns=[
            r"(?i)<!DOCTYPE[^>]*\[",
            r"(?i)<!ENTITY[^>]*SYSTEM",
            r"(?i)<!ENTITY[^>]*PUBLIC",
            r"(?i)<!ENTITY\s+\w+\s+SYSTEM",
            r"(?i)SYSTEM\s+['\"]file://",
            r"(?i)SYSTEM\s+['\"]http://",
            r"(?i)SYSTEM\s+['\"]https://",
            r"(?i)SYSTEM\s+['\"]expect://",
            r"(?i)SYSTEM\s+['\"]php://",
        ],
        check_in=["params", "body"],
        remediation=(
            "Disable external entity processing in your XML parser. "
            "In Python: use defusedxml instead of xml.etree. "
            "Set feature_external_ges=False in SAX parsers."
        ),
    ),
    Rule(
        id="XXE-002",
        name="XML billion laughs / entity expansion",
        description="Recursive entity expansion causing DoS",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-776",
        patterns=[
            r"(?i)<!ENTITY\s+\w+\s+['\"]&\w+;",
            r"(?i)&\w+;&\w+;&\w+;&\w+;",
            r"(?i)<!ENTITY\s+lol",
        ],
        check_in=["body"],
        remediation="Use defusedxml. Set entity expansion limits in your XML parser.",
    ),
    Rule(
        id="XXE-003",
        name="XML processing instruction injection",
        description="Malicious XML processing instructions",
        severity="medium",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-611",
        patterns=[
            r"<\?xml[^?]*\?>.*<!DOCTYPE",
            r"(?i)<\?php",
            r"(?i)xmlns:xi\s*=",
            r"(?i)xi:include",
        ],
        check_in=["body"],
        remediation="Disable XInclude processing. Validate XML against a strict schema.",
    ),
]

# ── JWT Attack Rules ───────────────────────────────────────────────────────────
JWT_RULES = [
    Rule(
        id="JWT-001",
        name="JWT algorithm none attack",
        description="JWT with alg:none to bypass signature verification",
        severity="critical",
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe_id="CWE-347",
        patterns=[
            r"(?i)eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.",
            r"(?i)\"alg\"\s*:\s*\"none\"",
            r"(?i)\"alg\"\s*:\s*\"None\"",
            r"(?i)\"alg\"\s*:\s*\"NONE\"",
            r"(?i)alg=none",
        ],
        check_in=["params", "headers", "body"],
        remediation=(
            "Always verify JWT algorithm. Reject tokens with alg:none. "
            "Use an allowlist of permitted algorithms (RS256, ES256). "
            "Never trust the algorithm from the token header."
        ),
    ),
    Rule(
        id="JWT-002",
        name="JWT key confusion attack",
        description="RS256→HS256 algorithm confusion to forge tokens",
        severity="critical",
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe_id="CWE-347",
        patterns=[
            r"(?i)\"alg\"\s*:\s*\"HS256\".*\"typ\"\s*:\s*\"JWT\"",
            r"(?i)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{10,}",
        ],
        check_in=["params", "headers"],
        remediation=(
            "Use separate keys for RS256 and HS256. "
            "Enforce algorithm type server-side, never from the token."
        ),
    ),
    Rule(
        id="JWT-003",
        name="JWT header injection",
        description="Injected jwk or jku header to supply attacker key",
        severity="critical",
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe_id="CWE-347",
        patterns=[
            r"(?i)\"jwk\"\s*:\s*\{",
            r"(?i)\"jku\"\s*:\s*\"http",
            r"(?i)\"x5u\"\s*:\s*\"http",
            r"(?i)\"kid\"\s*:\s*['\"].*\.\./",
            r"(?i)\"kid\"\s*:\s*['\"].*/etc/passwd",
        ],
        check_in=["params", "headers", "body"],
        remediation=(
            "Ignore jwk/jku/x5u headers from tokens. "
            "Use a local key store. Validate kid against an allowlist."
        ),
    ),
    Rule(
        id="JWT-004",
        name="JWT secret brute force indicator",
        description="Weak or common JWT secrets in Authorization header",
        severity="high",
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe_id="CWE-521",
        patterns=[
            r"(?i)Bearer\s+eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*$",
        ],
        check_in=["headers"],
        remediation=(
            "Use strong random secrets (256-bit minimum). "
            "Rotate secrets regularly. Use asymmetric keys (RS256) for production."
        ),
    ),
]

# ── LDAP Injection Rules ───────────────────────────────────────────────────────
LDAP_RULES = [
    Rule(
        id="LDAP-001",
        name="LDAP filter injection",
        description="Special LDAP characters injected into filter expressions",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-90",
        patterns=[
            r"\*\)\(",
            r"\)\(",
            r"(?i)\(objectClass=\*\)",
            r"(?i)\(cn=\*\)",
            r"(?i)\|\(uid=\*\)",
            r"(?i)&\(uid=\*\)",
            r"\)\s*\(",
            r"(?i)\(objectCategory=\*\)",
        ],
        check_in=["params", "body"],
        remediation=(
            "Escape all LDAP special characters: ( ) * \\ NUL. "
            "Use an LDAP library with built-in escaping. "
            "Validate input against a strict allowlist before building filters."
        ),
    ),
    Rule(
        id="LDAP-002",
        name="LDAP DN injection",
        description="Special characters injected into Distinguished Name",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-90",
        patterns=[
            r"(?i)dc\s*=\s*[^,]+,\s*dc\s*=",
            r"(?i)ou\s*=\s*[^,]+,\s*(dc|ou|cn)\s*=",
            r"(?i)cn\s*=\s*\*",
            r",\s*uid\s*=",
            r"(?i)ldap://",
            r"(?i)ldaps://",
        ],
        check_in=["params", "body"],
        remediation="Escape DN components. Use parameterized LDAP queries.",
    ),
]

# ── GraphQL Injection Rules ────────────────────────────────────────────────────
GRAPHQL_RULES = [
    Rule(
        id="GQL-001",
        name="GraphQL introspection abuse",
        description="Introspection queries used to enumerate schema",
        severity="medium",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-200",
        patterns=[
            r"(?i)__schema",
            r"(?i)__type",
            r"(?i)__typename",
            r"(?i)IntrospectionQuery",
            r"(?i)__enumValues",
            r"(?i)__inputFields",
            r"(?i)__fields",
        ],
        check_in=["params", "body"],
        remediation=(
            "Disable introspection in production. "
            "Use query depth limiting and complexity analysis. "
            "Implement field-level authorization."
        ),
    ),
    Rule(
        id="GQL-002",
        name="GraphQL injection via arguments",
        description="SQL/NoSQL injection through GraphQL arguments",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-89",
        patterns=[
            r"(?i)query\s*\{.*where.*['\"].*OR.*['\"]",
            r"(?i)mutation\s*\{.*['\"].*DROP.*['\"]",
            r"(?i)query\s*\{.*\$where\s*:",
            r"(?i)\{\s*\"\$gt\"\s*:",
            r"(?i)\{\s*\"\$regex\"\s*:",
            r"(?i)\{\s*\"\$where\"\s*:",
        ],
        check_in=["params", "body"],
        remediation=(
            "Validate and sanitize all GraphQL arguments. "
            "Use parameterized resolvers. "
            "Apply input validation at the resolver level."
        ),
    ),
    Rule(
        id="GQL-003",
        name="GraphQL batch / DoS attack",
        description="Batched queries or deep nesting to cause DoS",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-400",
        patterns=[
            r"(?i)\[\s*\{\s*['\"]query['\"]",
            r"(?i)query\s*\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{",
            r"(?i)fragment\s+\w+\s+on\s+\w+\s*\{[^}]*\.\.\.\w+",
        ],
        check_in=["body"],
        remediation=(
            "Limit query depth (max 5 levels). "
            "Limit query complexity. "
            "Disable batched queries or limit batch size to 10."
        ),
    ),
]

# ── NoSQL Injection Rules ──────────────────────────────────────────────────────
NOSQL_RULES = [
    Rule(
        id="NOSQL-001",
        name="MongoDB operator injection",
        description="MongoDB query operators injected via user input",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-943",
        patterns=[
            r"(?i)\[\$where\]",
            r"(?i)\[\$gt\]",
            r"(?i)\[\$lt\]",
            r"(?i)\[\$gte\]",
            r"(?i)\[\$lte\]",
            r"(?i)\[\$ne\]",
            r"(?i)\[\$in\]",
            r"(?i)\[\$nin\]",
            r"(?i)\[\$regex\]",
            r"(?i)\[\$exists\]",
            r'"\$where"\s*:',
            r'"\$gt"\s*:',
            r'"\$regex"\s*:',
            r'"\$ne"\s*:',
            r'"\$in"\s*:\s*\[',
        ],
        check_in=["params", "body"],
        remediation=(
            "Validate input types strictly — reject objects where strings expected. "
            "Use Mongoose schema validation. "
            "Never pass raw user input to MongoDB query objects."
        ),
    ),
    Rule(
        id="NOSQL-002",
        name="NoSQL JavaScript injection",
        description="JavaScript code injected into NoSQL where clauses",
        severity="critical",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-943",
        patterns=[
            r"(?i)\$where\s*:\s*['\"].*function",
            r"(?i)\$where\s*:\s*['\"].*return",
            r"(?i)\$where\s*:\s*['\"].*this\.",
            r"(?i)mapReduce.*function",
            r"(?i)db\.eval\s*\(",
        ],
        check_in=["params", "body"],
        remediation=(
            "Disable MongoDB $where and mapReduce in production. "
            "Use aggregation pipeline instead of JavaScript evaluation."
        ),
    ),
    Rule(
        id="NOSQL-003",
        name="CouchDB / Redis injection",
        description="Injection patterns for CouchDB views and Redis commands",
        severity="high",
        owasp_category="A03:2021 - Injection",
        cwe_id="CWE-943",
        patterns=[
            r"(?i)emit\s*\(",
            r"(?i)FLUSHALL",
            r"(?i)FLUSHDB",
            r"(?i)CONFIG\s+SET",
            r"(?i)SLAVEOF\s+",
            r"(?i)DEBUG\s+SLEEP",
            r"(?i)EVAL\s+['\"]",
        ],
        check_in=["params", "body"],
        remediation=(
            "Never pass user input to Redis commands directly. "
            "Use a Redis client with command allowlisting. "
            "Disable dangerous Redis commands in production (rename-command)."
        ),
    ),
]


# ── Add new rules to ALL_RULES ────────────────────────────────────────────────
ALL_RULES.extend(XXE_RULES + JWT_RULES + LDAP_RULES + GRAPHQL_RULES + NOSQL_RULES)

# Rebuild RULES_BY_ID with new rules
RULES_BY_ID = {r.id: r for r in ALL_RULES}
