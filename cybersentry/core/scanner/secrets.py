"""
CyberSentry Secrets Scanner.
Detects hardcoded API keys, passwords, tokens, and credentials in source files.
Approach: regex patterns + Shannon entropy analysis.
NEVER stores actual secret values — only redacted hints.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from cybersentry.utils.validators import redact_secret, shannon_entropy, is_high_entropy_string


@dataclass
class SecretMatch:
    file_path: str
    line_number: int
    secret_type: str
    redacted_value: str
    entropy: float
    severity: str
    confidence: str   # high / medium / low
    remediation: str
    line_context: str  # surrounding code (redacted)


# ── Secret patterns ────────────────────────────────────────────────────────────
# Each pattern: (secret_type, regex, severity, min_entropy)
SECRET_PATTERNS: list[tuple[str, str, str, float]] = [
    # AWS
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "critical", 3.0),
    ("aws_secret_key", r"(?i)aws.{0,20}secret.{0,20}=.{0,5}['\"]([A-Za-z0-9/+=]{40})", "critical", 4.0),
    ("aws_session_token", r"(?i)aws.{0,20}session.{0,20}token.{0,5}['\"]([A-Za-z0-9/+=]{100,})", "critical", 4.0),

    # Google
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", "critical", 3.0),
    ("google_oauth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "high", 3.0),

    # GitHub
    ("github_token", r"(?i)github.{0,5}['\"]?(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36})", "critical", 3.5),
    ("github_pat", r"ghp_[A-Za-z0-9]{36}", "critical", 3.5),

    # Stripe
    ("stripe_secret", r"sk_live_[0-9a-zA-Z]{24,}", "critical", 3.5),
    ("stripe_publishable", r"pk_live_[0-9a-zA-Z]{24,}", "medium", 3.0),
    ("stripe_test", r"sk_test_[0-9a-zA-Z]{24,}", "medium", 3.0),

    # OpenAI
    ("openai_key", r"sk-[A-Za-z0-9]{48}", "critical", 3.5),
    ("openai_org", r"org-[A-Za-z0-9]{24}", "medium", 3.0),

    # Slack
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]+", "critical", 3.5),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "high", 3.0),

    # Twilio
    ("twilio_sid", r"AC[a-z0-9]{32}", "high", 3.5),
    ("twilio_token", r"(?i)twilio.{0,20}['\"]([a-z0-9]{32})['\"]", "high", 3.5),

    # SendGrid
    ("sendgrid_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "critical", 3.5),

    # Mailgun
    ("mailgun_key", r"key-[0-9a-zA-Z]{32}", "high", 3.0),

    # JWT secrets / generic secrets
    ("jwt_secret", r"(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*['\"]([^'\"]{16,})", "critical", 3.5),
    ("generic_secret", r"(?i)(secret[_-]?key|app[_-]?secret|api[_-]?secret)\s*[=:]\s*['\"]([^'\"]{16,})", "high", 3.5),
    ("generic_password", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})", "high", 3.0),
    ("generic_api_key", r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['\"]([^'\"]{16,})", "high", 3.5),
    ("private_key_header", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", 0.0),

    # Database URLs
    ("database_url", r"(?i)(postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s\"']+", "critical", 3.5),

    # Generic high-entropy strings in assignments
    ("high_entropy_string", r"""(?i)(token|secret|key|auth|password)\s*[=:]\s*['"]((?:[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_\-]{32,}))['"]\s*""", "medium", 4.0),
]

_COMPILED_PATTERNS: list[tuple[str, re.Pattern, str, float]] = [
    (name, re.compile(pattern), severity, min_entropy)
    for name, pattern, severity, min_entropy in SECRET_PATTERNS
]

# Files to skip
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".whl", ".egg", ".pyc",
    ".lock", ".min.js", ".min.css",
}

_SKIP_DIRECTORIES = {
    ".git", "__pycache__", "node_modules", ".tox", "venv",
    ".venv", "env", "dist", "build", ".mypy_cache",
    ".pytest_cache", "htmlcov",
}

# Lines that are clearly safe to skip (test values, docs, etc.)
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"(?i)(example|sample|placeholder|dummy|fake|test|your[_-]?api|<.*>|{.*})"),
    re.compile(r"(?i)https?://"),   # skip URLs unless they contain credentials
    re.compile(r"^\s*#"),           # comments
    re.compile(r"^\s*//"),          # JS comments
    re.compile(r"(?i)(TODO|FIXME|CHANGEME)"),
]


def _is_likely_false_positive(line: str, value: str) -> bool:
    """Heuristically filter false positives."""
    for pattern in _FALSE_POSITIVE_PATTERNS:
        if pattern.search(value):
            return True
    # Very short values are likely not real secrets
    if len(value.strip("'\"")) < 12:
        return True
    return False


class SecretsScanner:
    """
    Scans source files for hardcoded secrets.
    Never stores actual secret values.
    """

    def __init__(
        self,
        min_entropy: float = 3.0,
        skip_extensions: set[str] | None = None,
        skip_directories: set[str] | None = None,
        max_file_size_mb: float = 5.0,
    ):
        self.min_entropy = min_entropy
        self.skip_extensions = skip_extensions or _SKIP_EXTENSIONS
        self.skip_directories = skip_directories or _SKIP_DIRECTORIES
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)

    def _should_skip(self, path: Path) -> bool:
        if path.suffix.lower() in self.skip_extensions:
            return True
        for part in path.parts:
            if part in self.skip_directories:
                return True
        if path.stat().st_size > self.max_file_size_bytes:
            return True
        return False

    def scan_file(self, file_path: Path) -> list[SecretMatch]:
        """Scan a single file for secrets."""
        matches: list[SecretMatch] = []

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            return matches

        for line_num, line in enumerate(text.splitlines(), start=1):
            # Skip obviously safe lines
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue

            for name, pattern, severity, min_ent in _COMPILED_PATTERNS:
                for match in pattern.finditer(line):
                    # Extract the actual secret value (last group, or full match)
                    groups = match.groups()
                    secret_value = groups[-1] if groups else match.group(0)
                    secret_value = secret_value.strip("'\"` \t")

                    if not secret_value or len(secret_value) < 8:
                        continue

                    # False positive filter
                    if _is_likely_false_positive(line, secret_value):
                        continue

                    # Entropy check (skip very low entropy values)
                    ent = shannon_entropy(secret_value)
                    if min_ent > 0 and ent < min_ent:
                        continue

                    # Redact for storage
                    redacted = redact_secret(secret_value)

                    # Redact the line context too
                    safe_line = line.replace(secret_value, redacted).strip()[:120]

                    confidence = "high" if ent >= 4.5 else "medium" if ent >= 3.5 else "low"

                    matches.append(SecretMatch(
                        file_path=str(file_path),
                        line_number=line_num,
                        secret_type=name,
                        redacted_value=redacted,
                        entropy=round(ent, 2),
                        severity=severity,
                        confidence=confidence,
                        remediation=(
                            "Move secret to environment variables. "
                            "Rotate the compromised credential immediately. "
                            "Add the file to .gitignore if it's config. "
                            "Use: os.environ['KEY_NAME'] or pydantic-settings."
                        ),
                        line_context=safe_line,
                    ))

        return matches

    def scan_directory(
        self,
        directory: Path,
        progress_callback=None,
    ) -> list[SecretMatch]:
        """Recursively scan a directory for secrets."""
        all_matches: list[SecretMatch] = []
        files = list(directory.rglob("*"))
        total = len(files)

        for i, file_path in enumerate(files):
            if not file_path.is_file():
                continue
            if self._should_skip(file_path):
                continue

            file_matches = self.scan_file(file_path)
            all_matches.extend(file_matches)

            if progress_callback:
                progress_callback(i + 1, total, str(file_path))

        return all_matches