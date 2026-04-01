# CyberSentry 🛡️

**Developer-first Security Simulator + Defense Engine**

> "The tool that shows developers exactly how their app gets hacked — and helps them fix it fast."

```
Attack → Detect → Explain → Fix
```

---

## Quick Start

```bash
# Install
git clone https://github.com/yourorg/cybersentry
cd cybersentry
pip install -e .

# Check your installation
cybersentry doctor

# Scan your project
cybersentry scan ./myapp

# Understand a vulnerability
cybersentry explain SQLI-001

# Simulate attacks against your local app (authorized only!)
cybersentry attack http://localhost:8000 --type sqli
```

---

## Commands

| Command | Description |
|---|---|
| `cybersentry scan <path>` | Scan project for secrets, CVEs, SAST issues |
| `cybersentry attack <url>` | Simulate attacks (SQLi, XSS, CMDi, etc.) |
| `cybersentry score` | View/calculate your security score (0-100) |
| `cybersentry explain <rule>` | Human explanation + code fix for a rule |
| `cybersentry protect` | Show middleware integration code |
| `cybersentry rules` | List all detection rules |
| `cybersentry report --pdf` | Generate PDF security report |
| `cybersentry doctor` | Check installation health |
| `cybersentry serve` | Launch dashboard API |

---

## Middleware Integration (one line)

```python
from fastapi import FastAPI
from cybersentry.middleware.fastapi import CyberSentryMiddleware

app = FastAPI()
app.add_middleware(CyberSentryMiddleware, block_attacks=True)
```

Instantly adds:
- ✅ Attack detection (SQLi, XSS, CMDi, Path Traversal, SSRF, SSTI)
- ✅ Rate limiting per IP
- ✅ Behavioral anomaly detection
- ✅ Security headers on all responses

---

## Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
# Now every commit is scanned for secrets and SAST issues
```

---

## Configuration

All settings via environment variables (prefix: `CYBERSENTRY_`):

```env
CYBERSENTRY_RATE_LIMIT_REQUESTS=100
CYBERSENTRY_RATE_LIMIT_WINDOW_SECONDS=60
CYBERSENTRY_ANOMALY_Z_SCORE_THRESHOLD=3.0
CYBERSENTRY_LOG_LEVEL=INFO
```

Or in `.env` file (never commit this!).

---

## Scan Types

```bash
cybersentry scan ./myapp --type full      # All checks
cybersentry scan ./myapp --type secrets   # Secrets only
cybersentry scan ./myapp --type deps      # CVE check only
```

---

## Attack Simulation

> ⚠️ **Only test applications you own or have explicit written permission to test.**

```bash
# Test all attack types
cybersentry attack http://localhost:8000 --type all

# Test specific params
cybersentry attack http://localhost:8000 --type sqli --params id,user_id

# POST method
cybersentry attack http://localhost:8000/login --type sqli --method POST
```

Supported attack types: `sqli`, `xss`, `cmdi`, `path_traversal`, `ssrf`, `ssti`

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## Security Score

| Score | Grade | Meaning |
|---|---|---|
| 95-100 | A+ | Excellent |
| 80-94 | A/A- | Good |
| 70-79 | B | Needs attention |
| 50-69 | C/D | Significant issues |
| < 50 | F | Critical risk |

---

## Tech Stack

- **Python 3.11+**
- **FastAPI** — API + middleware
- **Typer + Rich** — beautiful CLI
- **SQLAlchemy + SQLite** — local data persistence
- **httpx** — async HTTP for attack simulation
- **pip-audit** — CVE/SCA scanning
- **detect-secrets** — entropy-based secret detection
- **ReportLab** — PDF report generation
- **OWASP Top 10 2021** — all rules and explanations aligned

---

## Roadmap

**Phase 1 (current):** CLI + scanning + detection + explain/fix + pre-commit  
**Phase 2:** VS Code extension + GitHub Action + custom rules + LLM fix suggestions  
**Phase 3:** Real-time dashboard + learning mode + Cloudflare/NGINX integration  

---

Made with ❤️ for developers who want to understand security, not just comply with it.