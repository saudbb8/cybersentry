# CyberSentry 🛡️

![CI](https://github.com/saudbb8/cybersentry/actions/workflows/cybersentry.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/cybersentry-saud)
![Python](https://img.shields.io/pypi/pyversions/cybersentry-saud)

**Developer-first Security Simulator + Defense Engine**

> 100% detection rate · 32 OWASP rules · 6 defence layers · Zero false positives

## Install
```bash
pip install cybersentry-saud
```

## Quick start
```bash
cybersentry doctor
cybersentry scan .
cybersentry explain SQLI-001
cybersentry score --critical 0 --high 2 --medium 5
```

## 6 Defence Layers

| Layer | Protects Against |
|---|---|
| IP Reputation | Tor exits, Shodan, abusive ranges |
| Flood Guard | DDoS, slow loris, body bombs |
| Bot Fingerprinting | sqlmap, headless browsers, scrapers |
| OWASP Detection | SQLi, XSS, CMDi, SSRF, XXE, JWT, LDAP, GraphQL, NoSQL |
| Honeypot + Tarpit | /.env probes, auto-ban attackers |
| Security Headers | HSTS, X-Frame-Options, CSP |

## 32 Detection Rules

SQLi (6) · XSS (4) · CMDi (2) · Path Traversal (2) · SSRF (2) · SSTI (1) ·
Header (1) · XXE (3) · JWT (4) · LDAP (2) · GraphQL (3) · NoSQL (3)

## Benchmark
```
Total attacks tested : 43
Blocked              : 43  (100%)
False positives      : 0
```

## One-line middleware
```python
from fastapi import FastAPI
from cybersentry.middleware.fastapi_hardened import HardenedMiddleware

app = FastAPI()
app.add_middleware(HardenedMiddleware, block_tor=True, flood_rpm=300)
```

## CLI Commands

| Command | Description |
|---|---|
| `cybersentry scan .` | Scan for secrets + CVEs |
| `cybersentry attack <url>` | Simulate attacks |
| `cybersentry score` | Security score 0-100 |
| `cybersentry explain SQLI-001` | Learn + code fix |
| `cybersentry rules` | List all 32 rules |
| `cybersentry protect` | Middleware code |
| `cybersentry report` | Security report |
| `cybersentry doctor` | Check installation |

## License
MIT © 2026 saudbb8
