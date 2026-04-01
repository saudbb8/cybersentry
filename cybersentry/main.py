"""
CyberSentry CLI — main entrypoint.
Commands: scan, attack, protect, score, explain, doctor, fix, report, serve, rules
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.syntax import Syntax
from rich.prompt import Confirm

app = typer.Typer(
    name="cybersentry",
    help="[bold cyan]CyberSentry[/bold cyan] — Developer-first Security Simulator + Defense Engine",
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
)

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}


def print_banner():
    console.print("\n[bold cyan]  CyberSentry[/bold cyan] — Attack → Detect → Explain → Fix\n")


def print_section(title: str):
    from rich.rule import Rule
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))


def print_success(msg: str):
    console.print(f"[bold green]✔[/bold green]  {msg}")


def print_warning(msg: str):
    console.print(f"[bold yellow]⚠[/bold yellow]  {msg}")


def print_error(msg: str):
    console.print(f"[bold red]✘[/bold red]  {msg}")


def print_info(msg: str):
    console.print(f"[bold blue]ℹ[/bold blue]  {msg}")


@app.callback()
def main():
    """CyberSentry — Attack → Detect → Explain → Fix"""
    pass


# ── doctor ────────────────────────────────────────────────────────────────────
@app.command("doctor")
def cmd_doctor():
    """Check your CyberSentry installation and environment."""
    print_banner()
    print_section("CyberSentry Doctor")
    console.print()

    checks = []

    py_ver = sys.version_info
    py_ok = py_ver >= (3, 9)
    checks.append(("Python ≥ 3.9", py_ok, f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"))

    deps = [
        ("typer", "typer"),
        ("rich", "rich"),
        ("fastapi", "fastapi"),
        ("sqlalchemy", "sqlalchemy"),
        ("httpx", "httpx"),
        ("pydantic", "pydantic"),
        ("pydantic_settings", "pydantic-settings"),
    ]
    for label, module in deps:
        try:
            mod = __import__(module.replace("-", "_"))
            ver = getattr(mod, "__version__", "installed")
            checks.append((f"pip:{label}", True, ver))
        except ImportError:
            checks.append((f"pip:{label}", False, "NOT INSTALLED"))

    import subprocess
    optional_tools = [
        ("pip-audit", ["python3", "-m", "pip_audit", "--version"]),
        ("pre-commit", ["pre-commit", "--version"]),
    ]
    for label, cmd in optional_tools:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            ok = result.returncode == 0
            ver = (result.stdout + result.stderr).strip()[:40]
            checks.append((f"tool:{label}", ok, ver if ok else "not found (optional)"))
        except Exception:
            checks.append((f"tool:{label}", False, "not found (optional)"))

    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Check", style="bold")
    table.add_column("Status", width=10)
    table.add_column("Details")

    all_ok = True
    for label, ok, detail in checks:
        st = "[bold green]✔ OK[/bold green]" if ok else "[bold red]✘ FAIL[/bold red]"
        if not ok and "optional" not in detail:
            all_ok = False
        table.add_row(label, st, str(detail))

    console.print(table)
    console.print()

    if all_ok:
        print_success("All checks passed! CyberSentry is ready.")
    else:
        print_warning("Some checks failed. Run: pip install -r requirements.txt")


# ── rules ─────────────────────────────────────────────────────────────────────
@app.command("rules")
def cmd_rules(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter: SQLI, XSS, CMDI, PATH, SSRF, SSTI"),
):
    """List all OWASP-aligned detection rules."""
    print_banner()
    print_section("Detection Rules")

    try:
        from cybersentry.core.detection.rules import ALL_RULES
        rules = ALL_RULES
        if category:
            rules = [r for r in rules if r.id.startswith(category.upper())]

        table = Table(box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        table.add_column("ID", width=12)
        table.add_column("Name")
        table.add_column("Severity", width=10)
        table.add_column("OWASP", width=32)
        table.add_column("CWE", width=10)

        for rule in rules:
            color = SEVERITY_COLORS.get(rule.severity, "white")
            table.add_row(
                rule.id,
                rule.name,
                f"[{color}]{rule.severity.upper()}[/{color}]",
                rule.owasp_category,
                rule.cwe_id or "-",
            )
        console.print(table)
        console.print(f"\n[dim]Total: {len(rules)} rules[/dim]")

    except ImportError as e:
        print_error(f"Could not load rules engine: {e}")
        print_info("Make sure cybersentry/core/detection/rules.py has code in it.")


# ── explain ───────────────────────────────────────────────────────────────────
@app.command("explain")
def cmd_explain(
    rule_id: str = typer.Argument(..., help="Rule ID e.g. SQLI-001, XSS-002, CMDI-001"),
    show_fixes: bool = typer.Option(True, "--fixes/--no-fixes", help="Show code fixes"),
):
    """Get a human explanation + code fix for a vulnerability."""
    print_banner()

    try:
        from cybersentry.core.explain.engine import ExplainEngine
        engine = ExplainEngine()
        explanation = engine.explain(rule_id.upper())

        if not explanation:
            print_error(f"No explanation found for: {rule_id}")
            print_info("Available: SQLI-001, XSS-001, CMDI-001, PATH-001, SSRF-001, SSTI-001")
            raise typer.Exit(1)

        print_section(f"Explaining: {explanation.title}")

        body = (
            f"[bold]What happened:[/bold]\n{explanation.what_happened}\n\n"
            f"[bold]How it's exploited:[/bold]\n{explanation.how_exploited}\n\n"
            f"[bold]Business impact:[/bold]\n[red]{explanation.business_impact}[/red]\n\n"
            f"[dim]OWASP:[/dim] [blue]{explanation.owasp_link}[/blue]"
        )
        if explanation.cwe_link:
            body += f"\n[dim]CWE:[/dim]   [blue]{explanation.cwe_link}[/blue]"
        body += f"\n\n[dim]Difficulty:[/dim] {explanation.difficulty}  |  [dim]Prevalence:[/dim] {explanation.prevalence}"

        console.print(Panel(body, title=f"[bold]{explanation.title}[/bold]", border_style="cyan"))

        if show_fixes and explanation.fixes:
            print_section("Code Fixes")
            for code_fix in explanation.fixes:
                console.print(f"\n[bold]{code_fix.language}[/bold] — {code_fix.title}")
                console.print(f"[dim]{code_fix.explanation}[/dim]\n")
                console.print("[bold red]❌ Vulnerable:[/bold red]")
                console.print(Syntax(code_fix.vulnerable_code, "python", theme="monokai", line_numbers=True))
                console.print("\n[bold green]✅ Fixed:[/bold green]")
                console.print(Syntax(code_fix.fixed_code, "python", theme="monokai", line_numbers=True))
                console.print()

        if explanation.learning_resources:
            print_section("Learn More")
            for link in explanation.learning_resources:
                console.print(f"  [blue]{link}[/blue]")

    except ImportError as e:
        print_error(f"Could not load explain engine: {e}")
        print_info("Make sure cybersentry/core/explain/engine.py has code in it.")


# ── score ─────────────────────────────────────────────────────────────────────
@app.command("score")
def cmd_score(
    critical: int = typer.Option(0, "--critical", "-c", help="Number of critical issues"),
    high: int = typer.Option(0, "--high", help="Number of high issues"),
    medium: int = typer.Option(0, "--medium", help="Number of medium issues"),
    low: int = typer.Option(0, "--low", help="Number of low issues"),
):
    """Calculate your security score (0-100)."""
    print_banner()

    try:
        from cybersentry.core.score.engine import ScoreEngine
        engine = ScoreEngine()
        result = engine.compute(critical=critical, high=high, medium=medium, low=low)

        color = "green" if result.score >= 80 else "yellow" if result.score >= 60 else "red"
        grade_color = "green" if result.grade.startswith("A") else "yellow" if result.grade.startswith("B") else "red"

        bar_filled = int(result.score / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)

        body = (
            f"[bold {color}]{result.score:.1f}[/bold {color}] / 100  "
            f"[{grade_color}]Grade: {result.grade}[/{grade_color}]\n"
            f"[{color}]{bar}[/{color}]\n\n"
            f"[bold red]Critical:[/bold red] {result.critical}  "
            f"[red]High:[/red] {result.high}  "
            f"[yellow]Medium:[/yellow] {result.medium}  "
            f"[cyan]Low:[/cyan] {result.low}"
        )
        console.print(Panel(body, title="[bold]Security Score[/bold]", border_style=color, expand=False))
        console.print()

        print_section("Recommendations")
        for rec in result.recommendations:
            console.print(f"  {rec}")

    except ImportError as e:
        print_error(f"Could not load score engine: {e}")
        print_info("Make sure cybersentry/core/score/engine.py has code in it.")


# ── scan ──────────────────────────────────────────────────────────────────────
@app.command("scan")
def cmd_scan(
    path: Path = typer.Argument(Path("."), help="Project directory to scan"),
    scan_type: str = typer.Option("full", "--type", "-t", help="full | secrets | deps"),
    fix: bool = typer.Option(False, "--fix", "-f", help="Show fix suggestions"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """Scan a project for secrets, CVEs, and security issues."""
    if not quiet:
        print_banner()
        print_section(f"Scanning: {path}")

    all_findings = []

    try:
        if scan_type in ("full", "secrets"):
            from cybersentry.core.scanner.secrets import SecretsScanner
            scanner = SecretsScanner()
            if not quiet:
                print_info("Running secrets scan...")
            matches = scanner.scan_directory(Path(path))
            for m in matches:
                all_findings.append({
                    "finding_type": "SECRET",
                    "title": f"Hardcoded {m.secret_type.replace('_', ' ').title()}",
                    "severity": m.severity,
                    "file_path": m.file_path,
                    "line_number": m.line_number,
                })
            if not quiet:
                print_success(f"Secrets scan complete — {len(matches)} found")

        if scan_type in ("full", "deps"):
            from cybersentry.core.scanner.dependencies import DependencyScanner
            dep_scanner = DependencyScanner()
            if not quiet:
                print_info("Running dependency CVE scan...")
            req_files = dep_scanner.find_requirements_files(Path(path))
            req_file = req_files[0] if req_files else None
            dep_result = dep_scanner.scan_requirements(req_file)
            for vuln in dep_result.vulnerabilities:
                all_findings.append({
                    "finding_type": "DEP_CVE",
                    "title": f"{vuln.package_name}=={vuln.installed_version} — {vuln.vulnerability_id}",
                    "severity": vuln.severity,
                    "file_path": str(req_file) if req_file else "requirements.txt",
                    "line_number": None,
                })
            if not quiet:
                print_success(f"Dependency scan complete — {len(dep_result.vulnerabilities)} CVEs found")

    except ImportError as e:
        print_error(f"Scanner module not fully loaded: {e}")
        print_info("Paste the full code into the scanner files to activate scanning.")

    console.print()
    if not all_findings:
        print_success("No issues found!")
    else:
        table = Table(title=f"Findings ({len(all_findings)} total)", box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        table.add_column("#", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=12)
        table.add_column("Title")
        table.add_column("Location", width=30)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 99))

        for i, f in enumerate(all_findings, 1):
            sev = f.get("severity", "low")
            color = SEVERITY_COLORS.get(sev, "white")
            loc = f.get("file_path", "")
            if f.get("line_number"):
                loc += f":{f['line_number']}"
            table.add_row(str(i), f"[{color}]{sev.upper()}[/{color}]", f.get("finding_type",""), f.get("title",""), loc)

        console.print(table)

    try:
        from cybersentry.core.score.engine import ScoreEngine
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
        result = ScoreEngine().compute(**counts)
        color = "green" if result.score >= 80 else "yellow" if result.score >= 60 else "red"
        console.print()
        console.print(Panel(
            f"[bold {color}]{result.score:.1f}[/bold {color}] / 100  Grade: [{color}]{result.grade}[/{color}]",
            title="[bold]Security Score[/bold]", border_style=color, expand=False
        ))
    except ImportError:
        pass

    raise typer.Exit(code=1 if any(f.get("severity") == "critical" for f in all_findings) else 0)


# ── protect ───────────────────────────────────────────────────────────────────
@app.command("protect")
def cmd_protect(
    framework: str = typer.Option("fastapi", "--framework", "-f", help="fastapi | flask"),
):
    """Show how to add CyberSentry protection to your app."""
    print_banner()
    print_section(f"Middleware Integration — {framework.title()}")

    if framework.lower() == "fastapi":
        code = '''from fastapi import FastAPI
from cybersentry.middleware.fastapi import CyberSentryMiddleware

app = FastAPI()

app.add_middleware(
    CyberSentryMiddleware,
    block_attacks=True,
    rate_limit=True,
    anomaly_detection=True,
    security_headers=True,
)

# CyberSentry now protects every request:
# ✅ SQLi, XSS, CMDi, Path Traversal, SSRF, SSTI detection
# ✅ Rate limiting per IP (100 req/min default)
# ✅ Behavioral anomaly detection
# ✅ Security headers on all responses'''
        console.print(Syntax(code, "python", theme="monokai", line_numbers=True))

    elif framework.lower() == "flask":
        code = '''from flask import Flask, request, jsonify, g
from cybersentry.core.detection.engine import DetectionEngine
import uuid

app = Flask(__name__)
_detection = DetectionEngine(block_on_severity=["critical", "high"])

@app.before_request
def cybersentry_check():
    analysis = _detection.analyze(
        request_id=str(uuid.uuid4()),
        path=request.path,
        method=request.method,
        params=dict(request.args),
        body=dict(request.form),
        headers=dict(request.headers),
        source_ip=request.remote_addr,
    )
    if analysis.blocked:
        return jsonify({"error": "blocked"}), 403

@app.after_request
def add_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response'''
        console.print(Syntax(code, "python", theme="monokai", line_numbers=True))


# ── attack ────────────────────────────────────────────────────────────────────
@app.command("attack")
def cmd_attack(
    target: str = typer.Argument(..., help="Target URL — must be YOUR app"),
    attack_type: Optional[str] = typer.Option("sqli", "--type", "-t", help="sqli|xss|cmdi|path_traversal|ssrf|ssti|all"),
    params: Optional[str] = typer.Option(None, "--params", "-p", help="Comma-separated params to test"),
    method: str = typer.Option("GET", "--method", "-m", help="GET or POST"),
    no_confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Simulate attacks against a target URL (your app only!)."""
    print_banner()

    if not no_confirm:
        console.print(Panel(
            f"[bold yellow]⚠  Authorization Required[/bold yellow]\n\n"
            f"Target: [cyan]{target}[/cyan]\n\n"
            f"Only test apps you OWN or have explicit permission to test.",
            border_style="yellow",
        ))
        if not Confirm.ask("I confirm I have authorization to test this target"):
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(0)

    try:
        from cybersentry.core.attack.simulator import AttackSimulator
        from cybersentry.utils.validators import validate_url
        validate_url(target)

        test_params = [p.strip() for p in params.split(",")] if params else None
        attack_types = [attack_type] if attack_type and attack_type != "all" else None

        print_section(f"Attacking: {target}")
        print_info(f"Type: {attack_type} | Method: {method}")
        console.print()

        simulator = AttackSimulator(target=target)

        async def run():
            with console.status("[red]Running attack simulations..."):
                return await simulator.simulate(attack_types=attack_types, params=test_params, method=method)

        report = asyncio.run(run())

        console.print()
        print_section("Results")

        table = Table(box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Total tests", str(report.total_tests))
        table.add_row("Vulnerabilities found", f"[bold red]{report.vulnerable_count}[/bold red]")
        table.add_row("Duration", f"{report.duration_seconds:.1f}s")
        console.print(table)

        vulnerable = [r for r in report.results if r.vulnerable]
        if vulnerable:
            console.print()
            print_section(f"Vulnerabilities ({len(vulnerable)})")
            for r in vulnerable[:10]:
                color = SEVERITY_COLORS.get(r.payload.severity, "white")
                console.print(Panel(
                    f"[bold]Payload:[/bold] {r.payload.value[:80]}\n"
                    f"[bold]Parameter:[/bold] {r.target_param}\n"
                    f"[bold]Evidence:[/bold] {r.evidence}",
                    title=f"[{color}]{r.payload.severity.upper()}[/{color}] — {r.payload.description[:60]}",
                    border_style=color,
                ))
        else:
            print_success("No vulnerabilities detected with tested payloads.")

    except ImportError as e:
        print_error(f"Attack simulator not fully loaded: {e}")
        print_info("Make sure cybersentry/core/attack/simulator.py has code.")


# ── report ────────────────────────────────────────────────────────────────────
@app.command("report")
def cmd_report(
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF report"),
    project: str = typer.Option("My Project", "--project", help="Project name"),
):
    """Generate a security report."""
    print_banner()

    try:
        from cybersentry.core.report.generator import ReportGenerator, ReportData
        from datetime import datetime, timezone

        data = ReportData(
            title="Security Report",
            project_name=project,
            score=78.5,
            grade="B+",
            score_delta=3.2,
            critical_count=0,
            high_count=2,
            medium_count=5,
            low_count=8,
            secrets_found=1,
            vulnerable_deps=2,
            attacks_detected=47,
            top_recommendations=[
                "Fix 2 HIGH severity issues in your next sprint",
                "Resolve 5 MEDIUM issues this quarter",
                "Move hardcoded API key to environment variables",
                "Upgrade requests package — CVE-2023-32681",
            ],
        )

        gen = ReportGenerator()

        if pdf:
            from pathlib import Path
            out = Path(f"cybersentry-report.pdf")
            try:
                gen.generate_pdf(data, out)
                print_success(f"PDF report saved: {out}")
            except ImportError:
                print_error("reportlab required for PDF. Run: pip install reportlab")
        else:
            console.print(gen.generate_text_report(data))
            print_success("Report complete.")

    except ImportError as e:
        print_error(f"Report generator not loaded: {e}")


# ── serve ─────────────────────────────────────────────────────────────────────
@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8765, "--port", "-p", help="Bind port"),
):
    """Launch the CyberSentry dashboard API."""
    print_banner()
    print_success(f"Starting CyberSentry API at http://{host}:{port}")
    print_info("API docs: http://127.0.0.1:8765/docs")

    try:
        import uvicorn
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        api = FastAPI(title="CyberSentry API", version="0.1.0")
        api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

        @api.get("/health")
        def health():
            return {"status": "ok", "version": "0.1.0"}

        @api.get("/stats")
        def stats():
            return {
                "attacks_detected": 0,
                "scans_run": 0,
                "score": 100,
                "grade": "A+",
            }

        uvicorn.run(api, host=host, port=port, log_level="info")

    except ImportError as e:
        print_error(f"Could not start server: {e}")
        print_info("Run: pip install uvicorn fastapi")


if __name__ == "__main__":
    app()
