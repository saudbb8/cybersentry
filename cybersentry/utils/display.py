"""
CyberSentry display utilities.
Centralised Rich console helpers so every command looks consistent.
"""
from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

console = Console(stderr=False)
err_console = Console(stderr=True)

# ── Severity colours ──────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}

GRADE_COLORS = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "D": "red",
    "F": "bold red",
}


def severity_badge(severity: str) -> Text:
    color = SEVERITY_COLORS.get(severity.lower(), "white")
    return Text(f" {severity.upper()} ", style=f"bold {color} on grey11")


def print_banner() -> None:
    banner = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
"""
    console.print(banner, style="bold cyan", highlight=False)
    console.print(
        "  [dim]Attack → Detect → Explain → Fix[/dim]  |  "
        "[bold]Developer-first Security Engine[/bold]\n",
        justify="center",
    )


def print_section(title: str) -> None:
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="cyan"))


def print_success(msg: str) -> None:
    console.print(f"[bold green]✔[/bold green]  {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow]⚠[/bold yellow]  {msg}")


def print_error(msg: str) -> None:
    console.print(f"[bold red]✘[/bold red]  {msg}")


def print_info(msg: str) -> None:
    console.print(f"[bold blue]ℹ[/bold blue]  {msg}")


def print_finding(
    title: str,
    severity: str,
    description: str,
    file_path: str | None = None,
    line: int | None = None,
    fix: str | None = None,
    owasp: str | None = None,
) -> None:
    """Print a single finding as a rich panel."""
    color = SEVERITY_COLORS.get(severity.lower(), "white")
    location = ""
    if file_path:
        location = f"\n[dim]File:[/dim] [cyan]{file_path}[/cyan]"
        if line:
            location += f":[yellow]{line}[/yellow]"

    body = f"[bold]{title}[/bold]{location}\n\n{description}"

    if owasp:
        body += f"\n\n[dim]OWASP:[/dim] [blue]{owasp}[/blue]"

    if fix:
        body += f"\n\n[bold green]Fix:[/bold green]\n{fix}"

    console.print(
        Panel(
            body,
            title=f"[{color}] {severity.upper()} [/{color}]",
            border_style=color,
            expand=False,
            padding=(0, 1),
        )
    )


def findings_table(findings: list[dict[str, Any]], title: str = "Findings") -> Table:
    """Build a Rich table from a list of finding dicts."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        expand=False,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=18)
    table.add_column("Title")
    table.add_column("Location", width=30)

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "low")
        color = SEVERITY_COLORS.get(sev.lower(), "white")
        location = f.get("file_path", "") or ""
        if f.get("line_number"):
            location += f":{f['line_number']}"
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("finding_type", ""),
            f.get("title", ""),
            location,
        )

    return table


def score_panel(score: float, grade: str, issues: dict[str, int]) -> Panel:
    """Render a security score as a rich panel."""
    color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
    grade_color = GRADE_COLORS.get(grade, "white")

    bar_filled = int(score / 5)   # 20 chars = 100 points
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    body = (
        f"[bold {color}]{score:.1f}[/bold {color}] / 100  "
        f"[{grade_color}]Grade: {grade}[/{grade_color}]\n"
        f"[{color}]{bar}[/{color}]\n\n"
        f"[bold red]Critical:[/bold red] {issues.get('critical', 0)}  "
        f"[red]High:[/red] {issues.get('high', 0)}  "
        f"[yellow]Medium:[/yellow] {issues.get('medium', 0)}  "
        f"[cyan]Low:[/cyan] {issues.get('low', 0)}"
    )
    return Panel(body, title="[bold]Security Score[/bold]", border_style=color, expand=False)


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )