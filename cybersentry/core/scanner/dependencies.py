"""
CyberSentry Dependency Scanner.
Checks installed packages and requirements files for known CVEs.
Uses pip-audit (wraps PyPI Advisory Database) for vulnerability data.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DependencyVulnerability:
    package_name: str
    installed_version: str
    vulnerability_id: str    # CVE or GHSA ID
    description: str
    severity: str
    cvss_score: float | None
    fix_versions: list[str]
    fix_available: bool
    url: str | None = None


@dataclass
class DependencyScanResult:
    requirements_file: str | None
    packages_checked: int
    vulnerabilities: list[DependencyVulnerability]
    errors: list[str]

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "high")

    @property
    def vulnerable_packages(self) -> set[str]:
        return {v.package_name for v in self.vulnerabilities}


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    else:
        return "low"


class DependencyScanner:
    """
    Scans Python dependencies for known vulnerabilities using pip-audit.
    Supports requirements.txt, pyproject.toml, and the current environment.
    """

    def scan_requirements(
        self,
        requirements_path: Path | None = None,
        progress_callback=None,
    ) -> DependencyScanResult:
        """
        Run pip-audit against requirements or current environment.

        Args:
            requirements_path: Path to requirements.txt. None = scan current venv.
            progress_callback: Optional callable(message: str).
        """
        errors: list[str] = []

        cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"]

        if requirements_path:
            if not requirements_path.exists():
                return DependencyScanResult(
                    requirements_file=str(requirements_path),
                    packages_checked=0,
                    vulnerabilities=[],
                    errors=[f"Requirements file not found: {requirements_path}"],
                )
            cmd += ["-r", str(requirements_path)]

        if progress_callback:
            progress_callback("Running pip-audit...")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw = result.stdout or result.stderr

            if not raw.strip():
                return DependencyScanResult(
                    requirements_file=str(requirements_path) if requirements_path else None,
                    packages_checked=0,
                    vulnerabilities=[],
                    errors=["pip-audit returned no output. Is it installed? pip install pip-audit"],
                )

            data = json.loads(raw)
        except subprocess.TimeoutExpired:
            return DependencyScanResult(
                requirements_file=str(requirements_path) if requirements_path else None,
                packages_checked=0,
                vulnerabilities=[],
                errors=["pip-audit timed out after 120 seconds."],
            )
        except json.JSONDecodeError as exc:
            return DependencyScanResult(
                requirements_file=str(requirements_path) if requirements_path else None,
                packages_checked=0,
                vulnerabilities=[],
                errors=[f"Failed to parse pip-audit output: {exc}"],
            )
        except FileNotFoundError:
            return DependencyScanResult(
                requirements_file=str(requirements_path) if requirements_path else None,
                packages_checked=0,
                vulnerabilities=[],
                errors=["pip-audit not found. Install with: pip install pip-audit"],
            )

        vulnerabilities: list[DependencyVulnerability] = []
        packages_checked = 0

        # pip-audit JSON format: {"dependencies": [{"name": ..., "version": ..., "vulns": [...]}]}
        for dep in data.get("dependencies", []):
            packages_checked += 1
            pkg_name = dep.get("name", "")
            pkg_version = dep.get("version", "")

            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "")
                description = vuln.get("description", "")
                fix_versions = vuln.get("fix_versions", [])

                # Try to get CVSS from aliases
                cvss_score: float | None = None
                aliases = vuln.get("aliases", [])
                # pip-audit doesn't always include CVSS; use advisory severity if available
                severity_hint = vuln.get("severity", "").lower()
                severity_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}
                severity = severity_map.get(severity_hint, _cvss_to_severity(cvss_score))

                vulnerabilities.append(DependencyVulnerability(
                    package_name=pkg_name,
                    installed_version=pkg_version,
                    vulnerability_id=vuln_id,
                    description=description[:500],
                    severity=severity,
                    cvss_score=cvss_score,
                    fix_versions=fix_versions,
                    fix_available=bool(fix_versions),
                    url=f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else None,
                ))

        return DependencyScanResult(
            requirements_file=str(requirements_path) if requirements_path else None,
            packages_checked=packages_checked,
            vulnerabilities=vulnerabilities,
            errors=errors,
        )

    def scan_outdated(self) -> list[dict]:
        """Return a list of outdated packages (not necessarily vulnerable)."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--outdated", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

    def get_installed_packages(self) -> list[dict]:
        """List all installed packages with their versions."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return json.loads(result.stdout) if result.stdout else []
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

    def find_requirements_files(self, directory: Path) -> list[Path]:
        """Find all requirements files in a directory tree."""
        patterns = [
            "requirements.txt",
            "requirements/*.txt",
            "requirements-*.txt",
            "pyproject.toml",
        ]
        found = []
        for pattern in patterns:
            found.extend(directory.glob(pattern))
        return found
