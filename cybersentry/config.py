"""
CyberSentry configuration and application settings.
Uses pydantic-settings for env-var driven config.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ── Project paths ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = Path.home() / ".cybersentry"
DB_PATH = DATA_DIR / "cybersentry.db"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"


def ensure_dirs() -> None:
    """Create runtime directories if they don't exist."""
    for d in (DATA_DIR, REPORTS_DIR, LOGS_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ── Settings ─────────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CYBERSENTRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = Field(
        default_factory=lambda: f"sqlite+aiosqlite:///{DB_PATH}"
    )

    # Scoring
    score_history_days: int = 30
    critical_severity_weight: float = 10.0
    high_severity_weight: float = 5.0
    medium_severity_weight: float = 2.0
    low_severity_weight: float = 0.5

    # Rate limiting (middleware)
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    rate_limit_ban_threshold: int = 500  # requests before temp-ban

    # Behavioral anomaly
    anomaly_baseline_requests: int = 1000   # requests before baseline is set
    anomaly_z_score_threshold: float = 3.0  # std deviations before alert

    # Reporting
    report_schedule_days: int = 7

    # API (for middleware communication)
    api_host: str = "0.0.0.0"
    api_port: int = 8765

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # NVD / CVE database (optional API key for higher rate limits)
    nvd_api_key: str | None = None

    # OpenAI / Anthropic (Phase 2 — LLM fix suggestions)
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # Feature flags
    enable_llm_fixes: bool = False
    enable_dashboard: bool = True
    enable_behavioral_anomaly: bool = True


settings = Settings()
ensure_dirs()
