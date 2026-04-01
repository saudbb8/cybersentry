"""
CyberSentry database models.
Uses SQLAlchemy 2.0 with async support via aiosqlite.
All tables follow OWASP secure design: no raw passwords stored, UUIDs for IDs.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cybersentry.config import settings, DB_PATH, ensure_dirs


# ── Base ─────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Models ───────────────────────────────────────────────────────────────────
class AttackEvent(Base):
    """Records every simulated or real attack event detected."""
    __tablename__ = "attack_events"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    timestamp = Column(DateTime, default=_utcnow, index=True)
    attack_type = Column(String(64), nullable=False, index=True)
    # SQLi, XSS, BruteForce, CmdInjection, PathTraversal, SSRF, etc.
    payload = Column(Text, nullable=True)
    target_url = Column(String(512), nullable=True)
    target_param = Column(String(128), nullable=True)
    source_ip = Column(String(45), nullable=True)        # IPv4 + IPv6
    severity = Column(String(16), nullable=False)         # critical/high/medium/low
    detected = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)
    simulated = Column(Boolean, default=True)
    raw_request = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="attack_event", cascade="all, delete-orphan")


class Finding(Base):
    """A specific vulnerability finding from a scan or simulation."""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    timestamp = Column(DateTime, default=_utcnow, index=True)
    attack_event_id = Column(String(36), ForeignKey("attack_events.id"), nullable=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    finding_type = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    owasp_category = Column(String(64), nullable=True)
    cwe_id = Column(String(16), nullable=True)
    cvss_score = Column(Float, nullable=True)
    fix_available = Column(Boolean, default=False)
    fixed = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    remediation = Column(Text, nullable=True)

    attack_event = relationship("AttackEvent", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")


class Scan(Base):
    """A full scan run (secrets + deps + static analysis)."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    started_at = Column(DateTime, default=_utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    scan_type = Column(String(64), nullable=False)   # full/secrets/deps/sast
    target_path = Column(String(512), nullable=False)
    status = Column(String(16), default="running")   # running/completed/failed
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    score_before = Column(Float, nullable=True)
    score_after = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class SecurityScore(Base):
    """Point-in-time security score snapshots for trend tracking."""
    __tablename__ = "security_scores"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    timestamp = Column(DateTime, default=_utcnow, index=True)
    score = Column(Float, nullable=False)
    grade = Column(String(4), nullable=True)         # A+, A, B, C, D, F
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    project_path = Column(String(512), nullable=True)
    notes = Column(Text, nullable=True)


class BehaviorBaseline(Base):
    """Learned normal behavior baselines per endpoint / IP."""
    __tablename__ = "behavior_baselines"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    endpoint = Column(String(256), nullable=False, index=True)
    method = Column(String(8), nullable=False)
    sample_count = Column(Integer, default=0)
    avg_response_time = Column(Float, nullable=True)
    avg_payload_size = Column(Float, nullable=True)
    request_rate_mean = Column(Float, nullable=True)   # requests/min
    request_rate_stddev = Column(Float, nullable=True)
    last_updated = Column(DateTime, default=_utcnow)
    is_established = Column(Boolean, default=False)    # True after enough samples


class AnomalyEvent(Base):
    """Detected behavioral anomalies from the middleware."""
    __tablename__ = "anomaly_events"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    timestamp = Column(DateTime, default=_utcnow, index=True)
    endpoint = Column(String(256), nullable=False)
    source_ip = Column(String(45), nullable=True)
    anomaly_type = Column(String(64), nullable=False)
    z_score = Column(Float, nullable=True)
    observed_value = Column(Float, nullable=True)
    expected_value = Column(Float, nullable=True)
    severity = Column(String(16), nullable=False)
    action_taken = Column(String(32), nullable=True)   # logged/rate_limited/blocked


class DependencyVuln(Base):
    """Known CVEs found in project dependencies."""
    __tablename__ = "dependency_vulns"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    discovered_at = Column(DateTime, default=_utcnow, index=True)
    package_name = Column(String(128), nullable=False, index=True)
    installed_version = Column(String(64), nullable=False)
    safe_version = Column(String(64), nullable=True)
    vulnerability_id = Column(String(64), nullable=True)   # CVE-XXXX-XXXX
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)
    cvss_score = Column(Float, nullable=True)
    fix_available = Column(Boolean, default=False)
    fixed = Column(Boolean, default=False)


class SecretFinding(Base):
    """Detected hardcoded secrets / credentials."""
    __tablename__ = "secret_findings"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    discovered_at = Column(DateTime, default=_utcnow, index=True)
    secret_type = Column(String(64), nullable=False)     # api_key, password, token, etc.
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=True)
    # NEVER store actual secret value — only redacted hint
    redacted_value = Column(String(64), nullable=True)   # e.g. "AKIAXXX...XXX"
    entropy = Column(Float, nullable=True)
    severity = Column(String(16), nullable=False)
    false_positive = Column(Boolean, default=False)
    remediated = Column(Boolean, default=False)


# ── Engine + Session ─────────────────────────────────────────────────────────
ensure_dirs()

async_engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Sync engine for CLI operations
sync_engine = create_engine(
    str(settings.database_url).replace("sqlite+aiosqlite", "sqlite"),
    echo=False,
)
SyncSessionLocal = sessionmaker(bind=sync_engine, autoflush=False, autocommit=False)


# Enable WAL mode for SQLite (better concurrent reads)
@event.listens_for(sync_engine, "connect")
def set_sqlite_pragmas(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def init_db() -> None:
    """Create all tables. Safe to call multiple times."""
    ensure_dirs()
    Base.metadata.create_all(bind=sync_engine)


def get_sync_session():
    """Sync session context manager for CLI commands."""
    session = SyncSessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()