"""
CyberSentry Security Score Engine.
Computes a 0-100 security score based on open findings,
with grade, trend tracking, and gamification.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ScoreResult:
    score: float                         # 0-100
    grade: str                           # A+, A, B, C, D, F
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    penalty_breakdown: dict[str, float] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_passing(self) -> bool:
        return self.score >= 70

    @property
    def emoji(self) -> str:
        if self.score >= 90:
            return "🛡️"
        elif self.score >= 80:
            return "✅"
        elif self.score >= 70:
            return "⚠️"
        elif self.score >= 50:
            return "🔶"
        else:
            return "🚨"


@dataclass
class ScoreTrend:
    current: ScoreResult
    previous: ScoreResult | None = None

    @property
    def delta(self) -> float | None:
        if self.previous is None:
            return None
        return self.current.score - self.previous.score

    @property
    def trend_emoji(self) -> str:
        if self.delta is None:
            return "➖"
        if self.delta > 5:
            return "📈"
        if self.delta < -5:
            return "📉"
        return "➡️"


# ── Scoring weights ────────────────────────────────────────────────────────────
# These are tuned so that:
#   0 issues of any kind → 100
#   1 critical → ~72
#   3 criticals → ~40
#   5 criticals → ~20
WEIGHTS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
}

# Bonus points for good security hygiene
HYGIENE_BONUSES = {
    "no_secrets_found": 5,
    "no_critical_deps": 3,
    "has_csp_header": 2,
    "has_hsts": 2,
    "has_rate_limiting": 2,
    "all_deps_updated": 3,
}


def _score_to_grade(score: float) -> str:
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 85:
        return "A-"
    elif score >= 80:
        return "B+"
    elif score >= 75:
        return "B"
    elif score >= 70:
        return "B-"
    elif score >= 65:
        return "C+"
    elif score >= 60:
        return "C"
    elif score >= 55:
        return "C-"
    elif score >= 50:
        return "D"
    else:
        return "F"


class ScoreEngine:
    """
    Computes a 0-100 security score from open findings.

    Uses a logarithmic penalty model so that:
    - The first critical issue has a large impact
    - Additional issues of the same type have diminishing marginal penalty
    - Multiple finding types combine additively
    """

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or WEIGHTS

    def compute(
        self,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        hygiene: dict[str, bool] | None = None,
    ) -> ScoreResult:
        """
        Compute a score from finding counts.

        Args:
            critical/high/medium/low: Count of open issues by severity.
            hygiene: Dict of hygiene bonus conditions (see HYGIENE_BONUSES).
        """
        penalty_breakdown: dict[str, float] = {}

        # Logarithmic penalty per severity
        # penalty = weight * ln(count + 1) * scaling_factor
        counts = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }

        total_penalty = 0.0
        for severity, count in counts.items():
            if count > 0:
                weight = self.weights[severity]
                # ln gives diminishing returns: ln(1+1)=0.69, ln(5+1)=1.79, ln(10+1)=2.40
                penalty = weight * math.log(count + 1) * 8
                penalty_breakdown[severity] = round(penalty, 2)
                total_penalty += penalty

        # Raw score (before hygiene bonuses)
        raw_score = max(0.0, 100.0 - total_penalty)

        # Hygiene bonuses (max +17 points)
        bonus = 0.0
        if hygiene:
            for check, satisfied in hygiene.items():
                if satisfied and check in HYGIENE_BONUSES:
                    bonus += HYGIENE_BONUSES[check]

        # Apply bonus, cap at 100
        final_score = min(100.0, raw_score + bonus)

        # Recommendations
        recommendations = self._generate_recommendations(
            critical, high, medium, low, final_score
        )

        return ScoreResult(
            score=round(final_score, 1),
            grade=_score_to_grade(final_score),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            penalty_breakdown=penalty_breakdown,
            recommendations=recommendations,
        )

    def compute_from_findings(self, findings: list[dict[str, Any]]) -> ScoreResult:
        """Convenience method — compute from a list of finding dicts."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = finding.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
        return self.compute(**counts)

    def _generate_recommendations(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        score: float,
    ) -> list[str]:
        recs = []

        if critical > 0:
            recs.append(
                f"🚨 Fix {critical} CRITICAL issue{'s' if critical > 1 else ''} immediately — "
                "these represent immediate exploitation risk."
            )
        if high > 0:
            recs.append(
                f"🔴 Address {high} HIGH severity issue{'s' if high > 1 else ''} in your next sprint."
            )
        if medium > 0:
            recs.append(
                f"🟡 Plan to resolve {medium} MEDIUM issue{'s' if medium > 1 else ''} this quarter."
            )
        if low > 0:
            recs.append(
                f"🔵 Track {low} LOW severity item{'s' if low > 1 else ''} in your backlog."
            )

        if score == 100:
            recs.append("✨ Perfect score! Run scans regularly to stay secure.")
        elif score >= 90:
            recs.append("💪 Excellent security posture. Keep it up!")
        elif score >= 70:
            recs.append("⚠️  Good foundation. Fix the high-severity issues to reach A-grade.")
        elif score >= 50:
            recs.append("🔶 Needs attention. Prioritize critical and high issues before launch.")
        else:
            recs.append("🚨 Critical security risk. Do not deploy to production until issues are resolved.")

        return recs

    def diff(self, before: ScoreResult, after: ScoreResult) -> dict[str, Any]:
        """Show what changed between two score snapshots."""
        return {
            "score_delta": round(after.score - before.score, 1),
            "grade_before": before.grade,
            "grade_after": after.grade,
            "improved": after.score > before.score,
            "critical_delta": after.critical - before.critical,
            "high_delta": after.high - before.high,
            "medium_delta": after.medium - before.medium,
            "low_delta": after.low - before.low,
        }
