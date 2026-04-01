"""
Unit tests for CyberSentry secret and dependency scanners.
"""
import pytest
from pathlib import Path
import tempfile
import os

from cybersentry.core.scanner.secrets import SecretsScanner
from cybersentry.utils.validators import (
    looks_like_sqli, looks_like_xss, looks_like_cmdi,
    shannon_entropy, is_high_entropy_string, redact_secret,
)


# ── Secrets scanner ───────────────────────────────────────────────────────────
class TestSecretsScanner:
    @pytest.fixture
    def scanner(self):
        return SecretsScanner()

    def _write_temp_file(self, content: str, suffix=".py") -> Path:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return Path(path)

    def test_detects_aws_key(self, scanner):
        path = self._write_temp_file('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        try:
            matches = scanner.scan_file(path)
            assert len(matches) >= 1
            assert any(m.secret_type == "aws_access_key" for m in matches)
            # Verify it's redacted
            for m in matches:
                assert "AKIAIOSFODNN7EXAMPLE" not in m.redacted_value
        finally:
            path.unlink()

    def test_detects_openai_key(self, scanner):
        # 48-char alphanumeric after sk-
        fake_key = "sk-" + "a" * 48
        path = self._write_temp_file(f'OPENAI_KEY = "{fake_key}"\n')
        try:
            matches = scanner.scan_file(path)
            assert len(matches) >= 1
        finally:
            path.unlink()

    def test_detects_hardcoded_password(self, scanner):
        path = self._write_temp_file('password = "SuperSecret123!"\n')
        try:
            matches = scanner.scan_file(path)
            # Should find (password= pattern)
            assert len(matches) >= 1
        finally:
            path.unlink()

    def test_detects_database_url(self, scanner):
        path = self._write_temp_file(
            'DATABASE_URL = "postgresql://admin:P@ssw0rd@prod.db.example.com:5432/app"\n'
        )
        try:
            matches = scanner.scan_file(path)
            assert len(matches) >= 1
            assert any(m.secret_type == "database_url" for m in matches)
        finally:
            path.unlink()

    def test_skips_example_values(self, scanner):
        path = self._write_temp_file('API_KEY = "your-api-key-here"\n')
        try:
            matches = scanner.scan_file(path)
            # Should be filtered as false positive
            assert len(matches) == 0
        finally:
            path.unlink()

    def test_skips_placeholder_values(self, scanner):
        path = self._write_temp_file('SECRET_KEY = "<your-secret-key>"\n')
        try:
            matches = scanner.scan_file(path)
            assert len(matches) == 0
        finally:
            path.unlink()

    def test_secret_is_always_redacted(self, scanner):
        fake_key = "sk-" + "X" * 48
        path = self._write_temp_file(f'key = "{fake_key}"\n')
        try:
            matches = scanner.scan_file(path)
            for match in matches:
                # Actual key value must not be in redacted_value
                assert fake_key not in match.redacted_value
                assert fake_key not in match.line_context
        finally:
            path.unlink()

    def test_skips_binary_files(self, scanner):
        fd, path_str = tempfile.mkstemp(suffix=".png")
        os.write(fd, b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        os.close(fd)
        path = Path(path_str)
        try:
            assert scanner._should_skip(path)
        finally:
            path.unlink()

    def test_skips_git_directory(self, scanner):
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            config = git_dir / "config"
            config.write_text('SECRET = "AKIAIOSFODNN7EXAMPLE"')
            assert scanner._should_skip(config)


# ── Validator helpers ──────────────────────────────────────────────────────────
class TestValidators:
    def test_sqli_detected(self):
        assert looks_like_sqli("' OR 1=1--")[0]
        assert looks_like_sqli("UNION SELECT * FROM users")[0]
        assert looks_like_sqli("1; DROP TABLE users;--")[0]

    def test_clean_sqli_not_flagged(self):
        assert not looks_like_sqli("hello world")[0]
        assert not looks_like_sqli("user@example.com")[0]
        assert not looks_like_sqli("42")[0]

    def test_xss_detected(self):
        assert looks_like_xss('<script>alert(1)</script>')[0]
        assert looks_like_xss('<img onerror=alert(1)>')[0]
        assert looks_like_xss('javascript:void(0)')[0]

    def test_cmdi_detected(self):
        assert looks_like_cmdi("file.txt; cat /etc/passwd")[0]
        assert looks_like_cmdi("$(whoami)")[0]
        assert looks_like_cmdi("`id`")[0]

    def test_shannon_entropy_high_for_random(self):
        # Random-looking string should have high entropy
        entropy = shannon_entropy("aB3kP9mN2xQ7rT1wY5")
        assert entropy > 3.0

    def test_shannon_entropy_low_for_repeated(self):
        # Repeated chars have low entropy
        entropy = shannon_entropy("aaaaaaaaaaaaaaaa")
        assert entropy < 1.0

    def test_high_entropy_detection(self):
        assert is_high_entropy_string("aB3kP9mN2xQ7rT1wY5cD6gH8jK0lZ4vE")
        assert not is_high_entropy_string("hello world")
        assert not is_high_entropy_string("short")  # too short

    def test_redact_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = redact_secret(secret)
        assert secret not in redacted
        assert "AKIA" in redacted  # first 4 chars visible
        assert "..." in redacted

    def test_redact_short_secret(self):
        # Short secrets should be fully masked
        redacted = redact_secret("pass")
        assert "pass" not in redacted
        assert redacted == "****"


# ── Score engine ───────────────────────────────────────────────────────────────
class TestScoreEngine:
    def test_perfect_score_no_issues(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        result = eng.compute(0, 0, 0, 0)
        assert result.score == 100.0
        assert result.grade == "A+"

    def test_critical_issues_drop_score(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        result = eng.compute(critical=3)
        assert result.score < 70
        assert result.grade in ("C", "C+", "C-", "D", "F")

    def test_score_is_bounded_0_to_100(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        for c, h, m, l in [(100, 0, 0, 0), (0, 0, 0, 0), (5, 10, 20, 50)]:
            result = eng.compute(c, h, m, l)
            assert 0 <= result.score <= 100

    def test_grade_f_for_many_criticals(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        result = eng.compute(critical=10)
        assert result.grade == "F"

    def test_more_issues_worse_score(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        r1 = eng.compute(critical=1)
        r2 = eng.compute(critical=5)
        assert r1.score > r2.score

    def test_compute_from_findings(self):
        from cybersentry.core.score.engine import ScoreEngine
        eng = ScoreEngine()
        findings = [
            {"severity": "critical"}, {"severity": "high"},
            {"severity": "medium"}, {"severity": "low"},
        ]
        result = eng.compute_from_findings(findings)
        assert result.critical == 1
        assert result.high == 1
        assert result.medium == 1
        assert result.low == 1