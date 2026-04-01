"""
Unit tests for CyberSentry defence layers.
Tests cover: IP reputation, flood guard, fingerprinting, honeypot, credential guard.
"""
import pytest
import time

from cybersentry.core.defense.ip_reputation import IPReputationEngine, IPVerdict
from cybersentry.core.defense.flood_guard import FloodGuard, SlidingWindowCounter
from cybersentry.core.defense.fingerprint import FingerprintEngine
from cybersentry.core.defense.tarpit import HoneypotManager, ChallengeEngine
from cybersentry.core.defense.credential_guard import CredentialGuard


# ── Layer 1: IP Reputation ────────────────────────────────────────────────────
class TestIPReputation:
    @pytest.fixture
    def engine(self):
        return IPReputationEngine(block_tor=True, challenge_datacenters=True, block_abusive=True)

    def test_clean_ip_is_allowed(self, engine):
        result = engine.check("8.8.8.8")
        assert result.verdict == IPVerdict.ALLOW

    def test_private_ip_is_allowed(self, engine):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
            result = engine.check(ip)
            assert result.verdict == IPVerdict.ALLOW, f"Private IP {ip} should be allowed"

    def test_explicit_blocklist(self, engine):
        engine.add_to_blocklist("1.2.3.4")
        result = engine.check("1.2.3.4")
        assert result.verdict == IPVerdict.BLOCK
        assert "blocklist" in result.reason

    def test_explicit_allowlist_overrides_block(self, engine):
        engine.add_to_blocklist("5.5.5.5")
        engine.add_to_allowlist("5.5.5.5")
        result = engine.check("5.5.5.5")
        assert result.verdict == IPVerdict.ALLOW

    def test_temporary_ban(self, engine):
        engine.ban("9.9.9.9", duration_seconds=3600)
        result = engine.check("9.9.9.9")
        assert result.verdict == IPVerdict.BLOCK
        assert "temporary ban" in result.reason

    def test_aws_ip_challenged(self, engine):
        # 52.0.0.1 is in AWS range
        result = engine.check("52.0.0.1")
        assert result.verdict == IPVerdict.CHALLENGE
        assert result.is_datacenter

    def test_known_abusive_range_blocked(self, engine):
        # 80.82.77.1 is in Shodan scanning range
        result = engine.check("80.82.77.1")
        assert result.verdict == IPVerdict.BLOCK

    def test_invalid_ip_blocked(self, engine):
        result = engine.check("not_an_ip")
        assert result.verdict == IPVerdict.BLOCK

    def test_stats_returned(self, engine):
        stats = engine.get_stats()
        assert "blocklist_size" in stats
        assert "active_bans" in stats


# ── Layer 2: Flood Guard ──────────────────────────────────────────────────────
class TestFloodGuard:
    @pytest.fixture
    def guard(self):
        return FloodGuard(
            http_flood_rpm=10,
            http_flood_burst=5,
            max_header_size=1000,
            max_body_size=100,
            conn_rate_per_sec=100,  # high so tests don't trigger it
            global_rpm=10000,
        )

    def test_clean_request_allowed(self, guard):
        ok, reason = guard.check_request("1.2.3.4", "GET", "/")
        assert ok
        assert reason == "ok"

    def test_header_overflow_blocked(self, guard):
        ok, reason = guard.check_request(
            "2.2.2.2", "GET", "/", header_size=2000
        )
        assert not ok
        assert "header_too_large" in reason

    def test_body_bomb_blocked(self, guard):
        ok, reason = guard.check_request(
            "3.3.3.3", "POST", "/", content_length=1000
        )
        assert not ok
        assert "body_too_large" in reason

    def test_burst_limit(self, guard):
        ip = "4.4.4.4"
        results = []
        for _ in range(10):
            ok, _ = guard.check_request(ip, "GET", "/")
            results.append(ok)
        # After 5 requests (burst limit), should start blocking
        assert results[:5].count(True) >= 4  # first 5 should mostly pass
        assert not results[-1]  # last should be blocked

    def test_banned_ip_blocked(self, guard):
        guard.ban_ip("5.5.5.5", 3600)
        ok, reason = guard.check_request("5.5.5.5", "GET", "/")
        assert not ok
        assert "banned" in reason

    def test_stats_available(self, guard):
        stats = guard.get_stats()
        assert "global_rpm" in stats
        assert "active_bans" in stats


class TestSlidingWindowCounter:
    def test_counts_within_window(self):
        counter = SlidingWindowCounter(window_seconds=60)
        for _ in range(5):
            counter.add()
        assert counter.count() == 5

    def test_increments_correctly(self):
        counter = SlidingWindowCounter(window_seconds=60)
        assert counter.add() == 1
        assert counter.add() == 2
        assert counter.add() == 3


# ── Layer 3: Fingerprinting ───────────────────────────────────────────────────
class TestFingerprintEngine:
    @pytest.fixture
    def engine(self):
        return FingerprintEngine(bot_score_challenge_threshold=50, bot_score_block_threshold=80)

    def test_known_scanner_blocked(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={"user-agent": "sqlmap/1.7 (https://sqlmap.org)"},
        )
        assert result.bot_score >= 80
        assert result.is_known_bad_bot
        assert result.recommended_action == "block"

    def test_nikto_blocked(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={"user-agent": "Nikto/2.1.6"},
        )
        assert result.recommended_action == "block"

    def test_headless_chrome_challenged(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={"user-agent": "Mozilla/5.0 HeadlessChrome/110"},
        )
        assert result.is_headless
        assert result.bot_score >= 50

    def test_curl_detected(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={"user-agent": "curl/7.68.0"},
        )
        assert result.bot_score > 0   # curl is a known automation tool

    def test_real_browser_low_score(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/home",
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "accept": "text/html,application/xhtml+xml",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br",
            },
        )
        assert result.recommended_action == "allow"
        assert result.bot_score < 50

    def test_honeypot_field_triggers_block(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="POST",
            path="/contact",
            headers={"user-agent": "Mozilla/5.0"},
            form_data={"name": "John", "_email": "filled_by_bot@evil.com"},
            honeypot_fields={"_email"},
        )
        assert result.bot_score >= 100
        assert result.recommended_action == "block"
        assert any("honeypot" in s for s in result.signals)

    def test_missing_ua_increases_score(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={},  # no user-agent
        )
        assert result.bot_score > 0

    def test_googlebot_is_known_good(self, engine):
        result = engine.fingerprint(
            ip="1.2.3.4",
            method="GET",
            path="/",
            headers={"user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
        )
        assert result.is_known_good_bot
        assert result.recommended_action == "allow"

    def test_fingerprint_hash_is_consistent(self, engine):
        headers = {"user-agent": "TestAgent/1.0", "accept": "*/*"}
        r1 = engine.fingerprint("1.2.3.4", "GET", "/", headers)
        r2 = engine.fingerprint("1.2.3.4", "GET", "/other", headers)
        assert r1.fingerprint_hash == r2.fingerprint_hash  # same IP+UA+headers


# ── Layer 5: Honeypot ─────────────────────────────────────────────────────────
class TestHoneypotManager:
    @pytest.fixture
    def manager(self):
        banned = []
        def ban_cb(ip, dur): banned.append(ip)
        mgr = HoneypotManager(auto_ban_callback=ban_cb)
        mgr._banned = banned
        return mgr

    def test_env_file_is_honeypot(self, manager):
        assert manager.is_honeypot("/.env")
        assert manager.is_honeypot("/.env.production")

    def test_git_config_is_honeypot(self, manager):
        assert manager.is_honeypot("/.git/config")

    def test_wp_admin_is_honeypot(self, manager):
        assert manager.is_honeypot("/wp-admin")
        assert manager.is_honeypot("/wp-login.php")

    def test_legitimate_paths_not_honeypot(self, manager):
        for path in ("/health", "/api/users", "/", "/about", "/robots.txt"):
            assert not manager.is_honeypot(path), f"{path} should not be a honeypot"

    def test_hit_triggers_ban(self, manager):
        manager.record_hit("1.2.3.4", "/.env", "GET", "sqlmap/1.7")
        assert "1.2.3.4" in manager._banned

    def test_fake_env_response(self, manager):
        status, body = manager.get_fake_response("/.env")
        assert status == 200
        assert "APP_ENV" in body or "DB_" in body

    def test_stats_tracked(self, manager):
        manager.record_hit("2.3.4.5", "/.git/config", "GET", "Nikto/2.1")
        stats = manager.get_stats()
        assert stats["total_hits"] == 1
        assert stats["unique_offenders"] == 1


# ── Credential Guard ──────────────────────────────────────────────────────────
class TestCredentialGuard:
    @pytest.fixture
    def guard(self):
        return CredentialGuard(
            max_failures_per_ip=5,
            max_failures_per_account=3,
            reject_common_passwords=True,
        )

    def test_clean_attempt_allowed(self, guard):
        result = guard.check_login("1.2.3.4", "alice", "GoodP@ss1!")
        assert result.allowed

    def test_common_password_rejected(self, guard):
        result = guard.check_login("1.2.3.4", "alice", "password123")
        assert not result.allowed
        assert result.is_password_breached
        assert result.reason == "password_too_common"

    def test_ip_locked_after_failures(self, guard):
        for _ in range(5):
            guard.record_failure("2.3.4.5", "bob")
        result = guard.check_login("2.3.4.5", "bob", "NewPass1!")
        assert not result.allowed
        assert "ip" in result.reason or "failures" in result.reason

    def test_account_locked_after_failures(self, guard):
        for _ in range(3):
            guard.record_failure("1.1.1.1", "charlie")
        result = guard.check_login("2.2.2.2", "charlie", "AnyPass!")
        assert not result.allowed
        assert "account" in result.reason or "failures" in result.reason

    def test_success_resets_ip_lock(self, guard):
        guard.record_failure("3.3.3.3", "dave")
        guard.record_failure("3.3.3.3", "dave")
        guard.record_success("3.3.3.3", "dave")
        result = guard.check_login("3.3.3.3", "dave", "GoodPass1!")
        assert result.allowed

    def test_risk_increases_with_failures(self, guard):
        for _ in range(3):
            guard.record_failure("4.4.4.4", "eve")
        result = guard.check_login("4.4.4.4", "eve", "SomePass!")
        assert result.risk_score > 0

    def test_mfa_required_on_high_risk(self, guard):
        for _ in range(3):
            guard.record_failure("5.5.5.5", "frank")
        result = guard.check_login("5.5.5.5", "frank", "SomePass1!")
        if result.allowed:
            assert result.require_mfa

    def test_is_password_common(self, guard):
        assert guard.is_password_common("password")
        assert guard.is_password_common("123456")
        assert not guard.is_password_common("xK9#mP2@qR7$nL")

    def test_stats_available(self, guard):
        stats = guard.get_stats()
        assert "global_failures_per_min" in stats


# ── Challenge engine ──────────────────────────────────────────────────────────
class TestChallengeEngine:
    def test_issue_and_verify(self):
        engine = ChallengeEngine(difficulty=1)  # easy for tests
        challenge = engine.issue_challenge("1.2.3.4")
        assert "challenge_token" in challenge
        assert "nonce" in challenge

    def test_invalid_token_rejected(self):
        engine = ChallengeEngine(difficulty=1)
        assert not engine.verify_solution("fake_token", "12345")
