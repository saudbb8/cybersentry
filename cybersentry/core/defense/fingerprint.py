"""
CyberSentry Request Fingerprinting — Layer 3 (smart rate limiting).

Builds a behavioural fingerprint per client using:
  - User-Agent analysis (bot detection, headless browser detection)
  - Request pattern analysis (speed, path sequence, timing)
  - Header consistency scoring (real browsers send consistent headers)
  - Honeypot field detection (bots fill hidden fields)
  - Accept-Language / Accept-Encoding consistency
  - TLS fingerprint hints (from forwarded headers if behind proxy)

Assigns a bot_score 0-100. High score = likely automated.
"""
from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FingerprintResult:
    fingerprint_hash: str
    bot_score: int          # 0=human, 100=definitely bot
    signals: list[str]      # what triggered the score
    recommended_action: str  # allow / challenge / block / tarpit
    is_headless: bool = False
    is_known_good_bot: bool = False   # Googlebot, Bingbot, etc.
    is_known_bad_bot: bool = False    # scrapers, exploit scanners


# ── Known good bots (whitelist) ───────────────────────────────────────────────
GOOD_BOTS = {
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebot", "twitterbot", "linkedinbot", "applebot",
    "semrushbot", "ahrefsbot", "mj12bot", "dotbot",
}

# ── Known bad / scanner bots ──────────────────────────────────────────────────
BAD_BOT_PATTERNS = [
    r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster)",
    r"(?i)(burpsuite|owasp.zap|w3af|acunetix|nessus|openvas)",
    r"(?i)(scrapy|selenium|phantomjs|playwright|puppeteer)",
    r"(?i)(python-requests|go-http-client|okhttp|curl/|wget/)",
    r"(?i)(libwww-perl|lwp-|mechanize|httpclient)",
    r"(?i)(scanner|exploit|hacker|pentest|vuln)",
    r"(?i)(zgrab|masscan|shodan|censys)",
    r"(?i)^-$",    # empty or dash user agent
    r"(?i)^$",     # blank user agent
]
_BAD_BOT_COMPILED = [re.compile(p) for p in BAD_BOT_PATTERNS]

# ── Headless browser signals ───────────────────────────────────────────────────
HEADLESS_UA_PATTERNS = [
    r"(?i)headlesschrome",
    r"(?i)phantomjs",
    r"(?i)electron",
    r"(?i)seleniumide",
]
_HEADLESS_COMPILED = [re.compile(p) for p in HEADLESS_UA_PATTERNS]

# ── Headers a real browser always sends ───────────────────────────────────────
REAL_BROWSER_HEADERS = {"accept", "accept-language", "accept-encoding"}
# Headers that suggest automation when present
AUTOMATION_HEADERS = {
    "x-requested-with": "xmlhttprequest in non-AJAX context",
    "x-forwarded-for": None,   # OK in proxies, suspicious direct
}


class BehaviourTracker:
    """Tracks per-fingerprint request sequences for anomaly scoring."""

    def __init__(self, window: int = 60):
        self._window = window
        # fingerprint -> deque of (timestamp, path) tuples
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def record(self, fp_hash: str, path: str) -> None:
        self._history[fp_hash].append((time.monotonic(), path))

    def get_rpm(self, fp_hash: str) -> float:
        now = time.monotonic()
        history = self._history[fp_hash]
        return sum(1 for t, _ in history if now - t <= 60)

    def get_unique_paths(self, fp_hash: str, seconds: int = 60) -> int:
        now = time.monotonic()
        history = self._history[fp_hash]
        return len({p for t, p in history if now - t <= seconds})

    def looks_like_scanner(self, fp_hash: str) -> bool:
        """
        Scanners hit many different paths in rapid succession.
        Real users mostly stay within a small set of paths.
        """
        rpm = self.get_rpm(fp_hash)
        unique_paths = self.get_unique_paths(fp_hash, 60)
        # > 30 unique paths/minute + high RPM = scanner
        return rpm > 20 and unique_paths > 30

    def get_avg_inter_request_ms(self, fp_hash: str) -> float:
        """
        Bots often have very regular inter-request timing.
        Real users have irregular timing.
        """
        history = list(self._history[fp_hash])
        if len(history) < 3:
            return 0.0
        intervals = [
            (history[i][0] - history[i-1][0]) * 1000
            for i in range(1, len(history))
        ]
        return sum(intervals) / len(intervals)


class FingerprintEngine:
    """
    Builds a behavioural fingerprint and bot score for each request.
    """

    def __init__(
        self,
        bot_score_challenge_threshold: int = 50,
        bot_score_block_threshold: int = 80,
        track_behaviour: bool = True,
    ):
        self.challenge_threshold = bot_score_challenge_threshold
        self.block_threshold = bot_score_block_threshold
        self._tracker = BehaviourTracker() if track_behaviour else None
        self._honeypot_hits: set[str] = set()

    def fingerprint(
        self,
        ip: str,
        method: str,
        path: str,
        headers: dict[str, str],
        form_data: dict[str, str] | None = None,
        honeypot_fields: set[str] | None = None,
    ) -> FingerprintResult:
        """
        Analyse a request and return a fingerprint + bot score.

        Args:
            ip: Client IP.
            method / path: Request basics.
            headers: All request headers (lowercased keys).
            form_data: POST form fields (for honeypot detection).
            honeypot_fields: Set of field names that should never be filled by humans.
        """
        signals: list[str] = []
        bot_score = 0
        is_headless = False
        is_known_good = False
        is_known_bad = False

        user_agent = headers.get("user-agent", "").strip()

        # ── Known good bot ─────────────────────────────────────────────────
        ua_lower = user_agent.lower()
        for good_bot in GOOD_BOTS:
            if good_bot in ua_lower:
                is_known_good = True
                # Good bots get a small score (still watch them)
                bot_score = 5
                signals.append(f"known_good_bot:{good_bot}")
                break

        if not is_known_good:
            # ── Known bad bot / scanner ────────────────────────────────────
            for compiled, pattern in zip(_BAD_BOT_COMPILED, BAD_BOT_PATTERNS):
                if compiled.search(user_agent):
                    is_known_bad = True
                    bot_score += 80
                    signals.append(f"bad_bot_ua:{pattern[:30]}")
                    break

            # ── Headless browser ───────────────────────────────────────────
            for compiled in _HEADLESS_COMPILED:
                if compiled.search(user_agent):
                    is_headless = True
                    bot_score += 60
                    signals.append("headless_browser")
                    break

            # ── Missing UA ─────────────────────────────────────────────────
            if not user_agent or user_agent in ("-", "–"):
                bot_score += 40
                signals.append("missing_user_agent")

            # ── Missing real-browser headers ───────────────────────────────
            lower_headers = {k.lower() for k in headers}
            missing = REAL_BROWSER_HEADERS - lower_headers
            if missing:
                bot_score += len(missing) * 10
                signals.append(f"missing_browser_headers:{','.join(missing)}")

            # ── Accept header inconsistency ─────────────────────────────────
            accept = headers.get("accept", "")
            if user_agent and "Mozilla" in user_agent and not accept:
                bot_score += 15
                signals.append("mozilla_ua_no_accept")

            # ── Behavioural signals ─────────────────────────────────────────
            fp_hash = self._make_hash(ip, user_agent, headers)
            if self._tracker:
                self._tracker.record(fp_hash, path)

                if self._tracker.looks_like_scanner(fp_hash):
                    bot_score += 40
                    signals.append("scanning_pattern")

                avg_interval = self._tracker.get_avg_inter_request_ms(fp_hash)
                if 0 < avg_interval < 50:   # < 50ms between requests = automation
                    bot_score += 20
                    signals.append(f"robotic_timing:{avg_interval:.0f}ms_avg")

        # ── Honeypot field filled ───────────────────────────────────────────
        if form_data and honeypot_fields:
            for field_name in honeypot_fields:
                if form_data.get(field_name):
                    bot_score += 100
                    signals.append(f"honeypot_filled:{field_name}")
                    self._honeypot_hits.add(ip)

        # Cap at 100
        bot_score = min(100, bot_score)

        # Decide action
        if bot_score >= self.block_threshold or is_known_bad:
            action = "block"
        elif bot_score >= self.challenge_threshold or is_headless:
            action = "challenge"
        elif is_known_good:
            action = "allow"
        else:
            action = "allow"

        fp_hash = self._make_hash(ip, user_agent, headers)

        return FingerprintResult(
            fingerprint_hash=fp_hash,
            bot_score=bot_score,
            signals=signals,
            recommended_action=action,
            is_headless=is_headless,
            is_known_good_bot=is_known_good,
            is_known_bad_bot=is_known_bad,
        )

    def _make_hash(self, ip: str, user_agent: str, headers: dict[str, str]) -> str:
        """
        Create a stable fingerprint hash from request attributes.
        Uses IP + UA + header presence (not values) for stability.
        """
        header_keys = sorted(k.lower() for k in headers)
        raw = f"{ip}|{user_agent}|{','.join(header_keys)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def record_honeypot_hit(self, ip: str) -> None:
        self._honeypot_hits.add(ip)

    def is_honeypot_offender(self, ip: str) -> bool:
        return ip in self._honeypot_hits