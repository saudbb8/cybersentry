"""
CyberSentry Bot Fingerprinting.
Detects bots, scrapers, scanners, and headless browsers
using UA analysis, header consistency, timing, and honeypot fields.
"""
from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class FingerprintResult:
    fingerprint_hash: str
    bot_score: int
    signals: list[str]
    recommended_action: str
    is_headless: bool = False
    is_known_good_bot: bool = False
    is_known_bad_bot: bool = False


GOOD_BOTS = {
    "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
    "yandexbot", "facebot", "twitterbot", "applebot", "linkedinbot",
}

BAD_BOT_PATTERNS = [
    r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster)",
    r"(?i)(burpsuite|owasp.zap|w3af|acunetix|nessus|openvas)",
    r"(?i)(scrapy|selenium|phantomjs|playwright|puppeteer)",
    r"(?i)(python-requests|go-http-client|okhttp|libwww-perl)",
    r"(?i)(zgrab|masscan|shodan|censys)",
    r"(?i)(scanner|exploit|hacker|pentest)",
]
_BAD_BOT_RE = [re.compile(p) for p in BAD_BOT_PATTERNS]

HEADLESS_PATTERNS = [
    r"(?i)headlesschrome", r"(?i)phantomjs", r"(?i)electron",
]
_HEADLESS_RE = [re.compile(p) for p in HEADLESS_PATTERNS]

REAL_BROWSER_HEADERS = {"accept", "accept-language", "accept-encoding"}


class BehaviourTracker:
    def __init__(self, window: int = 60):
        self.window = window
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def record(self, fp_hash: str, path: str) -> None:
        self._history[fp_hash].append((time.monotonic(), path))

    def get_rpm(self, fp_hash: str) -> float:
        now = time.monotonic()
        return sum(1 for t, _ in self._history[fp_hash] if now - t <= 60)

    def get_unique_paths(self, fp_hash: str) -> int:
        now = time.monotonic()
        return len({p for t, p in self._history[fp_hash] if now - t <= 60})

    def looks_like_scanner(self, fp_hash: str) -> bool:
        return self.get_rpm(fp_hash) > 20 and self.get_unique_paths(fp_hash) > 30

    def avg_interval_ms(self, fp_hash: str) -> float:
        history = list(self._history[fp_hash])
        if len(history) < 3:
            return 0.0
        intervals = [(history[i][0] - history[i-1][0]) * 1000 for i in range(1, len(history))]
        return sum(intervals) / len(intervals)


class FingerprintEngine:
    def __init__(self, challenge_threshold: int = 50, block_threshold: int = 80):
        self.challenge_threshold = challenge_threshold
        self.block_threshold = block_threshold
        self._tracker = BehaviourTracker()
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
        signals: list[str] = []
        bot_score = 0
        is_headless = False
        is_good = False
        is_bad = False

        ua = headers.get("user-agent", "").strip()
        ua_lower = ua.lower()

        for good in GOOD_BOTS:
            if good in ua_lower:
                is_good = True
                bot_score = 5
                signals.append(f"known_good_bot:{good}")
                break

        if not is_good:
            for compiled in _BAD_BOT_RE:
                if compiled.search(ua):
                    is_bad = True
                    bot_score += 80
                    signals.append("bad_bot_ua")
                    break

            for compiled in _HEADLESS_RE:
                if compiled.search(ua):
                    is_headless = True
                    bot_score += 60
                    signals.append("headless_browser")
                    break

            if not ua or ua in ("-",):
                bot_score += 40
                signals.append("missing_ua")

            lower_keys = {k.lower() for k in headers}
            missing = REAL_BROWSER_HEADERS - lower_keys
            if missing:
                bot_score += len(missing) * 10
                signals.append(f"missing_headers:{','.join(missing)}")

            fp_hash = self._make_hash(ip, ua, headers)
            self._tracker.record(fp_hash, path)

            if self._tracker.looks_like_scanner(fp_hash):
                bot_score += 40
                signals.append("scanning_pattern")

            avg = self._tracker.avg_interval_ms(fp_hash)
            if 0 < avg < 50:
                bot_score += 20
                signals.append(f"robotic_timing:{avg:.0f}ms")

        if form_data and honeypot_fields:
            for field_name in honeypot_fields:
                if form_data.get(field_name):
                    bot_score += 100
                    signals.append(f"honeypot_filled:{field_name}")
                    self._honeypot_hits.add(ip)

        bot_score = min(100, bot_score)

        if bot_score >= self.block_threshold or is_bad:
            action = "block"
        elif bot_score >= self.challenge_threshold or is_headless:
            action = "challenge"
        else:
            action = "allow"

        fp_hash = self._make_hash(ip, ua, headers)
        return FingerprintResult(
            fingerprint_hash=fp_hash,
            bot_score=bot_score,
            signals=signals,
            recommended_action=action,
            is_headless=is_headless,
            is_known_good_bot=is_good,
            is_known_bad_bot=is_bad,
        )

    def _make_hash(self, ip: str, ua: str, headers: dict) -> str:
        keys = sorted(k.lower() for k in headers)
        raw = f"{ip}|{ua}|{','.join(keys)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
