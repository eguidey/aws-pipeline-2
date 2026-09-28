"""Runtime security controls: attack-signature detection, rate limiting,
brute-force tracking and security headers."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from urllib.parse import unquote_plus

from flask import request

# Lightweight detection signatures. These don't block traffic - they generate
# telemetry so the SIEM (CloudWatch) can alert on attack attempts.
SIGNATURES: dict[str, re.Pattern] = {
    "sql_injection": re.compile(
        r"('|%27)\s*(or|and)\s*('|%27|\d)|union(\s|%20|\+)+select|;\s*(drop|delete|insert|update)\s|--\s|/\*.*\*/|sleep\(\d+\)",
        re.IGNORECASE,
    ),
    "xss": re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*img[^>]+src\s*=", re.IGNORECASE),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e(%2f|/|%5c)", re.IGNORECASE),
    "command_injection": re.compile(r"[;&|`]\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b|\$\(", re.IGNORECASE),
}


def client_ip() -> str:
    """Client IP. Behind a load balancer the real client is the first X-Forwarded-For entry."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return request.remote_addr or "unknown"


def normalise(value: str, rounds: int = 2) -> str:
    """URL-decode repeatedly so encoded (and double-encoded) payloads are caught.

    Attack tools send `%27%20OR%20...` rather than `' OR ...`; matching only the raw
    text would miss them.
    """
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def detect(value: str) -> list[str]:
    """Return the names of every signature that matches the given text (raw or decoded)."""
    candidates = {value, normalise(value)}
    return [name for name, pattern in SIGNATURES.items() if any(pattern.search(c) for c in candidates)]


def scan_request() -> list[str]:
    """Check the path, query string and body of the current request."""
    parts = [request.path, request.query_string.decode("utf-8", "ignore")]
    if request.content_length and request.content_length <= 16 * 1024:
        parts.append(request.get_data(as_text=True, cache=True))
    found: set[str] = set()
    for part in parts:
        found.update(detect(part))
    return sorted(found)


class RateLimiter:
    """Sliding-window limiter per client IP (in memory, per worker).

    In production you'd back this with Redis or AWS WAF rate rules; this is enough
    to demonstrate the control and generate telemetry.
    """

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class FailedLoginTracker:
    """Counts failed logins per IP to flag likely brute-force attacks."""

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = window_seconds
        self._failures: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def record_failure(self, key: str) -> int:
        """Record a failure and return how many failures are in the current window."""
        now = time.monotonic()
        with self._lock:
            failures = self._failures[key]
            failures.append(now)
            while failures and now - failures[0] > self.window:
                failures.popleft()
            return len(failures)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def add_security_headers(response):
    """OWASP-recommended headers for a JSON API."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.pop("Server", None)
    return response
