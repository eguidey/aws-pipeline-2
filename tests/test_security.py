import pytest

from app import create_app
from app.security import FailedLoginTracker, RateLimiter, detect


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("' OR '1'='1", "sql_injection"),
        ("1 UNION SELECT password FROM users", "sql_injection"),
        ("<script>alert(1)</script>", "xss"),
        ('<img src=x onerror=alert(1)>', "xss"),
        ("../../etc/passwd", "path_traversal"),
        ("%2e%2e%2fetc%2fpasswd", "path_traversal"),
        ("; cat /etc/passwd", "command_injection"),
        ("$(whoami)", "command_injection"),
    ],
)
def test_detect_attack_signatures(payload, expected):
    assert expected in detect(payload)


@pytest.mark.parametrize("benign", ["Hardware security key", "O'Brien", "price=49.99", "/api/items/2", "rock & roll"])
def test_benign_input_not_flagged(benign):
    assert detect(benign) == []


def test_suspicious_query_string_is_logged(client, logs):
    client.get("/api/items?search=' OR '1'='1")
    events = logs.of_type("suspicious_input")
    assert events and "sql_injection" in events[0]["signatures"]
    assert events[0]["src_ip"]  # source IP is captured for investigation


@pytest.mark.parametrize(
    ("raw_query", "expected"),
    [
        ("q=%27%20OR%20%271%27%3D%271", "sql_injection"),          # URL-encoded, as real tools send it
        ("q=%2527%2520OR%2520%25271%2527%3D%25271", "sql_injection"),  # double-encoded evasion
        ("file=..%2F..%2Fetc%2Fpasswd", "path_traversal"),
        ("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss"),
    ],
)
def test_encoded_attacks_are_detected(client, logs, raw_query, expected):
    client.get("/api/items?" + raw_query)
    events = logs.of_type("suspicious_input")
    assert events and expected in events[0]["signatures"]


def test_suspicious_body_is_logged(client, logs):
    client.post("/api/items", json={"name": "<script>alert(1)</script>", "price": 1})
    assert "xss" in logs.of_type("suspicious_input")[0]["signatures"]


def test_security_headers_present(client):
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" in headers
    assert headers["X-Request-ID"]


def test_request_id_is_propagated(client, logs):
    client.get("/health", headers={"X-Request-ID": "trace-123"})
    assert logs.of_type("http_request")[-1]["request_id"] == "trace-123"


def test_forwarded_for_uses_first_address(client, logs):
    client.get("/health", headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    assert logs.of_type("http_request")[-1]["src_ip"] == "203.0.113.7"


def test_rate_limit_blocks_and_logs(logs):
    app = create_app({"TESTING": True, "DEMO_PASSWORD": "x", "RATE_LIMIT_PER_MINUTE": 3})
    client = app.test_client()
    codes = [client.get("/health").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert logs.of_type("rate_limited")


def test_rate_limiter_is_per_client():
    limiter = RateLimiter(limit=1)
    assert limiter.allow("a") and limiter.allow("b")
    assert not limiter.allow("a")


def test_failed_login_tracker_window(monkeypatch):
    clock = iter([0, 1, 400])  # third failure arrives after the 300s window
    monkeypatch.setattr("app.security.time.monotonic", lambda: next(clock))
    tracker = FailedLoginTracker(threshold=3, window_seconds=300)
    assert tracker.record_failure("ip") == 1
    assert tracker.record_failure("ip") == 2
    assert tracker.record_failure("ip") == 1  # older failures expired


def test_logs_are_valid_json_with_core_fields(client, logs):
    client.get("/api/items")
    event = logs.of_type("http_request")[-1]
    for field in ("timestamp", "level", "event_type", "service", "method", "path", "status", "duration_ms", "src_ip"):
        assert field in event
    assert event["service"] == "appsec-api"


def test_every_event_carries_release_version(monkeypatch, client, logs):
    monkeypatch.setenv("APP_VERSION", "abc1234")
    client.post("/api/login", json={"username": "analyst", "password": "wrong"})
    assert logs.of_type("auth_failure")[0]["version"] == "abc1234"
    assert all(e["version"] == "abc1234" for e in logs.events)


def test_random_password_when_unset(monkeypatch, logs):
    monkeypatch.delenv("APP_DEMO_PASSWORD", raising=False)
    app = create_app({"TESTING": True})
    assert len(app.config["DEMO_PASSWORD"]) >= 24
    assert logs.of_type("config_warning")
