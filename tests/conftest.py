import json
import logging

import pytest

from app import create_app, routes

TEST_PASSWORD = "Correct-Horse-Battery-9!"  # noqa: S105 - test-only credential


@pytest.fixture
def app():
    routes._login_tracker = None  # fresh brute-force state for every test
    return create_app({
        "TESTING": True,
        "DEMO_PASSWORD": TEST_PASSWORD,
        "RATE_LIMIT_PER_MINUTE": 1000,
        "BRUTE_FORCE_THRESHOLD": 3,
    })


@pytest.fixture
def client(app):
    return app.test_client()


class JsonLogCapture(logging.Handler):
    """Collects the JSON lines the app writes so tests can assert on telemetry."""

    def __init__(self):
        super().__init__()
        from app.logging_config import JsonFormatter
        self.setFormatter(JsonFormatter())
        self.events: list[dict] = []

    def emit(self, record):
        self.events.append(json.loads(self.format(record)))

    def of_type(self, event_type: str) -> list[dict]:
        return [e for e in self.events if e["event_type"] == event_type]


@pytest.fixture
def logs():
    handler = JsonLogCapture()
    root = logging.getLogger()
    root.addHandler(handler)
    yield handler
    root.removeHandler(handler)
