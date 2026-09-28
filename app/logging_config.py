"""Structured JSON logging to stdout.

Every line is one JSON object, so CloudWatch Logs can filter on fields directly
(e.g. `{ $.event_type = "auth_failure" }`) and Logs Insights can query them.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

from flask import g, has_request_context, request

from app.security import client_ip

_CONFIGURED = False
REDACTED_KEYS = {"password", "token", "secret", "authorization", "api_key"}


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event_type": getattr(record, "event_type", "log"),
            "message": record.getMessage(),
            "service": "appsec-api",
            # Which release produced this event - links runtime telemetry back to the
            # pipeline's deployment record (commit, image digest, scan results).
            "version": os.getenv("APP_VERSION", "dev"),
        }
        if has_request_context():
            entry.update(
                request_id=g.get("request_id"),
                method=request.method,
                path=request.path,
                src_ip=client_ip(),
                user_agent=(request.headers.get("User-Agent") or "")[:200],
            )
        entry.update(redact(getattr(record, "extra_fields", {})))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def redact(fields: dict) -> dict:
    """Never let secrets end up in logs, even by accident."""
    return {k: ("[REDACTED]" if k.lower() in REDACTED_KEYS else v) for k, v in fields.items()}


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # we log requests ourselves
    _CONFIGURED = True


def log_event(level: int, event_type: str, message: str, **fields) -> None:
    """Log a security-relevant event with structured fields."""
    logging.getLogger("app.security").log(
        level, message, extra={"event_type": event_type, "extra_fields": fields}
    )
