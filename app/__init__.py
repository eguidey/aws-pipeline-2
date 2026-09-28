"""Flask API that emits structured JSON security telemetry for CloudWatch."""

from __future__ import annotations

import logging
import os
import secrets
import time
import uuid

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from app.logging_config import configure_logging, log_event
from app.routes import api
from app.security import RateLimiter, add_security_headers, client_ip, scan_request

logger = logging.getLogger("app")


def create_app(config: dict | None = None) -> Flask:
    """Application factory - makes the app easy to configure in tests."""
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))

    app = Flask(__name__)
    app.config.update(
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=16 * 1024,  # reject oversized bodies (basic DoS protection)
        RATE_LIMIT_PER_MINUTE=int(os.getenv("RATE_LIMIT_PER_MINUTE", "120")),
        BRUTE_FORCE_THRESHOLD=int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),
        BRUTE_FORCE_WINDOW_SECONDS=int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "300")),
        DEMO_USERNAME=os.getenv("APP_DEMO_USERNAME", "analyst"),
        DEMO_PASSWORD=os.getenv("APP_DEMO_PASSWORD"),
        APP_VERSION=os.getenv("APP_VERSION", "dev"),
    )
    if config:
        app.config.update(config)

    if not app.config["DEMO_PASSWORD"]:
        # Never ship a default password: generate a random one and don't log its value.
        app.config["DEMO_PASSWORD"] = secrets.token_urlsafe(24)
        log_event(logging.WARNING, "config_warning",
                  "APP_DEMO_PASSWORD not set - generated a random password; /api/login will reject all attempts")

    limiter = RateLimiter(app.config["RATE_LIMIT_PER_MINUTE"], window_seconds=60)
    app.extensions["rate_limiter"] = limiter

    @app.before_request
    def start_request():
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.start_time = time.perf_counter()

        if not limiter.allow(client_ip()):
            log_event(logging.WARNING, "rate_limited", "Client exceeded request rate limit",
                      limit_per_minute=app.config["RATE_LIMIT_PER_MINUTE"])
            return jsonify(error="Too many requests"), 429

        findings = scan_request()
        if findings:
            log_event(logging.WARNING, "suspicious_input", "Request matched attack signatures",
                      signatures=findings)
        return None

    @app.after_request
    def finish_request(response):
        add_security_headers(response)
        response.headers["X-Request-ID"] = g.get("request_id", "")
        duration_ms = round((time.perf_counter() - g.get("start_time", time.perf_counter())) * 1000, 2)
        log_event(logging.INFO, "http_request", "Request completed",
                  status=response.status_code, duration_ms=duration_ms)
        return response

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        if exc.code == 404:
            log_event(logging.INFO, "not_found", "Unknown route requested")
        return jsonify(error=exc.description if exc.code != 500 else "Internal server error"), exc.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(exc: Exception):
        # Log the details for responders, but never leak stack traces to the client.
        log_event(logging.ERROR, "unhandled_exception", "Unhandled server error",
                  error_type=type(exc).__name__)
        return jsonify(error="Internal server error"), 500

    app.register_blueprint(api)
    return app
