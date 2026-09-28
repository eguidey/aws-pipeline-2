"""Gunicorn production settings."""

import multiprocessing
import os

import gunicorn.http.wsgi

# Don't advertise the server software/version in the "Server" response header
# (reduces information available to attackers fingerprinting the stack).
gunicorn.http.wsgi.SERVER = "api"

bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
workers = int(os.getenv("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2 + 1, 4)))
threads = 2
timeout = 30
graceful_timeout = 20
keepalive = 5

# The app writes its own structured JSON request logs, so disable Gunicorn's text access log.
accesslog = None
errorlog = "-"
loglevel = "warning"

# Harden request parsing against oversized headers.
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190

# Use shared memory for worker heartbeats (works with a read-only root filesystem).
worker_tmp_dir = "/dev/shm"  # noqa: S108  # nosec B108 - in-memory tmpfs recommended by Gunicorn; root FS is read-only
