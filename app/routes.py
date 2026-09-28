"""API endpoints. Small on purpose - the point is the security telemetry around them."""

from __future__ import annotations

import hmac
import itertools
import logging
import re
import threading

from flask import Blueprint, current_app, jsonify, request

from app.logging_config import log_event
from app.security import FailedLoginTracker, client_ip

api = Blueprint("api", __name__)

_items: dict[int, dict] = {
    1: {"id": 1, "name": "Firewall appliance", "price": 1299.00},
    2: {"id": 2, "name": "Hardware security key", "price": 49.99},
}
_next_id = itertools.count(3)
_items_lock = threading.Lock()
_login_tracker: FailedLoginTracker | None = None


def _tracker() -> FailedLoginTracker:
    global _login_tracker
    cfg = current_app.config
    if _login_tracker is None or _login_tracker.threshold != cfg["BRUTE_FORCE_THRESHOLD"]:
        _login_tracker = FailedLoginTracker(cfg["BRUTE_FORCE_THRESHOLD"], cfg["BRUTE_FORCE_WINDOW_SECONDS"])
    return _login_tracker


@api.get("/health")
def health():
    return jsonify(status="ok", version=current_app.config["APP_VERSION"])


@api.get("/api/items")
def list_items():
    items = list(_items.values())
    search = request.args.get("search")
    if search is None:
        return jsonify(items=items)
    term = search.strip()
    if not term or not ITEM_NAME.fullmatch(term):
        log_event(logging.WARNING, "validation_error", "Rejected invalid search term", errors=["search"])
        return jsonify(errors=["search may only contain letters, numbers, spaces and . , ' ( ) / + # -"]), 400
    needle = term.casefold()
    return jsonify(items=[item for item in items if needle in item["name"].casefold()])


@api.get("/api/items/<int:item_id>")
def get_item(item_id: int):
    item = _items.get(item_id)
    if item is None:
        return jsonify(error="Item not found"), 404
    return jsonify(item)


# Item names are plain product names: letters, digits, spaces and a little punctuation.
# Characters that can start markup or script (< > " ` { } ; & = \) are never stored, so a
# payload can't be saved and served back to another client (stored XSS; ZAP rule 40014).
ITEM_NAME = re.compile(r"^[\w .,'()/+#-]{1,100}$")


def validate_item(payload) -> tuple[dict | None, list[str]]:
    """Strict allow-list validation of the request body."""
    errors: list[str] = []
    if not isinstance(payload, dict):
        return None, ["Body must be a JSON object"]
    unexpected = set(payload) - {"name", "price"}
    if unexpected:
        errors.append(f"Unexpected field(s): {', '.join(sorted(unexpected))}")
    name = payload.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        errors.append("name must be a string of 1-100 characters")
    elif not ITEM_NAME.fullmatch(name.strip()):
        errors.append("name may only contain letters, numbers, spaces and . , ' ( ) / + # -")
    price = payload.get("price")
    if isinstance(price, bool) or not isinstance(price, (int, float)) or not 0 <= price <= 1_000_000:
        errors.append("price must be a number between 0 and 1,000,000")
    if errors:
        return None, errors
    return {"name": name.strip(), "price": round(float(price), 2)}, []


@api.post("/api/items")
def create_item():
    payload = request.get_json(silent=True)
    clean, errors = validate_item(payload)
    if errors:
        log_event(logging.WARNING, "validation_error", "Rejected invalid item payload", errors=errors)
        return jsonify(errors=errors), 400
    with _items_lock:
        item_id = next(_next_id)
        item = {"id": item_id, **clean}
        _items[item_id] = item
    log_event(logging.INFO, "item_created", "Item created", item_id=item_id)
    return jsonify(item), 201


@api.post("/api/login")
def login():
    """Demo login that produces authentication telemetry (success, failure, brute force)."""
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", ""))[:64]
    password = str(payload.get("password", ""))
    cfg = current_app.config
    ip = client_ip()

    user_ok = hmac.compare_digest(username.encode(), cfg["DEMO_USERNAME"].encode())
    pass_ok = hmac.compare_digest(password.encode(), cfg["DEMO_PASSWORD"].encode())

    if user_ok and pass_ok:
        _tracker().reset(ip)
        log_event(logging.INFO, "auth_success", "User logged in", user=username)
        return jsonify(message="Login successful")

    failures = _tracker().record_failure(ip)
    log_event(logging.WARNING, "auth_failure", "Failed login attempt", user=username, failures_in_window=failures)
    if failures >= cfg["BRUTE_FORCE_THRESHOLD"]:
        log_event(logging.ERROR, "brute_force_suspected", "Repeated failed logins from one source",
                  user=username, failures_in_window=failures)
    # Same message for bad username or bad password - avoids user enumeration.
    return jsonify(error="Invalid username or password"), 401
