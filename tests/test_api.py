from tests.conftest import TEST_PASSWORD


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_list_and_get_items(client):
    items = client.get("/api/items").get_json()["items"]
    assert len(items) >= 2
    assert client.get("/api/items/1").get_json()["id"] == 1
    assert client.get("/api/items/9999").status_code == 404


def test_create_item_valid(client, logs):
    resp = client.post("/api/items", json={"name": "  YubiKey  ", "price": 55})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["name"] == "YubiKey" and body["price"] == 55.0
    assert logs.of_type("item_created")


def test_create_item_rejects_bad_input(client, logs):
    resp = client.post("/api/items", json={"name": "", "price": -5, "is_admin": True})
    assert resp.status_code == 400
    errors = " ".join(resp.get_json()["errors"])
    assert "Unexpected field" in errors and "name" in errors and "price" in errors
    assert logs.of_type("validation_error")


def test_create_item_rejects_boolean_price(client):
    assert client.post("/api/items", json={"name": "x", "price": True}).status_code == 400


def test_create_item_rejects_non_json(client):
    assert client.post("/api/items", data="not json", content_type="text/plain").status_code == 400


def test_oversized_body_rejected(client):
    resp = client.post("/api/items", data="x" * 20_000, content_type="application/json")
    assert resp.status_code == 413


def test_login_success(client, logs):
    resp = client.post("/api/login", json={"username": "analyst", "password": TEST_PASSWORD})
    assert resp.status_code == 200
    assert logs.of_type("auth_success")[0]["user"] == "analyst"


def test_login_failure_same_message_for_user_and_password(client):
    bad_user = client.post("/api/login", json={"username": "nobody", "password": TEST_PASSWORD})
    bad_pass = client.post("/api/login", json={"username": "analyst", "password": "wrong"})
    assert bad_user.status_code == bad_pass.status_code == 401
    assert bad_user.get_json() == bad_pass.get_json()  # no username enumeration


def test_brute_force_detection(client, logs):
    for _ in range(3):
        client.post("/api/login", json={"username": "analyst", "password": "guess"})
    assert len(logs.of_type("auth_failure")) == 3
    alerts = logs.of_type("brute_force_suspected")
    assert alerts and alerts[0]["failures_in_window"] == 3


def test_successful_login_resets_failure_count(client, logs):
    client.post("/api/login", json={"username": "analyst", "password": "guess"})
    client.post("/api/login", json={"username": "analyst", "password": TEST_PASSWORD})
    client.post("/api/login", json={"username": "analyst", "password": "guess"})
    assert logs.of_type("auth_failure")[-1]["failures_in_window"] == 1


def test_password_never_logged(client, logs):
    client.post("/api/login", json={"username": "analyst", "password": "SuperSecret123"})
    assert all("SuperSecret123" not in str(e) for e in logs.events)


def test_unknown_route_returns_json_404(client, logs):
    resp = client.get("/admin")
    assert resp.status_code == 404
    assert resp.is_json
    assert logs.of_type("not_found")


def test_internal_errors_hide_details(app, logs):
    @app.get("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    resp = app.test_client().get("/boom")
    assert resp.status_code == 500
    assert "hunter2" not in resp.get_data(as_text=True)
    assert logs.of_type("unhandled_exception")[0]["error_type"] == "RuntimeError"
