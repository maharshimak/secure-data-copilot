from fastapi.testclient import TestClient

from data_copilot.api import app, build_planner


def test_remote_token_mode_requires_bearer(monkeypatch):
    monkeypatch.setenv("COPILOT_API_TOKEN", "test-secret")
    monkeypatch.delenv("COPILOT_DATABASE_PATH", raising=False)
    client = TestClient(app)

    denied = client.post("/v1/ask", json={"question": "total revenue"})
    assert denied.status_code == 401

    allowed = client.post(
        "/v1/ask",
        json={"question": "total revenue"},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert allowed.status_code == 503


def test_model_planner_requires_complete_configuration(monkeypatch):
    monkeypatch.setenv("COPILOT_MODEL_BASE_URL", "http://localhost:11434")
    monkeypatch.delenv("COPILOT_MODEL", raising=False)

    try:
        build_planner()
    except RuntimeError as error:
        assert "configured together" in str(error)
    else:
        raise AssertionError("partial model configuration must fail closed")


def test_bearer_api_denies_query_without_table_allowlist(monkeypatch, tmp_path):
    import sqlite3

    database = tmp_path / "copilot.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sales (amount INTEGER)")
        connection.execute("INSERT INTO sales VALUES (10)")

    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(database))
    monkeypatch.setenv("COPILOT_API_TOKEN", "test-secret")
    monkeypatch.delenv("COPILOT_ALLOWED_TABLES", raising=False)
    monkeypatch.delenv("COPILOT_MODEL_BASE_URL", raising=False)
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    client = TestClient(app)
    response = client.post(
        "/v1/ask",
        json={"question": "total sales"},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert response.status_code == 503
    assert "COPILOT_ALLOWED_TABLES" in response.json()["detail"]


def test_bearer_api_with_explicit_allowlist_is_not_blocked_by_config(monkeypatch, tmp_path):
    import sqlite3

    database = tmp_path / "copilot.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sales (amount INTEGER)")
        connection.execute("INSERT INTO sales VALUES (10)")

    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(database))
    monkeypatch.setenv("COPILOT_API_TOKEN", "test-secret")
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "sales")
    monkeypatch.delenv("COPILOT_MODEL_BASE_URL", raising=False)
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    client = TestClient(app)
    response = client.post(
        "/v1/ask",
        json={"question": "total sales"},
        headers={"Authorization": "Bearer test-secret"},
    )
    assert response.status_code != 503
