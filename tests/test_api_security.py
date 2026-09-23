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
