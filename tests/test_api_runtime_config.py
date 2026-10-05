import pytest

from data_copilot.api import build_access_policy, build_audit_store, build_planner, health


def test_build_audit_store_is_opt_in(monkeypatch, tmp_path):
    monkeypatch.delenv("COPILOT_AUDIT_LOG_PATH", raising=False)
    assert build_audit_store() is None

    path = tmp_path / "audit" / "events.jsonl"
    monkeypatch.setenv("COPILOT_AUDIT_LOG_PATH", str(path))
    store = build_audit_store()

    assert store is not None
    assert store.path == path


def test_health_reports_audit_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("COPILOT_AUDIT_LOG_PATH", str(tmp_path / "events.jsonl"))

    payload = health()

    assert payload["audit_persistence_configured"] is True


def test_model_timeout_must_be_positive(monkeypatch):
    monkeypatch.setenv("COPILOT_MODEL_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("COPILOT_MODEL", "demo")
    monkeypatch.setenv("COPILOT_MODEL_TIMEOUT_SECONDS", "0")

    with pytest.raises(RuntimeError, match="greater than zero"):
        build_planner()


def test_join_budget_cannot_be_negative(monkeypatch):
    monkeypatch.setenv("COPILOT_MAX_JOINS", "-1")

    with pytest.raises(RuntimeError, match="zero or greater"):
        build_access_policy()
