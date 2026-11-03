import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from data_copilot.api import app
from data_copilot.contracts import capabilities, run_operation

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts" / "makma.v1.schema.json"
VALIDATOR = Draft202012Validator(
    json.loads(SCHEMA_PATH.read_text(encoding="utf-8")), format_checker=FormatChecker()
)

ENV = (
    "COPILOT_API_TOKEN",
    "COPILOT_DATABASE_PATH",
    "COPILOT_ALLOWED_TABLES",
    "COPILOT_ALLOWED_COLUMNS",
    "COPILOT_DENIED_COLUMNS",
    "COPILOT_GUARDED_TABLES",
    "COPILOT_MAX_JOINS",
    "COPILOT_MODEL_BASE_URL",
    "COPILOT_MODEL",
    "COPILOT_AUDIT_LOG_PATH",
)


def assert_valid(envelope: dict) -> dict:
    errors = sorted(VALIDATOR.iter_errors(envelope), key=lambda item: list(item.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    json.dumps(envelope, allow_nan=False)
    return envelope


@pytest.fixture()
def configured(tmp_path, monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "contract.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE orders(id INTEGER PRIMARY KEY, region TEXT, amount REAL, note TEXT);
            CREATE TABLE payroll(id INTEGER PRIMARY KEY, salary REAL);
            INSERT INTO orders VALUES (1, 'north', 10.5, 'n1'), (2, 'south', 4.5, 'n2');
            INSERT INTO payroll VALUES (1, 5000);
            """
        )
    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(path))
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "orders")
    monkeypatch.setenv("COPILOT_ALLOWED_COLUMNS", "orders.region,orders.amount")
    monkeypatch.setenv("COPILOT_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    return tmp_path


def test_schema_file_is_present_and_valid_json():
    Draft202012Validator.check_schema(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def test_capabilities_declare_real_operations(configured):
    declared = capabilities()
    assert declared["contract_version"] == "makma.v1"
    assert declared["system"] == "secure-data-copilot"
    names = [op["name"] for op in declared["operations"]]
    assert names == ["describe_schema", "validate_sql", "query"]
    for op in declared["operations"]:
        assert op["side_effects"] is False and op["requires_approval"] is False
        assert op["timeout_s"] > 0
        Draft202012Validator.check_schema(op["input_schema"])


def test_describe_schema_lists_only_authorized_columns(configured):
    envelope = assert_valid(run_operation("describe_schema", {}))
    assert envelope["status"] == "ok"
    assert envelope["execution_mode"] == "deterministic_offline"
    assert envelope["data"]["tables"] == [
        {
            "name": "orders",
            "columns": [
                {"name": "region", "type": "TEXT", "nullable": True},
                {"name": "amount", "type": "REAL", "nullable": True},
            ],
        }
    ]
    assert str(configured) not in json.dumps(envelope)
    assert envelope["provenance"][0]["kind"] == "dataset"


def test_validate_sql_allow_and_deny(configured):
    allowed = assert_valid(
        run_operation("validate_sql", {"sql": "SELECT region FROM orders"}, run_id="r-1")
    )
    assert allowed["run_id"] == "r-1" and allowed["correlation_id"] == "r-1"
    assert allowed["status"] == "ok"
    assert allowed["data"]["allowed"] is True
    assert allowed["policy"] == {"decision": "allow", "reasons": []}

    denied = assert_valid(run_operation("validate_sql", {"sql": "SELECT note FROM orders"}))
    assert denied["status"] == "ok"
    assert denied["data"]["allowed"] is False
    assert denied["data"]["stage"] == "execution_guard"
    assert denied["policy"]["decision"] == "deny"
    assert any("orders.note" in reason for reason in denied["policy"]["reasons"])


def test_query_sql_returns_rows_and_audit_id(configured):
    envelope = assert_valid(
        run_operation(
            "query",
            {"sql": "SELECT region, amount FROM orders ORDER BY amount DESC", "max_rows": 1},
            correlation_id="corr-7",
        )
    )
    assert envelope["status"] == "ok"
    assert envelope["correlation_id"] == "corr-7"
    assert envelope["data"]["rows"] == [{"region": "north", "amount": 10.5}]
    assert envelope["data"]["row_count"] == 1
    event_id = envelope["data"]["audit_event_id"]
    assert event_id
    audit = (configured / "audit.jsonl").read_text(encoding="utf-8")
    assert event_id in audit
    assert "north" not in audit
    kinds = [item["kind"] for item in envelope["provenance"]]
    assert kinds == ["query", "record"]


def test_query_question_uses_deterministic_planner(configured, monkeypatch):
    monkeypatch.delenv("COPILOT_ALLOWED_COLUMNS")
    envelope = assert_valid(run_operation("query", {"question": "total revenue"}))
    assert envelope["status"] == "ok"
    assert envelope["execution_mode"] == "deterministic_offline"
    assert envelope["data"]["rows"] == [{"total_revenue": 15.0}]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT salary FROM payroll",
        "SELECT note FROM orders",
        "DELETE FROM orders",
        "SELECT region FROM orders; DROP TABLE orders",
    ],
)
def test_query_policy_denial_is_blocked(configured, sql):
    envelope = assert_valid(run_operation("query", {"sql": sql}))
    assert envelope["status"] == "blocked"
    assert envelope["data"] is None
    assert envelope["error"]["code"] == "POLICY_DENIED"
    assert envelope["policy"]["decision"] == "deny"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"question": "x", "sql": "SELECT 1"},
        {"sql": ""},
        {"sql": "SELECT 1", "max_rows": 0},
        {"sql": "SELECT 1", "database_path": "/etc/other.db"},
    ],
)
def test_invalid_input(configured, payload):
    envelope = assert_valid(run_operation("query", payload))
    assert envelope["status"] == "error"
    assert envelope["error"]["code"] == "INVALID_INPUT"


@pytest.mark.parametrize("name", ["drop_everything", "Not-A-Valid-Name", ""])
def test_unknown_operation(configured, name):
    envelope = assert_valid(run_operation(name, {}))
    assert envelope["status"] == "error"
    assert envelope["error"]["code"] == "UNKNOWN_OPERATION"


def test_not_configured(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    envelope = assert_valid(run_operation("describe_schema", {}))
    assert envelope["error"]["code"] == "NOT_CONFIGURED"


def test_oversized_caller_ids_are_rejected(configured):
    envelope = assert_valid(run_operation("describe_schema", {}, run_id="x" * 129))
    assert envelope["error"]["code"] == "INVALID_INPUT"


def test_api_routes_require_auth_and_return_envelopes(configured, monkeypatch):
    monkeypatch.setenv("COPILOT_API_TOKEN", "test-secret")
    client = TestClient(app)
    assert client.get("/v1/capabilities").status_code == 401
    assert client.post("/v1/ops/query", json={"sql": "SELECT 1"}).status_code == 401

    headers = {"Authorization": "Bearer test-secret", "X-Correlation-ID": "abc"}
    caps = client.get("/v1/capabilities", headers=headers)
    assert caps.status_code == 200
    assert caps.json()["system"] == "secure-data-copilot"

    ok = client.post(
        "/v1/ops/query", json={"sql": "SELECT region FROM orders WHERE amount < 5"}, headers=headers
    )
    assert ok.status_code == 200
    assert assert_valid(ok.json())["data"]["rows"] == [{"region": "south"}]
    assert ok.json()["correlation_id"] == "abc"

    blocked = client.post(
        "/v1/ops/query", json={"sql": "SELECT salary FROM payroll"}, headers=headers
    )
    assert blocked.status_code == 403
    assert assert_valid(blocked.json())["status"] == "blocked"

    unknown = client.post("/v1/ops/nope", json={}, headers=headers)
    assert unknown.status_code == 404
    assert assert_valid(unknown.json())["error"]["code"] == "UNKNOWN_OPERATION"

    invalid = client.post("/v1/ops/validate_sql", json={"sql": 5}, headers=headers)
    assert invalid.status_code == 422
    assert assert_valid(invalid.json())["error"]["code"] == "INVALID_INPUT"
