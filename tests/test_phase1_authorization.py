import json
import sqlite3
from contextlib import closing
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler

import pytest
from fastapi.testclient import TestClient

from data_copilot.access import AccessPolicy, AccessPolicyError
from data_copilot.ai_planner import OpenAICompatiblePlanner
from data_copilot.api import app
from data_copilot.audit import JsonlAuditStore
from data_copilot.config import build_copilot
from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan, TableInfo


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "synthetic.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript("""
            CREATE TABLE items(id INTEGER PRIMARY KEY, tenant TEXT COLLATE NOCASE, secret TEXT);
            INSERT INTO items VALUES (1, 'north', 'hidden'), (2, 'south', 'hidden'),
                (3, 'NORTH', 'hidden');
            CREATE TABLE events(item_id INTEGER, tenant TEXT);
            INSERT INTO events VALUES (1, 'north'), (1, 'south'), (2, 'south');
            CREATE TABLE "straße"(value TEXT);
            INSERT INTO "straße" VALUES ('hidden');
            CREATE TABLE "strasse"(value TEXT);
        """)
    return str(path)


@pytest.fixture()
def scoped(db, monkeypatch):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", db)
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "items,events")
    monkeypatch.setenv("COPILOT_ALLOWED_COLUMNS", "items.id,events.item_id")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_COLUMN", "tenant")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north")
    return build_copilot()


def test_line_comment_cannot_erase_required_predicate(db):
    policy = AccessPolicy(require_where_for_tables=frozenset({"items"}))
    result = DataCopilot(db, access_policy=policy).query_sql(
        "SELECT id FROM items -- preserve line break\nWHERE id = 1"
    )
    assert result.rows == [{"id": 1}]


def test_literal_whitespace_is_preserved(db):
    sql = "SELECT 'a  b\t\nc' AS value"
    assert DataCopilot(db).query_sql(sql).rows == [{"value": "a  b\t\nc"}]


@pytest.mark.parametrize("sql", [
    "SELECT id FROM items WHERE 1=1",
    "SELECT i.id FROM items i JOIN events e ON i.id=e.item_id",
    "WITH visible AS (SELECT id FROM items) SELECT id FROM visible",
    "SELECT id FROM items UNION ALL SELECT item_id AS id FROM events",
    "SELECT id FROM items WHERE EXISTS (SELECT 1 FROM events WHERE item_id=id)",
])
def test_every_scan_has_an_exact_server_scope(scoped, sql):
    result = scoped.query_sql(sql)
    assert result.rows == [{"id": 1}] * (2 if "UNION" in sql else 1)


@pytest.mark.parametrize("sql", [
    "SELECT id FROM main.items",
    "WITH items AS (SELECT id FROM main.items) SELECT id FROM items",
    "SELECT (SELECT secret FROM items) AS leak",
    "SELECT oid FROM items",
    "SELECT name FROM sqlite_master",
    "SELECT items.* FROM items",
    'SELECT "tenant" FROM items',
])
def test_bypasses_fail_validation_and_execution(scoped, sql):
    assert not scoped.validate_sql(sql).allowed
    with pytest.raises((ValueError, sqlite3.DatabaseError)):
        scoped.query_sql(sql)


def test_allowlist_matches_sqlite_identifier_rules(db):
    policy = AccessPolicy(allowed_tables=frozenset({"strasse"}))
    copilot = DataCopilot(db, access_policy=policy)
    assert not copilot.validate_sql('SELECT value FROM "straße"').allowed
    assert [item.name for item in copilot.visible_schema()] == ["strasse"]


def test_planner_and_direct_sql_share_the_scope(scoped, monkeypatch):
    class Planner:
        def plan(self, question, schema):
            return QueryPlan(question, "SELECT id FROM items WHERE 1=1", "synthetic", None)

    monkeypatch.setattr(scoped, "planner", Planner())
    assert scoped.ask("list all tenants").rows == [{"id": 1}]


def test_remote_tenant_headers_cannot_choose_scope(scoped, monkeypatch):
    monkeypatch.setenv("COPILOT_API_TOKEN", "synthetic-shared-key")
    response = TestClient(app).post(
        "/v1/ops/query", json={"sql": "SELECT id FROM items WHERE 1=1"},
        headers={"Authorization": "Bearer synthetic-shared-key", "X-Tenant-ID": "south"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["rows"] == [{"id": 1}]


def test_partial_scope_is_rejected(db, monkeypatch):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", db)
    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north")
    with pytest.raises(RuntimeError, match="ROW_SCOPE"):
        build_copilot()


def test_scoped_table_without_scope_column_fails_closed(db, monkeypatch):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", db)
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "strasse")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_COLUMN", "tenant")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north")
    assert not build_copilot().validate_sql("SELECT value FROM strasse").allowed


def test_audit_omits_question_and_attacker_controlled_diagnostics(db, tmp_path):
    path = tmp_path / "audit.jsonl"
    copilot = DataCopilot(db, access_policy=AccessPolicy(allowed_tables=frozenset({"items"})),
                          audit_store=JsonlAuditStore(str(path)))
    with pytest.raises(AccessPolicyError):
        copilot.query_sql('SELECT * FROM "private@example.test"', question="another@example.test")
    event = json.loads(path.read_text(encoding="utf-8"))
    assert "@example.test" not in json.dumps(event)
    assert event["decision"] == "deny"



def test_scoped_count_uses_server_filter(scoped):
    assert scoped.query_sql("SELECT COUNT(*) AS n FROM items").rows == [{"n": 1}]


@pytest.mark.parametrize("guarded", [False, True])
def test_bearer_access_fails_closed_on_missing_policy(db, monkeypatch, guarded):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", db)
    monkeypatch.setenv("COPILOT_API_TOKEN", "synthetic-shared-key")
    if guarded:
        monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "items")
        monkeypatch.setenv("COPILOT_GUARDED_TABLES", "items")
    response = TestClient(app).post(
        "/v1/ops/query", json={"sql": "SELECT id FROM items WHERE 1=1"},
        headers={"Authorization": "Bearer synthetic-shared-key", "X-Tenant-ID": "north"},
    )
    assert response.json()["error"]["code"] == "CONFIGURATION_ERROR"


def test_result_byte_budget_counts_utf8(db):
    from data_copilot.database import ResultTooLargeError, SQLiteCatalog

    with pytest.raises(ResultTooLargeError):
        SQLiteCatalog(db, max_result_bytes=4).execute("SELECT 'ééé'")



def test_remote_model_cannot_use_plain_http():
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAICompatiblePlanner("http://model.invalid", "synthetic", api_key="synthetic")


def test_planner_rejects_redirects_before_forwarding_credentials(monkeypatch):
    handlers = []

    def open_request(req, timeout):
        assert req.get_header("Authorization") == "Bearer synthetic"
        handler = handlers[0] if handlers else HTTPRedirectHandler()
        redirected = handler.redirect_request(
            req, None, 302, "Redirect", {}, "https://different.invalid/v1"
        )
        assert redirected is None, "planner followed an untrusted redirect"

    class Opener:
        open = staticmethod(open_request)

    def build_opener(*custom_handlers):
        handlers.extend(custom_handlers)
        return Opener()

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    monkeypatch.setattr("urllib.request.build_opener", build_opener)
    planner = OpenAICompatiblePlanner("https://model.invalid/v1", "synthetic", api_key="synthetic")
    with pytest.raises(HTTPError, match="redirects are disabled"):
        planner.plan("synthetic question", [TableInfo(name="items", columns=[])])
