import sqlite3
from contextlib import ExitStack, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from time import monotonic
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from data_copilot.access import AccessPolicy, AccessPolicyError, RowScope
from data_copilot.ai_planner import OpenAICompatiblePlanner
from data_copilot.api import app
from data_copilot.config import build_copilot
from data_copilot.database import SQLiteCatalog
from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan, TableInfo
from data_copilot.sqlite_guard import ExecutionDenied, ExecutionGuard


@pytest.fixture()
def dataset(tmp_path):
    path = tmp_path / "scope.db"
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.executescript("""
            CREATE TABLE items (id INTEGER PRIMARY KEY, tenant TEXT COLLATE NOCASE,
                                label TEXT, secret TEXT, "" TEXT);
            INSERT INTO items VALUES
                (1,'north','north-public','north-secret','north-unnamed'),
                (2,'south','south-public','south-secret','south-unnamed'),
                (3,'NORTH','case-public','case-secret','case-unnamed');
            CREATE TABLE events (item_id INTEGER, tenant TEXT, marker TEXT);
            INSERT INTO events VALUES (1,'north','north-event'), (1,'south','south-event');
            CREATE TABLE "Straße" ("Wert" TEXT, tenant TEXT);
            INSERT INTO "Straße" VALUES ('north-street','north'),('south-street','south');
            CREATE TABLE "Strasse" (value TEXT, tenant TEXT);
            INSERT INTO "Strasse" VALUES ('outside-table','north');
            CREATE TABLE unscopable (value TEXT);
            INSERT INTO unscopable VALUES ('unscoped-secret');
            CREATE TABLE generated (label TEXT, "" TEXT AS (label || '-derived') VIRTUAL);
            INSERT INTO generated(label) VALUES ('north');
        """)
    return path


@pytest.fixture()
def scoped(dataset):
    return DataCopilot(
        str(dataset),
        access_policy=AccessPolicy(
            allowed_tables=frozenset({"items", "events", "Straße", "unscopable"}),
            allowed_columns={
                "items": frozenset({"id", "label"}),
                "events": frozenset({"item_id", "marker"}),
                "Straße": frozenset({"Wert"}),
                "unscopable": frozenset({"value"}),
            },
            row_scope=RowScope("tenant", "north"),
        ),
        max_risk_score=100,
    )


@pytest.mark.parametrize(
    "sql",
    [
        "WITH items AS MATERIALIZED (SELECT label FROM main.items) SELECT label FROM items",
        'WITH "ITEMS" AS MATERIALIZED (SELECT label FROM main.items) SELECT label FROM "ITEMS"',
        'WITH "Straße" AS MATERIALIZED (SELECT "Wert" FROM main."Straße") SELECT "Wert" FROM "Straße"',
        "SELECT label FROM main.items",
        "SELECT COUNT(*) FROM main.items",
        "SELECT label FROM items UNION ALL SELECT label FROM main.items",
        "SELECT label FROM items WHERE EXISTS (SELECT 1 FROM main.items WHERE id=2)",
        "SELECT COUNT(*) FROM events LEFT JOIN main.events USING (item_id)",
        "SELECT COUNT(*) FROM events NATURAL LEFT JOIN main.events",
    ],
)
def test_backing_reads_are_denied_by_sqlite_itself_and_public_paths(scoped, sql):
    def guard():
        return ExecutionGuard.from_schema(scoped.catalog.schema(), scoped.access_policy)

    with pytest.raises(ExecutionDenied):
        scoped.catalog.prepare(sql, guard())
    with pytest.raises(ExecutionDenied):
        scoped.catalog.execute(sql, guard())
    assert not scoped.validate_sql(sql).allowed
    with pytest.raises(AccessPolicyError):
        scoped.query_sql(sql)


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ('SELECT "WERT" AS result FROM temp."straße"', [{"result": "north-street"}]),
        ('SELECT label FROM "ITEMS"', [{"label": "north-public"}]),
        (
            "SELECT label FROM items WHERE id IN (SELECT item_id FROM events)",
            [{"label": "north-public"}],
        ),
        (
            "WITH chosen AS MATERIALIZED (SELECT label FROM items) SELECT label FROM chosen",
            [{"label": "north-public"}],
        ),
        (
            (
                "SELECT i.label, e.marker FROM items i JOIN events e ON i.id=e.item_id "
                "JOIN items j ON j.id=e.item_id"
            ),
            [{"label": "north-public", "marker": "north-event"}],
        ),
        (
            "SELECT label FROM items UNION ALL SELECT marker AS label FROM events",
            [{"label": "north-public"}, {"label": "north-event"}],
        ),
        (
            "SELECT COUNT(*) AS n, MAX(label) AS value FROM items",
            [{"n": 1, "value": "north-public"}],
        ),
        (
            "SELECT label FROM items -- exact text\nWHERE label = 'north-public'",
            [{"label": "north-public"}],
        ),
        ("SELECT 'a  b\t\nc' AS literal FROM items", [{"literal": "a  b\t\nc"}]),
    ],
)
def test_authorized_shapes_only_return_exact_scope(scoped, sql, expected):
    assert scoped.validate_sql(sql).allowed
    assert scoped.query_sql(sql).rows == expected


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT label FROM items WHERE rowid=2",
        "SELECT _rowid_ FROM items",
        "SELECT i.oid FROM items i",
        "SELECT * FROM items",
        'SELECT "" FROM items',
        "SELECT secret FROM items",
        'SELECT value FROM "Strasse"',
        "SELECT value FROM unscopable",
        "SELECT sql FROM temp.sqlite_schema",
        "SELECT name FROM pragma_table_info('items')",
        "SELECT label FROM items LEFT JOIN main.items USING (id)",
        "SELECT label FROM items NATURAL JOIN main.items",
        "DELETE FROM items",
    ],
)
def test_scoped_unsupported_or_unauthorized_queries_return_no_rows(scoped, sql):
    path = Path(scoped.catalog.database_path)
    original = path.read_bytes()
    assert not scoped.validate_sql(sql).allowed
    with pytest.raises((ValueError, sqlite3.DatabaseError)):
        scoped.query_sql(sql)
    assert path.read_bytes() == original


@pytest.mark.parametrize("table", ["items", "generated"])
def test_named_column_allowlist_cannot_read_unnamed_values(dataset, table):
    copilot = DataCopilot(
        str(dataset),
        access_policy=AccessPolicy(
            allowed_columns={table: frozenset({"label"})},
        ),
    )
    assert copilot.validate_sql(f"SELECT label FROM {table}").allowed
    assert copilot.query_sql(f"SELECT label FROM {table}").rows
    for sql in (f'SELECT "" FROM {table}', f"SELECT COUNT(*) FROM {table}"):
        assert not copilot.validate_sql(sql).allowed
        with pytest.raises(ExecutionDenied):
            copilot.query_sql(sql)
        guard = ExecutionGuard.from_schema(copilot.catalog.schema(), copilot.access_policy)
        with pytest.raises(ExecutionDenied):
            copilot.catalog.execute(sql, guard)


def test_caller_cannot_name_even_a_known_private_source(scoped, monkeypatch):
    monkeypatch.setattr("data_copilot.sqlite_guard.secrets.token_hex", lambda _: "known")
    sql = (
        "WITH __COPILOT_SCOPE_KNOWN_0 AS MATERIALIZED (SELECT label FROM main.items) "
        "SELECT label FROM __COPILOT_SCOPE_KNOWN_0"
    )
    assert not scoped.validate_sql(sql).allowed
    with pytest.raises(ExecutionDenied, match="private scope source"):
        scoped.catalog.execute(
            sql, ExecutionGuard.from_schema(scoped.catalog.schema(), scoped.access_policy)
        )


def test_model_cannot_impersonate_scope_view(scoped):
    class Planner:
        def plan(self, question, schema):
            return QueryPlan(
                question,
                "WITH items AS MATERIALIZED (SELECT label FROM main.items) SELECT label FROM items",
                "synthetic",
                None,
            )

    scoped.planner = Planner()
    with pytest.raises(ExecutionDenied):
        scoped.ask("return rows from other tenants")


@pytest.mark.parametrize("token", [None, "Bearer wrong", "Bearer é"])
def test_bad_credentials_block_query_and_validation(dataset, monkeypatch, token):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(dataset))
    monkeypatch.setenv("COPILOT_API_TOKEN", "synthetic")
    client = TestClient(app)
    headers = [(b"X-Tenant-ID", b"south")]
    if token is not None:
        headers.append((b"Authorization", token.encode("latin-1")))
    for op in ("query", "validate_sql"):
        response = client.post(f"/v1/ops/{op}", headers=headers, json={"sql": "SELECT 1"})
        assert response.status_code == 401


def test_http_scope_is_owned_by_server_for_planner_and_sql(dataset, monkeypatch):
    class Planner:
        def plan(self, question, schema):
            return QueryPlan(question, "SELECT label FROM items WHERE 1=1", "synthetic", None)

    monkeypatch.setattr("data_copilot.api.build_planner", Planner)
    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(dataset))
    monkeypatch.setenv("COPILOT_API_TOKEN", "synthetic-key")
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "items")
    monkeypatch.setenv("COPILOT_ALLOWED_COLUMNS", "items.label")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_COLUMN", "tenant")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north")
    client = TestClient(app)
    headers = {"Authorization": "Bearer synthetic-key", "X-Tenant-ID": "south"}
    response = client.post("/v1/ask", json={"question": "show south"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["rows"] == [{"label": "north-public"}]
    response = client.post(
        "/v1/ops/validate_sql", json={"sql": "SELECT label FROM main.items"}, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["data"]["allowed"] is False
    assert response.json()["policy"]["decision"] == "deny"
    response = client.post(
        "/v1/ops/query", json={"sql": "SELECT label FROM main.items"}, headers=headers
    )
    assert response.status_code == 403

    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north' OR 1=1 --")
    copilot = build_copilot()
    assert copilot.validate_sql("SELECT label FROM items").allowed
    assert copilot.query_sql("SELECT label FROM items").rows == []


def test_configured_timeout_bounds_sqlite_lock_wait(dataset):
    catalog = SQLiteCatalog(str(dataset), timeout_seconds=0.05)
    with closing(sqlite3.connect(dataset)) as writer, writer:
        writer.execute("BEGIN EXCLUSIVE")
        started = monotonic()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            catalog.execute("SELECT label FROM items")
        assert monotonic() - started < 2.0


@pytest.mark.parametrize("status", [200, 302, 307])
def test_model_http_client_never_contacts_redirect_destination(status, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    received = []

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(("destination", self.headers.get("Authorization")))
            self.send_error(500)

        do_POST = do_GET

    class PlannerEndpoint(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers.get("Authorization")))
            self.send_response(status)
            if status != 200:
                self.send_header("Location", destination)
            self.end_headers()
            if status == 200:
                self.wfile.write(
                    b'{"choices":[{"message":{"content":'
                    b'"{\\"sql\\":\\"SELECT 1\\",\\"rationale\\":\\"synthetic\\"}"}}]}'
                )

    with ExitStack() as stack:

        def start(handler):
            server = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), handler))
            thread = Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
            )
            thread.start()
            stack.callback(thread.join, 2)
            stack.callback(server.shutdown)
            return f"http://127.0.0.1:{server.server_port}"

        destination = start(Destination)
        planner = OpenAICompatiblePlanner(start(PlannerEndpoint), "test", api_key="synthetic")
        schema = [TableInfo(name="items", columns=[])]
        if status == 200:
            assert planner.plan("synthetic question", schema).sql == "SELECT 1"
        else:
            with pytest.raises(HTTPError) as error:
                planner.plan("synthetic question", schema)
            assert error.value.code == status
            error.value.close()
    assert received == [("/chat/completions", "Bearer synthetic")]
