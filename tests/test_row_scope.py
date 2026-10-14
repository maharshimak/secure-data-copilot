"""Row-scoping regression tests with two tenants and malicious query shapes."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from data_copilot.access import AccessPolicy, AccessPolicyError
from data_copilot.api import app
from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan
from data_copilot.row_scope import RowScope, apply_row_scope


class Planner:
    def __init__(self, sql):
        self.sql = sql

    def plan(self, question, schema):
        return QueryPlan(question, self.sql, "adversarial SQL regression")


@pytest.fixture
def tenant_database(tmp_path):
    db = tmp_path / "tenants.db"
    with sqlite3.connect(db) as connection:
        connection.executescript(
            """
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY, tenant_id TEXT, name TEXT
            );
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY, tenant_id TEXT,
                customer_id INTEGER, amount INTEGER
            );
            INSERT INTO customers VALUES
              (1, 'north', 'North Co'), (2, 'south', 'South Secret');
            INSERT INTO orders VALUES
              (1, 'north', 1, 5), (2, 'south', 2, 9999);
            """
        )
    return db


def copilot(database, sql, value="north"):
    policy = AccessPolicy(allowed_tables=frozenset({"customers", "orders"}))
    scope = RowScope("tenant_id", value, policy.allowed_tables)
    return DataCopilot(
        str(database), planner=Planner(sql), access_policy=policy,
        row_scope=scope, max_risk_score=100,
    )


@pytest.mark.parametrize(
    "sql, expected",
    [
        ("SELECT name FROM customers ORDER BY name", ["North Co"]),
        ("SELECT SUM(amount) AS total FROM orders", [5]),
        (
            "WITH c AS (SELECT name FROM customers) SELECT name FROM c",
            ["North Co"],
        ),
        (
            "SELECT c.name FROM customers c JOIN orders o ON o.customer_id=c.id",
            ["North Co"],
        ),
        (
            "SELECT name FROM customers WHERE EXISTS (SELECT 1 FROM orders WHERE amount > 100)",
            [],
        ),
        (
            "SELECT name FROM customers UNION ALL SELECT name FROM customers",
            ["North Co", "North Co"],
        ),
    ],
)
def test_row_scope_covers_physical_scans(tenant_database, sql, expected):
    result = copilot(tenant_database, sql).ask("test row boundaries")
    values = list(result.rows[0].values()) if result.rows else []
    if len(expected) == 2:
        assert [next(iter(row.values())) for row in result.rows] == expected
    elif expected:
        assert values == expected
    else:
        assert result.rows == []
    assert "north" not in result.audit.sql
    assert "?" in result.audit.sql


def test_server_scope_value_is_bound_not_interpolated(tenant_database):
    hostile = "north' OR 1=1 --"
    result = copilot(
        tenant_database, "SELECT name FROM customers", value=hostile
    ).ask("attempt bypass")
    assert result.rows == []
    assert hostile not in result.audit.sql


def test_scoping_rejects_unknown_tables_and_untrusted_parameters():
    scope = RowScope("tenant_id", "north", frozenset({"customers"}))
    for sql in (
        "SELECT * FROM payroll",
        "SELECT * FROM main.customers",
        "SELECT * FROM customers WHERE name = ?",
    ):
        with pytest.raises(AccessPolicyError):
            apply_row_scope(sql, scope)


def test_missing_row_scope_column_fails_before_plan_execution(tenant_database):
    policy = AccessPolicy(allowed_tables=frozenset({"customers", "orders"}))
    with pytest.raises(ValueError, match="Row-scope column"):
        DataCopilot(
            str(tenant_database),
            access_policy=policy,
            row_scope=RowScope("unavailable", "north", policy.allowed_tables),
        ).ask("select customers")


def test_remote_row_scope_configuration_fails_closed(monkeypatch, tenant_database):
    monkeypatch.setenv("COPILOT_DATABASE_PATH", str(tenant_database))
    monkeypatch.setenv("COPILOT_API_TOKEN", "dev-test")
    monkeypatch.setenv("COPILOT_ALLOWED_TABLES", "customers,orders")
    monkeypatch.setenv("COPILOT_ROW_SCOPE_VALUE", "north")
    monkeypatch.delenv("COPILOT_ROW_SCOPE_COLUMN", raising=False)
    client = TestClient(app)
    response = client.post(
        "/v1/ask", json={"question": "show customers"},
        headers={"Authorization": "Bearer dev-test"},
    )
    assert response.status_code == 503
    assert "COPILOT_ROW_SCOPE" in response.json()["detail"]
