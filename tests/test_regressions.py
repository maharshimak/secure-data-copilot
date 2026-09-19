import sqlite3

import pytest
from fastapi.testclient import TestClient

from data_copilot.api import app
from data_copilot.database import SQLiteCatalog
from data_copilot.safety import validate_read_only


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM items -- LIMIT 1",
        "SELECT * FROM items WHERE id IN (SELECT id FROM items LIMIT 100)",
        "SELECT * FROM items LIMIT -1",
        "SELECT * FROM items LIMIT 0, 100",
        "SELECT 'LIMIT 1' AS text, id FROM items",
    ],
)
def test_limit_enforced_on_actual_result(tmp_path, sql):
    path = tmp_path / "data?#.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE items (id INTEGER)")
        db.executemany("INSERT INTO items VALUES (?)", [(i,) for i in range(100)])
    _, rows = SQLiteCatalog(str(path)).execute(validate_read_only(sql, 3))
    assert len(rows) == 3
    with pytest.raises(sqlite3.OperationalError):
        SQLiteCatalog(str(path)).execute("DELETE FROM items")


@pytest.mark.parametrize("limit", [0, -1, 1001, True])
def test_invalid_row_limits(limit):
    with pytest.raises(ValueError):
        validate_read_only("SELECT 1", limit)


def test_api_does_not_accept_client_filesystem_path(monkeypatch):
    monkeypatch.delenv("COPILOT_DATABASE_PATH", raising=False)
    response = TestClient(app).post(
        "/v1/ask", json={"question": "orders", "database_path": "/private.db"}
    )
    assert response.status_code == 503
