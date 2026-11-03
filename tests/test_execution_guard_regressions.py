"""Regression tests for defects reproduced against main before the execution guard.

They use only the public DataCopilot/AccessPolicy API so the same file can be run
against the previous revision to show the failures.
"""

import sqlite3

import pytest

from data_copilot.access import AccessPolicy
from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan


class StaticPlanner:
    def __init__(self, sql: str) -> None:
        self.sql = sql

    def plan(self, question, schema):
        del schema
        return QueryPlan(question=question, sql=self.sql, rationale="test", confidence=None)


@pytest.fixture()
def database(tmp_path):
    path = tmp_path / "guard.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE accounts(id INTEGER PRIMARY KEY, region TEXT, balance REAL);
            INSERT INTO accounts VALUES (7301, 'north', 10.0), (7302, 'south', 20.0);
            """
        )
    return str(path)


def _run(database, sql, policy=None):
    return DataCopilot(database, planner=StaticPlanner(sql), access_policy=policy).ask("q")


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT rowid AS r FROM accounts",
        "SELECT _rowid_ AS r FROM accounts",
        "SELECT oid AS r FROM accounts",
        "SELECT r FROM (SELECT rowid AS r FROM accounts)",
        # Used only as a predicate, the rowid still acts as an oracle on the key.
        "SELECT region FROM accounts WHERE rowid = 7301",
    ],
)
def test_rowid_alias_cannot_read_denied_integer_primary_key(database, sql):
    # accounts.id is an INTEGER PRIMARY KEY, so rowid/_rowid_/oid return its value.
    policy = AccessPolicy(denied_columns=frozenset({"id"}))
    with pytest.raises(ValueError):
        _run(database, sql, policy)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM pragma_database_list",
        "SELECT name FROM pragma_table_info('accounts')",
        "SELECT sql FROM sqlite_master",
        "SELECT name FROM sqlite_schema",
    ],
)
def test_internal_catalogs_are_not_readable_without_policy(database, sql):
    with pytest.raises(ValueError):
        _run(database, sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT length(zeroblob(50000000)) AS n",
        "SELECT length(randomblob(5000000)) AS n",
        "SELECT length(printf('%.*c', 5000000, 'x')) AS n",
        "SELECT length(replace(hex(zeroblob(2000000)), '0', 'ab')) AS n",
    ],
)
def test_oversized_values_cannot_be_materialized(database, sql):
    # The value must either be refused (forbidden function / "string or blob too
    # big") or never built: SQLite's printf returns NULL once SQLITE_LIMIT_LENGTH
    # would be exceeded.
    try:
        result = _run(database, sql)
    except (ValueError, sqlite3.DataError, sqlite3.OperationalError):
        return
    assert result.rows == [{"n": None}]


def test_count_star_is_allowed_when_columns_are_denied(database):
    policy = AccessPolicy(denied_columns=frozenset({"balance"}))
    result = _run(database, "SELECT region, COUNT(*) AS n FROM accounts GROUP BY region", policy)
    assert result.rows == [{"region": "north", "n": 1}, {"region": "south", "n": 1}]


def test_using_join_on_denied_column_is_refused(database):
    policy = AccessPolicy(denied_columns=frozenset({"balance"}))
    with pytest.raises(ValueError):
        _run(
            database,
            "SELECT a.region FROM accounts a JOIN accounts b USING (balance)",
            policy,
        )


def test_cte_column_list_is_not_silently_dropped(tmp_path):
    # sqlglot's SQLite generator drops "t(a, b)" column lists. Executing the
    # rewritten SQL returned y (2) where the submitted SQL means x (1).
    path = tmp_path / "cte.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE src(x INTEGER, y INTEGER)")
        connection.execute("INSERT INTO src VALUES (1, 2)")
    sql = "WITH t(a, b) AS (SELECT x AS b, y AS a FROM src) SELECT a FROM t"
    with sqlite3.connect(path) as connection:
        assert connection.execute(sql).fetchall() == [(1,)]
    try:
        result = _run(str(path), sql)
    except ValueError:
        return
    assert result.rows == [{"a": 1}]
