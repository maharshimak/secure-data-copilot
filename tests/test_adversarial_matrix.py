"""Adversarial query matrix: no unauthorized data may be returned under any case.

The database holds sentinel values in an unauthorized table, an unauthorized
column and an unauthorized primary key. Every attack runs through the full
DataCopilot pipeline (AST authorization, complexity budget, risk budget, SQL safety,
SQLite authorizer, read-only connection). Each attack must be refused; in addition
the database file must be byte-identical after the whole matrix.
"""

import hashlib
import sqlite3
import time

import pytest

from data_copilot.access import AccessPolicy
from data_copilot.audit import JsonlAuditStore
from data_copilot.database import QueryTimeoutError, ResultTooLargeError, SQLiteCatalog
from data_copilot.executor import DataCopilot
from data_copilot.models import TableInfo
from data_copilot.sqlite_guard import ExecutionDenied, ExecutionGuard

SECRET_TEXT = "SENTINEL-SECRET"
SECRET_SALARY = 987654.25
SECRET_IDS = {9101, 9102, 9103}

POLICY = AccessPolicy(
    allowed_tables=frozenset({"sales"}),
    allowed_columns={"sales": frozenset({"tenant", "region", "amount"})},
    require_where_for_tables=frozenset({"sales"}),
)


@pytest.fixture()
def database(tmp_path):
    path = tmp_path / "matrix.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            f"""
            CREATE TABLE sales(
                id INTEGER PRIMARY KEY,
                tenant TEXT NOT NULL,
                region TEXT NOT NULL,
                amount REAL NOT NULL,
                card_token TEXT NOT NULL
            );
            CREATE TABLE payroll(id INTEGER PRIMARY KEY, employee TEXT, salary REAL);
            CREATE VIEW payroll_view AS SELECT employee, salary FROM payroll;
            INSERT INTO sales VALUES
              (9101, 'tenant-a', 'north', 10.0, '{SECRET_TEXT}-1'),
              (9102, 'tenant-a', 'south', 20.0, '{SECRET_TEXT}-2'),
              (9103, 'tenant-b', 'north', 30.0, '{SECRET_TEXT}-3');
            INSERT INTO payroll VALUES (1, '{SECRET_TEXT}-employee', {SECRET_SALARY});
            """
        )
    return path


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _leaks(rows) -> list[object]:
    leaked = []
    for row in rows:
        for value in row.values():
            if isinstance(value, str) and SECRET_TEXT in value or value == SECRET_SALARY or value in SECRET_IDS:
                leaked.append(value)
    return leaked


ATTACKS = {
    # unauthorized tables
    "table_direct": "SELECT salary FROM payroll WHERE salary > 0",
    "table_single_quoted": "SELECT salary FROM 'payroll' WHERE salary > 0",
    "table_bracket_quoted": "SELECT salary FROM [payroll] WHERE salary > 0",
    "table_backtick_quoted": "SELECT salary FROM `payroll` WHERE salary > 0",
    "table_case_variant": 'SELECT salary FROM "PAYROLL" WHERE salary > 0',
    "table_schema_qualified": "SELECT salary FROM main.payroll WHERE salary > 0",
    "table_in_subquery": (
        "SELECT region FROM sales WHERE tenant = 'tenant-a' "
        "AND amount < (SELECT salary FROM payroll)"
    ),
    "table_in_cte": (
        "WITH p AS (SELECT salary FROM payroll) "
        "SELECT region FROM sales WHERE tenant = 'tenant-a' AND amount IN (SELECT salary FROM p)"
    ),
    "table_in_exists": (
        "SELECT region FROM sales WHERE tenant = 'tenant-a' "
        "AND EXISTS (SELECT 1 FROM payroll WHERE salary > 900000)"
    ),
    "table_union": (
        "SELECT region FROM sales WHERE tenant = 'tenant-a' "
        "UNION ALL SELECT employee FROM payroll"
    ),
    "table_view": "SELECT salary FROM payroll_view WHERE salary > 0",
    "catalog_sqlite_master": "SELECT sql FROM sqlite_master WHERE type = 'table'",
    "catalog_pragma_function": "SELECT name FROM pragma_table_info('payroll') WHERE cid >= 0",
    "catalog_database_list": "SELECT file FROM pragma_database_list WHERE seq = 0",
    # unauthorized columns in an authorized table
    "column_direct": "SELECT card_token FROM sales WHERE tenant = 'tenant-a'",
    "column_star": "SELECT * FROM sales WHERE tenant = 'tenant-a'",
    "column_qualified_star": "SELECT s.* FROM sales s WHERE s.tenant = 'tenant-a'",
    "column_nested_star": (
        "SELECT region FROM (SELECT * FROM sales WHERE tenant = 'tenant-a') AS x"
    ),
    "column_alias_shadow": (
        "SELECT 'x' AS region, card_token AS amount FROM sales WHERE tenant = 'tenant-a'"
    ),
    "column_in_predicate_oracle": (
        "SELECT region FROM sales WHERE tenant = 'tenant-a' AND card_token LIKE 'SENT%'"
    ),
    "column_in_order_by": "SELECT region FROM sales WHERE tenant = 'tenant-a' ORDER BY card_token",
    "column_in_group_by": (
        "SELECT COUNT(*) AS n FROM sales WHERE tenant = 'tenant-a' GROUP BY card_token"
    ),
    "column_through_function": (
        "SELECT length(card_token) AS n FROM sales WHERE tenant = 'tenant-a'"
    ),
    "column_scalar_subquery": (
        "SELECT (SELECT card_token FROM sales WHERE tenant = 'tenant-b') AS v "
        "FROM sales WHERE tenant = 'tenant-a'"
    ),
    "column_cte_rename": (
        "WITH t(a) AS (SELECT card_token FROM sales WHERE tenant = 'tenant-a') SELECT a FROM t"
    ),
    "column_primary_key": "SELECT id FROM sales WHERE tenant = 'tenant-a'",
    "column_rowid": "SELECT rowid FROM sales WHERE tenant = 'tenant-a'",
    "column_rowid_in_subquery": (
        "SELECT r FROM (SELECT _rowid_ AS r FROM sales WHERE tenant = 'tenant-a')"
    ),
    "column_using_join": (
        "SELECT a.region FROM sales a JOIN sales b USING (card_token) WHERE a.tenant = 'tenant-a'"
    ),
    "column_natural_join": (
        "SELECT a.region FROM sales a NATURAL JOIN sales b WHERE a.tenant = 'tenant-a'"
    ),
    "column_quoted_case": 'SELECT "CARD_TOKEN" FROM sales WHERE tenant = \'tenant-a\'',
    # missing tenant predicate on a guarded table
    "missing_where": "SELECT region, amount FROM sales",
    "missing_where_aggregate": "SELECT SUM(amount) AS total FROM sales",
    # comment and whitespace variants
    "comment_block_inline": "SELECT/**/card_token/**/FROM/**/sales/**/WHERE tenant = 'tenant-a'",
    "comment_line_then_column": "SELECT region, -- harmless\ncard_token FROM sales WHERE tenant = 'tenant-a'",
    "whitespace_tabs_newlines": "SELECT\tcard_token\r\nFROM\tsales\nWHERE tenant = 'tenant-a'",
    "mixed_case_keywords": "sElEcT CaRd_ToKeN fRoM SaLeS wHeRe tenant = 'tenant-a'",
    # multi-statement
    "multi_select": "SELECT region FROM sales WHERE tenant = 'tenant-a'; SELECT salary FROM payroll",
    "multi_write": "SELECT region FROM sales WHERE tenant = 'tenant-a'; DELETE FROM sales",
    "multi_comment_hidden": (
        "SELECT region FROM sales WHERE tenant = 'tenant-a' /* x */; DROP TABLE sales"
    ),
    # forbidden functions
    "fn_load_extension": "SELECT load_extension('evil') AS x",
    "fn_readfile": "SELECT readfile('matrix.db') AS x",
    "fn_writefile": "SELECT writefile('out.bin', 'x') AS x",
    "fn_edit": "SELECT edit('x') AS x",
    "fn_fts3_tokenizer": "SELECT fts3_tokenizer('simple') AS x",
    "fn_randomblob": "SELECT randomblob(900000000) AS x",
    "fn_zeroblob": "SELECT zeroblob(900000000) AS x",
    "fn_sqlite_version": "SELECT sqlite_version() AS x",
    "fn_sqlite_compileoption": "SELECT sqlite_compileoption_get(0) AS x",
    "fn_sqlite_offset": (
        "SELECT sqlite_offset(region) AS x FROM sales WHERE tenant = 'tenant-a'"
    ),
    "fn_changes": "SELECT changes() AS x",
    "fn_unknown_udf": "SELECT my_udf(1) AS x",
    # expensive queries
    "expensive_recursive_cte": (
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) "
        "SELECT COUNT(*) AS c FROM r"
    ),
    "expensive_cross_join": (
        "SELECT COUNT(*) AS n FROM sales a CROSS JOIN sales b CROSS JOIN sales c "
        "WHERE a.tenant = 'tenant-a'"
    ),
    "expensive_join_count": (
        "SELECT a.region FROM sales a JOIN sales b ON a.amount = b.amount "
        "JOIN sales c ON b.amount = c.amount JOIN sales d ON c.amount = d.amount "
        "JOIN sales e ON d.amount = e.amount JOIN sales f ON e.amount = f.amount "
        "WHERE a.tenant = 'tenant-a'"
    ),
    # write and administrative attempts
    "write_insert": "INSERT INTO sales VALUES (1, 'x', 'x', 1, 'x')",
    "write_update": "UPDATE sales SET amount = 0",
    "write_delete": "DELETE FROM sales",
    "write_replace": "REPLACE INTO sales VALUES (9101, 'x', 'x', 1, 'x')",
    "write_upsert": (
        "INSERT INTO sales VALUES (9101, 'x', 'x', 1, 'x') "
        "ON CONFLICT(id) DO UPDATE SET amount = 0"
    ),
    "write_cte_insert": "WITH x AS (SELECT 1) INSERT INTO sales SELECT * FROM sales",
    "ddl_create": "CREATE TABLE stolen AS SELECT * FROM payroll",
    "ddl_create_temp": "CREATE TEMP TABLE stolen(x)",
    "ddl_drop": "DROP TABLE sales",
    "ddl_alter": "ALTER TABLE sales ADD COLUMN pwned TEXT",
    "admin_attach": "ATTACH DATABASE 'other.db' AS other",
    "admin_detach": "DETACH DATABASE main",
    "admin_pragma_write": "PRAGMA writable_schema = 1",
    "admin_pragma_query_only": "PRAGMA query_only = 0",
    "admin_vacuum": "VACUUM",
    "admin_vacuum_into": "VACUUM INTO 'copy.db'",
    "admin_reindex": "REINDEX",
    "admin_analyze": "ANALYZE",
    "admin_begin": "BEGIN IMMEDIATE",
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_attack_is_refused_without_returning_data(database, name):
    before = _digest(database)
    copilot = DataCopilot(str(database), access_policy=POLICY)
    try:
        result = copilot.query_sql(ATTACKS[name], question=name)
    except (ValueError, sqlite3.Error):
        pass
    else:
        pytest.fail(f"{name} was executed; leaked={_leaks(result.rows)!r}")
    assert _digest(database) == before


def test_authorized_controls_still_work(database):
    copilot = DataCopilot(str(database), access_policy=POLICY)
    for sql, expected in (
        (
            ("SELECT region, SUM(amount) AS total FROM sales WHERE tenant = 'tenant-a' "
            "GROUP BY region ORDER BY region"),
            [{"region": "north", "total": 10.0}, {"region": "south", "total": 20.0}],
        ),
        (
            "SELECT COUNT(*) AS n FROM sales WHERE tenant = 'tenant-a'",
            [{"n": 2}],
        ),
        (
            ("SELECT upper(region) AS r, round(amount, 1) AS a FROM "
            "(SELECT region, amount FROM sales WHERE tenant = 'tenant-b') AS t "
            "WHERE amount > 0"),
            [{"r": "NORTH", "a": 30.0}],
        ),
    ):
        result = copilot.query_sql(sql)
        assert result.rows == expected
        assert not _leaks(result.rows)


def test_planner_only_sees_authorized_columns(database):
    schema = DataCopilot(str(database), access_policy=POLICY).visible_schema()
    assert [(t.name, [c.name for c in t.columns]) for t in schema] == [
        ("sales", ["tenant", "region", "amount"])
    ]


# Defense in depth: the SQLite authorizer must refuse these even when every
# earlier AST layer is skipped and the raw statement goes straight to SQLite.
# Known gap: SQLite does not report USING/NATURAL join columns to the authorizer,
# so those joins are refused by the AST layer (see column_using_join above).
GUARD_ONLY = [
    "SELECT salary FROM payroll",
    "SELECT card_token FROM sales",
    "SELECT * FROM sales",
    "SELECT rowid FROM sales",
    "SELECT id FROM sales",
    "SELECT 1 AS region, card_token FROM sales",
    "SELECT salary FROM payroll_view",
    "SELECT sql FROM sqlite_master",
    "SELECT * FROM pragma_database_list",
    "SELECT * FROM json_each('[1]')",
    "SELECT randomblob(10)",
    "SELECT sqlite_version()",
    "SELECT load_extension('evil')",
    "INSERT INTO sales VALUES (1, 'x', 'x', 1, 'x')",
    "DELETE FROM sales",
    "ATTACH DATABASE ':memory:' AS other",
    "PRAGMA user_version",
    "PRAGMA query_only = 0",
    "CREATE TEMP TABLE t(x)",
    "BEGIN",
]


def _matrix_schema() -> list[TableInfo]:
    from data_copilot.models import ColumnInfo

    def cols(*names):
        return [ColumnInfo(name=n, type="TEXT", nullable=True) for n in names]

    return [
        TableInfo(name="sales", columns=cols("id", "tenant", "region", "amount", "card_token")),
        TableInfo(name="payroll", columns=cols("id", "employee", "salary")),
    ]


@pytest.mark.parametrize("sql", GUARD_ONLY)
def test_execution_guard_alone_refuses(database, sql):
    before = _digest(database)
    guard = ExecutionGuard.from_schema(_matrix_schema(), POLICY)
    with pytest.raises((ExecutionDenied, sqlite3.Error)):
        SQLiteCatalog(str(database)).execute(sql, guard)
    assert _digest(database) == before


def test_execution_guard_records_reason(database):
    guard = ExecutionGuard.from_schema(_matrix_schema(), POLICY)
    with pytest.raises(ExecutionDenied, match="sales.card_token"):
        SQLiteCatalog(str(database)).execute("SELECT card_token FROM sales", guard)


def test_without_policy_only_catalog_tables_are_readable(database):
    copilot = DataCopilot(str(database))
    assert copilot.query_sql("SELECT employee FROM payroll").rows == [
        {"employee": f"{SECRET_TEXT}-employee"}
    ]
    with pytest.raises(ValueError, match="internal catalogs"):
        copilot.query_sql("SELECT name FROM sqlite_master")
    # The execution guard independently refuses catalogs and recursive CTEs.
    guard = ExecutionGuard.from_schema(_matrix_schema())
    for sql in (
        "SELECT name FROM sqlite_master",
        ("WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r LIMIT 3) "
        "SELECT n FROM r"),
    ):
        with pytest.raises(ExecutionDenied):
            SQLiteCatalog(str(database)).execute(sql, guard)


def test_expensive_query_is_stopped_by_execution_deadline(tmp_path):
    path = tmp_path / "big.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE n(v INTEGER)")
        connection.executemany("INSERT INTO n VALUES (?)", [(i,) for i in range(2000)])
    copilot = DataCopilot(str(path), max_risk_score=100, timeout_seconds=0.3)
    started = time.perf_counter()
    with pytest.raises(QueryTimeoutError):
        copilot.query_sql("SELECT COUNT(*) AS c FROM n a CROSS JOIN n b CROSS JOIN n c")
    assert time.perf_counter() - started < 5


def test_result_byte_budget_discards_oversized_results(database):
    catalog = SQLiteCatalog(str(database), max_result_bytes=64)
    with pytest.raises(ResultTooLargeError):
        catalog.execute(
            "SELECT printf('%.100c', 'x') AS wide FROM sales",
            ExecutionGuard.from_schema(_matrix_schema()),
        )


def test_denials_are_audited_without_sql_text_or_values(database, tmp_path):
    log = tmp_path / "audit.jsonl"
    copilot = DataCopilot(
        str(database), access_policy=POLICY, audit_store=JsonlAuditStore(str(log))
    )
    for name in ("column_direct", "table_direct", "write_delete", "column_alias_shadow"):
        with pytest.raises((ValueError, sqlite3.Error)):
            copilot.query_sql(ATTACKS[name], question=name)
    allowed = copilot.query_sql(
        "SELECT region FROM sales WHERE tenant = 'tenant-b'", question="allowed"
    )
    text = log.read_text(encoding="utf-8")
    assert SECRET_TEXT not in text
    assert "tenant-b" not in text
    assert ATTACKS["column_direct"] not in text

    import json

    events = [json.loads(line) for line in text.splitlines()]
    assert [event["decision"] for event in events] == ["deny"] * 4 + ["allow"]
    assert events[-1]["event_id"] == allowed.audit.event_id
    assert events[-1]["row_count"] == 1
    assert events[3]["stage"] == "execution_guard"
    assert all(event["sql_fingerprint"] for event in events)


def test_validate_sql_compiles_without_executing(tmp_path):
    path = tmp_path / "big.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE n(v INTEGER)")
        connection.executemany("INSERT INTO n VALUES (?)", [(i,) for i in range(2000)])
    copilot = DataCopilot(str(path), max_risk_score=100, timeout_seconds=0.3)
    decision = copilot.validate_sql("SELECT COUNT(*) AS c FROM n a CROSS JOIN n b CROSS JOIN n c")
    assert decision.allowed and decision.stage == "validated"
    assert decision.bounded_sql.endswith("LIMIT 200")


@pytest.mark.parametrize("name", ["column_alias_shadow", "column_direct", "table_view"])
def test_validate_sql_reports_denial_stage(database, name):
    decision = DataCopilot(str(database), access_policy=POLICY).validate_sql(ATTACKS[name])
    assert not decision.allowed
    assert decision.reasons
    assert decision.stage in {"authorization", "execution_guard"}
