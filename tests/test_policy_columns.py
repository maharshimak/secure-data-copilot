import pytest

from data_copilot.access import AccessPolicy, AccessPolicyError, authorize_sql, authorized_schema
from data_copilot.ai_planner import OpenAICompatiblePlanner
from data_copilot.config import build_access_policy, planner_execution_mode
from data_copilot.models import ColumnInfo, TableInfo
from data_copilot.safety import UnsafeQueryError, validate_read_only

COLUMNS = AccessPolicy(
    allowed_tables=frozenset({"orders"}),
    allowed_columns={"Orders": ["Region", "amount"]},
)


def test_allowed_columns_are_normalized_case_insensitively():
    assert COLUMNS.allowed_columns == {"orders": frozenset({"region", "amount"})}
    assert COLUMNS.restricts_columns


@pytest.mark.parametrize("bad", [{"orders": "region"}, {"": ["a"]}, ["orders"]])
def test_allowed_columns_rejects_malformed_values(bad):
    with pytest.raises((TypeError, ValueError)):
        AccessPolicy(allowed_columns=bad)


def test_authorized_schema_projects_allowed_columns_and_hides_unlisted_tables_columns():
    schema = [
        TableInfo(
            name="orders",
            columns=[
                ColumnInfo(name="id", type="INTEGER", nullable=False),
                ColumnInfo(name="region", type="TEXT", nullable=True),
                ColumnInfo(name="amount", type="REAL", nullable=True),
            ],
        ),
        TableInfo(name="events", columns=[ColumnInfo(name="kind", type="TEXT", nullable=True)]),
    ]
    policy = AccessPolicy(allowed_columns={"orders": frozenset({"region", "amount"})})
    projected = authorized_schema(schema, policy)
    assert [(t.name, [c.name for c in t.columns]) for t in projected] == [
        ("orders", ["region", "amount"]),
        ("events", []),
    ]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM orders",
        "SELECT o.* FROM orders o",
        "SELECT rowid FROM orders",
        "SELECT a.region FROM orders a JOIN orders b USING (region)",
        "SELECT a.region FROM orders a NATURAL JOIN orders b",
    ],
)
def test_ast_layer_rejects_constructs_the_authorizer_cannot_verify(sql):
    with pytest.raises(AccessPolicyError):
        authorize_sql(sql, COLUMNS)


def test_count_star_and_explicit_columns_pass_ast_layer():
    authorize_sql("SELECT region, COUNT(*) AS n FROM orders GROUP BY region", COLUMNS)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM sqlite_master",
        "SELECT * FROM SQLITE_TEMP_MASTER",
        "SELECT name FROM pragma_table_info('orders')",
        "SELECT randomblob(10)",
        "SELECT ZEROBLOB(10)",
        "SELECT sqlite_version()",
        "SELECT sqlite_source_id()",
        "WITH t(a) AS (SELECT 1) SELECT a FROM t",
    ],
)
def test_safety_layer_rejects_internal_sources_and_hostile_functions(sql):
    with pytest.raises(UnsafeQueryError):
        validate_read_only(sql)


def test_columns_named_like_functions_are_not_rejected():
    # Only function calls are checked against the extended deny list.
    assert validate_read_only("SELECT changes, edit FROM history", 5).endswith("LIMIT 5")


def test_env_allowed_columns_parsing(monkeypatch):
    for name in ("COPILOT_ALLOWED_TABLES", "COPILOT_DENIED_COLUMNS", "COPILOT_GUARDED_TABLES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("COPILOT_MAX_JOINS", raising=False)
    monkeypatch.setenv("COPILOT_ALLOWED_COLUMNS", "orders.region, orders.amount ,events.kind")
    policy = build_access_policy()
    assert policy.allowed_columns == {
        "orders": frozenset({"region", "amount"}),
        "events": frozenset({"kind"}),
    }
    monkeypatch.setenv("COPILOT_ALLOWED_COLUMNS", "orders")
    with pytest.raises(RuntimeError, match="table.column"):
        build_access_policy()


@pytest.mark.parametrize(
    ("base_url", "mode"),
    [
        ("http://localhost:11434/v1", "local_model"),
        ("http://127.0.0.1:8080", "local_model"),
        ("https://api.example.invalid/v1", "remote_model"),
    ],
)
def test_planner_execution_mode_is_truthful(base_url, mode):
    planner = OpenAICompatiblePlanner(base_url=base_url, model="m")
    assert planner_execution_mode(planner) == mode
    assert planner_execution_mode(None) == "deterministic_offline"
