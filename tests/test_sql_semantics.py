import sqlite3

import pytest

from data_copilot.access import AccessPolicy
from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan
from data_copilot.risk import assess_query_risk
from data_copilot.safety import validate_read_only


@pytest.mark.parametrize("value", ["two  spaces", "line\nbreak", "tab\tvalue"])
def test_sql_literal_whitespace_is_preserved(value):
    sql = "SELECT '" + value + "' AS value"
    with sqlite3.connect(":memory:") as db:
        assert db.execute(validate_read_only(sql)).fetchone()[0] == value


def test_line_comment_cannot_erase_filter_after_authorization(tmp_path):
    path = tmp_path / "scope.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE items (id INTEGER)")
        db.executemany("INSERT INTO items VALUES (?)", [(1,), (2,)])

    class CommentedPlanner:
        def plan(self, question, schema):
            return QueryPlan(
                question=question,
                sql="SELECT id FROM items -- caller comment\nWHERE id = 1",
                rationale="Only the selected row",
            )

    result = DataCopilot(
        str(path),
        planner=CommentedPlanner(),
        access_policy=AccessPolicy(
            allowed_tables=frozenset({"items"}),
            require_where_for_tables=frozenset({"items"}),
        ),
    ).ask("selected row")
    assert result.rows == [{"id": 1}]


@pytest.mark.parametrize("separator", [" ", "\n", "\t"])
def test_cte_risk_factor_accepts_sql_whitespace(separator):
    sql = f"WITH{separator}selected AS (SELECT 1) SELECT * FROM selected"
    assert "CTE" in assess_query_risk(sql).factors

