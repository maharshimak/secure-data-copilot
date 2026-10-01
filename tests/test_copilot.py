import sqlite3

import pytest

from data_copilot.executor import DataCopilot
from data_copilot.models import QueryPlan
from data_copilot.query_budget import QueryBudget, QueryBudgetExceeded
from data_copilot.safety import UnsafeQueryError


class StaticPlanner:
    def __init__(self, sql: str) -> None:
        self.sql = sql

    def plan(self, question, schema):
        del schema
        return QueryPlan(
            question=question,
            sql=self.sql,
            rationale="test plan",
            confidence=None,
        )


def test_top_customer_query(tmp_path) -> None:
    db = tmp_path / "demo.db"
    connection = sqlite3.connect(db)
    connection.executescript(
        """
        CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, created_at TEXT);
        INSERT INTO customers VALUES (1, 'Alpha'), (2, 'Beta');
        INSERT INTO orders VALUES
          (1, 1, 100.0, '2026-01-01'),
          (2, 1, 50.0, '2026-01-02'),
          (3, 2, 70.0, '2026-01-03');
        """
    )
    connection.commit()
    connection.close()

    result = DataCopilot(str(db)).ask("show top customers by revenue")

    assert result.rows[0]["name"] == "Alpha"
    assert result.rows[0]["revenue"] == 150.0
    assert result.audit.row_count == 2
    assert result.audit.risk_level == "low"
    assert result.audit.risk_score >= 0
    assert result.audit.complexity_score >= 0



def _build_three_table_db(path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE a(id INTEGER PRIMARY KEY);
        CREATE TABLE b(id INTEGER PRIMARY KEY);
        CREATE TABLE c(id INTEGER PRIMARY KEY);
        INSERT INTO a VALUES (1);
        INSERT INTO b VALUES (1);
        INSERT INTO c VALUES (1);
        """
    )
    connection.commit()
    connection.close()


def test_runtime_blocks_query_over_structural_budget(tmp_path) -> None:
    db = tmp_path / "budget.db"
    _build_three_table_db(db)
    copilot = DataCopilot(
        str(db),
        planner=StaticPlanner(
            "SELECT a.id FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id"
        ),
        query_budget=QueryBudget(max_joins=1),
    )

    with pytest.raises(QueryBudgetExceeded):
        copilot.ask("test structural budget")


def test_runtime_blocks_high_risk_read_only_query(tmp_path) -> None:
    db = tmp_path / "risk.db"
    _build_three_table_db(db)
    copilot = DataCopilot(
        str(db),
        planner=StaticPlanner(
            "SELECT * FROM a CROSS JOIN b UNION SELECT id, id FROM c"
        ),
        max_risk_score=20,
    )

    with pytest.raises(UnsafeQueryError, match="risk score"):
        copilot.ask("test risk budget")
