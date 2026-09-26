import pytest

from data_copilot.query_budget import (
    QueryBudget,
    QueryBudgetExceeded,
    analyze_query_complexity,
    enforce_query_budget,
)


def test_query_complexity_counts_structural_cost():
    sql = "SELECT COUNT(*) FROM users u JOIN orders o ON o.user_id = u.id"
    complexity = analyze_query_complexity(sql)
    assert complexity.joins == 1
    assert complexity.functions >= 1
    assert complexity.tables == 2


def test_query_budget_blocks_overly_complex_query():
    sql = "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id"
    with pytest.raises(QueryBudgetExceeded):
        enforce_query_budget(sql, QueryBudget(max_joins=1))
