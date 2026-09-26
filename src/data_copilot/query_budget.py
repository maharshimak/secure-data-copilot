from __future__ import annotations

from dataclasses import dataclass

from sqlglot import exp

from data_copilot.safety import _parse_query


class QueryBudgetExceeded(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class QueryBudget:
    max_joins: int = 4
    max_subqueries: int = 4
    max_ctes: int = 6
    max_functions: int = 30
    max_tables: int = 8

    def __post_init__(self) -> None:
        for name, value in (
            ("max_joins", self.max_joins),
            ("max_subqueries", self.max_subqueries),
            ("max_ctes", self.max_ctes),
            ("max_functions", self.max_functions),
            ("max_tables", self.max_tables),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class QueryComplexity:
    joins: int
    subqueries: int
    ctes: int
    functions: int
    tables: int

    @property
    def score(self) -> int:
        return self.joins * 4 + self.subqueries * 3 + self.ctes * 2 + self.functions + self.tables


def analyze_query_complexity(sql: str) -> QueryComplexity:
    statement = _parse_query(sql)
    joins = sum(1 for _ in statement.find_all(exp.Join))
    subqueries = sum(1 for _ in statement.find_all(exp.Subquery))
    ctes = sum(1 for _ in statement.find_all(exp.CTE))
    functions = sum(1 for _ in statement.find_all(exp.Func))
    tables = len({table.sql(dialect="sqlite") for table in statement.find_all(exp.Table)})
    return QueryComplexity(
        joins=joins,
        subqueries=subqueries,
        ctes=ctes,
        functions=functions,
        tables=tables,
    )


def enforce_query_budget(sql: str, budget: QueryBudget | None = None) -> QueryComplexity:
    budget = budget or QueryBudget()
    complexity = analyze_query_complexity(sql)
    violations: list[str] = []
    for label, actual, maximum in (
        ("joins", complexity.joins, budget.max_joins),
        ("subqueries", complexity.subqueries, budget.max_subqueries),
        ("CTEs", complexity.ctes, budget.max_ctes),
        ("functions", complexity.functions, budget.max_functions),
        ("tables", complexity.tables, budget.max_tables),
    ):
        if actual > maximum:
            violations.append(f"{label} {actual} > {maximum}")
    if violations:
        raise QueryBudgetExceeded("Query complexity budget exceeded: " + ", ".join(violations))
    return complexity
