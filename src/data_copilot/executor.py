from time import perf_counter
from typing import Protocol

from data_copilot.access import AccessPolicy, authorize_sql, authorized_schema
from data_copilot.database import SQLiteCatalog
from data_copilot.insights import summarize_rows
from data_copilot.models import QueryAudit, QueryPlan, QueryResult, TableInfo
from data_copilot.planner import DeterministicPlanner
from data_copilot.query_budget import QueryBudget, enforce_query_budget as enforce_complexity_budget
from data_copilot.risk import enforce_query_budget as enforce_risk_budget


class Planner(Protocol):
    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan: ...


class DataCopilot:
    def __init__(
        self,
        database_path: str,
        max_rows: int = 200,
        planner: Planner | None = None,
        access_policy: AccessPolicy | None = None,
        query_budget: QueryBudget | None = None,
        max_risk_score: int = 40,
    ) -> None:
        self.catalog = SQLiteCatalog(database_path)
        self.planner = planner or DeterministicPlanner()
        self.max_rows = max_rows
        self.access_policy = access_policy
        self.query_budget = query_budget or QueryBudget()
        self.max_risk_score = max_risk_score

    def ask(self, question: str) -> QueryResult:
        schema = self.catalog.schema()
        planner_schema = (
            authorized_schema(schema, self.access_policy)
            if self.access_policy is not None
            else schema
        )
        plan = self.planner.plan(question, planner_schema)
        if self.access_policy is not None:
            authorize_sql(plan.sql, self.access_policy)
        complexity = enforce_complexity_budget(plan.sql, self.query_budget)
        safe_sql, risk = enforce_risk_budget(
            plan.sql,
            max_risk_score=self.max_risk_score,
            max_rows=self.max_rows,
        )

        started = perf_counter()
        columns, rows = self.catalog.execute(safe_sql)
        duration_ms = (perf_counter() - started) * 1000

        return QueryResult(
            plan=plan,
            rows=rows,
            audit=QueryAudit(
                sql=safe_sql,
                duration_ms=duration_ms,
                row_count=len(rows),
                columns=columns,
                risk_score=risk.score,
                risk_level=risk.level,
                complexity_score=complexity.score,
            ),
            insights=summarize_rows(rows),
        )
