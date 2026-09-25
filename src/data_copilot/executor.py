from time import perf_counter
from typing import Protocol

from data_copilot.access import AccessPolicy, authorize_sql
from data_copilot.database import SQLiteCatalog
from data_copilot.insights import summarize_rows
from data_copilot.models import QueryAudit, QueryPlan, QueryResult, TableInfo
from data_copilot.planner import DeterministicPlanner
from data_copilot.safety import validate_read_only


class Planner(Protocol):
    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan: ...


class DataCopilot:
    def __init__(
        self,
        database_path: str,
        max_rows: int = 200,
        planner: Planner | None = None,
        access_policy: AccessPolicy | None = None,
    ) -> None:
        self.catalog = SQLiteCatalog(database_path)
        self.planner = planner or DeterministicPlanner()
        self.max_rows = max_rows
        self.access_policy = access_policy

    def ask(self, question: str) -> QueryResult:
        schema = self.catalog.schema()
        plan = self.planner.plan(question, schema)
        if self.access_policy is not None:
            authorize_sql(plan.sql, self.access_policy)
        safe_sql = validate_read_only(plan.sql, max_rows=self.max_rows)

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
            ),
            insights=summarize_rows(rows),
        )
