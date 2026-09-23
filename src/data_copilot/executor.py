from time import perf_counter
from typing import Protocol

from data_copilot.database import SQLiteCatalog
from data_copilot.insights import summarize_rows
from data_copilot.models import QueryAudit, QueryResult, TableInfo, QueryPlan
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
    ) -> None:
        self.catalog = SQLiteCatalog(database_path)
        self.planner = planner or DeterministicPlanner()
        self.max_rows = max_rows

    def ask(self, question: str) -> QueryResult:
        schema = self.catalog.schema()
        plan = self.planner.plan(question, schema)
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
