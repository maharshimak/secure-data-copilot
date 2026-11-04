import sqlite3
from dataclasses import dataclass
from time import perf_counter
from typing import Protocol

from data_copilot.access import AccessPolicy, AccessPolicyError, authorize_sql, authorized_schema
from data_copilot.audit import AuditEvent, JsonlAuditStore, build_event, sql_fingerprint
from data_copilot.database import (
    DEFAULT_TIMEOUT_SECONDS,
    QueryTimeoutError,
    ResultTooLargeError,
    SQLiteCatalog,
)
from data_copilot.insights import summarize_rows
from data_copilot.models import QueryAudit, QueryPlan, QueryResult, TableInfo
from data_copilot.planner import DeterministicPlanner
from data_copilot.query_budget import QueryBudget, QueryBudgetExceeded, QueryComplexity
from data_copilot.query_budget import enforce_query_budget as enforce_complexity_budget
from data_copilot.risk import QueryRisk
from data_copilot.risk import enforce_query_budget as enforce_risk_budget
from data_copilot.safety import UnsafeQueryError
from data_copilot.sqlite_guard import ExecutionDenied, ExecutionGuard

# Exceptions that represent a policy decision to refuse the query (not a fault).
POLICY_ERRORS: tuple[type[Exception], ...] = (
    AccessPolicyError,
    UnsafeQueryError,
    QueryBudgetExceeded,
    ResultTooLargeError,
)


def failure_stage(error: Exception) -> str:
    if isinstance(error, ExecutionDenied):
        return "execution_guard"
    if isinstance(error, AccessPolicyError):
        return "authorization"
    if isinstance(error, QueryBudgetExceeded):
        return "complexity_budget"
    if isinstance(error, UnsafeQueryError):
        return "sql_safety"
    if isinstance(error, ResultTooLargeError):
        return "result_budget"
    if isinstance(error, QueryTimeoutError):
        return "timeout"
    return "execute"


def failure_reasons(error: Exception) -> tuple[str, ...]:
    if isinstance(error, ExecutionDenied):
        return error.reasons
    if isinstance(error, sqlite3.Error):
        # Database error text can echo fragments of the statement; keep the class only.
        return (f"database error: {type(error).__name__}",)
    return (str(error),)


class Planner(Protocol):
    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan: ...


@dataclass(frozen=True, slots=True)
class SqlDecision:
    """Outcome of running every pre-execution gate without reading any rows."""

    allowed: bool
    stage: str
    reasons: tuple[str, ...]
    sql_fingerprint: str
    bounded_sql: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    risk_factors: tuple[str, ...] = ()
    complexity_score: int | None = None


class DataCopilot:
    def __init__(
        self,
        database_path: str,
        max_rows: int = 200,
        planner: Planner | None = None,
        access_policy: AccessPolicy | None = None,
        query_budget: QueryBudget | None = None,
        max_risk_score: int = 40,
        audit_store: JsonlAuditStore | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.catalog = SQLiteCatalog(database_path, timeout_seconds=timeout_seconds)
        self.planner = planner or DeterministicPlanner()
        self.max_rows = max_rows
        self.access_policy = access_policy
        self.query_budget = query_budget or QueryBudget()
        self.max_risk_score = max_risk_score
        self.audit_store = audit_store

    def visible_schema(self, schema: list[TableInfo] | None = None) -> list[TableInfo]:
        """User tables and columns the policy allows a planner or caller to see."""

        schema = self.catalog.schema() if schema is None else schema
        visible = [table for table in schema if not table.name.casefold().startswith("sqlite_")]
        if self.access_policy is None:
            return visible
        return authorized_schema(visible, self.access_policy)

    def _guard(self, schema: list[TableInfo]) -> ExecutionGuard:
        return ExecutionGuard.from_schema(schema, self.access_policy)

    def _enforce(self, sql: str) -> tuple[str, QueryRisk, QueryComplexity]:
        if self.access_policy is not None:
            authorize_sql(sql, self.access_policy)
        complexity = enforce_complexity_budget(sql, self.query_budget)
        safe_sql, risk = enforce_risk_budget(
            sql,
            max_risk_score=self.max_risk_score,
            max_rows=self.max_rows,
        )
        return safe_sql, risk, complexity

    def _record(self, event: AuditEvent) -> None:
        if self.audit_store is not None:
            self.audit_store.append(event)

    def validate_sql(self, sql: str) -> SqlDecision:
        """Run authorization, safety, budgets and the SQLite authorizer (via EXPLAIN).

        No table rows are read: the statement is only compiled. The decision is
        audited when an audit store is configured.
        """

        if not isinstance(sql, str):
            raise TypeError("sql must be a string")
        fingerprint = sql_fingerprint(sql) if sql else ""
        try:
            safe_sql, risk, complexity = self._enforce(sql)
            self.catalog.prepare(safe_sql, self._guard(self.catalog.schema()))
        except (*POLICY_ERRORS, sqlite3.DatabaseError) as error:
            decision = SqlDecision(
                allowed=False,
                stage="sqlite_compile" if isinstance(error, sqlite3.DatabaseError)
                else failure_stage(error),
                reasons=failure_reasons(error),
                sql_fingerprint=fingerprint,
            )
        else:
            decision = SqlDecision(
                allowed=True,
                stage="validated",
                reasons=(),
                sql_fingerprint=fingerprint,
                bounded_sql=safe_sql,
                risk_score=risk.score,
                risk_level=risk.level,
                risk_factors=risk.factors,
                complexity_score=complexity.score,
            )
        self._record(
            build_event(
                question="",
                sql=sql,
                duration_ms=0.0,
                row_count=0,
                decision="allow" if decision.allowed else "deny",
                reasons=decision.reasons,
                stage="validate:" + decision.stage,
            )
        )
        return decision

    def ask(self, question: str) -> QueryResult:
        schema = self.catalog.schema()
        try:
            plan = self.planner.plan(question, self.visible_schema(schema))
        except Exception as error:
            self._record(
                build_event(
                    question=question if isinstance(question, str) else "",
                    sql="",
                    duration_ms=0.0,
                    row_count=0,
                    decision="error",
                    reasons=(type(error).__name__,),
                    stage="planning",
                )
            )
            raise
        return self._execute_plan(plan, schema)

    def query_sql(self, sql: str, question: str = "") -> QueryResult:
        """Execute caller- or model-supplied SQL through exactly the same gates as ask()."""

        if not isinstance(sql, str) or not sql.strip():
            raise ValueError("sql must be a non-empty string.")
        plan = QueryPlan(
            question=question,
            sql=sql,
            rationale="Caller-supplied SQL; treated as untrusted.",
            confidence=None,
        )
        return self._execute_plan(plan, self.catalog.schema())

    def _execute_plan(self, plan: QueryPlan, schema: list[TableInfo]) -> QueryResult:
        started = perf_counter()
        try:
            safe_sql, risk, complexity = self._enforce(plan.sql)
            columns, rows = self.catalog.execute(safe_sql, self._guard(schema))
        except (*POLICY_ERRORS, QueryTimeoutError, sqlite3.Error) as error:
            self._record(
                build_event(
                    question=plan.question,
                    sql=plan.sql,
                    duration_ms=(perf_counter() - started) * 1000,
                    row_count=0,
                    decision="deny" if isinstance(error, POLICY_ERRORS) else "error",
                    reasons=failure_reasons(error),
                    stage=failure_stage(error),
                )
            )
            raise
        duration_ms = (perf_counter() - started) * 1000
        event = build_event(
            question=plan.question,
            sql=safe_sql,
            duration_ms=duration_ms,
            row_count=len(rows),
        )
        self._record(event)

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
                event_id=event.event_id,
            ),
            insights=summarize_rows(rows),
        )
