from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ColumnInfo:
    name: str
    type: str
    nullable: bool


@dataclass(frozen=True, slots=True)
class TableInfo:
    name: str
    columns: list[ColumnInfo]


@dataclass(frozen=True, slots=True)
class QueryPlan:
    question: str
    sql: str
    rationale: str
    confidence: float


@dataclass(frozen=True, slots=True)
class QueryAudit:
    sql: str
    duration_ms: float
    row_count: int
    columns: list[str]


@dataclass(frozen=True, slots=True)
class QueryResult:
    plan: QueryPlan
    rows: list[dict[str, Any]]
    audit: QueryAudit
    insights: dict[str, Any] = field(default_factory=dict)
