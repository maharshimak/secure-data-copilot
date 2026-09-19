import re
from dataclasses import dataclass

from data_copilot.safety import UnsafeQueryError, normalize_sql, validate_read_only


@dataclass(frozen=True, slots=True)
class QueryRisk:
    score: int
    level: str
    factors: tuple[str, ...]


def assess_query_risk(sql: str) -> QueryRisk:
    normalized = normalize_sql(sql)
    lowered = normalized.lower()
    score = 0
    factors: list[str] = []

    def add(condition: bool, points: int, factor: str) -> None:
        nonlocal score
        if condition:
            score += points
            factors.append(factor)

    join_count = len(re.findall(r"\bjoin\b", lowered))
    select_count = len(re.findall(r"\bselect\b", lowered))
    add(bool(re.search(r"\bselect\s+\*", lowered)), 10, "wildcard projection")
    add(join_count >= 2, min(24, join_count * 8), "multiple joins")
    add(bool(re.search(r"\bcross\s+join\b", lowered)), 30, "cross join")
    add(bool(re.search(r"\bunion(?:\s+all)?\b", lowered)), 20, "set union")
    add(select_count > 1, min(24, (select_count - 1) * 12), "nested query")
    add("--" in normalized or "/*" in normalized, 10, "SQL comments")
    add(bool(re.search(r"\border\s+by\s+random\s*\(", lowered)), 20, "random ordering")
    add(lowered.startswith("with "), 8, "CTE")

    score = min(score, 100)
    level = "low" if score < 20 else "medium" if score < 50 else "high"
    return QueryRisk(score=score, level=level, factors=tuple(factors))


def enforce_query_budget(
    sql: str,
    *,
    max_risk_score: int = 40,
    max_rows: int = 200,
) -> tuple[str, QueryRisk]:
    if isinstance(max_risk_score, bool) or not isinstance(max_risk_score, int):
        raise TypeError("max_risk_score must be an integer")
    if not 0 <= max_risk_score <= 100:
        raise ValueError("max_risk_score must be between 0 and 100")

    bounded_sql = validate_read_only(sql, max_rows=max_rows)
    risk = assess_query_risk(sql)
    if risk.score > max_risk_score:
        raise UnsafeQueryError(
            f"Query risk score {risk.score} exceeds configured maximum {max_risk_score}: "
            + ", ".join(risk.factors)
        )
    return bounded_sql, risk
