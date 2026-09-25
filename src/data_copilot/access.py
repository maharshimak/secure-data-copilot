from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError


class AccessPolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """Defense-in-depth authorization applied after planning and before execution."""

    allowed_tables: frozenset[str] | None = None
    denied_columns: frozenset[str] = field(default_factory=frozenset)
    require_where_for_tables: frozenset[str] = field(default_factory=frozenset)
    max_joins: int = 4

    def __post_init__(self) -> None:
        if isinstance(self.max_joins, bool) or not isinstance(self.max_joins, int):
            raise TypeError("max_joins must be an integer.")
        if self.max_joins < 0:
            raise ValueError("max_joins must be non-negative.")


def authorize_sql(sql: str, policy: AccessPolicy) -> None:
    """Validate table/column scope without trusting the LLM planner."""

    try:
        statements = sqlglot.parse(sql, read="sqlite")
    except ParseError as error:
        raise AccessPolicyError("SQL could not be parsed for authorization.") from error
    if len(statements) != 1 or not isinstance(statements[0], exp.Query):
        raise AccessPolicyError("Authorization requires exactly one query.")
    query = statements[0]

    tables = {table.name.casefold() for table in query.find_all(exp.Table)}
    if policy.allowed_tables is not None:
        allowed = {name.casefold() for name in policy.allowed_tables}
        outside = sorted(tables - allowed)
        if outside:
            raise AccessPolicyError("Query references unauthorized tables: " + ", ".join(outside))

    joins = sum(1 for _ in query.find_all(exp.Join))
    if joins > policy.max_joins:
        raise AccessPolicyError(
            f"Query contains {joins} joins; policy maximum is {policy.max_joins}."
        )

    denied = {name.casefold() for name in policy.denied_columns}
    if denied:
        if any(isinstance(node, exp.Star) for node in query.walk()):
            raise AccessPolicyError(
                "Wildcard projection is not allowed when columns are explicitly denied."
            )
        used_denied = sorted(
            {
                column.name.casefold()
                for column in query.find_all(exp.Column)
                if column.name.casefold() in denied
            }
        )
        if used_denied:
            raise AccessPolicyError(
                "Query references denied columns: " + ", ".join(used_denied)
            )

    guarded = {name.casefold() for name in policy.require_where_for_tables}
    if tables & guarded and query.args.get("where") is None:
        raise AccessPolicyError(
            "Queries over guarded tables require an explicit WHERE predicate."
        )
