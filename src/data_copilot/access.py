from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError
from sqlglot.optimizer.scope import traverse_scope

from data_copilot.models import TableInfo


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

    # Resolve SQL sources by lexical scope. A global list of CTE names is unsafe:
    # it can mistake a physical table for a CTE declared in another scope.
    # selected_sources distinguishes tables from nested queries and CTEs.
    physical_tables: set[str] = set()
    guarded = {name.casefold() for name in policy.require_where_for_tables}
    scopes = traverse_scope(query)
    if not scopes:
        raise AccessPolicyError("Could not resolve SQL scopes for authorization.")
    for scope in scopes:
        local_tables: set[str] = set()
        for _, source in scope.selected_sources.values():
            if not isinstance(source, exp.Table):
                continue
            # An allowlist of bare table names must never authorize access to
            # an attached database or another schema using the same table name.
            if source.db or source.catalog:
                raise AccessPolicyError("Schema-qualified tables are not authorized.")
            table_name = source.name.casefold()
            local_tables.add(table_name)
            physical_tables.add(table_name)
        # The WHERE must protect the physical scan in its own SELECT scope.
        if (
            isinstance(scope.expression, exp.Select)
            and local_tables & guarded
            and scope.expression.args.get("where") is None
        ):
            raise AccessPolicyError(
                "Queries over guarded tables require an explicit WHERE predicate."
            )

    if policy.allowed_tables is not None:
        allowed = {name.casefold() for name in policy.allowed_tables}
        outside = sorted(physical_tables - allowed)
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



def authorized_schema(schema: list[TableInfo], policy: AccessPolicy) -> list[TableInfo]:
    """Project a catalog down to exactly the metadata the planner may observe."""

    allowed = (
        {name.casefold() for name in policy.allowed_tables}
        if policy.allowed_tables is not None
        else None
    )
    denied = {name.casefold() for name in policy.denied_columns}
    projected: list[TableInfo] = []
    for table in schema:
        if allowed is not None and table.name.casefold() not in allowed:
            continue
        projected.append(
            TableInfo(
                name=table.name,
                columns=[
                    column
                    for column in table.columns
                    if column.name.casefold() not in denied
                ],
            )
        )
    return projected
