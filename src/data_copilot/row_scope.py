"""Server-owned row scope, applied to every physical table scan before SQLite.

One deployment-wide scope value is configured by the operator, never supplied
by a prompt, LLM, SQL planner or untrusted request body. This is not multi-user
identity or a database-native row-level security replacement.
"""
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError
from sqlglot.optimizer.scope import traverse_scope

from data_copilot.access import AccessPolicyError


@dataclass(frozen=True, slots=True)
class RowScope:
    column: str
    value: str
    tables: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.column.isidentifier() or not self.tables:
            raise ValueError("Row scope needs a valid column and nonempty table allowlist.")
        if not self.value:
            raise ValueError("Row scope value must be configured by the server.")
        if any(not table.isidentifier() for table in self.tables):
            raise ValueError("Row-scope tables must be simple identifiers.")


def apply_row_scope(sql: str, scope: RowScope) -> tuple[str, tuple[str, ...]]:
    """Replace table scans by parameterized, filtered subqueries.

    A full AST walk with resolved scopes handles aliases, CTEs, scalar
    subqueries, joins and UNION branches. Fail closed on unexpected sources.
    """
    try:
        statements = sqlglot.parse(sql, read="sqlite")
    except ParseError as error:
        raise AccessPolicyError("Row-scoped SQL could not be parsed.") from error
    if len(statements) != 1 or not isinstance(statements[0], exp.Query):
        raise AccessPolicyError("Row scoping requires exactly one query.")
    query = statements[0]
    # The planner must not supply its own parameters; those are exclusively
    # introduced by the trusted row-scope compiler.
    if any(isinstance(node, exp.Placeholder) for node in query.walk()):
        raise AccessPolicyError("Planner SQL placeholders are not allowed.")

    scopes = traverse_scope(query)
    if not scopes:
        raise AccessPolicyError("Row-scoped SQL has no resolvable source scopes.")
    count = 0
    tables = {table.casefold() for table in scope.tables}
    for resolved in scopes:
        for _, source in resolved.selected_sources.values():
            if not isinstance(source, exp.Table):
                continue
            table_name = source.name.casefold()
            if source.db or source.catalog or table_name not in tables:
                raise AccessPolicyError("Row scope blocked an unapproved physical table.")
            # Preserve the original table's outside alias so JOIN ON, WHERE,
            # GROUP BY and correlated references still resolve correctly.
            alias = source.alias_or_name
            filtered = (
                exp.select("*")
                .from_(source.copy())
                .where(exp.column(scope.column, quoted=True).eq(exp.Placeholder()))
            )
            derived = exp.Subquery(
                this=filtered,
                alias=exp.TableAlias(this=exp.to_identifier(alias)),
            )
            source.replace(derived)
            count += 1
    if count == 0:
        raise AccessPolicyError("Row-scoped query did not scan an authorized table.")
    return query.sql(dialect="sqlite"), (scope.value,) * count
