from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from data_copilot.models import TableInfo

# SQLite pseudo-columns that read a table's rowid. When a table declares an
# INTEGER PRIMARY KEY they return that column's value under a different name.
ROWID_ALIASES = frozenset({"rowid", "_rowid_", "oid"})


class AccessPolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """Defense-in-depth authorization applied after planning and before execution.

    ``allowed_columns`` optionally maps a table name to the only columns that may be
    read from it. When it is set, a readable table without an entry exposes no
    column values (fail closed). ``denied_columns`` is a global name deny list that
    applies to every table.
    """

    allowed_tables: frozenset[str] | None = None
    denied_columns: frozenset[str] = field(default_factory=frozenset)
    require_where_for_tables: frozenset[str] = field(default_factory=frozenset)
    max_joins: int = 4
    allowed_columns: Mapping[str, frozenset[str]] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.max_joins, bool) or not isinstance(self.max_joins, int):
            raise TypeError("max_joins must be an integer.")
        if self.max_joins < 0:
            raise ValueError("max_joins must be non-negative.")
        if self.allowed_columns is not None:
            if not isinstance(self.allowed_columns, Mapping):
                raise TypeError("allowed_columns must map table names to column names.")
            normalized: dict[str, frozenset[str]] = {}
            for table, columns in self.allowed_columns.items():
                if not isinstance(table, str) or not table.strip():
                    raise ValueError("allowed_columns keys must be non-empty table names.")
                if isinstance(columns, str):
                    raise TypeError("allowed_columns values must be collections of names.")
                normalized[table.casefold()] = frozenset(str(name).casefold() for name in columns)
            object.__setattr__(self, "allowed_columns", normalized)

    @property
    def restricts_columns(self) -> bool:
        return bool(self.denied_columns) or self.allowed_columns is not None


def _is_count_star(star: exp.Star) -> bool:
    # COUNT(*) counts rows without reading any column value.
    return isinstance(star.parent, exp.Count)


def authorize_sql(sql: str, policy: AccessPolicy) -> None:
    """Validate table/column scope without trusting the LLM planner.

    This is an early AST check. Column resolution is approximate here (aliases and
    unqualified names are not bound to tables); the SQLite authorizer installed by
    :mod:`data_copilot.sqlite_guard` performs the exact per-column check at execution.
    """

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

    joins = list(query.find_all(exp.Join))
    if len(joins) > policy.max_joins:
        raise AccessPolicyError(
            f"Query contains {len(joins)} joins; policy maximum is {policy.max_joins}."
        )

    if policy.restricts_columns:
        if any(
            isinstance(node, exp.Star) and not _is_count_star(node) for node in query.walk()
        ):
            raise AccessPolicyError(
                "Wildcard projection is not allowed when column access is restricted."
            )
        # SQLite's authorizer does not report the columns (or even the right-hand
        # table) of USING/NATURAL joins, so the execution guard cannot verify them.
        for join in joins:
            if str(join.args.get("method") or "").upper() == "NATURAL" or join.args.get(
                "using"
            ):
                raise AccessPolicyError(
                    "NATURAL and USING joins are not allowed when column access is "
                    "restricted; use an explicit ON condition."
                )
        referenced = {column.name.casefold() for column in query.find_all(exp.Column)}
        rowid_refs = sorted(referenced & ROWID_ALIASES)
        if rowid_refs:
            raise AccessPolicyError(
                "rowid pseudo-columns are not allowed when column access is restricted: "
                + ", ".join(rowid_refs)
            )
        denied = {name.casefold() for name in policy.denied_columns}
        used_denied = sorted(referenced & denied)
        if used_denied:
            raise AccessPolicyError(
                "Query references denied columns: " + ", ".join(used_denied)
            )

    guarded = {name.casefold() for name in policy.require_where_for_tables}
    if tables & guarded and query.args.get("where") is None:
        raise AccessPolicyError(
            "Queries over guarded tables require an explicit WHERE predicate."
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
        column_allow = (
            policy.allowed_columns.get(table.name.casefold(), frozenset())
            if policy.allowed_columns is not None
            else None
        )
        projected.append(
            TableInfo(
                name=table.name,
                columns=[
                    column
                    for column in table.columns
                    if column.name.casefold() not in denied
                    and (column_allow is None or column.name.casefold() in column_allow)
                ],
            )
        )
    return projected
