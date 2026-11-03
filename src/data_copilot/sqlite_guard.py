"""Execution-layer authorization enforced by SQLite itself.

The AST checks in :mod:`data_copilot.access` and :mod:`data_copilot.safety` run
before execution and give early, readable rejections. They cannot see how SQLite
finally resolves names (``*`` expansion, unqualified columns, ``rowid`` aliases of
an ``INTEGER PRIMARY KEY``, view bodies). This module installs a
``sqlite3.Connection.set_authorizer`` callback that SQLite invokes while compiling
the statement, with the physical table and column it actually resolved. Anything
the guard does not explicitly allow is denied, so an unexpected construct fails
closed instead of reading data.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from data_copilot.access import ROWID_ALIASES, AccessPolicy, AccessPolicyError
from data_copilot.models import TableInfo

# Scalar, aggregate, window, date/time, math and JSON functions that read only
# their arguments. Deliberately absent: load_extension, readfile, writefile, edit,
# fts3_tokenizer, randomblob, zeroblob, sqlite_* introspection, changes(),
# last_insert_rowid(), total_changes() and any application-defined function.
DEFAULT_ALLOWED_FUNCTIONS: frozenset[str] = frozenset(
    {
        # core scalar
        "abs", "char", "coalesce", "concat", "concat_ws", "format", "glob", "hex",
        "ifnull", "iif", "instr", "length", "like", "likelihood", "likely", "lower",
        "ltrim", "max", "min", "nullif", "octet_length", "printf", "quote", "random",
        "replace", "round", "rtrim", "sign", "substr", "substring", "trim", "typeof",
        "unicode", "unlikely", "upper",
        # aggregate
        "avg", "count", "group_concat", "string_agg", "sum", "total",
        # window
        "row_number", "rank", "dense_rank", "percent_rank", "cume_dist", "ntile",
        "lag", "lead", "first_value", "last_value", "nth_value",
        # date and time
        "date", "time", "datetime", "julianday", "unixepoch", "strftime", "timediff",
        # math (present when SQLite is compiled with SQLITE_ENABLE_MATH_FUNCTIONS)
        "acos", "acosh", "asin", "asinh", "atan", "atan2", "atanh", "ceil", "ceiling",
        "cos", "cosh", "degrees", "exp", "floor", "ln", "log", "log10", "log2", "mod",
        "pi", "pow", "power", "radians", "sin", "sinh", "sqrt", "tan", "tanh", "trunc",
        # JSON scalar/aggregate (table-valued json_each/json_tree stay denied as sources)
        "json", "json_array", "json_array_length", "json_extract", "json_group_array",
        "json_group_object", "json_object", "json_quote", "json_type", "json_valid",
        "->", "->>",
    }
)

# Values above are SQLite defaults that are far larger than an analytics answer
# needs; tightening them bounds memory and parser work for hostile SQL.
DEFAULT_MAX_VALUE_BYTES = 1_000_000
DEFAULT_MAX_SQL_BYTES = 100_000
DEFAULT_MAX_EXPR_DEPTH = 200
DEFAULT_MAX_COMPOUND_SELECT = 50


class ExecutionDenied(AccessPolicyError):
    """SQLite's authorizer refused part of the compiled statement."""

    def __init__(self, reasons: Iterable[str]) -> None:
        self.reasons = tuple(dict.fromkeys(reasons)) or ("statement not authorized",)
        super().__init__("Execution guard denied the query: " + "; ".join(self.reasons))


def _action_name(action: int) -> str:
    for name in (
        "SQLITE_ATTACH", "SQLITE_DETACH", "SQLITE_PRAGMA", "SQLITE_INSERT",
        "SQLITE_UPDATE", "SQLITE_DELETE", "SQLITE_TRANSACTION", "SQLITE_ANALYZE",
        "SQLITE_CREATE_TABLE", "SQLITE_DROP_TABLE", "SQLITE_ALTER_TABLE",
        "SQLITE_REINDEX", "SQLITE_SAVEPOINT", "SQLITE_CREATE_VTABLE",
    ):
        if getattr(sqlite3, name, None) == action:
            return name.removeprefix("SQLITE_").lower()
    return f"action {action}"


@dataclass(slots=True)
class ExecutionGuard:
    """Fail-closed SQLite authorizer for one statement.

    ``readable_tables`` maps a case-folded physical table name to the case-folded
    column names that may be read, or ``None`` when every column not listed in
    ``denied_columns`` may be read.
    """

    readable_tables: Mapping[str, frozenset[str] | None]
    denied_columns: frozenset[str] = frozenset()
    allowed_functions: frozenset[str] = DEFAULT_ALLOWED_FUNCTIONS
    denials: list[str] = field(default_factory=list)

    @classmethod
    def from_schema(
        cls,
        schema: list[TableInfo],
        policy: AccessPolicy | None = None,
        *,
        allowed_functions: frozenset[str] = DEFAULT_ALLOWED_FUNCTIONS,
    ) -> ExecutionGuard:
        """Build a guard from the introspected user tables and an optional policy.

        Only real user tables discovered by the catalog are readable. SQLite's
        internal ``sqlite_*`` tables, ``pragma_*`` table-valued functions, views and
        other virtual tables are never readable, even without an access policy.
        """

        allowed = (
            {name.casefold() for name in policy.allowed_tables}
            if policy is not None and policy.allowed_tables is not None
            else None
        )
        column_allow = (
            {
                table.casefold(): frozenset(column.casefold() for column in columns)
                for table, columns in policy.allowed_columns.items()
            }
            if policy is not None and policy.allowed_columns is not None
            else None
        )
        readable: dict[str, frozenset[str] | None] = {}
        for table in schema:
            name = table.name.casefold()
            if name.startswith("sqlite_"):
                continue
            if allowed is not None and name not in allowed:
                continue
            readable[name] = (
                None if column_allow is None else column_allow.get(name, frozenset())
            )
        denied = (
            frozenset(name.casefold() for name in policy.denied_columns)
            if policy is not None
            else frozenset()
        )
        return cls(
            readable_tables=readable,
            denied_columns=denied,
            allowed_functions=frozenset(name.casefold() for name in allowed_functions),
        )

    def _deny(self, reason: str) -> int:
        self.denials.append(reason)
        return sqlite3.SQLITE_DENY

    def __call__(
        self,
        action: int,
        arg1: str | None,
        arg2: str | None,
        db_name: str | None,
        _source: str | None,
    ) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            return self._authorize_read(arg1 or "", arg2 or "", db_name)
        if action == sqlite3.SQLITE_FUNCTION:
            name = (arg2 or "").casefold()
            if name in self.allowed_functions:
                return sqlite3.SQLITE_OK
            return self._deny(f"function {name or '?'} is not allowed")
        # Everything else is denied, including SQLITE_RECURSIVE: SQLite reports the
        # recursive CTE's self-reference as a read of a table the catalog does not
        # know, and resolving that safely would require trusting CTE names.
        return self._deny(f"{_action_name(action)} is not allowed")

    def _authorize_read(self, table: str, column: str, db_name: str | None) -> int:
        table_key = table.casefold()
        if db_name not in (None, "main"):
            return self._deny(f"schema {db_name} is not readable")
        if table_key not in self.readable_tables:
            return self._deny(f"table {table} is not readable")
        if not column:
            # SQLite reports an empty column when a table is touched without reading
            # a value from it (for example COUNT(*)); table access is authorized above.
            return sqlite3.SQLITE_OK
        column_key = column.casefold()
        if column_key in self.denied_columns:
            return self._deny(f"column {table}.{column} is denied")
        allowed_columns = self.readable_tables[table_key]
        if allowed_columns is not None and column_key not in allowed_columns:
            if column_key in ROWID_ALIASES:
                return self._deny(f"rowid of {table} is not readable")
            return self._deny(f"column {table}.{column} is not readable")
        return sqlite3.SQLITE_OK


def apply_connection_limits(
    connection: sqlite3.Connection,
    *,
    max_value_bytes: int = DEFAULT_MAX_VALUE_BYTES,
) -> None:
    """Tighten SQLite run-time limits on a connection that runs untrusted SQL."""

    connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, max_value_bytes)
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, DEFAULT_MAX_SQL_BYTES)
    connection.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, DEFAULT_MAX_EXPR_DEPTH)
    connection.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, DEFAULT_MAX_COMPOUND_SELECT)
    defensive = getattr(sqlite3, "SQLITE_DBCONFIG_DEFENSIVE", None)
    if defensive is not None and hasattr(connection, "setconfig"):
        connection.setconfig(defensive, True)
