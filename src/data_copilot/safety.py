import re

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

FORBIDDEN_AST_KEYS = {
    "alter",
    "attach",
    "command",
    "commit",
    "create",
    "delete",
    "detach",
    "drop",
    "grant",
    "insert",
    "merge",
    "pragma",
    "revoke",
    "rollback",
    "savepoint",
    "transaction",
    "truncate",
    "update",
    "use",
    "vacuum",
}
FORBIDDEN_FUNCTIONS = {
    "load_extension",
    "readfile",
    "writefile",
}


class UnsafeQueryError(ValueError):
    pass


def normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip().rstrip(";")).strip()


def _parse_query(sql: str) -> exp.Query:
    try:
        statements = sqlglot.parse(sql, read="sqlite")
    except ParseError as error:
        raise UnsafeQueryError("SQL could not be parsed safely.") from error

    if len(statements) != 1:
        raise UnsafeQueryError("Exactly one SQL statement is allowed.")

    statement = statements[0]
    if not isinstance(statement, exp.Query):
        raise UnsafeQueryError("Only read-only query expressions are allowed.")

    for node in statement.walk():
        key = str(getattr(node, "key", "")).casefold()
        if key in FORBIDDEN_AST_KEYS:
            raise UnsafeQueryError(f"Forbidden SQL operation: {key}")

        name = str(getattr(node, "name", "")).casefold()
        if name in FORBIDDEN_FUNCTIONS:
            raise UnsafeQueryError(f"Forbidden SQL function: {name}")

    return statement


def validate_read_only(sql: str, max_rows: int = 200) -> str:
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= 1000:
        raise UnsafeQueryError("max_rows must be an integer between 1 and 1000.")

    normalized = normalize_sql(sql)
    if not normalized:
        raise UnsafeQueryError("SQL cannot be empty.")

    statement = _parse_query(normalized)
    canonical = statement.sql(dialect="sqlite")

    # Bound the outer result regardless of nested LIMITs or CTEs. The database
    # connection independently enforces query_only mode and a wall-clock progress limit.
    return f"SELECT * FROM (\n{canonical}\n) AS bounded_result LIMIT {max_rows}"
