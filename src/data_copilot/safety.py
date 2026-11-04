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
# Function calls rejected at parse time in addition to FORBIDDEN_FUNCTIONS. The
# SQLite authorizer in sqlite_guard enforces a stricter allow-list at execution;
# this list exists so obviously hostile calls are refused before a connection opens.
FORBIDDEN_FUNCTION_CALLS = FORBIDDEN_FUNCTIONS | {
    "changes",
    "edit",
    "fts3_tokenizer",
    "last_insert_rowid",
    "randomblob",
    "total_changes",
    "zeroblob",
}
FORBIDDEN_FUNCTION_PREFIXES = ("sqlite_",)
# Schema catalogs and PRAGMA table-valued functions expose metadata (including the
# database file path) that the catalog deliberately hides from planners.
INTERNAL_SOURCE_PREFIXES = ("sqlite_", "pragma_")
# sqlglot parses sqlite_version() into a typed node rather than an anonymous call.
_CURRENT_VERSION = getattr(exp, "CurrentVersion", None)


class UnsafeQueryError(ValueError):
    pass


def normalize_sql(sql: str) -> str:
    # Whitespace belongs to string literals and terminates line comments. Keep
    # it intact until SQLGlot parses and serializes the query structurally.
    return sql.strip()


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

        if _CURRENT_VERSION is not None and isinstance(node, _CURRENT_VERSION):
            raise UnsafeQueryError("Forbidden SQL function: sqlite_version")
        if isinstance(node, exp.Anonymous) and (
            name in FORBIDDEN_FUNCTION_CALLS or name.startswith(FORBIDDEN_FUNCTION_PREFIXES)
        ):
            raise UnsafeQueryError(f"Forbidden SQL function: {name}")

        if isinstance(node, exp.Table):
            source = node.this
            source_name = (
                source.name if isinstance(source, exp.Func) else node.name
            ).casefold()
            if source_name.startswith(INTERNAL_SOURCE_PREFIXES):
                raise UnsafeQueryError(
                    f"SQLite internal catalogs are not queryable: {source_name}"
                )

        # sqlglot's SQLite generator drops alias column lists such as
        # "WITH t(a, b) AS (...)", which would silently rename or reorder columns
        # in the executed SQL. Refuse instead of executing different semantics.
        if isinstance(node, exp.TableAlias) and node.args.get("columns"):
            raise UnsafeQueryError(
                "Column lists on CTE or table aliases are not supported; "
                "alias the columns inside the query instead."
            )

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
