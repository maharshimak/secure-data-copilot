import re

FORBIDDEN = {
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "replace",
    "truncate",
    "attach",
    "detach",
    "pragma",
    "vacuum",
    "reindex",
    "grant",
    "revoke",
    "commit",
    "rollback",
    "savepoint",
}


class UnsafeQueryError(ValueError):
    pass


def normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip().rstrip(";")).strip()


def _tokens(sql: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_]+", sql.lower()))


def validate_read_only(sql: str, max_rows: int = 200) -> str:
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= 1000:
        raise UnsafeQueryError("max_rows must be an integer between 1 and 1000.")
    normalized = normalize_sql(sql)
    lowered = normalized.lower()

    if not normalized:
        raise UnsafeQueryError("SQL cannot be empty.")

    if ";" in normalized:
        raise UnsafeQueryError("Multiple statements are not allowed.")

    first = lowered.split(maxsplit=1)[0]
    if first not in {"select", "with"}:
        raise UnsafeQueryError("Only SELECT or WITH queries are allowed.")

    blocked = sorted(_tokens(normalized).intersection(FORBIDDEN))
    if blocked:
        raise UnsafeQueryError(f"Forbidden SQL operation(s): {', '.join(blocked)}")

    # Bound the outer result regardless of nested LIMITs, literals or comments.
    # Newlines prevent a trailing SQL line comment from swallowing the wrapper.
    return f"SELECT * FROM (\n{normalized}\n) AS bounded_result LIMIT {max_rows}"
