import sqlite3
from contextlib import closing
from pathlib import Path
from time import monotonic

from data_copilot.models import ColumnInfo, TableInfo
from data_copilot.sqlite_guard import (
    DEFAULT_MAX_VALUE_BYTES,
    ExecutionDenied,
    ExecutionGuard,
    apply_connection_limits,
)

DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_RESULT_BYTES = 8 * 1024 * 1024


class ResultTooLargeError(ValueError):
    """The result set exceeded the configured byte budget and was discarded."""


class QueryTimeoutError(ValueError):
    """SQLite's progress handler interrupted the statement at its deadline."""


def _value_size(value: object) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, bytes):
        return len(value)
    return 8


class SQLiteCatalog:
    def __init__(
        self,
        database_path: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_value_bytes: int = DEFAULT_MAX_VALUE_BYTES,
        max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not 0 < float(timeout_seconds) <= 60:
            raise ValueError("timeout_seconds must be within (0, 60].")
        for name, value in (
            ("max_value_bytes", max_value_bytes),
            ("max_result_bytes", max_result_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer.")
        self.database_path = str(Path(database_path))
        self.timeout_seconds = float(timeout_seconds)
        self.max_value_bytes = max_value_bytes
        self.max_result_bytes = max_result_bytes

    def _connect(self) -> sqlite3.Connection:
        uri = Path(self.database_path).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        apply_connection_limits(connection, max_value_bytes=self.max_value_bytes)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _arm_deadline(connection: sqlite3.Connection, timeout_seconds: float) -> None:
        deadline = monotonic() + timeout_seconds
        connection.set_progress_handler(lambda: int(monotonic() > deadline), 1000)

    def schema(self) -> list[TableInfo]:
        with closing(self._connect()) as connection:
            self._arm_deadline(connection, self.timeout_seconds)
            tables = connection.execute(
                """
                SELECT name
                FROM pragma_table_list
                WHERE schema = 'main' AND type = 'table'
                  AND lower(substr(name, 1, 7)) <> 'sqlite_'
                ORDER BY name
                """
            ).fetchall()

            result: list[TableInfo] = []
            for table in tables:
                name = table["name"]
                escaped = name.replace('"', '""')
                columns = connection.execute(f'PRAGMA table_info("{escaped}")').fetchall()
                result.append(
                    TableInfo(
                        name=name,
                        columns=[
                            ColumnInfo(
                                name=column["name"],
                                type=column["type"] or "UNKNOWN",
                                nullable=not bool(column["notnull"]),
                            )
                            for column in columns
                        ],
                    )
                )
            return result

    def _translate(
        self, error: sqlite3.DatabaseError, guard: ExecutionGuard | None
    ) -> Exception:
        if guard is not None and guard.denials:
            return ExecutionDenied(guard.denials)
        if "interrupted" in str(error).casefold():
            return QueryTimeoutError(
                f"Query exceeded the {self.timeout_seconds:g}s execution deadline."
            )
        return error

    def execute(
        self,
        sql: str,
        guard: ExecutionGuard | None = None,
    ) -> tuple[list[str], list[dict[str, object]]]:
        """Execute one statement under the connection limits and optional authorizer.

        Rows are fetched incrementally; the whole result is discarded if it grows
        past ``max_result_bytes`` so a hostile query cannot exhaust memory with a
        bounded number of very wide rows.
        """

        with closing(self._connect()) as connection:
            if guard is not None:
                guard.install(connection)
            self._arm_deadline(connection, self.timeout_seconds)
            rows: list[dict[str, object]] = []
            total = 0
            try:
                cursor = connection.execute(sql)
                columns = [item[0] for item in cursor.description or []]
                while batch := cursor.fetchmany(100):
                    for row in batch:
                        total += sum(_value_size(value) for value in row)
                        if total > self.max_result_bytes:
                            raise ResultTooLargeError(
                                f"Result exceeded the {self.max_result_bytes} byte budget."
                            )
                        rows.append(dict(row))
            except sqlite3.DatabaseError as error:
                translated = self._translate(error, guard)
                if translated is error:
                    raise
                raise translated from error
            return columns, rows

    def prepare(self, sql: str, guard: ExecutionGuard) -> None:
        """Compile ``sql`` under the authorizer without reading any rows.

        ``EXPLAIN`` makes SQLite resolve every table, column and function (which
        invokes the authorizer) and return bytecode instead of executing the query.
        """

        with closing(self._connect()) as connection:
            guard.install(connection)
            self._arm_deadline(connection, self.timeout_seconds)
            try:
                connection.execute("EXPLAIN " + sql).fetchall()
            except sqlite3.DatabaseError as error:
                translated = self._translate(error, guard)
                if translated is error:
                    raise
                raise translated from error
