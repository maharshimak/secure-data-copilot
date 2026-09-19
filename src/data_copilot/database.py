import sqlite3
from contextlib import closing
from pathlib import Path
from time import monotonic

from data_copilot.models import ColumnInfo, TableInfo


class SQLiteCatalog:
    def __init__(self, database_path: str) -> None:
        self.database_path = str(Path(database_path))

    def _connect(self) -> sqlite3.Connection:
        uri = Path(self.database_path).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        deadline = monotonic() + 2.0
        connection.set_progress_handler(lambda: int(monotonic() > deadline), 1000)
        connection.row_factory = sqlite3.Row
        return connection

    def schema(self) -> list[TableInfo]:
        with closing(self._connect()) as connection:
            tables = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name NOT LIKE 'sqlite_%'
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

    def execute(self, sql: str) -> tuple[list[str], list[dict[str, object]]]:
        with closing(self._connect()) as connection:
            cursor = connection.execute(sql)
            columns = [item[0] for item in cursor.description or []]
            rows = [dict(row) for row in cursor.fetchall()]
            return columns, rows
