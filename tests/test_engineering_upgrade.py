import pytest

from data_copilot.planner import DeterministicPlanner


@pytest.mark.parametrize(
    "question",
    [
        "delete orders",
        "drop customers",
        "pragma orders",
        "reindex orders",
        "commit orders",
        "rollback orders",
        "savepoint orders",
        "",
    ],
)
def test_mutation_intent_is_rejected_before_planning(question):
    with pytest.raises(ValueError):
        DeterministicPlanner().plan(question, [])


from data_copilot.access import AccessPolicy, authorized_schema
from data_copilot.models import ColumnInfo, TableInfo


def test_authorized_schema_hides_tables_and_denied_columns():
    schema = [
        TableInfo(
            name="sales",
            columns=[
                ColumnInfo(name="id", type="INTEGER", nullable=False),
                ColumnInfo(name="secret_note", type="TEXT", nullable=True),
            ],
        ),
        TableInfo(
            name="payroll",
            columns=[ColumnInfo(name="salary", type="REAL", nullable=False)],
        ),
    ]
    policy = AccessPolicy(
        allowed_tables=frozenset({"sales"}),
        denied_columns=frozenset({"secret_note"}),
    )

    projected = authorized_schema(schema, policy)

    assert [table.name for table in projected] == ["sales"]
    assert [column.name for column in projected[0].columns] == ["id"]



def test_data_copilot_blocks_credential_columns_before_planning(tmp_path):
    import sqlite3

    from data_copilot.executor import DataCopilot

    database = tmp_path / "sensitive.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE users(id INTEGER, api_key TEXT)")
        connection.execute("INSERT INTO users VALUES (1, 'synthetic')")
        connection.commit()

    with pytest.raises(ValueError, match="credential-like"):
        DataCopilot(str(database)).ask("show users")
