import pytest

from data_copilot.safety import UnsafeQueryError, validate_read_only


def test_select_gets_limit() -> None:
    assert validate_read_only("SELECT * FROM orders", 10).endswith("LIMIT 10")


def test_large_limit_is_reduced() -> None:
    sql = validate_read_only("SELECT * FROM orders LIMIT 5000", 25)
    assert sql.endswith("LIMIT 25")


def test_with_query_remains_supported() -> None:
    sql = validate_read_only(
        "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
        12,
    )
    assert sql.endswith("LIMIT 12")
    assert "WITH recent AS" in sql


def test_operation_words_inside_string_literals_are_not_false_positives() -> None:
    sql = validate_read_only("SELECT 'delete update drop' AS words", 5)
    assert sql.endswith("LIMIT 5")


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "DROP TABLE orders",
        "SELECT * FROM orders; DELETE FROM orders",
        "PRAGMA user_version",
        "ATTACH DATABASE 'other.db' AS other",
        "SELECT load_extension('/tmp/unsafe')",
        "SELECT readfile('/etc/passwd')",
    ],
)
def test_unsafe_queries_are_blocked(sql: str) -> None:
    with pytest.raises(UnsafeQueryError):
        validate_read_only(sql)
