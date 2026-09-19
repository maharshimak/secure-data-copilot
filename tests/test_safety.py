import pytest

from data_copilot.safety import UnsafeQueryError, validate_read_only


def test_select_gets_limit() -> None:
    assert validate_read_only("SELECT * FROM orders", 10).endswith("LIMIT 10")


def test_large_limit_is_reduced() -> None:
    sql = validate_read_only("SELECT * FROM orders LIMIT 5000", 25)
    assert sql.endswith("LIMIT 25")


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "DROP TABLE orders",
        "SELECT * FROM orders; DELETE FROM orders",
        "PRAGMA user_version",
    ],
)
def test_unsafe_queries_are_blocked(sql: str) -> None:
    with pytest.raises(UnsafeQueryError):
        validate_read_only(sql)
