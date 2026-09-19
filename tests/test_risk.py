import pytest

from data_copilot.risk import assess_query_risk, enforce_query_budget
from data_copilot.safety import UnsafeQueryError


def test_simple_bounded_query_has_low_risk() -> None:
    bounded, risk = enforce_query_budget("SELECT id, total FROM orders", max_rows=25)
    assert bounded.endswith("LIMIT 25")
    assert risk.level == "low"


def test_complex_query_can_be_blocked_by_risk_budget() -> None:
    sql = "SELECT * FROM a CROSS JOIN b UNION SELECT * FROM c"
    report = assess_query_risk(sql)
    assert report.level == "high"
    with pytest.raises(UnsafeQueryError, match="risk score"):
        enforce_query_budget(sql, max_risk_score=20)


def test_write_query_still_fails_read_only_gate_first() -> None:
    with pytest.raises(UnsafeQueryError):
        enforce_query_budget("DELETE FROM orders")
