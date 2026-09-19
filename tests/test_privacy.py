import pytest

from data_copilot.privacy import privacy_risk_score, scan_schema


def test_schema_scanner_classifies_sensitive_columns() -> None:
    findings = scan_schema(
        ["customer_id", "email", "passport_number", "apiKey", "created_at"]
    )

    categories = {(item.column, item.category) for item in findings}

    assert ("email", "contact") in categories
    assert ("passport_number", "government_id") in categories
    assert ("apiKey", "credential") in categories
    assert privacy_risk_score(findings) == 14


def test_schema_scanner_ignores_generic_analytics_columns() -> None:
    assert scan_schema(["revenue", "order_count", "created_at"]) == ()


def test_schema_scanner_rejects_blank_column_names() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        scan_schema([""])
