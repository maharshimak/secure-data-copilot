from data_copilot.audit import sql_fingerprint
from data_copilot.visualize import infer_chart_spec


def test_chart_inference_for_category_and_metric() -> None:
    rows = [
        {"customer": "A", "revenue": 10.0},
        {"customer": "B", "revenue": 7.5},
    ]
    spec = infer_chart_spec(rows)
    assert spec is not None
    assert spec["encoding"]["y"]["field"] == "revenue"


def test_sql_fingerprint_is_normalized() -> None:
    assert sql_fingerprint("SELECT  * FROM orders") == sql_fingerprint("select * from orders")
