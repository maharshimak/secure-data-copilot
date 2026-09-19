from numbers import Number
from typing import Any


def infer_chart_spec(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Infer a small Vega-Lite-compatible chart specification.

    The function intentionally returns None when a safe, obvious chart cannot
    be inferred instead of inventing a misleading visualization.
    """
    if not rows or len(rows) > 100:
        return None

    columns = list(rows[0])
    numeric = [
        column
        for column in columns
        if all(
            isinstance(row.get(column), Number) and not isinstance(row.get(column), bool)
            for row in rows
        )
    ]
    categorical = [column for column in columns if column not in numeric]

    if len(numeric) != 1 or not categorical:
        return None

    category = categorical[0]
    value = numeric[0]

    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "mark": "bar",
        "encoding": {
            "x": {"field": category, "type": "nominal", "sort": "-y"},
            "y": {"field": value, "type": "quantitative"},
            "tooltip": [
                {"field": category, "type": "nominal"},
                {"field": value, "type": "quantitative"},
            ],
        },
        "data": {"values": rows},
    }
