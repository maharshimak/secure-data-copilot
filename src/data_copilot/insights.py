from numbers import Number
from typing import Any


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"row_count": len(rows)}
    if not rows:
        return summary

    numeric: dict[str, list[float]] = {}
    for row in rows:
        for key, value in row.items():
            if isinstance(value, Number) and not isinstance(value, bool):
                numeric.setdefault(key, []).append(float(value))

    summary["numeric"] = {
        key: {
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / len(values),
            "sum": sum(values),
        }
        for key, values in numeric.items()
        if values
    }
    return summary
