import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PrivacyFinding:
    column: str
    category: str
    severity: str
    reason: str


_RULES: tuple[tuple[str, str, str, frozenset[str]], ...] = (
    (
        "credential",
        "critical",
        "column name indicates authentication or secret material",
        frozenset({"password", "passwd", "secret", "token", "api_key", "apikey"}),
    ),
    (
        "government_id",
        "high",
        "column name resembles a government-issued identifier",
        frozenset({"ssn", "social_security", "passport", "national_id", "tax_id"}),
    ),
    (
        "financial",
        "high",
        "column name indicates financial account or payment data",
        frozenset({"iban", "swift", "card_number", "credit_card", "bank_account"}),
    ),
    (
        "contact",
        "medium",
        "column name indicates direct contact information",
        frozenset({"email", "phone", "mobile", "telephone"}),
    ),
    (
        "location",
        "medium",
        "column name indicates precise address or coordinates",
        frozenset({"address", "street_address", "latitude", "longitude", "gps"}),
    ),
    (
        "health",
        "high",
        "column name indicates health or clinical information",
        frozenset({"diagnosis", "medical_record", "mrn", "condition", "medication"}),
    ),
)

_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8}


def _variants(column: str) -> set[str]:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", column).casefold()
    snake = re.sub(r"[^a-z0-9]+", "_", snake).strip("_")
    tokens = [token for token in snake.split("_") if token]
    variants = {snake, *tokens}
    variants.update("_".join(tokens[index : index + 2]) for index in range(len(tokens) - 1))
    return variants


def scan_schema(columns: Iterable[str]) -> tuple[PrivacyFinding, ...]:
    findings: list[PrivacyFinding] = []
    seen: set[tuple[str, str]] = set()
    for column in columns:
        if not isinstance(column, str) or not column.strip():
            raise ValueError("columns must contain non-empty strings")
        variants = _variants(column.strip())
        for category, severity, reason, indicators in _RULES:
            if not variants.intersection(indicators):
                continue
            key = (column, category)
            if key not in seen:
                findings.append(
                    PrivacyFinding(
                        column=column,
                        category=category,
                        severity=severity,
                        reason=reason,
                    )
                )
                seen.add(key)
    return tuple(sorted(findings, key=lambda item: (-_SEVERITY_WEIGHT[item.severity], item.column)))


def privacy_risk_score(findings: Iterable[PrivacyFinding]) -> int:
    return sum(_SEVERITY_WEIGHT[item.severity] for item in findings)
