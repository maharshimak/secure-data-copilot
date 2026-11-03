"""Server-side configuration read from environment variables.

Callers (HTTP clients, makma.v1 operations) never supply database paths or
policies; both come only from the deployment environment.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from data_copilot.access import AccessPolicy
from data_copilot.ai_planner import OpenAICompatiblePlanner
from data_copilot.audit import JsonlAuditStore
from data_copilot.executor import DataCopilot

LOCAL_MODEL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def build_planner() -> OpenAICompatiblePlanner | None:
    base_url = os.environ.get("COPILOT_MODEL_BASE_URL", "").strip()
    model = os.environ.get("COPILOT_MODEL", "").strip()
    if not base_url and not model:
        return None
    if not base_url or not model:
        raise RuntimeError(
            "COPILOT_MODEL_BASE_URL and COPILOT_MODEL must be configured together."
        )
    try:
        timeout_seconds = float(os.environ.get("COPILOT_MODEL_TIMEOUT_SECONDS", "45"))
    except ValueError as error:
        raise RuntimeError("COPILOT_MODEL_TIMEOUT_SECONDS must be numeric.") from error
    return OpenAICompatiblePlanner(
        base_url=base_url,
        model=model,
        api_key=os.environ.get("COPILOT_MODEL_API_KEY", ""),
        timeout_seconds=timeout_seconds,
    )


def planner_execution_mode(planner: OpenAICompatiblePlanner | None) -> str:
    """makma.v1 execution_mode for planning with ``planner``."""

    if planner is None:
        return "deterministic_offline"
    host = (urlparse(planner.base_url).hostname or "").casefold()
    return "local_model" if host in LOCAL_MODEL_HOSTS else "remote_model"


def _csv_set(name: str) -> frozenset[str]:
    return frozenset(
        item.strip()
        for item in os.environ.get(name, "").split(",")
        if item.strip()
    )


def _allowed_columns() -> dict[str, frozenset[str]] | None:
    entries = _csv_set("COPILOT_ALLOWED_COLUMNS")
    if not entries:
        return None
    columns: dict[str, set[str]] = {}
    for entry in entries:
        table, dot, column = entry.partition(".")
        if not dot or not table.strip() or not column.strip() or "." in column:
            raise RuntimeError(
                "COPILOT_ALLOWED_COLUMNS entries must be formatted as table.column."
            )
        columns.setdefault(table.strip(), set()).add(column.strip())
    return {table: frozenset(names) for table, names in columns.items()}


def build_access_policy() -> AccessPolicy | None:
    allowed = _csv_set("COPILOT_ALLOWED_TABLES")
    denied = _csv_set("COPILOT_DENIED_COLUMNS")
    guarded = _csv_set("COPILOT_GUARDED_TABLES")
    allowed_columns = _allowed_columns()
    raw_max_joins = os.environ.get("COPILOT_MAX_JOINS", "").strip()
    if not allowed and not denied and not guarded and not raw_max_joins and not allowed_columns:
        return None
    try:
        max_joins = int(raw_max_joins or "4")
    except ValueError as error:
        raise RuntimeError("COPILOT_MAX_JOINS must be an integer.") from error
    return AccessPolicy(
        allowed_tables=allowed or None,
        denied_columns=denied,
        require_where_for_tables=guarded,
        max_joins=max_joins,
        allowed_columns=allowed_columns,
    )


def access_policy_configured() -> bool:
    return any(
        os.environ.get(name)
        for name in (
            "COPILOT_ALLOWED_TABLES",
            "COPILOT_ALLOWED_COLUMNS",
            "COPILOT_DENIED_COLUMNS",
            "COPILOT_GUARDED_TABLES",
            "COPILOT_MAX_JOINS",
        )
    )


def build_audit_store() -> JsonlAuditStore | None:
    path = os.environ.get("COPILOT_AUDIT_LOG_PATH", "").strip()
    return JsonlAuditStore(path) if path else None


def build_copilot(
    max_rows: int = 200,
    *,
    planner: OpenAICompatiblePlanner | None = None,
) -> DataCopilot:
    """Build the server-configured DataCopilot.

    Raises ``LookupError`` when no database is configured and ``RuntimeError`` for
    unsafe or incomplete configuration.
    """

    database_path = os.environ.get("COPILOT_DATABASE_PATH")
    if not database_path:
        raise LookupError("No server database configured.")
    access_policy = build_access_policy()
    if planner is not None and (access_policy is None or access_policy.allowed_tables is None):
        raise RuntimeError(
            "Model-backed planning requires COPILOT_ALLOWED_TABLES so unauthorized "
            "schema metadata is never disclosed to the model provider."
        )
    return DataCopilot(
        database_path=database_path,
        max_rows=max_rows,
        planner=planner,
        access_policy=access_policy,
        audit_store=build_audit_store(),
    )
