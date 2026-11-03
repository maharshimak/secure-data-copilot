"""makma.v1 execution contract for secure-data-copilot.

Operations run in-process against the server-configured database and policy; the
payload can never choose a database path, an access policy or a planner. See
``contracts/makma.v1.schema.json`` for the envelope schema shared across systems.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata
from time import perf_counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from data_copilot.config import (
    access_policy_configured,
    build_copilot,
    build_planner,
    planner_execution_mode,
)
from data_copilot.database import DEFAULT_TIMEOUT_SECONDS, QueryTimeoutError
from data_copilot.executor import POLICY_ERRORS, failure_reasons, failure_stage

CONTRACT_VERSION = "makma.v1"
SYSTEM = "secure-data-copilot"
_OPERATION_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

Status = Literal["ok", "error", "blocked", "pending_approval"]
ExecutionMode = Literal["deterministic_offline", "local_model", "remote_model"]


class ContractError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    message: str = Field(max_length=2000)
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["document", "chunk", "artifact", "dataset", "model", "query", "record"]
    id: str = Field(min_length=1)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    span: tuple[int, int] | None = None
    uri: str | None = None


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "deny", "requires_approval"]
    reasons: list[str] = Field(default_factory=list)


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["makma.v1"] = CONTRACT_VERSION
    system: Literal["secure-data-copilot"] = SYSTEM
    operation: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    run_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    status: Status
    execution_mode: ExecutionMode
    data: Any = None
    error: ContractError | None = None
    provenance: list[Provenance] = Field(default_factory=list)
    policy: PolicyDecision | None = None
    started_at: str
    duration_ms: float = Field(ge=0)

    @model_validator(mode="after")
    def _status_rules(self) -> Envelope:
        if self.status == "ok" and self.error is not None:
            raise ValueError("status ok requires error null")
        if self.status in {"error", "blocked"} and (self.error is None or self.data is not None):
            raise ValueError("error/blocked status requires an error and null data")
        if self.status == "pending_approval" and (
            self.policy is None or self.policy.decision != "requires_approval"
        ):
            raise ValueError("pending_approval requires policy.decision requires_approval")
        return self


# ----------------------------------------------------------------- operation inputs


class DescribeSchemaInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ValidateSqlInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str = Field(min_length=1, max_length=20000)
    max_rows: int = Field(default=200, ge=1, le=1000)


class QueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str | None = Field(default=None, min_length=1, max_length=4000)
    sql: str | None = Field(default=None, min_length=1, max_length=20000)
    max_rows: int = Field(default=200, ge=1, le=1000)

    @model_validator(mode="after")
    def _exactly_one_source(self) -> QueryInput:
        if (self.question is None) == (self.sql is None):
            raise ValueError("Provide exactly one of question or sql.")
        return self


class _OperationFailure(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: Status = "error",
        retryable: bool = False,
        details: dict[str, Any] | None = None,
        policy: PolicyDecision | None = None,
        execution_mode: ExecutionMode = "deterministic_offline",
    ) -> None:
        super().__init__(message)
        self.error = ContractError(
            code=code, message=message[:2000], retryable=retryable, details=details or {}
        )
        self.status = status
        self.policy = policy
        self.execution_mode = execution_mode


class _Outcome(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    data: Any
    execution_mode: ExecutionMode = "deterministic_offline"
    provenance: list[Provenance] = Field(default_factory=list)
    policy: PolicyDecision | None = None


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return "hex:" + value.hex()
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def _copilot(max_rows: int = 200, planner=None):
    try:
        return build_copilot(max_rows, planner=planner)
    except LookupError as error:
        raise _OperationFailure("NOT_CONFIGURED", str(error)) from error
    except RuntimeError as error:
        raise _OperationFailure("CONFIGURATION_ERROR", str(error)) from error


def _blocked(error: Exception, mode: ExecutionMode) -> _OperationFailure:
    reasons = list(failure_reasons(error))
    return _OperationFailure(
        "POLICY_DENIED",
        "Query refused by policy.",
        status="blocked",
        details={"stage": failure_stage(error), "reasons": reasons},
        policy=PolicyDecision(decision="deny", reasons=reasons),
        execution_mode=mode,
    )


# ----------------------------------------------------------------- operations


def _describe_schema(_: DescribeSchemaInput) -> _Outcome:
    copilot = _copilot()
    try:
        tables = copilot.visible_schema()
    except sqlite3.Error as error:
        raise _OperationFailure(
            "QUERY_FAILED", f"Schema introspection failed: {type(error).__name__}"
        ) from error
    policy = copilot.access_policy
    guarded = (
        sorted(
            table.name
            for table in tables
            if table.name.casefold()
            in {name.casefold() for name in policy.require_where_for_tables}
        )
        if policy is not None
        else []
    )
    data = {
        "tables": [
            {
                "name": table.name,
                "columns": [
                    {"name": column.name, "type": column.type, "nullable": column.nullable}
                    for column in table.columns
                ],
            }
            for table in tables
        ],
        "guarded_tables": guarded,
        "access_policy_configured": access_policy_configured(),
    }
    return _Outcome(
        data=data,
        provenance=[
            Provenance(
                kind="dataset",
                id="sqlite:authorized-schema",
                sha256=_canonical_sha256(data["tables"]),
            )
        ],
    )


def _validate_sql(payload: ValidateSqlInput) -> _Outcome:
    copilot = _copilot(payload.max_rows)
    try:
        decision = copilot.validate_sql(payload.sql)
    except sqlite3.Error as error:
        raise _OperationFailure(
            "QUERY_FAILED", f"SQL could not be compiled: {type(error).__name__}"
        ) from error
    except QueryTimeoutError as error:
        raise _OperationFailure("QUERY_TIMEOUT", str(error)) from error
    data = {
        "allowed": decision.allowed,
        "stage": decision.stage,
        "reasons": list(decision.reasons),
        "sql_fingerprint": decision.sql_fingerprint,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "risk_factors": list(decision.risk_factors),
        "complexity_score": decision.complexity_score,
    }
    return _Outcome(
        data=data,
        provenance=[
            Provenance(kind="query", id="submitted-sql", sha256=_sha256_text(payload.sql))
        ],
        policy=PolicyDecision(
            decision="allow" if decision.allowed else "deny", reasons=list(decision.reasons)
        ),
    )


def _query(payload: QueryInput) -> _Outcome:
    planner = None
    mode: ExecutionMode = "deterministic_offline"
    if payload.question is not None:
        try:
            planner = build_planner()
        except RuntimeError as error:
            raise _OperationFailure("CONFIGURATION_ERROR", str(error)) from error
        mode = planner_execution_mode(planner)  # type: ignore[assignment]
    copilot = _copilot(payload.max_rows, planner)
    try:
        if payload.sql is not None:
            result = copilot.query_sql(payload.sql)
        else:
            result = copilot.ask(payload.question or "")
    except POLICY_ERRORS as error:
        raise _blocked(error, mode) from error
    except QueryTimeoutError as error:
        raise _OperationFailure("QUERY_TIMEOUT", str(error), execution_mode=mode) from error
    except sqlite3.Error as error:
        raise _OperationFailure(
            "QUERY_FAILED",
            f"Database query could not be completed: {type(error).__name__}",
            execution_mode=mode,
        ) from error
    except ValueError as error:
        raise _OperationFailure("PLANNING_FAILED", str(error), execution_mode=mode) from error
    except OSError as error:
        raise _OperationFailure(
            "PLANNING_FAILED",
            f"Planner request failed: {type(error).__name__}",
            retryable=True,
            execution_mode=mode,
        ) from error

    rows = [{key: _json_value(value) for key, value in row.items()} for row in result.rows]
    data = {
        "columns": result.audit.columns,
        "rows": rows,
        "row_count": result.audit.row_count,
        "audit_event_id": result.audit.event_id,
        "executed_sql_sha256": _sha256_text(result.audit.sql),
        "risk_score": result.audit.risk_score,
        "risk_level": result.audit.risk_level,
        "complexity_score": result.audit.complexity_score,
        "planner_rationale": result.plan.rationale,
        "insights": result.insights,
    }
    provenance = [
        Provenance(kind="query", id="executed-sql", sha256=_sha256_text(result.audit.sql)),
        Provenance(kind="record", id=f"audit:{result.audit.event_id}"),
    ]
    return _Outcome(
        data=data,
        execution_mode=mode,
        provenance=provenance,
        policy=PolicyDecision(decision="allow", reasons=[]),
    )


_OPERATIONS: dict[str, tuple[type[BaseModel], Callable[[Any], _Outcome], str]] = {
    "describe_schema": (
        DescribeSchemaInput,
        _describe_schema,
        "Tables and columns the server policy allows callers and planners to see.",
    ),
    "validate_sql": (
        ValidateSqlInput,
        _validate_sql,
        ("Policy decision for untrusted SQL: AST authorization, budgets, safety and the "
        "SQLite authorizer at compile time (EXPLAIN); no rows are read."),
    ),
    "query": (
        QueryInput,
        _query,
        ("Read-only execution of a question (server planner) or untrusted SQL, returning "
        "bounded rows and the audit event id."),
    ),
}


def _package_version() -> str:
    try:
        return metadata.version("secure-data-copilot")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def capabilities() -> dict[str, Any]:
    query_timeout = 3 * DEFAULT_TIMEOUT_SECONDS
    try:
        planner = build_planner()
    except RuntimeError:
        planner = None
    if planner is not None:
        query_timeout += planner.timeout_seconds
    timeouts = {
        "describe_schema": DEFAULT_TIMEOUT_SECONDS,
        "validate_sql": 2 * DEFAULT_TIMEOUT_SECONDS,
        "query": query_timeout,
    }
    return {
        "contract_version": CONTRACT_VERSION,
        "system": SYSTEM,
        "version": _package_version(),
        "operations": [
            {
                "name": name,
                "description": description,
                "side_effects": False,
                "requires_approval": False,
                "input_schema": model.model_json_schema(),
                "timeout_s": math.ceil(timeouts[name]),
            }
            for name, (model, _, description) in _OPERATIONS.items()
        ],
    }


def _valid_id(value: str | None) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128


def run_operation(
    operation: str,
    payload: dict[str, Any] | None,
    *,
    run_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Execute one makma.v1 operation and return the envelope as plain JSON data."""

    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    started = perf_counter()
    caller_ids_valid = (run_id is None or _valid_id(run_id)) and (
        correlation_id is None or _valid_id(correlation_id)
    )
    resolved_run_id = run_id if run_id is not None and _valid_id(run_id) else uuid.uuid4().hex
    resolved_correlation = (
        correlation_id
        if correlation_id is not None and _valid_id(correlation_id)
        else resolved_run_id
    )
    name = operation if isinstance(operation, str) else ""
    envelope_operation = name if _OPERATION_NAME.match(name) else "unknown"

    status: Status = "ok"
    data: Any = None
    error: ContractError | None = None
    provenance: list[Provenance] = []
    policy: PolicyDecision | None = None
    mode: ExecutionMode = "deterministic_offline"

    try:
        if not caller_ids_valid:
            raise _OperationFailure(
                "INVALID_INPUT", "run_id and correlation_id must be 1 to 128 characters."
            )
        if name not in _OPERATIONS:
            raise _OperationFailure("UNKNOWN_OPERATION", "Unknown operation.")
        model, handler, _ = _OPERATIONS[name]
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise _OperationFailure("INVALID_INPUT", "Payload must be a JSON object.")
        try:
            parsed = model.model_validate(payload)
        except ValidationError as validation_error:
            raise _OperationFailure(
                "INVALID_INPUT",
                "Payload failed validation.",
                details={
                    "errors": [
                        {"loc": [str(part) for part in item["loc"]], "msg": item["msg"]}
                        for item in validation_error.errors()
                    ]
                },
            ) from validation_error
        outcome = handler(parsed)
        data = outcome.data
        provenance = outcome.provenance
        policy = outcome.policy
        mode = outcome.execution_mode
    except _OperationFailure as failure:
        status = failure.status
        error = failure.error
        policy = failure.policy
        mode = failure.execution_mode
        data = None
    except Exception as unexpected:  # noqa: BLE001 - the envelope must always be returned
        status = "error"
        error = ContractError(
            code="INTERNAL_ERROR",
            message=f"Unexpected {type(unexpected).__name__}.",
        )
        data = None

    envelope = Envelope(
        operation=envelope_operation,
        run_id=resolved_run_id,
        correlation_id=resolved_correlation,
        trace_id=uuid.uuid4().hex,
        span_id=secrets.token_hex(8),
        status=status,
        execution_mode=mode,
        data=data,
        error=error,
        provenance=provenance,
        policy=policy,
        started_at=started_at,
        duration_ms=max(0.0, (perf_counter() - started) * 1000),
    )
    return envelope.model_dump(mode="json")


_HTTP_STATUS = {
    "UNKNOWN_OPERATION": 404,
    "INVALID_INPUT": 422,
    "NOT_CONFIGURED": 503,
    "CONFIGURATION_ERROR": 503,
    "QUERY_TIMEOUT": 408,
    "INTERNAL_ERROR": 500,
}


def http_status_for(envelope: dict[str, Any]) -> int:
    if envelope["status"] == "ok":
        return 200
    if envelope["status"] == "blocked":
        return 403
    return _HTTP_STATUS.get((envelope.get("error") or {}).get("code", ""), 400)
