import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One query decision. Never contains result values or the raw SQL text.

    ``decision`` is ``allow`` when rows were returned, ``deny`` when a policy,
    safety, budget or execution-guard check refused the query and ``error`` when the
    query was authorized but failed (for example a timeout).
    """

    event_id: str
    timestamp: str
    question: str
    sql_fingerprint: str
    duration_ms: float
    row_count: int
    decision: str = "allow"
    reasons: tuple[str, ...] = ()
    stage: str = "execute"


def sql_fingerprint(sql: str) -> str:
    normalized = " ".join(sql.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def build_event(
    *,
    question: str,
    sql: str,
    duration_ms: float,
    row_count: int,
    decision: str = "allow",
    reasons: tuple[str, ...] = (),
    stage: str = "execute",
) -> AuditEvent:
    if decision not in {"allow", "deny", "error"}:
        raise ValueError("decision must be allow, deny or error")
    timestamp = datetime.now(UTC).isoformat()
    fingerprint = sql_fingerprint(sql) if sql else ""
    # A random component keeps identifiers unique for identical queries issued
    # within the same clock tick.
    event_id = hashlib.sha256(
        f"{timestamp}:{fingerprint}:{secrets.token_hex(8)}".encode()
    ).hexdigest()[:20]
    return AuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        question=question,
        sql_fingerprint=fingerprint,
        duration_ms=duration_ms,
        row_count=row_count,
        decision=decision,
        reasons=tuple(reasons),
        stage=stage,
    )


class JsonlAuditStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
