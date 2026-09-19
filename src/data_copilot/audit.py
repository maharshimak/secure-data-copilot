import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    timestamp: str
    question: str
    sql_fingerprint: str
    duration_ms: float
    row_count: int


def sql_fingerprint(sql: str) -> str:
    normalized = " ".join(sql.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def build_event(
    *,
    question: str,
    sql: str,
    duration_ms: float,
    row_count: int,
) -> AuditEvent:
    timestamp = datetime.now(UTC).isoformat()
    fingerprint = sql_fingerprint(sql)
    event_id = hashlib.sha256(f"{timestamp}:{fingerprint}".encode()).hexdigest()[:20]
    return AuditEvent(
        event_id=event_id,
        timestamp=timestamp,
        question=question,
        sql_fingerprint=fingerprint,
        duration_ms=duration_ms,
        row_count=row_count,
    )


class JsonlAuditStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
