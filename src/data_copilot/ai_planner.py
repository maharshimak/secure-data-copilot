from __future__ import annotations

import json
from dataclasses import dataclass
from urllib import request

from data_copilot.models import QueryPlan, TableInfo


def _schema_payload(schema: list[TableInfo]) -> list[dict[str, object]]:
    return [
        {
            "table": table.name,
            "columns": [
                {
                    "name": column.name,
                    "type": column.type,
                    "nullable": column.nullable,
                }
                for column in table.columns
            ],
        }
        for table in schema
    ]


@dataclass(slots=True)
class OpenAICompatiblePlanner:
    """Model-backed planner that proposes SQL but never executes it directly."""

    base_url: str
    model: str
    api_key: str = ""
    timeout_seconds: float = 45.0
    temperature: float = 0.0

    def __post_init__(self) -> None:
        if not self.base_url.strip() or not self.model.strip():
            raise ValueError("base_url and model are required")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def plan(self, question: str, schema: list[TableInfo]) -> QueryPlan:
        if not isinstance(question, str) or not question.strip() or len(question) > 4000:
            raise ValueError("A question of 1 to 4000 characters is required.")
        if not schema:
            raise ValueError("Database schema is empty.")

        system = (
            "You are a SQL planning component. Produce exactly one JSON object with keys "
            "sql and rationale. Use only the supplied SQLite schema. The SQL must be a "
            "single read-only SELECT or WITH...SELECT statement. Never use INSERT, UPDATE, "
            "DELETE, DDL, PRAGMA, ATTACH, DETACH, filesystem functions, extensions, or "
            "multiple statements. Do not invent tables or columns. Do not include markdown."
        )
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"question": question, "schema": _schema_payload(schema)},
                        ensure_ascii=False,
                    ),
                },
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        endpoint = self.base_url.rstrip("/") + "/chat/completions"
        req = request.Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read().decode())

        data = json.loads(str(body["choices"][0]["message"]["content"]).strip())
        sql = str(data.get("sql", "")).strip()
        rationale = str(data.get("rationale", "")).strip()
        if not sql or not rationale:
            raise ValueError("Planner response must contain non-empty sql and rationale.")

        return QueryPlan(
            question=question,
            sql=sql,
            rationale=rationale,
            confidence=None,
        )
