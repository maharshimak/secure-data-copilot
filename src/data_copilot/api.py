import os
import secrets
import sqlite3
from dataclasses import asdict

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from data_copilot.ai_planner import OpenAICompatiblePlanner
from data_copilot.executor import DataCopilot
from data_copilot.safety import UnsafeQueryError


app = FastAPI(
    title="Secure Data Copilot",
    version="0.2.0",
    description=(
        "Read-only analytics copilot with SQL AST enforcement, database query-only mode, "
        "optional model-backed planning and bearer-protected remote access."
    ),
)


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=4000)
    max_rows: int = Field(default=200, ge=1, le=1000)


async def require_auth(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    token = os.environ.get("COPILOT_API_TOKEN")
    if token:
        scheme, _, supplied = (authorization or "").partition(" ")
        if (
            scheme.lower() != "bearer"
            or not supplied
            or not secrets.compare_digest(supplied, token)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid bearer token required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return

    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Remote access requires COPILOT_API_TOKEN.",
        )


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


protected = [Depends(require_auth)]


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "planner": (
            "model"
            if os.environ.get("COPILOT_MODEL_BASE_URL")
            and os.environ.get("COPILOT_MODEL")
            else "deterministic"
        ),
    }


@app.post("/v1/ask", dependencies=protected)
def ask(request: AskRequest) -> dict[str, object]:
    database_path = os.environ.get("COPILOT_DATABASE_PATH")
    if not database_path:
        raise HTTPException(status_code=503, detail="No server database configured.")
    try:
        planner = build_planner()
        result = DataCopilot(
            database_path=database_path,
            max_rows=request.max_rows,
            planner=planner,
        ).ask(request.question)
        return asdict(result)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except (ValueError, UnsafeQueryError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=400,
            detail="Database query could not be completed.",
        ) from error
