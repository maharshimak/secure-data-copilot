import os
import secrets
import sqlite3
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from data_copilot.config import (
    access_policy_configured,
    build_access_policy,
    build_audit_store,
    build_planner,
)
from data_copilot.contracts import capabilities, http_status_for, run_operation
from data_copilot.executor import DataCopilot
from data_copilot.safety import UnsafeQueryError

__all__ = ["app", "build_access_policy", "build_planner"]

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
    host_header = request.headers.get("host", "").casefold()
    local_host = (
        host_header in {"localhost", "127.0.0.1", "[::1]", "testserver"}
        or host_header.startswith(("localhost:", "127.0.0.1:", "[::1]:"))
    )
    if (
        client_host not in {"127.0.0.1", "::1", "localhost", "testclient"}
        or not local_host
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Remote access requires COPILOT_API_TOKEN.",
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
        "access_policy_configured": access_policy_configured(),
    }


@app.post("/v1/ask", dependencies=protected)
def ask(request: AskRequest) -> dict[str, object]:
    database_path = os.environ.get("COPILOT_DATABASE_PATH")
    if not database_path:
        raise HTTPException(status_code=503, detail="No server database configured.")
    try:
        planner = build_planner()
        access_policy = build_access_policy()
        # Bearer-authenticated deployments must explicitly restrict database tables,
        # regardless of whether planning is deterministic or model-backed.
        if os.environ.get("COPILOT_API_TOKEN") and (
            access_policy is None or not access_policy.allowed_tables
        ):
            raise RuntimeError(
                "Bearer-authenticated access requires COPILOT_ALLOWED_TABLES."
            )
        if planner is not None and (
            access_policy is None or not access_policy.allowed_tables
        ):
            raise RuntimeError(
                "Model-backed planning requires COPILOT_ALLOWED_TABLES so unauthorized "
                "schema metadata is never disclosed to the model provider."
            )
        result = DataCopilot(
            database_path=database_path,
            max_rows=request.max_rows,
            planner=planner,
            access_policy=access_policy,
            audit_store=build_audit_store(),
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


@app.get("/v1/capabilities", dependencies=protected)
def get_capabilities() -> dict[str, object]:
    return capabilities()


@app.post("/v1/ops/{operation}", dependencies=protected)
def post_operation(
    operation: str,
    payload: Annotated[dict[str, Any] | None, Body()] = None,
    x_correlation_id: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    envelope = run_operation(operation, payload or {}, correlation_id=x_correlation_id)
    return JSONResponse(status_code=http_status_for(envelope), content=envelope)
