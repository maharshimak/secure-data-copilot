# 🔐 Secure Data Copilot

**A MAK'MA Studio Product · MAK'MA Labs**

[Live Product Demo](https://maharshimak.github.io/makma-ai-os/projects/secure-data-copilot/) · [MAK'MA Labs](https://maharshimak.github.io/makma-ai-os/projects/)

A local **read-only analytics copilot** for relational data. The system is designed around a strict rule: an AI assistant may help reason over business data, but it must not silently gain write access to the database.


## Product contract — engineering upgrade

**Problem and audience:** A safe local analytics workspace for engineers inspecting how questions become bounded business-data queries.

**Live tool:** https://maharshimak.github.io/makma-ai-os/projects/secure-data-copilot/

**Implemented browser workflow:** Editable synthetic customers/orders, supported natural-language question templates, schema privacy findings with reasons, read-only query inspection, risk budget, computed rows/statistics and CSV/JSON export. Mutation intent is rejected before planning.

**Backend and parity contract:** Browser executes a structured deterministic local query plan, NOT the displayed SQL. Python parses SQLite SQL with `sqlglot`, requires exactly one read-only query expression, rejects forbidden AST operations/functions, wraps the result with an outer row limit, and executes through a native read-only/query-only SQLite connection. The planner remains deterministic and returns confidence=None because its rules do not produce calibrated probabilities. CSV cells beginning with formula characters are neutralized.

**Architecture:** `makma-ai-os/demo` is the shared web product source and Pages deployment. This repository owns its Python domain package. The central `tests/e2e` suite exercises all nine products; `tests/fixtures/python-parity.json` plus `scripts/generate_parity.py` guard shared mathematical contracts. Backend revisions used for regeneration are pinned in the central `backend-lock.json`.

**Safety and limitations:** Four browser query families, in-memory data, column-name privacy heuristics and no general language-to-SQL model. Browser permits at most 1000 customers and 10000 orders. Authentication and multi-tenant data governance are not implemented. Inputs are validated, rendered user values are escaped, and deterministic results are not presented as model inference.

**Verification:** Run `python -m ruff check .` and `python -m pytest -q`. `tests/test_engineering_upgrade.py` protects the new rejection/correctness paths. Central web checks: `npm ci`, `npm test`, `npm run build`, `npx playwright install --with-deps chromium`, `npm run test:e2e`. CI gates publishing on browser interactions and validates all public URLs after deployment.

**Highest-value next work:** Richer schema-aware planning, row/column authorization, persistent audit wiring and query-cost limits.

**Provenance:** Independent MAK’MA Studio engineering implementation; examples are synthetic and no employer code or data is included. Existing MIT license applies.


## Implemented

- schema introspection for SQLite
- parsed read-only SQL AST policy engine using `sqlglot`
- multi-statement blocking
- row-limit enforcement
- query audit metadata
- typed query plans
- deterministic local planner baseline
- execution timing
- automatic numeric summaries
- FastAPI service
- tests
- Docker

## Architecture

```mermaid
flowchart LR
U[User Question] --> P[Planner]
P --> V[SQL Policy Validator]
V -->|allowed| E[Read-only Executor]
V -->|blocked| B[Safety Response]
E --> D[(SQL Database)]
D --> R[Result Set]
R --> I[Insight Generator]
I --> A[Answer + Audit Metadata]
```

## Why this project matters

Many "chat with your database" demos give a model a database connection and hope for the best. This project instead separates **planning, policy, execution, observation and interpretation**.

The included planner is deterministic so the repository works offline and its tests are reproducible. A model-backed planner can later implement the same contract without weakening the safety boundary.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python examples/bootstrap_demo.py
export COPILOT_DATABASE_PATH=examples/demo.db
uvicorn data_copilot.api:app --reload
```

Open `http://localhost:8000/docs`.

## Example

```json
{
  "question": "show the top customers by revenue"
}
```

## Security model

Only `SELECT` and `WITH ... SELECT` queries are accepted. Write, DDL, privileged, multi-statement and oversized queries are blocked before execution. SQLite is also opened in native read-only mode.

This is defense in depth, not a claim that AST validation alone is a complete SQL sandbox. The parser boundary is combined with SQLite native read-only/query-only mode, a progress deadline and a bounded outer result. A production PostgreSQL version should additionally use a dedicated least-privilege database role and row/column authorization.

## Roadmap

- structured LLM planner adapter
- PostgreSQL adapter
- semantic business metrics layer
- row/column-level authorization
- chart specifications
- query-result caching
- OpenTelemetry traces

## Scope and limitations

SQL policy is parsed with `sqlglot` and rejects non-query statements, forbidden administrative/write nodes and dangerous SQLite file/extension functions. SQLite read-only/query-only modes provide an additional mutation boundary; query progress has a two-second deadline, not a full memory sandbox. The API uses only the server-configured database path. It has no authentication or row/column authorization and must remain local or behind an access-controlled gateway. Planner templates still target a small demo schema rather than arbitrary business reasoning. Query audit metadata is returned; the optional JSONL audit utility is not wired into the request path.

## Installation and development

Requires Python 3.12 or newer. Run from this project directory.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m pip wheel --no-deps . -w dist
```

On Windows, activate with `.venv\Scripts\Activate.ps1`.

## Library usage

```python
from data_copilot import DataCopilot
result = DataCopilot("examples/demo.db", max_rows=20).ask("top customers by revenue")
print(result.rows)
print(result.audit)
```

Run `python examples/bootstrap_demo.py` first to create the synthetic database.

## Configuration

See [.env.example](.env.example). Export variables into the process environment; the application does not automatically load that file. Keep real credentials out of Git.

## Service and API schema

```bash
python -m uvicorn data_copilot.api:app --host 127.0.0.1 --port 8000
```

Interactive endpoint schemas are at `http://127.0.0.1:8000/docs`; machine-readable schemas are at `/openapi.json`. These APIs have no built-in authentication. Use trusted local data and local access.

## Container

```bash
docker build -t secure-data-copilot .
docker run --rm -p 127.0.0.1:8000:8000 secure-data-copilot
```

The service returns 503 until a database is configured. Mount a synthetic database read-only and set `COPILOT_DATABASE_PATH` to its container path, for example `-v "$PWD/examples/demo.db:/data/demo.db:ro" -e COPILOT_DATABASE_PATH=/data/demo.db`.

## Repository structure

| Path | Purpose |
| --- | --- |
| `src/data_copilot/` | Implementation |
| `tests/` | Offline unit and regression tests |
| `docs/DESIGN.md` | Architecture and trust boundaries |
| `.github/workflows/ci.yml` | Install, lint, tests, wheel and container build |
| `pyproject.toml` | Dependencies and package configuration |

## Next engineering work

Schema-aware structured model planning; database roles and row/column authorization; authenticated dataset selection; persistent audit wiring; PostgreSQL adapter; query-cost estimation. These are planned work, not current capabilities.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). CI runs on every push and pull request through `.github/workflows/ci.yml`.

## License and provenance

[MIT](LICENSE), copyright 2026 Maharshi Patel. This public portfolio implementation is independent of employer systems and contains no confidential employer code or data. Examples and test fixtures are synthetic.
