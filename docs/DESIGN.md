# Design and operating boundaries

Local read-only SQLite analytics with deterministic planning, SQL restrictions, bounded results and query audit metadata.

## Scope

SQL policy is conservative lexical filtering, not a complete SQL parser. SQLite read-only/query-only modes provide an additional mutation boundary; query progress has a two-second deadline, not a full memory sandbox. The API uses only the server-configured database path. It has no authentication or row/column authorization and must remain local or behind an access-controlled gateway. Planner templates target a small demo schema, not arbitrary business reasoning. Query audit metadata is returned; the optional JSONL audit utility is not wired into the request path.

## Interfaces

Implementation lives in `src/data_copilot/`. Public examples in the README use its Python API. FastAPI exposes the same local capabilities; `/openapi.json` is the endpoint schema.

## Validation

Tests include synthetic regression fixtures. Package and container checks verify installation separately from source-tree imports. Tests do not certify general model quality, clinical correctness or multi-tenant isolation.

## Planned evolution

AST-based validation; database roles and row/column authorization; authenticated dataset selection; persistent audit wiring; PostgreSQL adapter.
