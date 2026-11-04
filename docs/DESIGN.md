# Design and operating boundaries

Local read-only SQLite analytics with deterministic planning, SQL restrictions, bounded results and query audit metadata.

## Scope

SQL policy is parsed before execution. SQLite resolves and reauthorizes table, column and function access inside a read-only connection with a progress deadline. Server-owned temporary views enforce an optional deployment-wide text scope on every allowed base table. API callers and model planners receive only the authorized schema. Bearer authentication is shared, so per-tenant ownership requires a separate identity boundary. The configured JSONL audit store records decisions with redacted diagnostics.

## Interfaces

Implementation lives in `src/data_copilot/`. Public examples in the README use its Python API. FastAPI exposes the same local capabilities; `/openapi.json` is the endpoint schema.

## Validation

Tests include synthetic regression fixtures. Package and container checks verify installation separately from source-tree imports. Tests do not certify general model quality, clinical correctness or multi-tenant isolation.

## Planned evolution

Authenticated tenant selection, database-native row-level security and a PostgreSQL adapter.
