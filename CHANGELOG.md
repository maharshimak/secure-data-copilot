# Changelog

All notable engineering changes to this repository are documented here.

The format follows the intent of [Keep a Changelog](https://keepachangelog.com/) and uses semantic versioning principles where releases are created.

## [Unreleased]

### Security
- SQLite authorizer (`sqlite_guard.py`) enforces table, column and function allow-lists at compile time and denies all other actions.
- Fixed: `rowid`/`_rowid_`/`oid` returned a denied `INTEGER PRIMARY KEY` column.
- Fixed: `sqlite_master`, `sqlite_schema` and `pragma_*` table-valued functions (including the database file path) were readable when no policy was configured.
- Fixed: `randomblob`/`zeroblob`/`printf` could materialize values of hundreds of megabytes; values are now capped at 1,000,000 bytes and results at 8 MiB.
- Fixed: CTE column lists (`WITH t(a, b) AS ...`) were silently dropped by SQL canonicalization, changing query results; they are now refused.
- `COUNT(*)` is no longer rejected when columns are denied; `NATURAL`/`USING` joins are refused when column access is restricted.
- Column allow-lists (`AccessPolicy.allowed_columns`, `COPILOT_ALLOWED_COLUMNS`).
- Audit events record allow/deny/error decisions with stage and reasons; `COPILOT_AUDIT_LOG_PATH` wires the JSONL store into the API.

### Contract
- `makma.v1` operations `describe_schema`, `validate_sql` and `query` via `data_copilot.contracts`, `GET /v1/capabilities` and `POST /v1/ops/{operation}`.

### Engineering
- Added repository ownership and structured contribution workflows.
- Added Dependabot coverage for Python and GitHub Actions dependencies.
- Added issue and pull-request templates focused on reproducibility, validation, risk, and rollback.
- Added consistent editor configuration and engineering standards.

## Release policy

A release should describe user-visible behavior, compatibility notes, validation evidence, and any migration or rollback requirements. Repository history remains the source of truth for individual commits.
