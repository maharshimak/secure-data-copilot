# Security

SQL policy is parsed with `sqlglot` and enforced again by a SQLite authorizer callback at compile time, inside a read-only/query-only connection with tightened SQLite limits, a two-second progress deadline and a result byte budget (see the Security model section of the README). This is defense in depth, not a complete sandbox or a memory isolation boundary. The API uses only the server-configured database path, is local-only by default and supports a single shared bearer token for remote access; it has no per-user identity or row-level security. Planner templates target a small demo schema, not arbitrary business reasoning. Audit records are written only when `COPILOT_AUDIT_LOG_PATH` is set.

Use synthetic or explicitly authorized public data. Do not commit API keys, databases, model credentials, patient records or private employer material. Remote model adapters transmit supplied text to the configured endpoint; choose the provider deliberately.

For a suspected vulnerability, use GitHub private vulnerability reporting if enabled. Otherwise contact the maintainer privately through the [portfolio](https://maharshipatel-portfolio.vercel.app/). Do not put secrets or exploit payloads containing private data in a public issue. No response SLA is promised.
