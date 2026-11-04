# Security

SQL policy is parsed with `sqlglot` and enforced at compilation by a SQLite authorizer. The connection uses read-only mode, query-only mode, tightened limits and a progress deadline. A configured server scope filters each allowed base table through a temporary view before rows become available to caller SQL. Bearer-protected database access requires an explicit table allowlist. The shared token grants access to a single configured security domain. Authenticated per-tenant ownership remains a prerequisite for shared multi-tenant deployments.

Use synthetic or explicitly authorized public data. Do not commit API keys, databases, model credentials, patient records or private employer material. Remote model adapters transmit supplied text to the configured endpoint; choose the provider deliberately.

For a suspected vulnerability, use GitHub private vulnerability reporting if enabled. Otherwise contact the maintainer privately through the [portfolio](https://maharshipatel-portfolio.vercel.app/). Do not put secrets or exploit payloads containing private data in a public issue. No response SLA is promised.
