# Security

SQL policy is conservative lexical filtering, not a complete SQL parser. SQLite read-only/query-only modes provide an additional mutation boundary; query progress has a two-second deadline, not a full memory sandbox. The API uses only the server-configured database path. It has no authentication or row/column authorization and must remain local or behind an access-controlled gateway. Planner templates target a small demo schema, not arbitrary business reasoning. Query audit metadata is returned; the optional JSONL audit utility is not wired into the request path.

Use synthetic or explicitly authorized public data. Do not commit API keys, databases, model credentials, patient records or private employer material. Remote model adapters transmit supplied text to the configured endpoint; choose the provider deliberately.

For a suspected vulnerability, use GitHub private vulnerability reporting if enabled. Otherwise contact the maintainer privately through the [portfolio](https://maharshipatel-portfolio.vercel.app/). Do not put secrets or exploit payloads containing private data in a public issue. No response SLA is promised.
