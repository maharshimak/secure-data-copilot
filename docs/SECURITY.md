# Security design

The project uses these layers of protection (details in the README "Security model" section):

1. AST-level table/column authorization and SQL safety checks (`sqlglot`);
2. structural complexity and lexical risk budgets;
3. a forced outer row limit and a result byte budget;
4. a SQLite authorizer callback that re-checks every resolved table, column and function at compile time and denies anything not explicitly allowed;
5. a SQLite connection opened with `mode=ro`, `PRAGMA query_only`, `trusted_schema=OFF`, defensive mode, no attached databases, tightened length limits and a progress-handler deadline.

A production PostgreSQL deployment should additionally use a dedicated database role with only the minimum SELECT privileges required for the authorized schemas.

AST validation alone is not a complete SQL sandbox, which is why the authorizer and connection limits exist. A production version should still execute under database-native least privilege and row-level security.
