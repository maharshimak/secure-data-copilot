# Security design

The project uses three layers of protection:

1. application-level SQL validation;
2. forced row budgets;
3. a SQLite connection opened in read-only mode.

A production PostgreSQL deployment should additionally use a dedicated database role with only the minimum SELECT privileges required for the authorized schemas.

String-level validation is not a complete substitute for parsing a SQL AST. A production version should validate a dialect-aware AST and still execute under database-native least privilege.
