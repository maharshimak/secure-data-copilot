# Production engineering

The copilot already enforces read-only SQL and outer row limits. `data_copilot.risk` adds a second, explainable query-complexity budget.

Risk scoring flags wildcard projections, join-heavy queries, cross joins, unions, nested queries, comments, random ordering and CTEs. `enforce_query_budget` first applies the hard read-only safety gate, then rejects queries that exceed the configured complexity score.

## Operational practice

- Keep read-only database credentials at the database layer; SQL parsing is defense in depth, not the only control.
- Set conservative execution timeouts and row limits.
- Record risk factors in the audit log without storing credentials.
- Use per-dataset risk thresholds for expensive warehouses.
