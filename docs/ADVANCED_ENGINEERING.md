# Advanced engineering: schema privacy scanning

`data_copilot.privacy` adds a pre-query privacy signal based on schema metadata.

The scanner classifies suspicious column names into credential, government identifier, financial,
contact, location and health categories, assigns transparent severity levels and exposes an additive
risk score.

This is intentionally a schema-name heuristic, not a guarantee that data is or is not personal
information. A production deployment should combine it with catalog classifications, access policy
and value-level discovery. Its purpose here is to make privacy-aware query planning explicit and
testable before SQL execution.
