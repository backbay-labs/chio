# chio-metering

`chio-metering` provides receipt metering and economics for the Chio protocol:
per-receipt cost attribution (compute time, data volume, API cost), cumulative
cost queries by session, agent, tool, or time range, monetary budget
enforcement via `chio-link` oracle integration, and billing-export-compatible
cost metadata.

Use this crate when you need to attribute cost to receipts, enforce monetary
budgets, or export billing data for metered tool access.
