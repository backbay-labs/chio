# Chiodos 6.11 Shadow

The next room is relay observability and dashboarding over the hardened static directory lifecycle.

Candidate scope:

- Operator dashboards for directory freshness, removed-peer quarantine, outbox pressure, catch-up pressure, replay conflicts, stale leases, and dead letters.
- Report aggregation over the existing relay health, drill, tick, and operator report schemas.
- Alert threshold recommendations with bounded metric labels.
- Runbook drill summaries that can be reviewed without reading raw SQLite state.

Non-goals remain dynamic trust, peer crawling, pheromone-driven authority decisions, hidden predicates, VC DI BBS, zkVM, FROST, settlement, new transports, and multi-region HA.
