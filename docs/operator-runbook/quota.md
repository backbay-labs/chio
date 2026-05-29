# Healthcare Pilot Quota Lane

This page records quota lane sizing for the healthcare design-partner pilot. Capacity evidence is maintained under `compliance/hitrust/`
(see `compliance/hitrust/control-mapping.csv` for the per-control mapping).

## Bound

The quota lane honors BOUNDED_OPERATIONAL_PROFILE. Monetary budgets remain
single-node atomic on one SQLite store. The pilot does not claim
distributed-linearizable budget enforcement.

## Baseline

The P0 planning baseline is 25,000 receipts/day. P2 replayed that baseline at:

- 1x baseline
- 2x replay
- 5x replay

The 5x replay row stayed inside the P1 SLO envelope with p95 under 250 ms,
p99 under 1 s, and exporter backpressure under 250 ms.

## Sizing Rule

Provision the pilot for 5x replayed baseline and no more:

| Lane | Daily receipts | Purpose |
|------|----------------|---------|
| 1x | 25,000 | Normal shadow or production operating baseline. |
| 2x | 50,000 | Expected burst headroom. |
| 5x | 125,000 | Maximum tested headroom. |

Do not silently promote the lane above 5x. A spike above 5x is a P1 incident
per `docs/operator-runbook/incidents.md`, not a larger release claim.

## Budget Store

Budget state stays in the tenant-local SQLite budget database configured by:

```bash
chio trust serve --budget-db /var/lib/chio/healthcare-pilot/budgets.sqlite
```

The operator must not split this store across writers. If lock contention or
write latency threatens p99 mediation, fail closed and open a P1.

## Operational Checks

Before cutover:

1. Confirm the budget database path is tenant-local.
2. Confirm one writer owns budget state.
3. Replay the 1x / 2x / 5x report after any policy change that alters budget
   checks.
4. Confirm receipt-write errors stay under 0.1%.
5. Confirm p95 mediation stays under 250 ms at 5x.
6. Confirm p99 mediation stays under 1 s at 5x.

## Incident Boundary

Open P1 when:

- Traffic exceeds 5x replayed baseline for more than 15 minutes.
- SQLite budget lock contention causes p99 mediation over 1 s.
- Receipt persistence fails because budget evaluation blocks.
- Budget state appears to have two active writers.

Open P0 if a budget, policy, or receipt failure allows a tool call that should
have been denied.
