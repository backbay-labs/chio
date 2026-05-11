# Relay Observability

The canonical relay observability report is the first operator view for the pheromone relay. It is read-only and aggregates verifier-owned directory state plus durable local relay evidence.

## Report Flow

1. Run `chio chiodos pheromone relay observe`.
2. Check `accepted`, `code`, and `recommendations`.
3. Inspect bounded event reports from `--report-dir` only when a recommendation needs evidence.
4. Export `chio chiodos pheromone relay metrics --format prometheus` for alerting.
5. Use raw SQLite inspection only after the report and bounded event files have narrowed the incident.

## Bounded Metrics

Prometheus labels are limited to:

- `status` for queue depth.
- `reason` for bounded rejection and dead-letter classes.

Do not use peer ids, treaty ids, hashes, nonces, cursors, or outbox ids as labels.

## Alert Starting Points

- `chio_pheromone_relay_queue_depth{status="retry"} > 100` for retry pressure.
- `chio_pheromone_relay_queue_depth{status="dead_letter"} > 0` for dead-letter triage.
- `chio_pheromone_relay_stale_leases > 0` for scheduler or restart issues.
- `increase(chio_pheromone_relay_rejections_total{reason="relay_nonce_replay"}[5m]) > 10` for replay storms.

The alert annotations should point back to `docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md`.
