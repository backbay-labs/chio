# Relay Observability

The canonical relay observability report is the first operator view for the pheromone relay. It is read-only and aggregates verifier-owned directory state plus durable local relay evidence.

## Report Flow

1. Run `chio chiodos pheromone relay observe`.
2. Run `chio chiodos pheromone relay alert evaluate` against the observability report, routing profile, suppression state, and bounded event directory.
3. Run `chio chiodos pheromone relay trend` across committed observability and event report artifacts for the operator window.
4. Check `relay-alert-report.v1` before opening raw store rows.
5. Inspect bounded event reports from `--report-dir` only when an alert requires evidence.
6. Export `chio chiodos pheromone relay metrics --format prometheus` for downstream alerting.
7. Use raw SQLite inspection only after alert, trend, observability, and bounded event files have narrowed the incident.

## Bounded Metrics

Prometheus labels are limited to:

- `status` for queue depth.
- `reason` for bounded rejection and dead-letter classes.
- `notification_route`, `opsgenie`, `service`, and `severity` for downstream alert routing.

Do not use peer ids, treaty ids, hashes, nonces, cursors, or outbox ids as labels.

## Alert Routing Artifacts

The relay alert routing profile is verifier-owned operator input. It maps bounded alert codes to route aliases for PagerDuty, OpsGenie, Slack, email, or generic webhook handoff. The profile must not contain inline secrets or dynamic URLs. Secrets stay in downstream Alertmanager, PagerDuty, OpsGenie, Slack, or email systems.

The alert report records firing, suppressed, and accepted states from the canonical observability report plus bounded event evidence. Critical classes such as dead letters, replay storms, stale directories, catch-up overload, and endpoint or auth denial remain visible even when suppression state exists.

The trend report aggregates long-horizon observability and event artifacts using bounded alert and metric codes only. It does not inspect raw SQLite and does not reconstruct relay truth outside canonical reports.

## Alert Starting Points

- `chio_pheromone_relay_queue_depth{status="retry"} > 100` for retry pressure.
- `chio_pheromone_relay_queue_depth{status="dead_letter"} > 0` for dead-letter triage.
- `chio_pheromone_relay_stale_leases > 0` for scheduler or restart issues.
- `increase(chio_pheromone_relay_rejections_total{reason="relay_nonce_replay"}[5m]) > 10` for replay storms.

The alert annotations should point back to `docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md`.
