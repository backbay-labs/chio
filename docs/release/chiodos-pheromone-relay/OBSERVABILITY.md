# Relay Observability

The canonical relay observability report is the first operator view for the pheromone relay. It is read-only and aggregates verifier-owned directory state plus durable local relay evidence.

## Report Flow

1. Run `chio chiodos pheromone relay observe`.
2. Run `chio chiodos pheromone relay alert evaluate` against the observability report, routing profile, suppression state, and bounded event directory.
3. Run `chio chiodos pheromone relay trend` across committed observability and event report artifacts for the operator window.
4. Run `chio chiodos pheromone relay alert handoff` against the alert report, trend report, routing profile, and handoff profile.
5. Run `chio chiodos pheromone relay alert delivery import` against the handoff report, delivery profile, and local downstream evidence directory.
6. Run `chio chiodos pheromone relay alert delivery acknowledge` against the handoff and delivery reports.
7. Run `chio chiodos pheromone relay alert delivery drift` across handoff and delivery report directories.
8. Check `relay-alert-report.v1`, `relay-trend-report.v1`, `relay-alert-handoff-report.v1`, `relay-alert-delivery-report.v1`, `relay-alert-acknowledgement-report.v1`, and `relay-alert-handoff-drift-report.v1` before opening raw store rows.
9. Inspect bounded event reports from `--report-dir` only when an alert requires evidence.
10. Export `chio chiodos pheromone relay metrics --format prometheus` for downstream alerting.
11. Use raw SQLite inspection only after alert, trend, handoff, delivery, acknowledgement, drift, observability, and bounded event files have narrowed the incident.

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

## Alert Handoff Artifacts

The relay alert handoff profile maps routing aliases to downstream receiver aliases such as Alertmanager, PagerDuty, OpsGenie, Slack, email, or generic webhook handoff. The profile contains no inline secrets, dynamic endpoints, request bodies, or credential material.

The handoff report is a dry-run readiness artifact. It checks route coverage, bounded labels, dedupe keys, severity mapping, runbook refs, escalation mapping, stale inputs, and critical alert visibility. It never sends a notification. Downstream systems perform live delivery from their own credentialed configuration.

## Alert Delivery Evidence

The relay alert delivery profile defines bounded downstream receiver aliases and local runbook references. It contains no inline secrets, URLs, request bodies, or credential material.

The delivery report imports local downstream result artifacts and binds them to the handoff report hash, alert report hash, trend report hash, receiver aliases, route aliases, dedupe keys, severity, and runbook refs. It records delivered, accepted, failed, delayed, duplicate, unknown, and operator-acknowledged outcomes without sending notifications.

The acknowledgement report summarizes downstream outcomes for operator review. The drift report compares handoff and delivery report directories for missing critical delivery evidence, route alias drift, severity weakening, and stale windows.

Chio never calls downstream alerting APIs in this flow. Alertmanager, PagerDuty, OpsGenie, Slack, email, webhook, and SIEM systems remain downstream consumers.

## Alert Starting Points

- `chio_pheromone_relay_queue_depth{status="retry"} > 100` for retry pressure.
- `chio_pheromone_relay_queue_depth{status="dead_letter"} > 0` for dead-letter triage.
- `chio_pheromone_relay_stale_leases > 0` for scheduler or restart issues.
- `increase(chio_pheromone_relay_rejections_total{reason="relay_nonce_replay"}[5m]) > 10` for replay storms.

The alert annotations should point back to `docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md`.
