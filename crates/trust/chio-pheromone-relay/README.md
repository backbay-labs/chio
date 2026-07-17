# chio-pheromone-relay

`chio-pheromone-relay` is the networked relay for Chio pheromone signals: a
signed, store-and-forward HTTP service that moves pheromone batches between
kernels, backed by a durable SQLite store, plus the alert, delivery, and
archival assurance chain built on top of its own operational telemetry.

The shared pheromone and transit-evidence types are `chio-pheromone`; the
local receiver runtime a relay peer forwards batches into is
`chio-pheromone-runtime`. This crate is the network hop between them, plus
the operational assurance chain built on its own telemetry.

## Responsibilities

- Serve an Axum HTTP relay (`PheromoneRelayService`): batch relay, catch-up,
  health, ready, observability, and Prometheus/JSON metrics endpoints.
- Persist relay state durably in SQLite (`SqlitePheromoneRelayStore`): outbox
  lease/retry/dead-letter, an idempotent inbox with a reservation-based
  receive slot, replay-protected nonces, catch-up cursors, and event history.
- Sign and verify the peer-to-peer HTTP envelope (`sign_relay_http_request`,
  `PheromoneRelayHttpRequest`) and the peer directory (`PeerDirectory`,
  version-gated signed bundles with rollback protection).
- Deliver queued batches to peers (`PheromoneRelayClient`,
  `deliver_due_batches`) and enforce inbound/outbound per-peer directory scope
  (relay role, treaty subscription, frame caps, pinned transit ladders).
- Turn relay observability into a signed alert, delivery, acknowledgement,
  drift, and archival assurance chain (`alerts`, `delivery`, `assurance`,
  `archive`).

## Public API

Live relay:

| Item | Role |
|---|---|
| `PheromoneRelayService`, `PheromoneRelayConfig`, `RelayBatchReceiver` | Axum service; caller supplies the batch receiver |
| `SqlitePheromoneRelayStore`, `PheromoneRelayStore`, `RelayNonceRecorder` | durable store and its trait surface |
| `PheromoneRelayClient`, `deliver_due_batches` | signed outbound delivery |
| `PeerDirectory`, `PeerDirectoryBundleDocument`, `sign_peer_directory_bundle`, `promote_peer_directory_candidate` | signed peer directory and version rotation |
| `sign_relay_http_request`, `PheromoneRelayHttpRequest`, `RelayHttpVerificationContext` | signed request envelope |
| `RelayHealthReport`, `RelayObservabilityReport`, `RelayMetricsSnapshot` | operational reports |
| `relay_supervisor_profile_from_json`, `lint_relay_supervisor_profile` | deployment profile validation |
| `PheromoneRelayError` | crate error type, one stable `code()` per variant |

HTTP surface (`PHEROMONE_RELAY_PATH_PREFIX` = `/v1/chio/pheromone`):

| Method | Path | Handler |
|---|---|---|
| POST | `/v1/chio/pheromone/batches` | `handle_batch_relay` |
| POST | `/v1/chio/pheromone/catchup` | `handle_catchup_relay` |
| GET | `/v1/chio/pheromone/health` | `handle_health` |
| GET | `/v1/chio/pheromone/ready` | `handle_ready` |
| GET | `/v1/chio/pheromone/observability` | `handle_observability` (operator token) |
| GET | `/v1/chio/pheromone/metrics` | `handle_metrics` (operator token, Prometheus text) |

Alert assurance chain, `alerts` -> `delivery` -> `assurance` -> `archive`. Each
stage takes the previous stage's report(s), a signed profile document, and
`now_unix_ms`, and returns a schema-tagged report:

| Stage | Entry points |
|---|---|
| `alerts` | `evaluate_relay_alerts`, `generate_relay_trend_report`, `evaluate_relay_alert_handoff` |
| `delivery` | `normalize_relay_alert_delivery_evidence`, `evaluate_relay_alert_delivery`, `evaluate_relay_alert_acknowledgement`, `generate_relay_alert_delivery_drift_report`, `generate_relay_alert_route_review_packet` |
| `assurance` | `generate_relay_alert_assurance_package`, `sign_relay_alert_assurance_export_bundle`, `verify_relay_alert_assurance_export_bundle`, `generate_relay_alert_assurance_replay_report`, `generate_relay_alert_assurance_retention_report`, `generate_relay_alert_assurance_recovery_drill_report` |
| `archive` | `generate_relay_alert_assurance_archive_report`, `generate_relay_alert_assurance_closeout_report`, `sign_relay_alert_assurance_archive_package`, `verify_relay_alert_assurance_archive_package`, `generate_relay_alert_assurance_archive_restore_drill_report`, `generate_relay_alert_assurance_physical_archive_drill_report`, `generate_relay_alert_assurance_retention_handoff_report`, `generate_relay_alert_assurance_external_retention_review_report` |

Every report's `chio.pheromone.*` schema string is declared in `schema.rs`;
wire types live alongside each stage's evaluator.

## Testing

`cargo test -p chio-pheromone-relay`

Integration coverage lives under `tests/relay/`, one file per subsystem:
`alerts.rs`, `archive.rs`, `delivery.rs`, `directory.rs`, `observability.rs`,
`service.rs`.

## See also

- `chio-pheromone` - shared pheromone and transit-evidence types.
- `chio-pheromone-runtime` - the local receiver runtime a relay peer forwards batches into.
- `chio-federation` - supplies `PheromoneGossipBatch` and the transit-chain and ladder types this crate relays and scope-checks.
- `chio-http-serve` - request timeout, concurrency cap, and graceful-shutdown drain applied to the Axum router.
