# chio-pheromone-relay architecture

## Overview

`chio-pheromone-relay` is an untrusted network edge: it terminates signed HTTP
from other kernels, so every inbound request is verified before anything it
carries is trusted. It has two halves. The live relay (`directory`,
`http_signing`, `client`, `store`, `service`, `metrics`) is a store-and-forward
transport: peers exchange `PheromoneGossipBatch` frames over a signed
envelope, durably queued and retried through a SQLite outbox and inbox. The
alert assurance chain (`alerts`, `delivery`, `assurance`, `archive`) is a
reporting pipeline built on the live relay's own observability output: it
turns operational degradation into routed alerts, verifies those alerts were
delivered and acknowledged, and produces signed, retained, archived evidence
of the incident lifecycle. Both halves are schema-tagged JSON throughout, and
every multi-stage handoff re-hashes and re-checks its input instead of
trusting the caller.

## Module map

| Path | Responsibility |
|---|---|
| `src/lib.rs` | Facade: module declarations and the public re-export surface. |
| `src/error.rs` | `PheromoneRelayError`: fail-closed error taxonomy, one stable `code()` per variant. |
| `src/schema.rs` | `chio.pheromone.*` schema-string and HTTP-path constants for every wire document. |
| `src/validation.rs` | Endpoint scheme/credential checks, relay-profile limit checks, canonical SHA-256 hashing, `i64`/`u64` conversion helpers. |
| `src/directory.rs` | `PeerDirectory`: peer entries, signed bundle issuance and verification, version-gated candidate rotation with rollback protection. |
| `src/http_signing.rs` | `PheromoneRelayHttpRequest`: signed envelope construction and verification (schema, recipient, method, path, signature, body hash, freshness, nonce). |
| `src/client.rs` | `PheromoneRelayClient`: signs and POSTs a batch to a directory-resolved peer endpoint. |
| `src/store.rs` | `SqlitePheromoneRelayStore`: migrations, outbox lease/retry/dead-letter, idempotent inbox with a reservation-based receive slot, nonce table, catch-up cursors, event history. |
| `src/metrics.rs` | Queue and directory summaries, failure tallies, Prometheus/JSON rendering for `/metrics` and `/observability`. |
| `src/service.rs` | `PheromoneRelayService`: Axum router and handlers, directory-scope enforcement, `deliver_due_batches` delivery tick. |
| `src/alerts/mod.rs` | Facade: `evaluate_relay_alerts` -> `RelayAlertReport`; `generate_relay_trend_report` -> `RelayTrendReport`; `evaluate_relay_alert_handoff` -> `RelayAlertHandoffReport`. |
| `src/delivery/mod.rs` | Facade: raw downstream evidence -> `RelayAlertNormalizationReport`; handoff + evidence -> `RelayAlertDeliveryReport` -> `RelayAlertAcknowledgementReport`; drift and route-review reports. |
| `src/assurance/mod.rs` | Facade: chain of reports -> `RelayAlertAssurancePackage` -> signed `RelayAlertAssuranceExportBundle`; replay, retention, and recovery-drill reports. |
| `src/archive/mod.rs` | Facade: export bundles -> archive/closeout reports -> signed `RelayAlertAssuranceArchivePackage`; restore-drill, physical-drill, retention-handoff, and external-retention reports. |

Within `alerts/` and `delivery/`, `evaluators.rs` holds the public entry
points, `types.rs` the wire structs, and `helpers.rs` / `validators.rs` the
internal (`pub(crate)`) checks. `assurance/` and `archive/` follow the same
split: `generation.rs` / `generators.rs` (plus `archive/report/mod.rs`) hold
the public entry points, `export.rs` / `package.rs` hold Ed25519 signing and
verification, and `helpers.rs` / `validators.rs` hold internal checks.

## Batch relay lifecycle

1. A sender enqueues a batch (`SqlitePheromoneRelayStore::enqueue_batch`),
   deduplicated by a content-derived `outbox_id`.
2. `deliver_due_batches` leases due rows (30-second lease), checks
   `enforce_outbound_peer_batch_directory_scope` against the current peer
   directory, signs the batch (`sign_relay_http_request`), and POSTs it
   (`PheromoneRelayClient`).
3. The receiving `PheromoneRelayService::handle_batch_relay` verifies the
   envelope end to end (`PheromoneRelayHttpRequest::verify_payload`), applies
   `enforce_peer_batch_directory_scope` on the inbound side, hands the batch
   to the caller-supplied `RelayBatchReceiver`, and durably records the
   verdict (`record_inbox`) keyed by `(sender_kernel_id, nonce)`.
4. Delivery success calls `mark_delivered`; failure calls `mark_retry`
   (backoff scales with attempt count) or, past 3 attempts, `mark_dead_letter`.
5. Peers pull missed frames through `handle_catchup_relay` /
   `catchup_batches`, cursor-paginated and bounded by both frame count and
   byte size per peer.

## Alert assurance chain

`RelayObservabilityReport` (built from live store state) plus a signed
`RelayAlertRoutingProfileDocument` and event history feed
`evaluate_relay_alerts`. Each later stage consumes the previous stage's
report(s) by value and re-derives its hash before trusting it:

```
observability + events -> RelayAlertReport -> RelayTrendReport
  -> RelayAlertHandoffReport
  -> RelayAlertNormalizationReport -> RelayAlertDeliveryReport
  -> RelayAlertAcknowledgementReport
  -> (drift report, route-review packet)
  -> RelayAlertAssurancePackage -> RelayAlertAssuranceExportBundle (signed)
  -> RelayAlertAssuranceArchiveReport / closeout report
  -> RelayAlertAssuranceArchivePackage (signed)
  -> retention / restore-drill / physical-drill / retention-handoff reports
```

## Invariants and failure modes

- Every `PheromoneRelayError` variant maps to a stable `code()`; HTTP handlers
  translate a rejection into a `RelayOperatorReport` and durably record it
  (`emit_event_report`) before the response returns, so a rejected request is
  still visible to the observability and alert chain.
- HTTP envelope verification is fail-closed on schema, recipient, method,
  path, peer signature, canonical body hash, freshness-window skew, and nonce
  replay (`RelayNonceRecorder`) together; any one mismatch rejects.
- `promote_peer_directory_candidate` enforces monotonic bundle versions and a
  `previous_version_sha256` hash chain; a rejected candidate is durably
  recorded with a stable code. `validate_peer_directory_profile` requires
  HTTPS endpoints under `RelayProfile::Production` and bounds every peer's
  batch/catch-up frame and byte limits against the profile ceiling.
- Directory scope is enforced identically inbound
  (`enforce_peer_batch_directory_scope`) and outbound
  (`enforce_outbound_peer_batch_directory_scope`): peer role, frame cap,
  treaty subscription, and pinned transit-ladder hops must all match the
  directory entry.
- Inbox receive is exactly-once under concurrent redelivery: a caller must
  win `reserve_inbox_slot` before invoking `RelayBatchReceiver::receive_batch`.
  A slot marked via `mark_inbox_reservation_committed` survives process
  restart (clear-at-open reclaims only unmarked, provably-pre-commit rows),
  so a crash between the receiver's commit and `record_inbox` cannot cause a
  redelivery to re-enter the runtime replay window and reject already
  accepted deposits.
- Every assurance-chain stage hashes its input reports with
  `canonical_sha256` (RFC 8785 canonical JSON + SHA-256), and the next stage
  checks the hash before trusting it. Export bundles, archive packages, and
  directory bundles are Ed25519-signed and verified against an explicit trust
  list (`RelayAlertAssuranceTrustedExportersDocument`,
  `RelayAlertAssuranceTrustedArchivePackagersDocument`,
  `TrustedPeerDirectoryIssuer`), never an embedded key.
- `/observability` and `/metrics` are gated by a constant-time bearer-token
  comparison (`subtle::ConstantTimeEq`) when
  `PheromoneRelayConfig::operator_token` is set; unset, they are open.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

`chio-core-types` supplies canonical JSON, SHA-256, and the Ed25519
`Keypair` / `PublicKey` / `Signature` types behind every signed document.
`chio-federation` supplies `PheromoneGossipBatch` and the transit-chain and
ladder types this crate relays and scope-checks. `chio-pheromone-runtime`
supplies `PheromoneReceiveReport` and the batch-outcome types
`RelayBatchReceiver` returns. `chio-http-serve` applies request timeout,
concurrency cap, connection cap, and graceful-shutdown drain to the Axum
router. `axum` serves HTTP; `reqwest` (rustls) dials peers; `rusqlite` backs
the durable store; `subtle` gives the operator-token check constant time.
`chio-pheromone` is a declared dependency exercised by the integration tests
under `tests/`, not by `src/`.

## Extension points

- `RelayBatchReceiver` - the trait a caller implements to plug in local batch
  receipt (`chio-pheromone-runtime`'s receiver is the production
  implementation). Its default `recorded_report_for_batch` returns `None`; a
  receiver that can recover a durably-recorded verdict after a crash
  overrides it to avoid re-entering the replay window.
- `PheromoneRelayStore` / `RelayNonceRecorder` - traits `SqlitePheromoneRelayStore`
  implements; a caller can supply an alternate durable store.
- `ExtraMetricsHook` (`PheromoneRelayService::with_extra_metrics_hook`) - a
  callback whose Prometheus output is appended to `/metrics`. It exists so
  `chio-federation-transport-iroh`, which already depends on this crate, can
  publish its own metric families on the same scrape endpoint without a
  dependency cycle; unset, `/metrics` is unchanged.
