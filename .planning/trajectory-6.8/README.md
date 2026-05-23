# Chio 6.8 Live Pheromone Relay

Baseline: `main@fa34965bc5d3290cc851b2ee275c4752d87cd1de`

Branch: `codex/chio-6-8-live-pheromone-relay`

## Goal

Ship the first live pheromone relay surface while preserving the 6.7 local runtime boundary. Signed HTTP relay requests carry already-formed pheromone gossip batches between pinned peers, and receivers verify app-layer signatures, peer-directory trust, replay nonces, body hashes, and the existing runtime receive rules before storing evidence.

## Tickets

- C6.8-001 Integrator: branch, planning docs, baseline SHA, final gates, and no-planning-metadata rule.
- C6.8-002 Peer Directory And Auth: verifier-owned peer directory, endpoint pinning, signed relay HTTP request, payload hash, freshness, and nonce replay checks.
- C6.8-003 Relay Store: durable SQLite relay tables for nonces, outbox, inbox, attempts, cursors, and operator status.
- C6.8-004 Relay Authorization: only accepted relay artifacts may move into outbound state, with transit metadata outside signed deposits.
- C6.8-005 HTTP Service And Client: Axum receiver and reqwest client for signed batch delivery.
- C6.8-006 Bounded Catch-Up: signed catch-up request and response artifact shape with bounded limits.
- C6.8-007 CLI: relay serve, enqueue, tick, catchup, status, plus deterministic receive and query clocks.
- C6.8-008 Metrics And Reports: stable relay report schemas and bounded relay failure codes.
- C6.8-009 Fixtures And Negatives: committed peer directory, reports, catch-up artifacts, and negative corpus.
- C6.8-010 Assurance: gate script, CI trigger, final verification, PR review cleanup, and merge.

## Final Gates

- `cargo test -p chio-pheromone-relay`
- `cargo test -p chio-pheromone-runtime`
- `cargo test -p chio-federation pheromone`
- `cargo test -p chio-pheromone`
- `cargo test -p chio-cli chio`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- `bash scripts/check-chio-pheromone-relay.sh`
- `bash scripts/check-chio-pheromone-relay.sh --schema-only`
- `bash scripts/check-chio-pheromone-relay.sh --negative-only`
- Existing transit, runtime, authority, proof package, bounded, and threat mutant gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.

## Boundary

This lane does not add dynamic peer discovery, live lease or governance decisions, hidden predicates, VC DI BBS, zkVM, FROST, settlement execution, or reputation mutation. Planning names stay only under `.planning`.
