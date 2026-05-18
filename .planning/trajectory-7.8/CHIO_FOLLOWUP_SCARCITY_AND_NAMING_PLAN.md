# Chio Follow-up Plan: Scarcity Policy and Naming Convergence

## Scope

This plan is intentionally separate from the narrow P1 trust-boundary patch. It does not implement Pheromone Scarcity Policy v1 and does not perform Chiodos-to-Chio naming convergence.

## Phase 1: Pheromone Scarcity Policy v1

Goal: make pheromone admission scarcity explicit, epoch/window scoped, and auditable.

Deliverables:

1. Define `chio.pheromone-scarcity-policy.v1` with policy id, reputation epoch, window id, window start/end, token capacity, newcomer horizon, treaty scope, subject namespace, subject class, and observation-cost verification mode.
2. Replace lifetime/global-ish deposit counters with token buckets keyed by reputation epoch, window id, treaty id, subject class namespace, and subject class.
3. Preserve existing replay, passport, sqrt-N, and diversity gates as independent fail-closed checks.
4. Make newcomer discount horizon configurable through the scarcity policy, with the current eight-epoch behavior as an explicit compatibility default.
5. Require verified observation-cost commitments when the policy says they are mandatory. Verification must bind the commitment to the subject namespace, class, treaty scope, telemetry root, and verifier identity.
6. Add negative tests for exhausted buckets, cross-window isolation, cross-treaty isolation, namespace/class isolation, stale windows, unknown epochs, invalid newcomer horizon, and unverified cost commitments.
7. Add runtime policy loader and CLI fixtures for the new policy without changing existing signed artifact compatibility.

Suggested validation:

```bash
cargo test -p chio-pheromone --test pheromone_substrate -- --nocapture
cargo test -p chio-pheromone-runtime --test runtime_receiver -- --nocapture
cargo test -p chio-pheromone-relay --test relay -- --nocapture
cargo clippy -p chio-pheromone -p chio-pheromone-runtime -p chio-pheromone-relay --all-targets -- -D warnings
```

## Phase 2: Chiodos-to-Chio Naming Convergence

Goal: move public operator surfaces to Chio-native naming while preserving signed-artifact compatibility.

Deliverables:

1. Keep `chio chiodos` as a compatibility alias only.
2. Add new public CLI surfaces:
   - `chio federation`
   - `chio attest`
   - `chio runtime`
   - `chio pheromone`
3. Keep old schema ids readable and deprecated. Do not break verification of existing signed artifacts.
4. Emit Chio-native schema ids only where compatibility is safe for signed artifacts. Where a schema id is signed, add a versioned compatibility plan before changing emitters.
5. Update docs, examples, shell completion, and CLI help in one pass after command compatibility tests exist.
6. Add alias tests proving old commands still route to the new implementations.
7. Add fixture tests proving old signed artifacts still verify after new Chio-native command surfaces land.

Suggested validation:

```bash
cargo test -p chio-cli chiodos -- --nocapture
cargo test -p chio-cli federation -- --nocapture
cargo test -p chio-cli runtime -- --nocapture
cargo test -p chio-cli pheromone -- --nocapture
cargo clippy -p chio-cli --all-targets -- -D warnings
```
