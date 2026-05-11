# Chiodos 6.7 Tickets

## C6.7-001 Integrator

Create the branch from the pinned baseline SHA, add lane planning docs, record
owner tickets and final gates, and keep planning metadata under
`.planning/trajectory-6.7`.

Acceptance:

- Branch starts from `main@edeb4ab87f9403f770b8f63ed36ebe5a94ecf6c5`.
- Planning docs record baseline, scope, tickets, final gates, and the
  no-planning-metadata rule.
- Chiodos 6.8 shadow planning tracks live relay orchestration only.

## C6.7-002 Federation Hardening

Fix local pheromone gossip queue routing and add strict batch verification.

Acceptance:

- Push queues are sender-owned.
- Direct queue flushes use the local sender as gossiping peer.
- Deposits are delivered only to subscribed treaties in the deposit treaty
  scope.
- Batch verification checks schema, recipient, treaty consistency,
  authenticated sender, direct or relay shape, and final-hop receiver binding.

## C6.7-003 Runtime Crate

Add `chio-pheromone-runtime` with receiver, report, store, workflow resolver,
peer-weight, and stable error-code surfaces.

Acceptance:

- The crate depends on the pure pheromone crate, federation artifacts, Chiodos
  verifier types, SQLite storage, serde, and error utilities.
- Runtime errors expose stable machine-readable codes.
- Reports serialize as product JSON without planning language.

## C6.7-004 SQLite Store

Implement durable pheromone receiver state.

Acceptance:

- Deposits, replay nonces, treaty-pair counters, passport-cap state, and
  receive reports are durable.
- Restart preserves replay and diversity enforcement.
- Garbage collection prunes evaporated deposits and expired replay state.

## C6.7-005 Workflow Resolver

Resolve signed pheromone workflow context against verified Chiodos evidence.

Acceptance:

- Resolver verifies the proof package through existing Chiodos trust and
  verification context inputs.
- Evidence index checks workflow receipt hash, workflow intersection hash, step
  index, tool receipt id, DSSE hash, and consistency anchor.
- Package policy remains verifier-owned.

## C6.7-006 Receiver Pipeline

Implement batch receive flow.

Acceptance:

- Batch verification runs before deposit admission.
- Workflow context resolution runs before durable storage.
- Accepted deposits and rejected frames produce schema-valid reports.
- Rejected frames do not mutate replay or diversity state.

## C6.7-007 Advisory Concentration Policy

Add local query and report logic using injected peer weights.

Acceptance:

- Query reports include weighted and unweighted concentration.
- Invalid weights and unknown reputation epochs fail closed.
- The policy is advisory and does not mutate leases, governance, settlement, or
  orchestration state.

## C6.7-008 CLI

Add local pheromone receive and query commands under `chio chiodos pheromone`.

Acceptance:

- `receive` verifies a batch and writes a report.
- `query` reads the durable store and writes a concentration report.
- Negative commands exit nonzero with stable verifier failure codes.

## C6.7-009 Metrics

Register pheromone runtime metric families.

Acceptance:

- Metric names are added to `chio-metrics-spec`.
- Labels are bounded.
- Snapshot tests cover registry drift.

## C6.7-010 Fixtures And Negatives

Regenerate the three-vendor pheromone fixture through the runtime receiver and
make negative evidence executable.

Acceptance:

- Positive fixture verifies through runtime receive and query paths.
- Negative corpus covers routing, sender, recipient, treaty, authentication,
  final-hop, policy freshness, replay, treaty bucket, workflow evidence, peer
  weight, and reputation epoch failures.

## C6.7-011 Assurance

Wire gates, docs, CI triggers, PR review, and merge closeout.

Acceptance:

- `scripts/check-chiodos-pheromone-runtime.sh` supports default,
  `--schema-only`, and `--negative-only` modes.
- CI runs the runtime gate for runtime crate, CLI, fixtures, schemas, docs, and
  script changes.
- PR review threads are queried and resolved before merge.
- Final Chiodos gates pass on `main`.
