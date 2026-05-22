# Chio 6.6 Tickets

## C6.6-001 Integrator

Create the branch from the pinned baseline SHA, add lane planning docs, record
owner tickets and final gates, and keep planning metadata under
`.planning/trajectory-6.6`.

Acceptance:

- Branch starts from `main@82d090edd254b1f11247e5a146f31f832dcafc79`.
- Planning docs record baseline, scope, tickets, final gates, and the
  no-planning-metadata rule.
- Chio 6.7 shadow planning tracks live pheromone runtime and workflow
  context consumption.

## C6.6-002 Spec Contract

Freeze the signed workflow-context and unsigned relay-transit contract.

Acceptance:

- Pheromone deposits carry origin-owned `workflow_context` inside the signed
  body.
- Pheromone gossip envelopes carry relay-owned `transit_chain` outside the
  signed deposit.
- Direct gossip requires the frame treaty to appear in the deposit treaty
  scope.
- Relay gossip requires a valid transit chain from an in-scope ingress treaty
  to the downstream treaty.

## C6.6-003 Pheromone Crate

Add `chio-pheromone` with pure substrate types, signing, verification,
in-memory storage, replay tracking, decay, garbage collection, concentration,
and fixture helpers.

Acceptance:

- The crate has no dependency on reputation, Chio verifier, settlement, or
  live federation transport.
- Signed deposits verify against canonical JSON of the body.
- In-memory storage rejects invalid deposits before storing them.

## C6.6-004 Passport And Diversity

Enforce passport-key signing and source-diversity controls.

Acceptance:

- Kernel keys are rejected for deposits.
- Passport public-key hash and JWK thumbprint must match the signing key.
- Replay nonce, per-pair token bucket, and sqrt-N origin caps fail closed.

## C6.6-005 Cost And Workflow Context

Bind workflow context and observation-cost commitment policy.

Acceptance:

- Destructive or cost-committed subject classes require a cost commitment.
- Workflow context hashes resolve to expected workflow receipt, step, DSSE,
  tool receipt, and consistency-anchor material.
- Workflow context tampering invalidates the deposit signature.

## C6.6-006 Federation Transit

Add treaty-scoped local pheromone gossip queues and receiver checks.

Acceptance:

- Queue keys include recipient kernel id and treaty id.
- Flush order is deterministic FIFO with no coalescing and no empty batches.
- Receiver verification rejects forged relay paths, loops, broken hop
  adjacency, stale ladder refs, missing intersections, unknown action classes,
  and downstream treaty smuggling.

## C6.6-007 Schemas And Fixtures

Add pheromone schemas, registry entries, deterministic fixture artifacts, and
negative corpus.

Acceptance:

- Every committed pheromone JSON artifact validates with `chio-spec-validate`.
- Negative cases cover signature tamper, workflow hash mismatch, DSSE hash
  mismatch, consistency-anchor mismatch, missing cost commitment, replayed
  nonce, and stale transit policy.

## C6.6-008 Example Integration

Extend the three-vendor fixture with generated pheromone evidence.

Acceptance:

- Pheromone fixture evidence links to the existing workflow proof package by
  hashes and stable ids.
- Proof-package acceptance remains independent of pheromone evidence.

## C6.6-009 CLI And Gates

Add a local artifact verifier CLI only if the crate surface is stable enough,
then wire the new gate script and CI path triggers.

Acceptance:

- `scripts/check-chio-pheromone-transit.sh` supports default,
  `--schema-only`, and `--negative-only` modes.
- CI runs the pheromone gate for pheromone crate, federation gossip, schemas,
  fixtures, docs, and script changes.

## C6.6-010 Integrator

Open the PR, address all review threads, merge to `main`, and rerun Chio
gates on `main`.

Acceptance:

- PR review threads are queried and resolved before merge.
- Final Chio pheromone, authority, and proof-package gates pass on `main`.
