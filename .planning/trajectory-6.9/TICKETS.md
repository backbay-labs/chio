# Chiodos 6.9 Tickets

## C6.9-001 Integrator

Create the branch, planning docs, baseline SHA, final gate checklist, no-planning-metadata rule, and 6.10 shadow note.

Acceptance:

- Planning exists only under `.planning`.
- Baseline SHA is recorded.

## C6.9-002 Peer Directory Bundles

Implement signed peer-directory bundle parsing, verification, schema, monotonic version checks, rollback rejection, stale bundle rejection, and issuer trust.

Acceptance:

- Signed production bundle verifies against trusted issuer material.
- Unsigned, stale, rollback, unknown issuer, duplicate peer, and duplicate endpoint cases fail closed.

## C6.9-003 Production Profiles

Add relay profile validation and CLI linting for endpoint scheme, pinned paths, request/body limits, freshness windows, duplicate entries, and unsafe production settings.

Acceptance:

- `local-dev` accepts loopback HTTP.
- `production` rejects HTTP endpoints and excessive limits.
- Lint emits schema-valid JSON.

## C6.9-004 Scheduler Delivery

Make `relay tick` perform real signed outbound delivery with caller-supplied signing key material, deterministic retry/backoff, delivered state, and dead-letter state.

Acceptance:

- Loopback delivery posts a signed batch and marks it delivered.
- Sender-key mismatch does not sign with the wrong key.
- Delivery failures retry or dead-letter deterministically.

## C6.9-005 Supervision

Add health/readiness/status reports for store connectivity, stale leases, peer-directory freshness, outbox pressure, cursor lag, and graceful shutdown behavior.

Acceptance:

- Health report is schema-valid.
- Readiness fails when store-derived health is degraded.

## C6.9-006 Observability

Add health report schema, metrics descriptors, alert-ready fixture reports, and bounded labels.

Acceptance:

- Metrics snapshot matches the registry.
- Labels remain bounded.

## C6.9-007 Catch-Up Pressure

Add deterministic multi-peer catch-up pressure fixtures and tests for cursor, byte, frame, replay, stale nonce, and restart behavior.

Acceptance:

- Catch-up denies over-limit and unauthorized requests with stable failure codes.
- Poison-frame non-advancement remains covered by negative metadata.

## C6.9-008 Fixtures And Negatives

Extend relay fixtures and negative corpus for stale bundle, rollback bundle, unsafe endpoint, oversized catch-up, sender mismatch, recipient mismatch, stale request, key rotation misuse, and removed-peer access.

Acceptance:

- Negative corpus includes stable expected codes for each operational branch.

## C6.9-009 Docs And Assurance

Add TLS/deployment guidance, recovery runbooks, relay ops gate, CI path triggers, final verification, PR, review-thread cleanup, merge, and post-merge gate rerun.

Acceptance:

- `scripts/check-chiodos-pheromone-relay-ops.sh` covers schema, negative, and full modes.
- Operator docs cover stuck outbox, dead-letter triage, stale directory, replay storm, DB lock contention, catch-up overload, and safe requeue.
