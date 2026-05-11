# Chiodos 6.10 Tickets

## C6.10-001 Integrator

Status: in progress

Create the feature branch, record the baseline SHA, and keep planning metadata under `.planning`.

## C6.10-002 Directory State

Status: in progress

Implement active, candidate, and rejected directory state with schema-valid JSON, duplicate rejection, version floor, issuer trust, expiry checks, and previous-version hash continuity.

## C6.10-003 Rotation Semantics

Status: in progress

Implement promote and reject flows, last-known-good behavior, rollback rejection, key rotation overlap checks, endpoint-change checks, and removed-peer quarantine codes.

## C6.10-004 Relay Binding

Status: in progress

Make production serve, tick, catch-up, and lint consume verified active directory state and fail closed when state is stale, missing, rejected, or rollback-tainted.

## C6.10-005 Supervisor Packaging

Status: in progress

Add linted systemd, launchd, and reverse-proxy examples with signing-key permission checks, single-writer notes, restart policy, readiness paths, and pinned endpoint paths.

## C6.10-006 Operational Drills

Status: in progress

Add drill fixtures and reports for rotation, replay storm, catch-up overload, stale lease restart, dead-letter triage, stale bundle, removed peer, and bad key rotation.

## C6.10-007 Assurance

Status: in progress

Add the directory lifecycle gate with schema-only and negative-only modes, wire CI path triggers, update the relay runbook, and run final verification.

## C6.10-008 Integrator

Status: pending

Open the PR, confirm zero unresolved review threads, merge to `main`, and rerun the gate set on `main`.
