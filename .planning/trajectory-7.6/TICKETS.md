# Tickets

## C7.6-001, Integrator

Create the stacked branch, record baseline SHA, add active planning docs, and keep the prior 7.6 shadow from becoming production text.

## C7.6-002, Ladder And Treaty Contracts

Add governance ladder manifest, treaty scope, and ladder intersection contracts with strict validation and schema registration.

## C7.6-003, Cross-Boundary Admission

Compute treaty-bound admission reports that reject stale treaty material, missing ladder intersection, unknown action classes, destructive downgrade, and missing evidence.

## C7.6-004, Continuation And Lineage

Add continuation and receipt-lineage contracts that keep verified, observed, asserted, unverifiable, and rejected evidence classes distinct.

## C7.6-005, Buyer Attestation Packet

Verify buyer packets only when the packet hash bindings match a verified lineage statement. Budget refs may be bound, but settlement is not claimed.

## C7.6-006, CLI And Schemas

Add `chio chiodos treaty intersect`, `admit`, and `verify-packet`, plus schema files, registry entries, and CLI smoke coverage.

## C7.6-007, Negatives And Gate

Add executable negative coverage for missing required evidence and asserted lineage. The gate must detect wrong expected codes as it grows.

## C7.6-008, Review And Closeout

Run subagent review cycles, fix actionable issues, run final gates, open PR, resolve review threads, merge, and rerun treaty and runtime gates on `main`.
