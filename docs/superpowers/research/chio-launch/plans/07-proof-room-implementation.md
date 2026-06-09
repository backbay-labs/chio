# Proof Room Implementation Plan

Status: implementation plan
Depends on: `../architecture/07-proof-room-system.md`
Confidence: moderate.

## Objective

Make Chio's launch proof inspectable by developers, buyers, and partners.

## Registry Acceptance

The Proof Room consumes verifier output. It does not define proof semantics. `chio.proof-room.bundle.v1` and `chio.proof-room.verifier-report.v1` still need registry, manifest, fixture, and unknown-schema negative coverage before launch docs treat them as supported bundle formats.

## Phase 0 - CLI Contract

Tasks:

1. Define `chio proof` command namespace.
2. Define report JSON shape.
3. Define bundle layout.
4. Add fixture command conventions.

Tests:

- `chio proof verify` returns deterministic JSON;
- invalid proof returns nonzero exit;
- explanation output names failed claim ids.

## Phase 1 - Minimal Docker Quickstart

Tasks:

1. Add a Docker quickstart for Tier 0.
2. Include valid and invalid single-call fixtures.
3. Run CLI verifier inside container.
4. Emit proof room bundle.

Tests:

- fresh Docker run succeeds;
- invalid fixture fails;
- no private credentials required.

## Phase 2 - Static Proof Room

Tasks:

1. Build static UI around verifier report JSON.
2. Add overview, authority, graph, and failure tabs.
3. Add local bundle loading.
4. Add keyboard/search support for claim ids and artifact refs.

Tests:

- UI opens fixture bundle offline;
- failed claims are visible;
- artifact refs resolve.

## Phase 3 - Domain Tabs

Tasks:

1. Add commerce tab.
2. Add swarm tab.
3. Add disclosure tab.
4. Add settlement tab.
5. Add risk tab.
6. Add external envelope tab.

Tests:

- each tab renders valid and invalid fixtures;
- each failed domain claim links to evidence graph path;
- redacted values remain redacted in UI.

## Phase 4 - Release Truth Gate

Tasks:

1. Add script that checks release/package/docs truth.
2. Verify CLI/package availability before docs claim it.
3. Verify fixture bundle paths.
4. Verify quickstart command from clean checkout.

Tests:

- missing package fails gate;
- stale fixture path fails gate;
- docs reference to nonexistent release fails gate.

## Phase 5 - Launch Review Kit

Tasks:

1. Add README for reviewers.
2. Add fixture catalog.
3. Add expected verifier output snapshots.
4. Add public explanation of what Chio proves and does not prove.

Exit criteria:

- a reviewer can run the quickstart and inspect a valid and invalid proof;
- Proof Room output matches CLI verifier output;
- public docs do not overclaim release/package availability.
