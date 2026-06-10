# Transaction Passport Implementation Plan

Status: implementation plan
Depends on: `../architecture/01-transaction-passport-system.md`
Confidence: moderate.

## Objective

Create the canonical public proof root for Chio launch.

## Registry Acceptance

This plan creates verifier-facing signed artifacts. Before any verifier accepts them, follow `../indices/artifact-registry.md` and `../architecture/09-integration-contracts.md`: schema files, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, checked schema-root coverage, Rust signed-artifact constants or generated successor, claim registry rows, proof-manifest rows, positive fixtures, and unknown-schema negative fixtures.

## Phase 0 - Spec And Schemas

Tasks:

1. Add protocol text for `chio.transaction-passport.v1`, `chio.transaction.evidence-graph.v1`, `chio.transaction.claim-set.v1`, and `chio.transaction.verifier-report.v1`.
2. Add JSON schemas under the existing schema layout.
3. Define canonical JSON ordering and digest rules.
4. Define supported omission statuses.
5. Add schema tests for missing required fields, unknown versions, duplicate node ids, duplicate claim ids, cycles, and unresolved refs.

Tests:

- valid minimal passport schema fixture;
- invalid missing signature;
- invalid cycle in evidence graph;
- invalid unknown artifact type;
- valid omission with signed reason.

## Phase 1 - Verifier Library

Tasks:

1. Add verifier structs for passport, graph, claim set, and report.
2. Implement signature and digest validation.
3. Implement graph validation.
4. Implement policy loading and required claim evaluation.
5. Produce deterministic verifier reports.

Tests:

- verifier accepts valid fixture;
- verifier rejects mismatched graph root;
- verifier rejects unknown required claim;
- verifier report output snapshots remain stable.

## Phase 2 - Assembler

Tasks:

1. Implement a passport assembler that can ingest receipts, capability proofs, policy docs, evidence exports, commerce order context, disclosure capsule, settlement proof bundle, and risk report.
2. Add stable artifact reference resolution.
3. Add deterministic bundle layout.
4. Add omission reasoning for unavailable optional subgraphs.

Tests:

- assembler builds identical passport from same inputs;
- assembler records omitted optional artifacts;
- assembler refuses missing required receipt.

## Phase 3 - CLI

Tasks:

1. Add `chio proof collect`.
2. Add `chio proof verify`.
3. Add `chio proof explain`.
4. Add machine-readable and human-readable report modes.

Tests:

- CLI verifies bundled fixture;
- CLI exits nonzero on invalid proof;
- explanation names exact failed claim and evidence ref.

## Phase 4 - Proof Room Adapter

Tasks:

1. Define Proof Room bundle shape.
2. Render passport summary.
3. Render evidence graph.
4. Render claim table.
5. Render failure explorer.

Tests:

- UI fixture loads without network;
- valid and invalid fixture states render distinct outcomes;
- report JSON round-trips with CLI output.

## Phase 5 - Launch Fixture

Tasks:

1. Build a minimal single-agent call passport.
2. Build a commerce transaction passport.
3. Build a recursive swarm passport.
4. Add all negative fixtures listed in the architecture doc.

Exit criteria:

- every launch claim in `../indices/verification-gates.md` maps to a claim id;
- no proof room fixture depends on private environment secrets;
- public verifier can reproduce the same verdict from committed fixtures.
