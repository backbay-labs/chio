# Public Settlement Proof Implementation Plan

Status: implementation plan
Depends on: `../architecture/05-public-settlement-passport-system.md`
Confidence: moderate.

## Objective

Make public runtime and web3 settlement proof verifiable enough to support the homepage commerce claim.

## Registry Acceptance

The public settlement proof bundle is a verifier artifact over existing `chio-web3`, `chio-settle`, `chio-anchor`, and oracle evidence. Do not create duplicate settlement schema IDs or a second "settlement passport" root. Follow `../indices/artifact-registry.md` and `../architecture/09-integration-contracts.md` before the public verifier accepts any new settlement bundle.

## Phase 0 - Schema And Fixture Inventory

Tasks:

1. Define `chio.web3-settlement-proof-bundle.v1`.
2. Define `chio.public-settlement-verifier-report.v1`.
3. Define `chio.oracle-conversion-evidence.v1`.
4. Inventory current IOA web3 examples and proof files.
5. Decide which fixture becomes the canonical launch settlement fixture.

Tests:

- schema accepts valid proof bundle;
- schema rejects missing chain id, order ref, registry root, tx refs, or finality refs.

## Phase 1 - Verifier Core

Tasks:

1. Implement bundle parsing.
2. Verify digest and signature bindings.
3. Verify order and settlement instruction binding.
4. Verify registry, escrow, bond, tx, block, finality, oracle, dispute, and identity binding sections.
5. Produce deterministic verifier report.

Tests:

- valid public settlement fixture passes;
- wrong order id fails;
- wrong chain id fails;
- tx/block mismatch fails;
- stale oracle evidence fails.

## Phase 2 - IOA Evidence Promotion

Tasks:

1. Upgrade existing Internet-of-Agents web3 fixture into a complete proof bundle.
2. Add registry root evidence.
3. Add escrow and bond state evidence.
4. Add tx/block/finality evidence.
5. Add identity binding evidence.
6. Add dispute posture evidence.

Tests:

- fixture verifies offline where possible;
- live chain lookup fields are explicitly marked;
- missing dispute posture downgrades verdict.

## Phase 3 - Transaction Passport Binding

Tasks:

1. Add settlement nodes and edges to evidence graph.
2. Add claim ids for public settlement verification.
3. Bind public settlement verifier report into Transaction Passport.
4. Add Proof Room settlement tab.

Tests:

- Transaction Passport fails if settlement report references a different order;
- Proof Room shows chain, tx, finality, and dispute posture;
- invalid settlement proof is visible in claim table.

## Phase 4 - Launch Gate

Tasks:

1. Add CLI command or subcommand for settlement proof verification.
2. Add negative fixtures.
3. Add docs that distinguish Chio authority from chain evidence.
4. Add release gate for proof bundle verification.

Exit criteria:

- web3 settlement proof can be independently verified;
- settlement context claim is limited to verified finality and dispute posture;
- demo transcript is no longer the proof source of truth.
