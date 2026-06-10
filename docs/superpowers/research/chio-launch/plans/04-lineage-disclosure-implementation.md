# Lineage And Disclosure Implementation Plan

Status: implementation plan
Depends on: `../architecture/04-lineage-disclosure-system.md`
Confidence: moderate.

## Objective

Make lineage and selective disclosure launch-grade under verifier policy.

## Registry Acceptance

Disclosure capsules, BBS projection manifests, signed lineage subgraphs, leakage ledgers, and privacy profiles are verifier-facing artifacts. They must use the canonical schema names in `../indices/artifact-registry.md` and satisfy the registry-before-verifier contract in `../architecture/09-integration-contracts.md`.

## Phase 0 - Reconcile Current Projection Truth

Tasks:

1. Audit selective-disclosure spec and implementation for receipt, workflow, and step projection divergence.
2. Add tests that codify current v1 behavior before changing it.
3. Decide which v1 behavior remains legacy and which is corrected in v2.
4. Document v1 limitations explicitly.

Tests:

- v1 projection snapshot tests;
- spec/implementation mismatch tests where current behavior is intentional;
- v1 proof verifier regression tests.

## Phase 1 - Projection V2 Manifests

Tasks:

1. Define `chio.bbs-projection.manifest.v2`.
2. Add receipt, workflow, and step v2 manifests.
3. Add sensitivity classes and disclosure eligibility.
4. Add manifest digest binding.

Tests:

- stable message index ordering;
- unknown field fails;
- commitment-only field cannot be used for hidden predicate.

## Phase 2 - Kernel Runtime Modes

Tasks:

1. Add BBS runtime mode configuration.
2. Add key lookup and ciphersuite selection.
3. Bind BBS projection to receipt digest.
4. Implement required mode fail-closed behavior.

Tests:

- required mode fails when key unavailable;
- opportunistic mode emits standard receipt when BBS unavailable and reports omission;
- projection manifest mismatch fails.

## Phase 3 - Privacy Profiles And Hidden Predicates

Tasks:

1. Define verifier privacy profile schema.
2. Implement required/forbidden disclosed field checks.
3. Implement typed hidden predicates.
4. Reject excess disclosure by default under privacy profiles.

Tests:

- forbidden field fails even when cryptographic proof verifies;
- hidden predicate over undeclared field fails;
- amount cap predicate passes without disclosing exact amount;
- timing bucket policy rejects exact duration disclosure.

## Phase 4 - Signed Lineage Subgraph Export

Tasks:

1. Add lineage subgraph builder.
2. Add redaction reason support.
3. Wrap graph in signed export envelope.
4. Add verifier that checks roots, edges, redactions, and signatures.

Tests:

- missing required parent fails;
- invalid redaction reason fails;
- digest mismatch fails;
- graph signature mismatch fails.

## Phase 5 - Leakage Ledger

Tasks:

1. Add leakage ledger schema.
2. Generate ledger during disclosure export.
3. Verify ledger coverage against disclosed fields and derived facts.
4. Integrate ledger into Transaction Passport.

Tests:

- disclosed field absent from ledger fails;
- ledger entry not allowed by profile fails;
- residual inference note required for configured sensitivity classes.

## Phase 6 - Launch Qualification

Tasks:

1. Add one valid disclosure capsule fixture.
2. Add invalid fixtures for excess disclosure, hidden predicate mismatch, lineage omission, and ledger omission.
3. Add Proof Room disclosure tab.
4. Add CLI report section.

Exit criteria:

- launch can claim selective disclosure only for profiles covered by fixtures;
- excess disclosure fails closed;
- lineage graph is signed and transaction-bound.
