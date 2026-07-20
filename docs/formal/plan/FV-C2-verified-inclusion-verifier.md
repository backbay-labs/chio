# FV-C2: Verify the Merkle inclusion-proof verifier relying parties actually run

- Status: Implemented (2026-07-11; final post-A2 integration)
- Decisions: Keep non-Rust SDKs independent and bind them with differential tests; prove soundness rather than byte-level completeness in Lean; reuse the same verified walk for super-roots; keep the Kani PR bound at eight leaves; authenticate the extraction mirror through the production Aeneas registry and generated-equivalence proof; retire the mirror when direct core-types extraction is available.
- Theme: C - Turn verification into product surface
- Effort: M
- Depends on: [FV-A1](FV-A1-absorb-verified-helpers.md) (absorption pattern), helped by [FV-A2](FV-A2-aeneas-generated-equivalence.md); mirror-drift protection from [FV-A4](FV-A4-mirror-drift-hashes.md)
- Feeds: customer verifier trust path (anchor bundles, SDK replay), [FV-C5](FV-C5-proof-coverage-map.md), sharpens the crypto-boolean projection in [FV-C1](FV-C1-receipt-trace-validation.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2, G4), [FV-C3](FV-C3-canonical-json-injectivity.md), [FV-B2](FV-B2-regression-negative-tests.md)

## Summary

Receipts are signed decisions in an append-only Merkle-committed log [v], and the code a relying party executes to check "this receipt is in that log" is the single most customer-executed trust path in the system. This work factors that production verifier's index-directed fold into an extraction-safe step function, proves the fold sound against the existing Lean receipt model, binds public Kani harnesses to the real step and full bounded walk, and keeps every relying-party Rust path on that verified core. Authenticated Charon and Aeneas output is committed at its emitted module path, and `generated_inclusion_step_eq_model` proves the generated machine-integer step equivalent to `Chio.Core.inclusionStep`. The hash itself stays abstract under ASSUME-SHA256.

## Pre-implementation motivation and evidence

- G2: model-only verified helpers are not wired to production. `verify_oracle_inclusion_walk_parity` (crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs:1248-1281) asserts `verifier_accepts == leaf_present && chain_hashes_to_root` over free booleans; the real verifier could reverse sibling order on odd indices and this harness would still pass.
- The real walk has real failure modes, and the negative-test surface already knows it: conformance tests exist for forged roots and misordered proofs (crates/tooling/chio-conformance/tests/anchor_batch_forged_root_rejected.rs, anchor_batch_misordered_proof_rejected.rs), and the Rekor witness verifier carries truncated-path and padded-path rejection tests. Those are point tests; the fold deserves a proof.
- The anchored-root diff-tests already cross-check Rust against TypeScript over the 50-fixture replay corpus with a hardcoded canary leaf hash [v] (formal/diff-tests/tests/anchored_root.rs:18-21). Once the Rust core is verified, it becomes the oracle both language implementations bind to, upgrading that diff test from "two implementations agree" to "both agree with a proved core".
- Deliverable framing for Theme C: "the verifier you run is the verified one" is a sentence a customer can check, unlike "we have a model of a verifier".

## Current state

### The production verifier, located

The pure hash-chain core is `chio_core::merkle` in crates/core/chio-core-types/src/merkle.rs (RFC 6962-compatible, carry-last-node-upward rather than duplicate-last, per the header comment L1-9):

- `leaf_hash` (L21): `SHA256(0x00 || leaf_bytes)`; `node_hash` (L34): `SHA256(0x01 || left || right)`.
- `MerkleProof { tree_size, leaf_index, audit_path }` (L185-192).
- `MerkleProof::compute_root_from_hash` (L201-239): the index-directed fold. Per level: if `idx` is even and a right sibling exists (`idx + 1 < size`), combine `node_hash(h, sibling)`; if `idx` is odd, combine `node_hash(sibling, h)`; if even with no sibling, carry `h` upward consuming nothing; then `idx /= 2`, `size = size.div_ceil(2)`. Rejects out-of-range indices (L202-204), path underrun (L214-215, L222-223), and trailing unconsumed path elements (L234-236).
- `verify` (L243) and `verify_hash` (L252) compare the computed root against the expected root.

Callers that make this the canonical target:

- Relying-party anchor verification: `verify_anchor_inclusion_proof` (crates/economy/chio-web3/src/anchors.rs:434-484) canonicalizes the receipt body, computes `leaf_hash` (L463), and calls `proof.verify_hash(receipt_leaf, merkle_root)` (L464-472), plus an optional super-root `verify_hash` (L473-482). `verify_proof_bundle` (crates/economy/chio-anchor/src/bundle.rs:46) drives it (L67) for the multi-lane anchor bundle a customer checks.
- Kernel proof construction: `build_inclusion_proof` (crates/kernel/chio-kernel/src/checkpoint.rs:807-821) builds proofs from the same `MerkleTree` (`inclusion_proof`, merkle.rs:143-180), so build and verify share one index convention.
- The TypeScript conformance runner re-implements the same tuple semantics (sdks/typescript/packages/conformance/src/replay.ts, per anchored_root.rs:7-8).

Non-targets, named to avoid confusion: `chio_revocation_oracle::api::InclusionProof::verify` is the sparse revocation-oracle proof, a different structure with its own ordinary tests and fuzz target; the Rekor `verify_inclusion_proof` (crates/economy/chio-anchor/src/witness/rekor.rs:546) checks the external Rekor log, not the Chio receipt log; `chio-eval-receipt` verifies eval-report bundle envelopes and payload hashes (crates/sdk/chio-eval-receipt/src/verify.rs:1-6), not Merkle inclusion. **The canonical verification target is `chio_core::merkle::MerkleProof::compute_root_from_hash`**: it is the one implementation every Rust relying-party path shares.

### The formal side

- The bounded Lean model (formal/lean4/Chio/Chio/Core/Receipt.lean) has `applyProof` over direction-tagged proof steps (L66-73), `verifyInclusion` (L79-81), and `membershipProof` (L83-94), with `MerkleHash` as a free algebra (L34-37, no modeled hash).
- `membership_proof_sound` is already proved for the model (formal/lean4/Chio/Chio/Proofs/Receipt.lean:27) [v].
- The Kani binding precedent exists: `verify_delegation_chain_step` (kani_public_harnesses.rs:582) drives the real one-step attenuation predicate over small symbolic inputs and asserts equality with model expectations. That is the pattern to follow, versus the purely algebraic inclusion harness at L1248.
- Aeneas production extraction is currently scoped to the pure numeric/boolean style of crates/kernel/chio-kernel-core/src/formal_aeneas.rs; extraction outside that file is an excluded surface (formal/proof-manifest.toml `excluded_surfaces`, L145-151).

## Design

### Factor the fold into a step function

The error-prone content of `compute_root_from_hash` is not hashing; it is index arithmetic: when to consume a sibling, on which side to place it, and how `(idx, size)` evolve. Factor exactly that into a pure step function:

```rust
pub struct InclusionStep {
    pub consume_sibling: bool,  // false = carry h upward
    pub sibling_on_left: bool,  // combine order when consuming
    pub next_index: u64,
    pub next_size: u64,
}

pub fn inclusion_step(index: u64, size: u64) -> InclusionStep
```

Integers and booleans only - no slices, no Vec, no Hash type. The fold in `compute_root_from_hash` becomes a loop that queries `inclusion_step` and performs `node_hash` in the caller. The hash stays abstract per ASSUME-SHA256 (formal/assumptions.toml:20): the proofs never open SHA-256, they reason about the walk.

### The Aeneas constraint, honestly

The current formal_aeneas.rs style admits no slices or Vec, so the whole `audit_path` walk cannot be extracted as-is. Options considered:

- (a) Bounded-depth fixed-size array encoding (`[Hash; 64]` plus a length): extractable in principle, but imports a fake data representation into production code and still smuggles a 32-byte array type through the extraction boundary.
- (b) Verify the step function per-step and do the fold reasoning in Lean: prove in Lean that iterating the modeled step relation from `(leaf_index, tree_size)` reproduces `applyProof` on a direction-tagged proof derived from the same indices (induction over the level count).
- (c) Kani-only for the array walk plus Aeneas for the step function: Kani unrolls the real Vec-walking loop on small symbolic trees; Aeneas extracts only `inclusion_step`.

Recommendation: the (b)/(c) hybrid. Aeneas extracts `inclusion_step` (it is exactly formal_aeneas.rs-shaped); Lean owns the fold-level induction against `applyProof`; Kani owns the binding between the real Vec loop and the step semantics on bounded trees. No single tool is asked to do the part it is bad at.

Placement: dependency direction blocks putting the function only in chio-kernel-core (kernel-core depends on core-types, not the reverse). So `inclusion_step` lives in a new pure module `crates/core/chio-core-types/src/merkle_steps.rs` (production home, called by merkle.rs), with an extraction-safe semantic mirror in `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`. The mirror deliberately spells one Boolean branch more explicitly for the Aeneas subset. It is bound by (1) a Kani equivalence harness asserting `assert_eq!(production_step(i, s), formal_aeneas_step(i, s))` over symbolic bounded inputs, (2) FV-A4 mirror hashes binding both source bodies to the Lean model, and (3) the authenticated Aeneas registry plus generated-equivalence theorem. When the production extraction machinery can point Charon at a filtered core-types module directly, the mirror is deleted and both drift hashes are retired.

### Proof obligations

Statement sketches (names final, statements indicative):

```lean
-- Chio/Core/MerkleWalk.lean
structure StepDecision where
  consumeSibling : Bool
  siblingOnLeft  : Bool
  nextIndex : Nat
  nextSize  : Nat

def inclusionStep (index size : Nat) : StepDecision := ...

def stepFold : MerkleHash -> Nat -> Nat -> List MerkleHash -> Option MerkleHash

-- Chio/Proofs/MerkleWalk.lean
theorem stepFold_eq_applyProof
    (leafIndex treeSize : Nat) (path : List MerkleHash) (h : MerkleHash) :
    stepFold h leafIndex treeSize path
      = some (applyProof h (directedProof leafIndex treeSize path)) := ...

theorem bounded_stepFold_sound
    (h_geometry : BoundedWalkGeometry start leafIndex treeSize path root) :
    stepFold start leafIndex treeSize path = some root := ...
```

1. Lean model of the step: `inclusionStep : Nat -> Nat -> StepDecision` mirroring the Rust semantics, in a new formal/lean4/Chio/Chio/Core/MerkleWalk.lean, with `directedProof` converting `(leaf_index, tree_size, audit_path)` into the direction-tagged `ReceiptProof` the existing model consumes.
2. Fold equivalence: iterating `inclusionStep` from `(leafIndex, treeSize)` and interpreting decisions as `nodeHash` applications equals `applyProof` (Core/Receipt.lean:66-73) on the direction-tagged proof whose directions are read off the decisions. Proved by induction on the number of levels.
3. Soundness inheritance: composing (2) with the already-proved `membership_proof_sound` (Proofs/Receipt.lean:27) yields: a proof produced by `membershipProof` on the model tree drives the step-fold to the tree root. Completeness direction (wrong leaf or wrong path fails) is stated over the free `MerkleHash` algebra, where distinct trees have distinct roots by constructor injectivity - and the doc says plainly that transporting that to bytes is exactly ASSUME-SHA256.
4. Kani rebinding: replace the algebraic interior of `verify_oracle_inclusion_walk_parity` with a harness that builds small concrete trees (up to 8 leaves, depth 3), takes a symbolic `leaf_index` and two symbolic hash-relevant bytes per path node, and asserts the real `compute_root_from_hash` accepts exactly when the model fold accepts - the `verify_delegation_chain_step` precedent (assert_eq of model vs real on small symbolic instances).

### Production rewiring (FV-A1 absorption)

`compute_root_from_hash` is rewritten as the thin fold over `inclusion_step`, preserving its exact error behavior (out-of-range, underrun, trailing-path). No caller changes: web3 anchors, anchor bundles, kernel checkpointing, and the diff tests all keep calling `MerkleProof::verify_hash`. The anchored-root diff test then pins the verified core as the Rust oracle the TypeScript implementation is compared against, and the canary leaf hash (anchored_root.rs:21) guards the constant-level behavior.

## Implementation plan

1. Phase 1 - factor and bind (no proof yet).
   - Add `crates/core/chio-core-types/src/merkle_steps.rs` (`InclusionStep`, `inclusion_step`); modify `crates/core/chio-core-types/src/merkle.rs` so `compute_root_from_hash` folds over it; modify `crates/core/chio-core-types/src/lib.rs` for the module.
   - Add the mirror function to `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`; add the Kani mirror-equivalence harness and the rebound inclusion harness in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`; register both in `.kani/harnesses.toml` (lane `pr`).
   - Extend formal/diff-tests/tests/anchored_root_tamper.rs with step-level tamper cases (flipped sibling order at an odd index, padded path, truncated path) if not already covered.
2. Phase 2 - Lean model and fold induction.
   - Add `formal/lean4/Chio/Chio/Core/MerkleWalk.lean` (step model) and `formal/lean4/Chio/Chio/Proofs/MerkleWalk.lean` (fold equivalence, soundness inheritance theorems); modify `formal/lean4/Chio/Chio.lean` root imports and formal/proof-manifest.toml `root_modules`.
3. Phase 3 - Aeneas extraction of the step function.
   - Add a `merkle_walk` target to `formal/aeneas/production.toml`, regenerate the committed `FormalAeneas` snapshots with authenticated tools, and register `Chio.Proofs.generated_inclusion_step_eq_model` in `AeneasGeneratedEquivalence.lean`. The schema-v2 gate derives the exact source, type, function, and theorem inventories from the registry.
4. Phase 4 - mirror-drift hash and absorption completion.
   - Add FV-A4 drift-hash entries binding both `merkle_steps.rs` and its formal-aeneas mirror to the Lean model; document the deletion path once production extraction permits direct extraction from core-types.

## CI and gating changes

- The two new Kani harnesses join the PR lane via `.kani/harnesses.toml` (schema `chio.kani.multi-crate.v1`); the rebound inclusion harness replaces the algebraic one in the same lane so PR cost stays flat.
- `scripts/check-formal-proofs.sh` picks up the new Lean modules automatically once root-imported; sorry-hygiene applies.
- `scripts/check-aeneas-production.sh` checks the registry-driven step-function target, byte-identical generated snapshot, and registered axiom-audited theorem.
- The anchored-root diff test remains in `cargo test -p chio-formal-diff-tests` (already a proof-manifest gate command).

## Acceptance criteria

- [x] `inclusion_step` exists, is called by `compute_root_from_hash`, and merkle.rs behavior is byte-identical (existing merkle tests plus anchored-root canary pass unchanged).
- [x] Kani harness proves real-vs-model step equality over symbolic `(index, size)` up to the documented bound, in the PR lane.
- [x] `verify_oracle_inclusion_walk_parity` no longer free-floats on two booleans; it exercises the real fold on bounded trees.
- [x] Lean fold-equivalence theorem against `applyProof` is proved, root-imported, sorry-free.
- [x] The conditional inheritance lemma composes with `membership_proof_sound`; separate root-imported theorems establish all 36 supported carry-last-node geometries without assuming a decoded-proof equality.
- [x] Aeneas extracts the step mirror into the committed byte-identical snapshot, and the root-imported registered theorem proves the generated machine-integer function against `Chio.Core.inclusionStep` without an external semantic implementation.
- [x] Mirror-drift hashes guard both merkle_steps.rs and its formal_aeneas.rs copy against the same Lean model, with direct equality checked by Kani.
- [x] proof-manifest `covered_rust_symbols` lists `chio_core_types::merkle::MerkleProof::compute_root_from_hash` and `chio_core_types::merkle_steps::inclusion_step`.

## Risks and mitigations

- Refactor changes verifier behavior: mitigated by the tamper diff-tests, the canary leaf hash, and landing phase 1 with zero proof content so review focuses purely on behavior preservation.
- The carry-forward convention (no duplicate-last) is easy to model wrongly: the Lean relation enumerates every index for tree sizes 1 through 8, while Rust tests cross-check the same fixtures against the real builder and retain the existing larger-tree regression coverage.
- Mirror drift between core-types and formal_aeneas.rs: exactly the FV-A4 problem; the drift hash plus the Kani equality harness close it from both directions.
- Overclaiming: this verifies the walk, not the hash and not signature checking. Claim wording must keep P4-END-TO-END disallowed (docs/reference/CLAIM_REGISTRY.md:77); allowed wording is scoped to "the inclusion-proof walk executed by relying parties refines the proved model, with hashes under ASSUME-SHA256".
- `usize` vs `u64`: the step function takes u64; production uses usize. Casts are checked and fail closed on overflow (only reachable on 128-bit-fantasy platforms, but clippy discipline requires it).

## Decisions

- TypeScript keeps its independent implementation. The Rust-TypeScript anchored-root and tamper differentials are the binding until a separately reviewed wasm distribution design exists.
- Lean proves fold equivalence and soundness inheritance over the free hash algebra. Wrong-leaf and malformed-path rejection stays in the concrete Kani and differential lanes because transporting free-constructor completeness to bytes requires ASSUME-SHA256.
- Super-root verification needs no separate binding. It calls the same `MerkleProof::verify_hash` implementation with a different leaf value.
- Eight leaves is the PR Kani bound. A sixteen-leaf nightly bound is deferred until measured solver cost justifies another lane.
- Kani uses fixed proof fixtures for every index at every tree size from 1 through 8 to avoid symbolically expanding allocator internals. A normal Rust test checks the same fixtures against `MerkleTree::from_hashes`, `root`, and `inclusion_proof` before they enter the proof harness. The registry keeps CBMC unwinding assertions enabled for this fold proof.
- The formal-aeneas mirror is temporary but authenticated: it is a production-registry target whose generated snapshot and generated-equivalence theorem are mandatory. Direct extraction from the filtered core-types module will replace it and retire the paired mirror hashes once that source boundary is supported.

## Manifest and registry updates

- formal/proof-manifest.toml: add merkle_steps.rs and the two symbols to `covered_rust_modules` / `covered_rust_symbols`; extend the P4 row in `property_matrix` with the new theorem ids and the rebound public-Kani lane; add the MerkleWalk modules to `root_modules`.
- formal/theorem-inventory.json: entries for the step-model theorems and fold equivalence (`kind: theorem`, `claimClass: bounded_model` for the model-side, the Aeneas equivalence entries mirroring existing `aeneas_*_equiv_model` naming), `mapsTo: ["P4", "P7"]`.
- formal/MAPPING.md: rows for the two new Kani harness names and the retired algebraic harness (marked replaced, not deleted, per the file's audit-trail convention).
- .kani/harnesses.toml and formal/rust-verification/kani-public-harnesses.toml: harness registrations with unwind bounds and timeouts.
- formal/assumptions.toml: unchanged; ASSUME-SHA256 is cited, not modified.
- docs/reference/CLAIM_REGISTRY.md: tighten the P4 allowed wording to name the verified walk; P4-END-TO-END stays disallowed.
