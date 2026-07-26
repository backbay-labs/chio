# FV-A4: Content-hash the manual mirror seams

- Status: Implemented (2026-07-09)
- Theme: A - Make the proven code the running code
- Effort: S-M
- Depends on: none
- Feeds: [FV-E3](./FV-E3-pr-formal-smoke-tier.md),
  [FV-C5](./FV-C5-proof-coverage-map.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md),
  [FV-A3](./FV-A3-creusot-dedup.md),
  [FV-E5](./FV-E5-lane-ratchets.md)

## Summary

`cargo xtask check formal-mirrors` now fails when a Rust item registered as a
manual Lean transliteration or a TLA+ abstraction anchor changes without a
deliberate manifest bless. The required PR job runs the gate beside the
existing crate-path check and needs no Lean, Charon, Kani, or Why3 toolchain.

The proof manifest contains 57 `[[mirror]]` entries covering 171 Rust symbol
references across seven Lean models and seven TLA+ models. Every entry
records an ordered rollup and a digest for each symbol. The per-symbol digests
let a failure name the exact changed item; the rollup binds symbol order and
the complete entry.

This is review evidence, not an equivalence proof. A successful bless means a
reviewer must compare the named Rust item with the named model relationship.
TLA+ hashes explicitly do not claim that Rust enforces the modeled property.
Nightly proof lanes remain the semantic backstop.

## Decisions

- Persist per-symbol SHA-256 digests alongside the rollup. A rollup alone
  cannot identify which input changed without relying on Git history, so the
  earlier rollup-only design could not provide truthful diagnostics.
- Normalize parser tokens at symbol granularity. Ordinary comments and
  whitespace disappear during parsing; `#[doc = ...]` attributes are removed
  recursively. Signatures, bodies, literals, and non-doc attributes remain.
- Resolve free items and types by name, and methods by `Type::method`. Multiple
  matching impl methods fail as ambiguous, including an inherent method and a
  trait method with the same self type and name.
- Hash each method inside a clone of its containing impl with other items
  removed. Impl attributes, trait path, self type, generics, and where clause
  therefore participate, so moving or disabling an impl cannot bypass review.
- Build the rollup from length-prefixed normalized token streams in the listed
  order. Length prefixes avoid ambiguous concatenations while preserving the
  manifest's explicit ordering contract.
- Hash the Rust side only. Model-only edits already enter their proof or
  model-checking review path; forcing a hash bless for them would add ceremony
  without detecting Rust-side orphaning.
- Split Capability by its three actual source files. A combined directory or
  file-level hash would fire on unrelated edits and encourage reflexive blesses.
- Seed Protocol against the nine directly corresponding items in
  `formal_core.rs` and the private `finish_verified_evaluation` body that
  applies the projected guard decision. The extraction facade and runtime
  stores contain broader surfaces that the bounded Lean model does not
  transliterate directly.
- Hash `consult_revocation_view_at` directly for the Revocation Lean mirror
  and alongside its public wrapper for the `RevocationCutCompleteness`
  abstraction anchor. Wrapper-only hashing would miss changes to the lazy
  token and ancestor lookup decision.
- Seed Receipt against receipt bodies, signing, Merkle operations, and
  checkpoints. `ChioReceipt::verify_signature` lives in `receipt/body.rs`, not
  the kernel-core signing wrapper named in the earlier example.
- Generalize the schema to `model_file`, `model_kind`, and `relationship`.
  Lean entries require `lean` plus `transliteration`; TLA+ entries require
  `tla` plus `abstraction_anchor`. Invalid combinations fail closed.
- Repair TLA+ code mappings before hashing them. `ReceiptBeforeAllow` now maps
  persistence and response construction, `KernelTransitionCancelSafe` maps
  the drop guard, states that snapshot equality is by construction rather than
  a proof of Rust reversal, and is scoped to clean pre-dispatch cancellation.
  Revocation liveness names model fairness rather than a nonexistent runtime
  assumption.
- Register MonotoneLog storage code only as abstraction anchors. The SQLite
  items enforce append and transaction structure, but no registered Rust item
  enforces strictly increasing timestamps. The model-clock ordering remains
  bounded by `ASSUME-OS-CLOCK` and `ASSUME-SQLITE-ATOMICITY`.

## Manifest Schema

Each entry identifies one model/source pair:

```toml
[[mirror]]
model_file = "formal/lean4/Chio/Chio/Core/Scope.lean"
model_kind = "lean"
relationship = "transliteration"
rust_source = "crates/core/chio-core-types/src/capability/scope.rs"
rust_symbols = ["ToolGrant::is_subset_of", "ChioScope::is_subset_of"]
normalized_sha256 = "<entry rollup>"
symbol_sha256 = [
  { symbol = "ToolGrant::is_subset_of", sha256 = "<symbol digest>" },
  { symbol = "ChioScope::is_subset_of", sha256 = "<symbol digest>" },
]
```

TLA+ entries use the same hashes with an explicit abstraction relationship:

```toml
[[mirror]]
model_file = "formal/apalache/RevocationCutCompleteness.tla"
model_kind = "tla"
relationship = "abstraction_anchor"
rust_source = "crates/kernel/chio-kernel/src/kernel/delegation.rs"
rust_symbols = ["consult_revocation_view", "consult_revocation_view_at"]
normalized_sha256 = "<entry rollup>"
symbol_sha256 = [
  { symbol = "consult_revocation_view", sha256 = "<symbol digest>" },
  { symbol = "consult_revocation_view_at", sha256 = "<symbol digest>" },
]
```

The gate rejects absolute or non-normalized paths, missing files, duplicate
model/source pairs, empty or duplicate symbols, reordered per-symbol records,
invalid digests, missing symbols, and ambiguous methods. All entries resolve
and hash before a bless writes once, so a late failure cannot partially update
the manifest.

## Seed Inventory

| Lean model | Rust source | Symbols |
| --- | --- | --- |
| Capability | `capability/scope.rs` | `Operation`, `Constraint`, `ToolGrant`, `ChioScope` |
| Capability | `capability/attenuation.rs` | `Attenuation`, `DelegationLink` |
| Capability | `capability/token.rs` | `CapabilityToken`, validity and expiry methods |
| Scope | `capability/scope.rs` | raw tool and scope subset methods |
| Scope | `kernel-core/normalized.rs` | normalized tool and scope subset methods |
| Revocation | `kernel/validation.rs` | `ChioKernel::check_revocation` |
| Revocation | `capability/attenuation.rs` | `validate_delegation_chain` |
| Revocation | `kernel/delegation.rs` | `consult_revocation_view_at` |
| Revocation | `kernel-core/evaluate.rs` | `evaluate` |
| Protocol | `kernel-core/formal_core.rs` | 9 pure budget, admission, guard, revocation, and receipt items |
| Protocol | `kernel-core/evaluate.rs` | `finish_verified_evaluation` |
| Receipt | `kernel-core/receipts.rs` | `sign_receipt` |
| Receipt | `receipt/body.rs` | receipt body, receipt, signature verification |
| Receipt | `merkle.rs` | 10 tree and inclusion-proof items |
| Receipt | `checkpoint.rs` | 7 checkpoint and inclusion-proof items |
| MerkleWalk | `merkle_steps.rs` | scalar step decision and transition |
| MerkleWalk | `kernel-core/formal_aeneas.rs` | extraction-safe scalar step mirror |

The TLA+ inventory adds 24 entries and 44 symbol references:

| TLA+ model | Rust surfaces |
| --- | --- |
| RevocationPropagation | validation and async evaluation; receipt persistence; revocation view and freshness; gossip; scope attenuation; SQLite receipt append |
| MonotoneLogApalache | receipt persistence and SQLite receipt append |
| RevocationCutCompleteness | revocation validation, delegation view consultation, and revocation snapshot/view lookup |
| ReceiptBeforeAllow | allow-response construction and receipt persistence |
| KernelTransitionCancelSafe | post-admission drop guard and pre-execution budget reversal |
| PostAdmissionDropGuard | post-admission drop guard, runtime reservation disposition, and response finalization |

The seven Lean headers and seven TLA+ Code mapping blocks name the registered
paths and point authors to the manifest entries. Source-specific symbol lists
remain authoritative; adding a new model or expanding an abstraction requires
a new or updated entry.

## Check And Bless Flow

Normal check:

```bash
cargo xtask check formal-mirrors
```

After reviewing and, when needed, updating the model:

```bash
cargo xtask check formal-mirrors --bless
```

Blessing changes only `normalized_sha256` and the per-symbol `sha256` values.
The manifest path, model path, source path, symbol order, and surrounding
formatting are preserved. CI never blesses.

A token change reports the source, exact symbol, model, relationship-specific
review guidance, and bless command:

```text
formal-mirrors: MIRROR DRIFT in crates/kernel/chio-kernel-core/src/formal_core.rs
  lean mirror:     formal/lean4/Chio/Chio/Core/Protocol.lean
  changed symbol:  budget_precheck
  1. Review the Lean mirror and update it if the semantics changed.
  2. Run: cargo xtask check formal-mirrors --bless
```

## Implementation

1. `xtask/src/formal_mirrors.rs` parses Rust with `syn`, resolves items, removes
   doc attributes, computes hashes, reports drift, and performs one-shot
   formatting-preserving blesses with `toml_edit`.
2. The xtask CLI and dispatcher expose `check formal-mirrors [--bless]` with a
   dedicated fail-closed error category.
3. `formal/proof-manifest.toml` contains 57 entries and 171 symbol
   digests. The seven Lean mirror headers and seven TLA+ Code mapping blocks use
   corrected repository paths.
4. The required CI job runs the checker next to `check crate-paths`.
5. `formal/OWNERS.md` assigns bless review, and `formal/MAPPING.md` directs new
   manual seams to the manifest.
6. The no-`tomllib` fallback in `scripts/check-formal-proofs.sh` ignores the
   mirror array-of-tables after parsing the top-level fields it consumes.
7. The TLA+ mapping rows name exact implementation anchors, explicit model
   assumptions, and exclusions where the Rust surface is narrower than the
   model.

## CI And Gating Changes

- The existing required `Build, lint, test` job runs
  `cargo xtask check formal-mirrors` on every pull request and push to main.
- The gate adds no new job or fixed runner overhead.
- `--bless` is local-only. A CI mismatch always compares the submitted source
  with the submitted manifest.
- Nightly Lean, Aeneas, Creusot, Kani, and model-checking lanes are unchanged.

## Acceptance Criteria

- [x] `cargo xtask check formal-mirrors` passes with the seeded manifest.
- [x] Unit tests cover doc and ordinary-comment stability, body and attribute
  sensitivity, impl-header sensitivity, self-type method resolution,
  ambiguity, symbol order, missing symbols, exact drift diagnostics, and
  formatting-preserving blessing.
- [x] A live token-only edit to `budget_precheck` fails and names
  `budget_precheck`, `Protocol.lean`, and the bless command.
- [x] Doc-comment-only edits do not change a symbol digest.
- [x] All five seed model files have corrected, manifest-backed mirror paths.
- [x] `--bless` changes only hash values and preserves manifest formatting.
- [x] `formal/OWNERS.md` documents the bless-review obligation.
- [x] A missing or renamed item fails with `symbol not found`.
- [x] The schema supports `model_file` and `model_kind`, and validates the
  relationship between Lean transliterations and TLA+ abstraction anchors.
- [x] `RevocationPropagation.tla` and all five `formal/apalache/` modules have
  manifest-backed Code mapping blocks with exact Rust items.
- [x] TLA+ drift diagnostics state that matching hashes do not claim Rust
  enforces the modeled property.
- [x] A live token-only edit to `consult_revocation_view` fails and names the
  symbol, `RevocationCutCompleteness.tla`, and the abstraction-anchor limit.
- [x] `finish_verified_evaluation` and `consult_revocation_view_at` have direct
  Lean transliteration entries rather than relying on public wrapper hashes.
- [x] The `RevocationCutCompleteness` delegation entry hashes both the public
  wrapper and its private target-aware semantic body.
- [x] MonotoneLog documents the model-clock assumption boundary, revocation
  liveness names model-only fairness, and cancellation safety records its
  by-construction snapshot equality while excluding post-dispatch and fault
  cleanup.

## Risks And Mitigations

- Authors may bless without reviewing. The gate is symbol-granular, ignores
  doc-only edits, and makes every hash diff a formal-owner review obligation.
- Hashes prove review, not correctness. Diagnostics and documentation state
  that limit; TLA+ entries are labeled abstraction anchors and semantic proof
  lanes remain authoritative.
- Macro-generated, nested-module, associated-item, or const-only seams may not
  resolve. The checker fails rather than guessing. Such surfaces require an
  explicit resolver extension before registration.
- Two branches changing the same entry may conflict on hash lines. That is the
  correct signal: the later branch must re-review and re-bless against the
  integrated source.

## Manifest And Registry Updates

- `formal/proof-manifest.toml`: 57 `[[mirror]]` entries, an enforcement note,
  relationship labels, and the checker in `gate_commands`.
- `formal/OWNERS.md`: mirror hash and bless-review responsibility.
- `formal/MAPPING.md`: cross-reference to the mirror registry and checker.
- `formal/theorem-inventory.json`: unchanged; no theorem status changed.
- `docs/reference/CLAIM_REGISTRY.md`: unchanged; review evidence does not
  license a proof claim.
