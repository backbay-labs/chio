# FV-A4: Content-hash the manual mirror seams

- Status: Proposed (2026-07-09)
- Theme: A - Make the proven code the running code
- Effort: S-M
- Depends on: none (complements [FV-A2](./FV-A2-aeneas-generated-equivalence.md))
- Feeds: [FV-E3](./FV-E3-pr-formal-smoke-tier.md), [FV-C5](./FV-C5-proof-coverage-map.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4, G1), [FV-A3](./FV-A3-creusot-dedup.md), [FV-E5](./FV-E5-lane-ratchets.md)

## Summary

Every Lean model file that says "Mirrors: <rust file>" is a manual transliteration seam: when the Rust side changes, nothing tells the author a Lean mirror exists, and nothing tells the reviewer the mirror was not looked at. The proof lanes that would notice run nightly at best and need heavyweight toolchains. This document adds a content-hash tripwire that runs on every PR with no Lean, no Charon, and no Why3: the proof manifest records a normalized hash of the exact Rust symbols each mirror transliterates, and a new `cargo xtask check formal-mirrors` gate fails the PR when a hashed symbol changes without a deliberate re-bless. The gate does not prove equivalence (that is FV-A2's job for the Aeneas lane, nightly); it proves that a human was forced to look at the named mirror before the change merged.

## Motivation and evidence

- The pointer layer has already rotted, which demonstrates that nothing enforces it. Verified this session:
  - `formal/lean4/Chio/Chio/Core/Capability.lean:4` says `Mirrors: chio-kernel-core/src/capability.rs`. No such file exists; the mirrored types live under `crates/core/chio-core-types/src/capability/` (the subset predicates it models are in `capability/scope.rs`, `is_subset_of` impls at lines 29, 97, 175, 195).
  - `formal/lean4/Chio/Chio/Core/Scope.lean:3` names the same nonexistent `chio-kernel-core/src/capability.rs` for `ToolGrant::is_subset_of` and `ChioScope::is_subset_of`.
  - `formal/lean4/Chio/Chio/Core/Revocation.lean:3` says `Mirrors: chio-kernel/src/lib.rs (check_revocation, validate_delegation_chain)`; `check_revocation` actually lives in `crates/kernel/chio-kernel/src/kernel/validation.rs:441`.
  - `formal/lean4/Chio/Chio/Core/Receipt.lean:3-5` cites `chio-kernel-core/src/receipt.rs`; the file is `receipts.rs`.
  - `formal/lean4/Chio/Chio/Core/Protocol.lean` (the model file behind the DPoP, budget, guard, and receipt-coupling proofs) contains no `Mirrors:` annotation at all.
- Gap G4: the same decision logic exists in up to four handwritten copies (runtime, `formal_aeneas.rs`, Creusot contract bodies, Lean models), each pair a drift channel. FV-A2 and FV-A3 remove two channels structurally; the Rust-to-Lean-model channel cannot be removed (the model is deliberately not the code) so it must be tripwired.
- Gap G1: there is no PR-time proof gate at all today. Full Lean builds on every PR are the expensive answer (FV-E3 owns that tradeoff); a hash comparison is milliseconds and catches the dominant failure mode, which is not "the proof broke" but "nobody re-read the proof".
- The wiring precedent exists: `.github/workflows/ci.yml:101` runs `cargo xtask check crate-paths` as a required PR step [v: verified this session], and the xtask check family is set up for exactly this kind of gate (`xtask/src/cli.rs:156-157` registers `CheckCommand::CratePaths`, dispatched at `xtask/src/dispatch.rs:30`).
- `scripts/check-mapping.sh` already enforces name-level presence (TLA invariant names and `#[kani::proof]` fn names must have `formal/MAPPING.md` rows [v]), and `formal/proof-manifest.toml` syncs by symbol name only, with no content hashes [v]. Names catch additions and deletions; only content hashes catch edits.

## Current state

- Lean model files carry best-effort `Mirrors:` comment headers (see the rotted examples above); TLA modules carry "Code mapping" comment blocks [v]. Both are prose for humans; no tool reads them.
- `formal/proof-manifest.toml` (`schema = "chio.proof-manifest.v1"`) has `covered_rust_modules` and `covered_rust_symbols` lists but no notion of which model file transliterates which symbol, and no hashes.
- The only content hashing in the formal tree is the Aeneas lane's artifact report (`scripts/check-aeneas-equivalence.sh` hashes source and generated files into `target/formal/aeneas-production/equivalence-artifacts.json`), which is nightly-only and covers one seam.
- xtask exists with a `check` noun group, clap subcommands, and per-check modules (e.g. `xtask/src/crate_paths.rs`).

## Design

### Manifest schema: [[mirror]] entries

New section in `formal/proof-manifest.toml`:

```toml
[[mirror]]
lean_file = "formal/lean4/Chio/Chio/Core/Scope.lean"
rust_source = "crates/core/chio-core-types/src/capability/scope.rs"
rust_symbols = ["ChioScope::is_subset_of", "ToolGrant::is_subset_of", "ResourceGrant::is_subset_of", "PromptGrant::is_subset_of"]
normalized_sha256 = "<64 hex chars>"
```

- One entry per (lean_file, rust_source) pair; a model that mirrors two Rust files (Receipt.lean does) gets two entries:

```toml
[[mirror]]
lean_file = "formal/lean4/Chio/Chio/Core/Receipt.lean"
rust_source = "crates/kernel/chio-kernel-core/src/receipts.rs"
rust_symbols = ["sign_receipt", "ChioReceipt::verify_signature"]
normalized_sha256 = "<64 hex chars>"

[[mirror]]
lean_file = "formal/lean4/Chio/Chio/Core/Receipt.lean"
rust_source = "crates/kernel/chio-kernel/src/checkpoint.rs"
rust_symbols = ["..."]  # confirmed at seeding time
normalized_sha256 = "<64 hex chars>"
```
- `rust_symbols` are item paths resolvable by a Rust parser: free functions (`check_revocation`), inherent methods (`Type::method`), types (`BudgetUsageRecord`). Order matters: the hash is over the concatenation of the normalized symbols in listed order.
- `normalized_sha256` is one rollup hash per entry. On mismatch, the checker recomputes per-symbol digests against a `--bless`-time sidecar it derives on the fly, so the failure message still names the exact symbol that moved; persisting per-symbol hashes in the manifest was considered and rejected as noise (it roughly quadruples the section for no additional enforcement power; revisit if entries grow past a handful of symbols each).
- When phase 2 adds TLA seams, the schema generalizes `lean_file` to `model_file` plus `model_kind = "lean" | "tla"` with a manifest `schema` note; the seed phase keeps the task-shaped `lean_file` key to avoid designing for a consumer that does not exist yet.

### Normalization and hashing

`xtask/src/formal_mirrors.rs`:

1. Parse `rust_source` with `syn`, locate each named item (walking impl blocks for `Type::method` paths; fail loudly on ambiguity, e.g. the same method name in an inherent and a trait impl).
2. Normalize by printing the item's token stream (`proc-macro2` printing already discards comments and collapses whitespace) after stripping `#[doc = ...]` attributes, so comment and doc edits never trip the gate but any token-level change to signatures or bodies does.
3. SHA-256 the concatenated normalized strings; compare against `normalized_sha256`.

Granularity tradeoff, decided: symbol-level, not file-level. File-level hashing (hash the whole `rust_source`) is simpler but fires on every unrelated edit to shared files: `capability/scope.rs` and `kernel/validation.rs` are large, busy files where most edits have nothing to do with the mirrored predicates, and a gate that cries wolf gets `--bless`ed reflexively, which destroys its value. Symbol-level hashing fires only when a transliterated symbol actually changes, which keeps every firing meaningful. The cost is symbol resolution logic in the xtask (bounded, since `syn` does the parsing) and the requirement to keep `rust_symbols` accurate when items are renamed - which is itself desirable, because a rename that orphans a mirror entry fails the gate with "symbol not found", exactly the review moment we want.

### Check and bless flow

- `cargo xtask check formal-mirrors`: recompute all entries, exit nonzero on any mismatch or unresolvable symbol.
- Failure message (load-bearing; this is the whole UX):

```
formal-mirrors: MIRROR DRIFT in crates/core/chio-core-types/src/capability/scope.rs
  changed symbol:  ToolGrant::is_subset_of
  lean mirror:     formal/lean4/Chio/Chio/Core/Scope.lean
  This Rust symbol is hand-transliterated into the Lean model above.
  1. Review the Lean mirror and update it if the semantics changed.
  2. Run: cargo xtask check formal-mirrors --bless
  3. Commit the proof-manifest.toml diff together with your change.
  Semantic equivalence for the Aeneas lane is checked nightly (FV-A2);
  this gate only certifies that the mirror was reviewed.
```

- `cargo xtask check formal-mirrors --bless`: recompute and rewrite the `normalized_sha256` fields in place (via `toml_edit` to preserve manifest formatting and comments), printing a summary of which entries changed. The blessed manifest diff rides the same PR, so the reviewer sees "decision code changed AND the author attested to reviewing the mirror" as one unit. A bless with no accompanying Lean edit is reviewable as exactly that claim: "semantics unchanged, mirror still accurate".

### Relationship to FV-A2

Complementary, not overlapping. A4 is syntactic and universal: every PR, every seam, milliseconds, no toolchain, proves review happened. A2 is semantic and narrow: the Aeneas lane's generated-code equivalence, machine-checked in Lean, nightly, proves the transliteration is actually correct for those 15 symbols. A4 firing tells you to go look; A2 failing tells you what is wrong. Once A2's committed snapshots exist, they can be registered as `[[mirror]]` entries too (Rust source -> committed generated Lean), unifying the drift story under one gate; noted as an open question in FV-A2 and tracked there.

## Implementation plan

1. Phase 1: xtask gate.
   - Add `xtask/src/formal_mirrors.rs` (parse, normalize, hash, compare, `--bless` via `toml_edit`).
   - Modify `xtask/src/cli.rs` (register `CheckCommand::FormalMirrors` with `#[command(name = "formal-mirrors")]` and a `--bless` flag, next to `CratePaths` at lines 156-157) and `xtask/src/dispatch.rs` (dispatch arm next to line 30).
   - Modify `xtask/Cargo.toml` (add `syn`, `proc-macro2`, `sha2`, `toml_edit` if not already present).
   - Unit tests in `xtask/src/formal_mirrors.rs` with fixture snippets: doc-comment edit does not change the hash, body token edit does, ambiguous symbol errors.
2. Phase 2: seed the manifest and repair the headers.
   - Modify `formal/proof-manifest.toml`: seed `[[mirror]]` entries for the five highest-value model files, with corrected paths (the seeding pass confirms each symbol's current home before recording it):
     - `Core/Capability.lean` -> `crates/core/chio-core-types/src/capability/` items it models (CapabilityToken and its validity check, scope/grant/constraint types).
     - `Core/Scope.lean` -> `crates/core/chio-core-types/src/capability/scope.rs` (`is_subset_of` family) and `crates/kernel/chio-kernel-core/src/normalized.rs` (normalized subset logic).
     - `Core/Revocation.lean` -> `crates/kernel/chio-kernel/src/kernel/validation.rs` (`check_revocation`) and the delegation-chain validation it names (`chio_core::capability::attenuation::validate_delegation_chain`, called at `validation.rs:471`).
     - `Core/Protocol.lean` -> `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` (the pure decisions it models; today it has no mirror pointer at all).
     - `Core/Receipt.lean` -> `crates/kernel/chio-kernel-core/src/receipts.rs` and `crates/kernel/chio-kernel/src/checkpoint.rs`.
   - Modify the five Lean files' `Mirrors:` headers to the corrected paths, with a one-line note that the enforced pointer is the `[[mirror]]` entry in `formal/proof-manifest.toml` (headers stay as human convenience).
   - Run `--bless` to record the initial hashes.
3. Phase 3: CI wiring.
   - Modify `.github/workflows/ci.yml`: add `run: cargo xtask check formal-mirrors` in the required PR check job, next to the `cargo xtask check crate-paths` step at line 101.
4. Phase 4 (follow-up scope): TLA seams.
   - Extend the schema (`model_file`/`model_kind`), seed entries from the "Code mapping" comment blocks in `formal/tla/RevocationPropagation.tla` and the `formal/apalache/` modules, pointing at the Rust paths their `formal/MAPPING.md` rows constrain.
   - This phase deliberately trails phase 1-3 by enough time to observe the gate's false-positive rate on the Lean seams first.

## CI and gating changes

- One new required PR step in `.github/workflows/ci.yml` (phase 3), sub-second runtime, no toolchain beyond the workspace's existing Rust.
- No change to nightly lanes; the Lean/TLA/Kani/Creusot gates are unaffected. The division of labor is explicit: PR = hash tripwire (this doc), nightly = semantic proof lanes (FV-A2 and existing gates), with FV-E3 later deciding what else is cheap enough to promote to PR time.
- The gate must run in the same job as other xtask checks to avoid a new job's fixed overhead.
- `--bless` is a local-only flow; CI never blesses. A CI failure always means "the manifest in this PR does not match this PR's code".

## Acceptance criteria

- [ ] `cargo xtask check formal-mirrors` exists, passes on a clean tree, and its unit tests cover the doc-edit/body-edit/ambiguity cases.
- [ ] A token-level edit to any seeded symbol (e.g. `ToolGrant::is_subset_of`) fails CI with a message naming the symbol, the Lean mirror file, and the bless command (demonstrated with a red run in the seeding PR).
- [ ] A doc-comment-only edit to a seeded symbol does not fail the gate.
- [ ] All five seed model files have corrected, manifest-backed mirror pointers; the four stale headers and Protocol.lean's missing header are fixed in the same PR.
- [ ] `--bless` rewrites only `normalized_sha256` values and preserves manifest formatting.
- [ ] The bless flow is documented in this file and referenced from `formal/OWNERS.md`.
- [ ] Symbol rename or deletion of a mirrored item fails with "symbol not found" rather than passing silently.

## Risks and mitigations

- Reflexive blessing: if the gate fires too often on semantically irrelevant changes, authors will `--bless` without reading. Mitigations: symbol-level granularity (the design's main defense), doc-attribute stripping, and a quarterly look at bless frequency per entry (FV-E5's ratchet reviews are the natural home); if an entry blesses weekly, its symbol list is too coarse and gets split.
- Hash-only certifies review, not correctness: a wrong Lean edit plus a bless passes. Accepted by design; the semantic backstop is the nightly proof lanes and FV-A2. The failure message says this out loud so nobody mistakes the gate for an equivalence check.
- `syn` resolution fragility (macro-generated items, `cfg`-gated duplicates, trait-vs-inherent method ambiguity). Mitigations: seed symbols are all plain fns/methods/types today; the checker refuses ambiguity loudly rather than guessing; anything genuinely unresolvable stays out of the manifest and is listed in Open questions for that seam.
- Normalization too weak (token printing normalizes some things reviewers care about, e.g. it keeps literals but a `u32`->`u64` type change in a signature is a token change, which is correct) or too strong. Mitigation: fixtures pin the intended sensitivity; changes to the normalizer itself re-bless everything and are reviewed as such.
- Manifest merge conflicts on `normalized_sha256` when two PRs touch the same seeded file. Mitigation: conflicts are the correct behavior (both authors must re-review the mirror); rollup-hash-per-entry keeps the conflict a one-line resolve after re-running `--bless`.

## Open questions

- Should the gate also hash the Lean side (mirror file hash recorded next to the Rust hash) so a Lean-only edit to a model also forces a bless, keeping the attestation bidirectional? Cheap to add; deferred to phase 2 review because Lean edits already get proof-lane scrutiny.
- `Core/Capability.lean` mirrors a family of types across several files under `crates/core/chio-core-types/src/capability/`; is one `[[mirror]]` entry per rust file the right decomposition, or should closely-coupled files share an entry? Decide during seeding with the real symbol list in hand.
- Exact seed symbol list for `Protocol.lean`: all 15 `formal_aeneas.rs` symbols, or only the eight model-only ones until FV-A1 absorbs them? Leaning all 15 (the file models the whole pure core), with the note that FV-A1 phases will bless as they touch.
- Does `xtask` already carry `syn`/`toml_edit` (it has a codegen module)? Confirm in phase 1 before adding dependencies.
- Phase 4 TLA extension: hash the Rust side only (as with Lean), or also the TLA "Code mapping" blocks themselves so the comment blocks stop rotting the way the Lean headers did?

## Manifest and registry updates

- `formal/proof-manifest.toml`: new `[[mirror]]` section (seed entries above); a `notes` line stating the section is enforced by `cargo xtask check formal-mirrors`; schema version note if the manifest consumer cares about unknown sections (verify `check-proof-report.sh` tolerance in phase 2).
- `formal/OWNERS.md`: add a line assigning the formal-mirrors gate and the bless-review expectation (a blessed hash change in a PR is a review obligation for the formal owner set).
- `formal/MAPPING.md`: unaffected mechanically (its script greps TLA/Kani names); add a short cross-reference in its prose so authors adding new model files learn that mirrors are registered in the manifest, not just in headers.
- `docs/reference/CLAIM_REGISTRY.md`: no claim change; this gate is process evidence, not proof evidence.
- `formal/theorem-inventory.json`: unaffected.
- Lean model files: corrected `Mirrors:` headers (phase 2) with pointer to the manifest section.
