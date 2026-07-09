# FV-A3: Kill the Creusot contract body duplication

- Status: Proposed (2026-07-09)
- Theme: A - Make the proven code the running code
- Effort: S
- Depends on: none
- Feeds: none directly (reduces standing drift risk for [FV-E3](./FV-E3-pr-formal-smoke-tier.md) gates)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4), [FV-A1](./FV-A1-absorb-verified-helpers.md), [FV-A2](./FV-A2-aeneas-generated-equivalence.md), [FV-A4](./FV-A4-mirror-drift-hashes.md)

## Summary

The Creusot lane proves `#[ensures]` postconditions over contract functions in `formal/rust-verification/creusot-core/src/lib.rs` whose bodies duplicate the production `formal_aeneas.rs` logic by hand. If production and contract bodies drift, Creusot keeps proving true things about the stale copy and nobody is told - the exact failure mode gap G4 names, and the registry has already drifted once: the crate holds seven contract functions but `creusot-contracts.toml` lists only six. This document evaluates three de-duplication options and recommends a combination: `include!` the production source into the contracts crate so bodies are single-source (primary), plus a cheap body-identity gate as belt-and-braces, plus fixing the 6-vs-7 registry drift with a completeness check so it cannot recur.

## Motivation and evidence

- Duplication, verified: `formal/rust-verification/creusot-core/src/lib.rs` holds 7 contract functions. Five have bodies token-identical (modulo function name) to their `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` twins: `optional_u32_cap_subset_contract` (line 16), `required_true_preserved_contract` (line 26), `dpop_admits_contract` (line 34), `revocation_snapshot_denies_contract` (line 44), `receipt_fields_coupled_contract` (line 55). Two restate the logic in a different shape: `time_window_valid_contract` (line 4) inlines `issued_at <= now && now < expires_at` where production routes through `classify_time_window_code(..) == 0` (`formal_aeneas.rs:25-27`), and `budget_commit_remaining_contract` (line 11) is a one-dimensional `remaining - cost` shadow of the two-dimensional `budget_commit` (`formal_aeneas.rs:77-101`).
- Registry drift, verified: `formal/rust-verification/creusot-contracts.toml` `covered_symbols` (lines 19-24) lists six `creusot-core` contracts; `revocation_snapshot_denies_contract` is missing. Nothing checks the toml against the crate, so the P2-relevant contract is invisible to the manifest layer today. This is existing gap G4 damage, not a hypothetical.
- The duplication is structural, not accidental: `creusot-core` is a standalone mini-crate (own `[workspace]` in its `Cargo.toml`, `creusot-std` pinned to git rev `a12f3ac7f688c7b93cee2c2eb60282004a2bdb30`, proofs discharged through Why3find with z3/cvc5/alt-ergo/cvc4 [v]). It cannot see `chio-kernel-core` without either depending on it or splicing its source in.
- The lane is a required strict-CI lane (`creusot|required|formal/rust-verification/creusot-contracts.toml` in `formal/proof-manifest.toml` `rust_refinement_lanes`, line 106), and its own `contract_goals` claim the wrappers "verify pure branch conditions shared with chio-kernel-core::formal_core" (`creusot-contracts.toml:33`). "Shared" is currently a manual promise.

## Current state

- `formal/rust-verification/creusot-core/src/lib.rs` (68 lines): `use creusot_std::prelude::*;` then the seven `*_contract` functions with `#[requires]`/`#[ensures]` and hand-copied bodies.
- `formal/rust-verification/creusot-core/Cargo.toml`: `publish = false`, empty `[workspace]` (deliberately outside the main workspace so the pinned Creusot toolchain builds it in isolation), single dependency `creusot-std` at the pinned rev.
- Gates: `scripts/check-creusot-smoke.sh` and `scripts/check-creusot-core.sh` (named as `strict_smoke_command`/`strict_core_command` in the toml); `scripts/check-rust-verification-gates.sh` validates toml schemas and coverage presence, then requires the Creusot toolchain unless `CHIO_RUST_VERIFICATION_METADATA_ONLY=1`.
- No mechanism relates contract bodies to production bodies; no mechanism relates the toml symbol list to the crate contents.

## Design

Three options, evaluated then combined:

| Option | Drift protection | Toolchain risk | Cost | Verdict |
| --- | --- | --- | --- | --- |
| 1. Depend on `chio-kernel-core` | Structural (one copy) | High: Creusot must compile the whole dependency graph on its pinned rustc | M, recurring | Rejected for now |
| 2. `include!` the production source | Structural (one copy) | Low: included file is dependency-free by design | S, one-time | Primary |
| 3. Body-identity gate script | Detective (drift fails CI) | None (pure text processing) | S, one-time | Belt-and-braces |

### Option 1: depend on chio-kernel-core directly

Make `creusot-core` a normal dependent of `chio-kernel-core` and attach contracts to wrappers over `chio_kernel_core::formal_aeneas` items.

Honest feasibility: the Creusot toolchain must compile the entire dependency graph of whatever it verifies. `chio-kernel-core` keeps a portable profile (`./scripts/check-portable-kernel.sh` is a proof-manifest gate command), which helps, but the crate still pulls the core type/crypto graph, and Creusot rides a pinned rustc: every kernel-core dependency bump becomes a potential Creusot-lane breakage, and the standalone `[workspace]` isolation that keeps the lane cheap disappears. The failure mode is chronic toolchain fights in a required CI lane. Rejected for now; worth revisiting if Creusot's std/ecosystem coverage matures.

### Option 2 (primary recommendation): include! the production source

Splice the production file into the contracts crate so there is exactly one copy of every body:

- In `creusot-core/src/lib.rs`: `mod aeneas_body { include!("../../../../crates/kernel/chio-kernel-core/src/formal_aeneas.rs"); }` (path fixed relative to the including file; the crate already lives in-repo so the relative path is stable).
- Each `*_contract` function keeps its `#[requires]`/`#[ensures]` and becomes a thin wrapper whose body is a single delegation call. Before and after, for the DPoP contract:

```rust
// Today (lib.rs:34-41): hand-copied body, can drift from production.
#[ensures(result == (!dpop_required || (proof_present && proof_valid && nonce_fresh)))]
pub fn dpop_admits_contract(dpop_required: bool, proof_present: bool,
                            proof_valid: bool, nonce_fresh: bool) -> bool {
    !dpop_required || (proof_present && proof_valid && nonce_fresh)
}

// After: same contract, production body, zero copies.
#[ensures(result == (!dpop_required || (proof_present && proof_valid && nonce_fresh)))]
pub fn dpop_admits_contract(dpop_required: bool, proof_present: bool,
                            proof_valid: bool, nonce_fresh: bool) -> bool {
    aeneas_body::dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh)
}
```

  Creusot translates the included module as ordinary crate code, so the postcondition is proven against the production body, not a copy.
- Known mechanical wrinkle: `formal_aeneas.rs` opens with the inner attribute `#![allow(dead_code)]` (line 1), which does not survive `include!` into a module body. Fix: delete the inner attribute from `formal_aeneas.rs` and move it to the declaration site as an outer attribute (`#[allow(dead_code)] pub(crate) mod formal_aeneas;` in `crates/kernel/chio-kernel-core/src/lib.rs:65`). Zero semantic change to production; FV-A1's absorption work shrinks the need for the allow anyway.
- The two shape-divergent contracts get resolved rather than papered over:
  - `time_window_valid_contract` delegates to `aeneas_body::time_window_valid`; its existing ensures now pins the real classify-then-compare body. Strictly stronger than today.
  - `budget_commit_remaining_contract` is retired and replaced by `budget_precheck_contract` and `budget_commit_contract` wrapping the real two-dimensional functions, with ensures covering `accepted`, both `remaining_*` fields on the accept branch, and state preservation on the reject branch. If the Why3 encoding of the returned struct fights back, the fallback is field-projection wrappers (`budget_commit_accepted_contract`, `budget_commit_remaining_invocations_contract`, ...) that still call the real `budget_commit`.

Residual risk of Option 2: someone re-inlines a body into a wrapper during a "quick fix" and the single source silently forks again. That is what Option 3 is for.

### Option 3 (belt-and-braces): body-identity gate

New `scripts/check-creusot-body-sync.sh`, wired into `scripts/check-rust-verification-gates.sh` before the strict lane runs (it must also run under `CHIO_RUST_VERIFICATION_METADATA_ONLY=1`, since it needs no toolchain):

- Pre-Option-2 semantics (useful immediately, even if Option 2 slips): for each `*_contract` function, strip `#[requires]`/`#[ensures]`/`#[allow]` attributes and comments, normalize whitespace into a token stream, and compare against the similarly normalized body of its `formal_aeneas` twin via an explicit name map maintained in the script (or in the toml, see registry section). The two shape-divergent functions are listed with an explicit `divergent_body_allowed` marker and a comment explaining why, so the exception is visible instead of implicit.
- Post-Option-2 semantics (steady state): assert every `*_contract` body is exactly one delegation call into `aeneas_body::<twin>` and that the crate contains no other function bodies besides the included module. This is a cheap syntactic check that makes re-forking loud.
- Intended failure output, both modes:

```
creusot-body-sync: BODY DRIFT
  contract: dpop_admits_contract (formal/rust-verification/creusot-core/src/lib.rs)
  twin:     dpop_admits (crates/kernel/chio-kernel-core/src/formal_aeneas.rs)
  The normalized bodies differ. Either restore the delegation call
  (post-dedup: the contract body must be exactly `aeneas_body::dpop_admits(..)`)
  or, if the production semantics changed deliberately, update the contract
  and its #[ensures] in the same PR.
```

### Registry drift fix and completeness check

- Add `formal/rust-verification/creusot-core::revocation_snapshot_denies_contract` to `covered_symbols` in `creusot-contracts.toml` (fixes the observed 6-vs-7 drift).
- Extend the Python block in `scripts/check-rust-verification-gates.sh`: parse `creusot-core/src/lib.rs` for `pub fn *_contract` names and require each to appear in the toml's `covered_symbols` (and vice versa for the `creusot-core::` prefixed entries), failing with the missing name. Symbol-name syncing by grep is consistent with how `check-mapping.sh` already works [v]; content-level syncing across the repo's other mirror seams is FV-A4's job.

## Implementation plan

1. Phase 1: registry repair (no code motion).
   - Modify `formal/rust-verification/creusot-contracts.toml` (add the missing `revocation_snapshot_denies_contract` row).
   - Modify `scripts/check-rust-verification-gates.sh` (contract-name completeness check, both directions).
2. Phase 2: body-identity gate (pre-dedup form).
   - Add `scripts/check-creusot-body-sync.sh` (normalized token-stream comparison, explicit twin map, `divergent_body_allowed` markers for the two known divergent shapes).
   - Modify `scripts/check-rust-verification-gates.sh` (invoke the sync gate in metadata-only and strict modes).
3. Phase 3: single-source the bodies (Option 2).
   - Modify `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` (remove inner `#![allow(dead_code)]`) and `crates/kernel/chio-kernel-core/src/lib.rs` (outer allow on the module declaration).
   - Modify `formal/rust-verification/creusot-core/src/lib.rs` (`include!` module, wrappers become delegation calls, add `budget_precheck_contract`/`budget_commit_contract`, retire `budget_commit_remaining_contract`).
   - Modify `formal/rust-verification/creusot-contracts.toml` (symbol renames/additions) - the phase 1 completeness check forces this to stay in sync.
   - Modify `scripts/check-creusot-body-sync.sh` (flip to the post-Option-2 delegation-only assertion).
4. Phase 4: prove-out.
   - Run the strict lane (`scripts/check-creusot-core.sh`) and fix any Why3 encoding fallout on the struct-returning `budget_commit_contract`, using the field-projection fallback if needed; update `contract_goals` prose in the toml to say bodies are single-sourced.

## CI and gating changes

- `scripts/check-rust-verification-gates.sh` gains two cheap, toolchain-free checks (registry completeness, body sync) that run everywhere the script runs today, including metadata-only mode. No new workflow jobs.
- The strict Creusot lane's proof obligations change only in phase 3 (delegation bodies and the new budget contracts); expect a one-time Why3 re-run cost, no steady-state increase.
- Failure messages must name the exact contract function and its twin, and (post phase 3) print the expected delegation form, so the fix is obvious from CI output alone.

## Acceptance criteria

- [ ] `creusot-contracts.toml` lists all seven (post phase 3: eight, with the budget split and retirement accounted) contract functions; the completeness check fails CI when the crate and toml disagree in either direction.
- [ ] `check-creusot-body-sync.sh` fails on a one-token edit to any contract body that is not mirrored in `formal_aeneas.rs` (demonstrated in the PR with a red run).
- [ ] After phase 3, no logic body exists in `creusot-core/src/lib.rs` outside the included module; every `*_contract` is a single delegation call.
- [ ] `time_window_valid_contract`'s ensures is proven against the real `classify_time_window_code`-based body.
- [ ] `budget_precheck_contract` and `budget_commit_contract` cover the real two-dimensional functions, including reject-branch state preservation.
- [ ] Strict lane (`check-creusot-core.sh`) green; metadata-only mode exercises the new static checks.

## Risks and mitigations

- Creusot may choke on some construct in the included file (the struct return of `budget_commit` is the likely candidate). Mitigation: the included file is 140 lines of trait-free, borrow-free, heap-free code by design [v]; the field-projection fallback keeps single-sourcing even if the struct contract needs decomposing; phase 2's gate already delivers most of the drift protection if phase 3 stalls.
- `include!` path breakage on file moves: a rename of `formal_aeneas.rs` breaks the contracts crate build. Mitigation: that is the desired behavior (loud, immediate); the error names the path.
- Normalization false negatives in the phase 2 gate (two genuinely different bodies normalizing equal). Mitigation: normalization only strips attributes/comments/whitespace, never rewrites tokens; unit-test the normalizer with a known-divergent fixture pair.
- The retirement of `budget_commit_remaining_contract` drops a symbol other registries may reference. Mitigation: grep `formal/` and `docs/` for the symbol in phase 3; `proof-manifest.toml` does not name it today (verified: only `formal_core::budget_commit` appears, line 73).
- Creusot toolchain pin drift (`creusot-std` rev) vs the included production code using newer Rust syntax. Mitigation: the included file is deliberately boring Rust; FV-A1 additions to it inherit the same extraction-safe constraints already enforced by the Aeneas lane greps.

## Open questions

- Should the twin name map live in `creusot-contracts.toml` (machine-readable, next to `covered_symbols`) rather than inside `check-creusot-body-sync.sh`? Leaning toml (`[[contract_twin]]` entries), since FV-A4 establishes the pattern of manifests carrying seam metadata; decide in phase 2.
- Post phase 3, is there still value in the Aeneas-lane grep asserting the 15 symbol names (`scripts/check-aeneas-production.sh:56-77`) also matching the contracts crate, or is that redundant with the delegation-only assertion? Default: leave the lanes independent.
- Does the Creusot pinned rev handle `include!` across the workspace boundary cleanly (macro expansion happens in rustc, so it should)? Verify first thing in phase 3 with a spike before committing to the wrapper rewrite.
- When FV-A1 adds new helpers to `formal_aeneas.rs`, should the completeness check also require a corresponding `*_contract` (forcing the Creusot lane to keep pace), or is Creusot coverage allowed to lag the Aeneas symbol set? Proposed: allowed to lag, tracked as a warning list in the gate output, ratcheted by FV-E5.

## Manifest and registry updates

- `formal/rust-verification/creusot-contracts.toml`: add `revocation_snapshot_denies_contract` (phase 1); rename/add budget contract symbols and update `contract_goals` prose to "single-sourced bodies included from formal_aeneas.rs" (phase 3); optional `[[contract_twin]]` map (open question).
- `formal/proof-manifest.toml`: no structural change; `rust_refinement_lanes` row for creusot is unchanged. If the gate script gains a new invocation name, `gate_commands` stays accurate because the entry point remains `./scripts/check-rust-verification-gates.sh`.
- `formal/MAPPING.md`: not affected (script enforces TLA names and Kani harnesses only); no rows reference the contract functions.
- `docs/reference/CLAIM_REGISTRY.md`: no claim text change required; the `FORM-IMPLEMENTATION-LINKED` evidence list already cites the strict gates, which now mean more.
- `formal/theorem-inventory.json`: not affected (Creusot obligations are not tracked there today); if that changes, it is FV-C5 scope.
