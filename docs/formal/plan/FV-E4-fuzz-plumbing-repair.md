# FV-E4: Fuzz plumbing repair

Status: Proposed (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S
Depends on: none
Feeds: [FV-D4](FV-D4-wasm-noninterference.md) and [FV-B3](FV-B3-budget-conservation-law.md) (new fuzz targets land through this checklist), [FV-E5](FV-E5-lane-ratchets.md) (budget-cap posture), [FV-E1](FV-E1-spec-mutation-testing.md) (co-coverage replays depend on corpora being where the tools look)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G6), `docs/fuzzing/continuous.md`, `docs/fuzzing/mutants.md`, [FV-E3](FV-E3-pr-formal-smoke-tier.md)

## Summary

The fuzz estate's plumbing leaks in seven specific places (gap G6): three orphaned corpus directories hold the richest seeds while the live bin-named directories hold 1-3 files; four targets have no seed corpus at all; the smoke and inventory tests in `fuzz/tests/smoke.rs` run in no CI job; `scripts/check-corpus-metadata.sh` is wired to no workflow; `fuzz/owners.toml` is missing five targets, which breaks `scripts/promote_fuzz_seed.sh` owner resolution; and two workflows plus one doc claim the 1800 min/30d budget cap is a "hard halt" while `scripts/check-fuzz-budget.sh` defaults to warn and no lane sets `GH_FUZZ_BUDGET_CAP_MODE=fail`. Every item is cheap; this document is the exhaustive repair checklist with exact commands, paths, and a verification step per item. It is also the definition of done for future targets: the wasm guard-smith target from FV-D4 and the ledger-ops target from FV-B3 must land with every item on this list satisfied.

## Motivation and evidence

All verified this session:

- Orphans vs live dirs (file counts from `fuzz/corpus/`): `fuzz_canonical_json` (2 files) vs `canonical_json` (3); `fuzz_capability_receipt` (13 rich binding vectors, e.g. `binding-broken_delegation_chain_signature.json`) vs `capability_receipt` (1); `fuzz_manifest_roundtrip` (6) vs `manifest_roundtrip` (1). No `[[bin]]` in `fuzz/Cargo.toml` is named `fuzz_canonical_json`, `fuzz_capability_receipt`, or `fuzz_manifest_roundtrip`; the corresponding bins are `canonical_json`, `capability_receipt`, `manifest_roundtrip`. Note the other `fuzz_`-prefixed corpus dirs are NOT orphans: `fuzz_policy_parse_compile`, `fuzz_sql_parser`, `fuzz_merkle_checkpoint`, `fuzz_tool_action` are real bin names (their sources are the unprefixed `policy_parse_compile.rs` etc.).
- Git history: the orphaned dirs were added in `d2816aa06` ("test: harden production fuzzing baseline", PR #13, the original fuzz baseline); the bin-named dirs arrived later in `e29988889` (PR #288). Legacy bin naming, never migrated; the richer PR #13 seeds have been dead weight since.
- Corpus-less targets (no directory under `fuzz/corpus/` at all): `eval_receipt_bundle`, `federation_trust_establishment`, `underwriting_policy_input`, `revocation_oracle_merkle`. `fuzz/target-map.toml` already declares `seeds = "fuzz/corpus/<target>"` for each (lines 233, 67, 79, 282), pointing at directories that do not exist.
- `fuzz/tests/smoke.rs` contains 13 corpus smoke tests plus two inventory tests (`fuzz_workflow_matrix_matches_cargo_bins` at line 157, `all_matrix_targets_have_declared_smoke_posture` at line 162). `fuzz/` is a standalone cargo workspace excluded from `cargo test --workspace`; no CI job runs any of it.
- `scripts/check-corpus-metadata.sh` enforces one `[[seed]]` entry per corpus file with sha256, source enum, and adversarial class/threat pairing, fail-closed; `grep -rn check-corpus-metadata .github/workflows/` finds nothing.
- `fuzz/owners.toml` maps 20 targets; the workflow matrix has 25. Missing: `wasm_guard_escape`, `fuzz_policy_parse_compile`, `fuzz_sql_parser`, `fuzz_merkle_checkpoint`, `fuzz_tool_action`. `scripts/promote_fuzz_seed.sh` exits with "target not found in fuzz/owners.toml" (line 225) for all five, so a crash in any of them cannot be promoted.
- Budget honesty: `cflite_pr.yml:10` ("the budget script is the hard halt") and `:68-70`, `mutants.yml:16-17` and `:139-141` all claim a hard halt; `scripts/check-fuzz-budget.sh:54` defaults `cap_mode` to warn and lines 110-113 continue on over-cap; no workflow sets `GH_FUZZ_BUDGET_CAP_MODE=fail`. `mutants-nightly` alone sets it explicitly (to warn, `mutants.yml:348`). `docs/fuzzing/continuous.md:18-19,39` repeats the hard-halt claim and its line 60-62 claim that the script "counts only cflite_* minutes" is stale (the script sums five workflows, `check-fuzz-budget.sh:29`).

## Current state

See the evidence list; in short, the fuzz program's execution lanes (cflite_pr, cflite_batch, fuzz.yml, cocoverage) run, but the bookkeeping that makes them trustworthy (corpus resolution, metadata gate, inventory sync, owner resolution, budget posture) is partially disconnected. Each repair below is independent; they can land as one PR or seven small ones (recommended: items 1+2+7 together since they touch the same three files, the rest independently).

## Design

The design is the checklist itself. Each item: action, exact commands/paths, verification step.

### Item 1: merge orphaned corpus dirs into the bin-named dirs

Action: move seeds, keep filenames (collision check first), delete the orphan dirs.

```bash
# Collision check (expect no common names; verified none exist today):
comm -12 <(ls fuzz/corpus/fuzz_canonical_json | sort) <(ls fuzz/corpus/canonical_json | sort)
comm -12 <(ls fuzz/corpus/fuzz_capability_receipt | sort) <(ls fuzz/corpus/capability_receipt | sort)
comm -12 <(ls fuzz/corpus/fuzz_manifest_roundtrip | sort) <(ls fuzz/corpus/manifest_roundtrip | sort)

git mv fuzz/corpus/fuzz_canonical_json/* fuzz/corpus/canonical_json/
git mv fuzz/corpus/fuzz_capability_receipt/* fuzz/corpus/capability_receipt/
git mv fuzz/corpus/fuzz_manifest_roundtrip/* fuzz/corpus/manifest_roundtrip/
rmdir fuzz/corpus/fuzz_canonical_json fuzz/corpus/fuzz_capability_receipt fuzz/corpus/fuzz_manifest_roundtrip
```

Bookkeeping that must follow in the same commit:

- `fuzz/corpus_metadata.toml`: the moved seeds already have `[[seed]]` entries under the OLD target and path (e.g. `target = "fuzz_canonical_json"`, `path = "fuzz/corpus/fuzz_canonical_json/binding-canonical-v1.json"` at lines 265-266); rewrite `target` to the bin name and `path` to the new location for all 21 moved seeds. `sha256` values are unchanged (content did not move).
- `fuzz/target-map.toml`: re-verify `seeds` paths; the three affected targets already point at the bin-named dirs (lines 29, 43, 55), so no edit is expected, but the check is part of the item.

Verification: `bash scripts/check-corpus-metadata.sh` passes (it fails on any un-indexed file or dangling entry, lines 185-201); `cargo +nightly fuzz run canonical_json -- -runs=0 fuzz/corpus/canonical_json` loads all seeds without crashing (repeat for the other two).

### Item 2: seed the four corpus-less targets

Action: create `fuzz/corpus/<target>/` with at least 3 meaningful seeds each, plus `[[seed]]` metadata (`source = "hand_curated_coverage"` for fixtures; adversarial-suite imports use `adversarial_curated` with the mandatory class/threat_id pairing enforced by `check-corpus-metadata.sh:164-183`).

Per-target sourcing, based on what each target parses (read this session):

- `eval_receipt_bundle`: the target passes UTF-8 bytes to `chio_eval_receipt::verify_bundle` as a JSON bundle string. Seeds: serialized bundle fixtures from the `crates/sdk/chio-eval-receipt` unit tests and any sample bundles under `spec/eval/**` (both trigger globs in `target-map.toml:227-232`); one valid bundle, one signature-tampered variant, one truncated JSON.
- `federation_trust_establishment`: `serde_json` decodes of `HandshakeChallenge`, `PeerHandshakeEnvelope`, `FederationPeer`, and `KernelTrustExchange` types. Seeds: `serde_json::to_vec` of values constructed by the `chio-federation` `trust_establishment` unit tests (a 10-line dump helper in a test writes them once); one well-formed envelope, one bad-signature envelope, one stale-freshness peer.
- `underwriting_policy_input`: `serde_json` decodes across `UnderwritingPolicyInputQuery`, `UnderwritingDecisionPolicy`, `UnderwritingSimulationRequest`, `UnderwritingDecisionArtifact`, and friends. Seeds: JSON fixtures from `crates/economy/chio-underwriting` tests and `spec/schemas/underwriting/**` examples; one per major decoded type.
- `revocation_oracle_merkle`: input is an `arbitrary`-derived op sequence (Insert/InclusionProof/NonInclusionProof), so hand-writing the byte encoding is impractical. Seeds: run libFuzzer briefly and minimize:

  ```bash
  cd fuzz
  cargo +nightly fuzz run revocation_oracle_merkle -- -runs=200000
  cargo +nightly fuzz cmin revocation_oracle_merkle
  # commit the minimized handful from fuzz/corpus/revocation_oracle_merkle/
  ```

Verification: `bash scripts/check-corpus-metadata.sh` passes with the new entries; each dir has >= 3 files; `cargo +nightly fuzz run <target> -- -runs=0 fuzz/corpus/<target>` loads them.

### Item 3: wire fuzz/tests/smoke.rs into CI

Action: a CI job runs `cd fuzz && cargo test` (the fuzz workspace's own test lane).

Honest build-cost note: the two inventory tests are pure toml/fs checks at RUNTIME (verified: they only read `fuzz/Cargo.toml` and `.github/workflows/fuzz.yml`, `smoke.rs:104-149`), but they live in the same integration-test binary as the corpus smoke tests, which `use` the fuzz entry points of chio-credentials, chio-kernel-core, chio-wasm-guards, and friends; compiling the binary builds that full dependency set (estimate: 10-20 minutes cold, mostly cached on repeat runs).

Recommendation:

- PR tier, path-scoped: new job in `.github/workflows/formal-pr-smoke.yml` or a small `fuzz-smoke.yml` with `paths: ["fuzz/**", ".github/workflows/fuzz.yml"]`, running `cd fuzz && cargo test --test smoke`. Inventory drift can only be introduced by changes under those paths, so the build cost is paid exactly when it buys signal. At minimum the two inventory-sync tests must run on such PRs; running the whole smoke binary costs nothing extra once it is built.
- Nightly: `cd fuzz && cargo test` joins `nightly.yml` as a `fuzz-smoke` job (catches upstream panics between scheduled fuzz campaigns, which is the corpus smoke tests' stated purpose, `smoke.rs:5-13`).
- Fallback if the PR-tier build cost proves unacceptable in practice: a 40-line `scripts/check-fuzz-inventory.py` mirroring the two inventory tests' parsing, added to the ci.yml structural-gates step; recorded here as fallback only, since duplicating the logic invites drift.

Verification: introduce a deliberate mismatch on a scratch branch (add a `[[bin]]` without a matrix entry); the PR job fails with `fuzz_workflow_matrix_matches_cargo_bins`.

### Item 4: wire scripts/check-corpus-metadata.sh into the required check job

Action: add `bash ./scripts/check-corpus-metadata.sh` to the "Workspace structural gates" step of the required check job in `.github/workflows/ci.yml` (the step at lines 73-95 that already runs the other structural gates). Cost: about a second of python hashing; no toolchain implications.

Verification: corrupt one `sha256` in `fuzz/corpus_metadata.toml` on a scratch branch; the required check fails with the mismatch message.

### Item 5: complete fuzz/owners.toml

Action: add the five missing targets, owners derived from `fuzz/target-map.toml` crate fields:

```toml
[targets.wasm_guard_escape]
crate = "chio-wasm-guards"
path  = "crates/guards/chio-wasm-guards"

[targets.fuzz_policy_parse_compile]
crate = "chio-policy"
path  = "crates/guards/chio-policy"

[targets.fuzz_sql_parser]
crate = "chio-data-guards"
path  = "crates/guards/chio-data-guards"

[targets.fuzz_merkle_checkpoint]
crate = "chio-kernel"
path  = "crates/kernel/chio-kernel"

[targets.fuzz_tool_action]
crate = "chio-guards"
path  = "crates/guards/chio-guards"
```

Verification: two layers. (1) One-off: for each of the five, run `scripts/promote_fuzz_seed.sh` against a scratch crash file and confirm it resolves the owner directory instead of exiting at line 225 (abort before writing, or delete the generated test). (2) Standing: add an inventory test to `fuzz/tests/smoke.rs`, `owners_toml_covers_all_matrix_targets`, asserting every workflow matrix target has an `[targets.<name>]` entry; it rides item 3's CI wiring so the sixth missing target can never happen silently.

### Item 6: budget cap honesty

Action: set `GH_FUZZ_BUDGET_CAP_MODE` explicitly in every lane that calls `scripts/check-fuzz-budget.sh`, and rewrite the comments to match the configured reality. Recommended postures:

| Lane | Setting | Why |
| --- | --- | --- |
| `cflite_batch.yml`, `fuzz.yml` (scheduled) | `fail` | Scheduled batch lanes are the dominant budget consumers and nobody is blocked when they halt; failing closed at the cap is what protects the envelope. |
| `cflite_pr.yml` budget-check | `warn` (explicit) | An over-cap trailing window is almost always caused by scheduled lanes; blocking unrelated PR merges over a 60 s sample lane punishes the wrong actor. The PR lane's own consumption is small and bounded by its 30-minute job timeout. |
| `mutants.yml` mutants-pr (when revived per [FV-E3](FV-E3-pr-formal-smoke-tier.md)) | `warn` (explicit) | Same PR-availability argument; the in-diff scope keeps consumption small. |
| `mutants.yml` mutants-nightly | `warn` (already explicit at line 348) | Deliberate, documented measurement-must-keep-flowing posture; unchanged. |
| `mutants-fuzz-cocoverage.yml` | `warn` (explicit) | Advisory measurement lane by design. |

Comment fixes in the same change: `cflite_pr.yml:10` and `:68-70` ("hard halt" becomes "advisory report; scheduled lanes enforce the cap"); `mutants.yml:16-17` and `:139-141` likewise; `docs/fuzzing/continuous.md:18-19` and `:39` (hard halt applies to scheduled lanes only) and `:60-62` (the script sums cflite_pr, cflite_batch, fuzz, mutants, and mutants-fuzz-cocoverage, per `check-fuzz-budget.sh:29`).

Verification: `grep -rn "check-fuzz-budget" .github/workflows/ | xargs -I{} sh -c '...'` review shows every call site paired with an explicit `GH_FUZZ_BUDGET_CAP_MODE`; run `GH_FUZZ_BUDGET_MINUTES=1 GH_FUZZ_BUDGET_CAP_MODE=fail scripts/check-fuzz-budget.sh` locally and confirm exit 1, then with `=warn` and confirm exit 0 with the warning line.

### Item 7: update declared smoke postures for newly seeded targets

Action: in `fuzz/tests/smoke.rs`, move targets that now have corpora AND an in-process entry point from `NO_CORPUS_SMOKE_TARGETS` (lines 39-52) to `CORPUS_SMOKE_TARGETS` (lines 23-37) and add the `<target>_smoke` test fn. Concretely: `eval_receipt_bundle` qualifies immediately (`chio_eval_receipt::verify_bundle` is directly callable, matching the pattern of the existing 13 smoke fns); `federation_trust_establishment` and `underwriting_policy_input` qualify if the owning crates expose (or gain) a `fuzz::` entry fn like the other smoked crates do; `revocation_oracle_merkle` stays in `NO_CORPUS_SMOKE_TARGETS` with a comment (its input is an `arbitrary`-encoded op stream, not meaningful to replay byte-wise outside libFuzzer), as do the merged targets from item 1 unless their crates expose entry fns. The declared-posture test (`all_matrix_targets_have_declared_smoke_posture`) forces this file to be updated whenever the matrix changes, which is exactly why item 3 must land.

Verification: `cd fuzz && cargo test --test smoke` green; the posture lists and corpus reality agree by construction of that test.

## Implementation plan

1. Phase 1 - corpus consolidation (items 1, 2, 7). Files to modify: `fuzz/corpus_metadata.toml`, `fuzz/tests/smoke.rs`; files to add: `fuzz/corpus/eval_receipt_bundle/*`, `fuzz/corpus/federation_trust_establishment/*`, `fuzz/corpus/underwriting_policy_input/*`, `fuzz/corpus/revocation_oracle_merkle/*`; files to remove: the three orphan dirs (contents moved via `git mv`).
2. Phase 2 - gates (items 4, 5). Files to modify: `.github/workflows/ci.yml` (one line in the structural-gates step), `fuzz/owners.toml`, `fuzz/tests/smoke.rs` (owners inventory test).
3. Phase 3 - CI wiring for the fuzz test lane (item 3). Files to add or modify: `.github/workflows/formal-pr-smoke.yml` (new path-scoped job) or `.github/workflows/fuzz-smoke.yml`; `.github/workflows/nightly.yml` (nightly `fuzz-smoke` job).
4. Phase 4 - budget posture (item 6). Files to modify: `.github/workflows/cflite_batch.yml`, `.github/workflows/fuzz.yml`, `.github/workflows/cflite_pr.yml`, `.github/workflows/mutants.yml`, `.github/workflows/mutants-fuzz-cocoverage.yml`, `docs/fuzzing/continuous.md`.
5. Phase 5 - close the loop: update `docs/formal/GAP_ANALYSIS.md` G6 status; record in `docs/fuzzing/continuous.md` that this checklist is the definition of done for new targets (FV-D4's `wasm_guard_smith`, FV-B3's ledger-ops target).

## CI and gating changes

- Required check job gains one cheap structural gate (`check-corpus-metadata.sh`), the only change to a required context in this document.
- New path-scoped PR job and nightly job for the fuzz workspace tests (advisory by virtue of not being ruleset-required; [FV-E5](FV-E5-lane-ratchets.md) can promote the PR job once stable).
- Budget-cap env made explicit in five workflows; scheduled batch lanes become genuinely fail-closed at the cap, matching the fail-closed house rule.
- No changes to fuzz execution lanes themselves (cflite build scripts, oss-fuzz mirrors) beyond corpus paths already handled by item 1's bookkeeping; `.clusterfuzzlite/build.sh` and `fuzz/oss-fuzz/build.sh` reference targets, not corpus dirs, and need no edit (re-verify during phase 1 per `target-map.toml:8-10`'s lockstep note).

## Acceptance criteria

- [ ] No directory under `fuzz/corpus/` fails to match a `[[bin]]` name in `fuzz/Cargo.toml` (item 1).
- [ ] All 25 matrix targets have a corpus dir with >= 3 seeds OR a documented posture exception in `smoke.rs` (items 2, 7; `revocation_oracle_merkle`'s minimized set may be smaller if cmin produces fewer, with a comment).
- [ ] `bash scripts/check-corpus-metadata.sh` runs in the required check job and passes (item 4).
- [ ] `cd fuzz && cargo test` runs in CI on fuzz-touching PRs and nightly; the inventory tests plus the new owners test are among them (items 3, 5).
- [ ] `fuzz/owners.toml` covers all 25 targets; `promote_fuzz_seed.sh` resolves each (item 5).
- [ ] Every `check-fuzz-budget.sh` call site sets `GH_FUZZ_BUDGET_CAP_MODE` explicitly; no workflow or doc claims a hard halt where warn is configured (item 6).
- [ ] The three formerly orphaned seed sets (2 + 13 + 6 files) are loaded by their targets in a `-runs=0` replay (item 1 verification).
- [ ] G6 in `docs/formal/GAP_ANALYSIS.md` updated to point here with status.

## Risks and mitigations

- Moved seeds crash their targets (they were never actually run against current code). Mitigation: that is signal, not risk; triage as ordinary fuzz findings, and land the move even if some seeds get quarantined into `fuzz/corpus_quarantine/` with metadata (better than dead orphan dirs).
- The fuzz workspace test build is slow enough to annoy PR authors. Mitigation: path-scoped so only fuzz-touching PRs pay; `Swatinem/rust-cache` on the fuzz workspace; fallback python inventory check specified in item 3.
- Enforcing `fail` on scheduled batch lanes silences fuzzing for the rest of a window after a budget spike. Mitigation: intended behavior (the cap exists to stay inside the public-repo free tier per `docs/fuzzing/continuous.md:18-19`); the warn-mode measurement lanes keep the dashboard alive, and the cap value remains tunable via `GH_FUZZ_BUDGET_MINUTES`.
- corpus_metadata edits are fiddly by hand (21 path/target rewrites). Mitigation: a 15-line one-off python script in the PR description (not committed) or careful sed; `check-corpus-metadata.sh` catches every mistake fail-closed, which is the point of item 4 landing in the same effort.
- Owners for the five added targets drift from `target-map.toml` crates. Mitigation: the standing owners inventory test cross-checks names; crate fields are copied from target-map, the single source that cflite already trusts.

## Open questions

- Should `fuzz/corpus_quarantine/` (for seeds that crash on load) be formalized in `check-corpus-metadata.sh`'s schema now or only if item 1 actually surfaces crashers? Proposal: only if needed.
- Does the nightly fuzz-smoke job belong in `nightly.yml` or `fuzz.yml`? `fuzz.yml` groups it with fuzz execution but its schedule (03:23) predates the corpus smoke purpose; either works, decide at phase 3.
- Item 2's fixture-dump helpers: commit them as `#[test] #[ignore]` writers in the owning crates, or keep them in the PR description only? Committed ignored writers make reseeding reproducible; mild clutter. Proposal: commit them.

## Manifest and registry updates

- `fuzz/corpus_metadata.toml`: 21 entries rewritten (item 1), new entries for every added seed (item 2).
- `fuzz/owners.toml`: five new target tables (item 5).
- `fuzz/target-map.toml`: verify-only (seeds paths already correct for the merged targets); new targets from FV-D4/FV-B3 must add their table here plus owners, metadata, smoke posture, and budget-lane membership per this checklist.
- `fuzz/tests/smoke.rs`: posture lists updated (item 7), owners inventory test added (item 5).
- `docs/fuzzing/continuous.md` and `docs/fuzzing/mutants.md`: budget posture table and corrected workflow-sum claim (item 6).
- `docs/formal/GAP_ANALYSIS.md`: G6 closure note.
