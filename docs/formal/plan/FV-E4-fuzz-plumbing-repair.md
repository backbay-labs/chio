# FV-E4: Fuzz plumbing repair

Status: Proposed (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S
Depends on: none
Feeds: [FV-D4](FV-D4-wasm-noninterference.md) and [FV-B3](FV-B3-budget-conservation-law.md) (new fuzz targets land through this checklist), [FV-E5](FV-E5-lane-ratchets.md) (budget-cap posture), [FV-E1](FV-E1-spec-mutation-testing.md) (co-coverage replays depend on corpora being where the tools look)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G6), `docs/fuzzing/continuous.md`, `docs/fuzzing/mutants.md`, [FV-E3](FV-E3-pr-formal-smoke-tier.md)

## Summary

The fuzz estate's plumbing leaks in seven specific places (gap G6): three orphaned corpus directories hold the richest seeds while the live bin-named directories hold 1-3 files; four targets have no seed corpus at all; the smoke and inventory tests in `fuzz/tests/smoke.rs` run in no CI job; `scripts/check-corpus-metadata.sh` is wired to no workflow; `fuzz/owners.toml` is missing five targets, which breaks `scripts/promote_fuzz_seed.sh` owner resolution; and the budget-cap contract (PR lanes hard halt, scheduled lanes advisory) is written into the docs, the workflow comments, and a dedicated contract test, yet neither PR budget step sets `GH_FUZZ_BUDGET_CAP_MODE`, `scripts/check-fuzz-budget.sh` defaults to warn, and the contract test runs in no CI job. Every item is cheap; this document is the exhaustive repair checklist with exact commands, paths, and a verification step per item. It is also the definition of done for future targets: the wasm guard-smith target from FV-D4 and the ledger-ops target from FV-B3 must land with every item on this list satisfied.

## Motivation and evidence

All verified this session:

- Orphans vs live dirs (file counts from `fuzz/corpus/`): `fuzz_canonical_json` (2 files) vs `canonical_json` (3); `fuzz_capability_receipt` (13 rich binding vectors, e.g. `binding-broken_delegation_chain_signature.json`) vs `capability_receipt` (1); `fuzz_manifest_roundtrip` (6) vs `manifest_roundtrip` (1). No `[[bin]]` in `fuzz/Cargo.toml` is named `fuzz_canonical_json`, `fuzz_capability_receipt`, or `fuzz_manifest_roundtrip`; the corresponding bins are `canonical_json`, `capability_receipt`, `manifest_roundtrip`. Note the other `fuzz_`-prefixed corpus dirs are NOT orphans: `fuzz_policy_parse_compile`, `fuzz_sql_parser`, `fuzz_merkle_checkpoint`, `fuzz_tool_action` are real bin names (their sources are the unprefixed `policy_parse_compile.rs` etc.).
- Git history: the orphaned dirs were added in `d2816aa06` ("test: harden production fuzzing baseline", PR #13, the original fuzz baseline); the bin-named dirs arrived later in `e29988889` (PR #288). Legacy bin naming, never migrated; the richer PR #13 seeds have been dead weight since.
- Corpus-less targets (no directory under `fuzz/corpus/` at all): `eval_receipt_bundle`, `federation_trust_establishment`, `underwriting_policy_input`, `revocation_oracle_merkle`. `fuzz/target-map.toml` already declares `seeds = "fuzz/corpus/<target>"` for each (lines 233, 67, 79, 282), pointing at directories that do not exist.
- `fuzz/tests/smoke.rs` contains 13 corpus smoke tests plus two inventory tests (`fuzz_workflow_matrix_matches_cargo_bins` at line 157, `all_matrix_targets_have_declared_smoke_posture` at line 162). `fuzz/` is a standalone cargo workspace excluded from `cargo test --workspace`; no CI job runs any of it.
- `scripts/check-corpus-metadata.sh` enforces one `[[seed]]` entry per corpus file with sha256, source enum, and adversarial class/threat pairing, fail-closed; `grep -rn check-corpus-metadata .github/workflows/` finds nothing.
- `fuzz/owners.toml` maps 20 targets; the workflow matrix has 25. Missing: `wasm_guard_escape`, `fuzz_policy_parse_compile`, `fuzz_sql_parser`, `fuzz_merkle_checkpoint`, `fuzz_tool_action`. `scripts/promote_fuzz_seed.sh` exits with "target not found in fuzz/owners.toml" (line 225) for all five, so a crash in any of them cannot be promoted.
- Budget honesty: the contract is PR-hard-halt, scheduled-advisory. `cflite_pr.yml:10` ("the budget script is the hard halt") and `:68-70`, `mutants.yml:16-17` and `:139-141`, and `docs/fuzzing/continuous.md:18-19,39` state it, and `scripts/tests/fuzz-budget-hard-halt.test.sh` enforces the wording (it rejects an explicit warn on either PR budget step and requires the hard-halt text). But `scripts/check-fuzz-budget.sh:54` defaults `cap_mode` to warn (lines 110-113 continue on over-cap), neither PR budget step sets the variable at all, and the contract test is invoked by no workflow, so effective behavior is warn everywhere. The four scheduled lanes set warn explicitly and deliberately (`cflite_batch.yml:47`, `fuzz.yml:96`, `mutants.yml:348`, `mutants-fuzz-cocoverage.yml:110`). Separately, `continuous.md:60-62`'s claim that the script "counts only cflite_* minutes" is stale (the script sums five workflows, `check-fuzz-budget.sh:29`).

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

The contract here is already decided; the defect is that it is not enforced in behavior. `docs/fuzzing/continuous.md:18-19,39` and both PR budget-step comments (`cflite_pr.yml:68-70`, `mutants.yml:139-141`) say PR-time budget gates hard halt because they are release qualification signals, the four scheduled lanes deliberately opt into warn for measurement continuity, and a dedicated contract test (`scripts/tests/fuzz-budget-hard-halt.test.sh`) rejects an explicit warn on either PR budget step and requires the hard-halt wording. Meanwhile neither PR budget step sets `GH_FUZZ_BUDGET_CAP_MODE` at all, so the script's warn default (`check-fuzz-budget.sh:54`) applies, and the contract test itself is invoked by no workflow. The absence-of-warn check is vacuous against a warn default.

Action: make behavior match the contract instead of rewording the contract to match behavior.

| Lane | Setting | Why |
| --- | --- | --- |
| `cflite_pr.yml` budget-check | `fail` (explicit, new) | PR-time fuzz is a release qualification signal; the step's own comment, `continuous.md`, and the contract test already promise a hard halt. |
| `mutants.yml` mutants-pr (when revived per [FV-E3](FV-E3-pr-formal-smoke-tier.md)) | `fail` (explicit, new) | Same contract; the contract test checks exactly this block. |
| `cflite_batch.yml:47`, `fuzz.yml:96`, `mutants.yml:348` (nightly), `mutants-fuzz-cocoverage.yml:110` | `warn` (already explicit) | Deliberate, documented measurement-must-keep-flowing posture; unchanged. |

In the same change: harden `scripts/tests/fuzz-budget-hard-halt.test.sh` to require the explicit `GH_FUZZ_BUDGET_CAP_MODE: fail` on both PR budget steps (not merely the absence of warn), and wire it into the required check job's structural-gates step alongside the other `scripts/tests/*.test.sh` invocations (`ci.yml:82-123`). The only comment fix left is `docs/fuzzing/continuous.md:60-62`, whose claim that the script "counts only cflite_* minutes" is stale (the script sums five workflows, `check-fuzz-budget.sh:29`).

Availability note: an over-cap trailing window is usually consumed by the scheduled lanes, and a hard halt on the PR gate then blocks fuzz-scoped PRs until the window drains. That trade is the documented, tested contract choice. If it proves too aggressive in practice, the escape is a deliberate contract revision (continuous.md, both step comments, and the contract test changed together in one PR), never a silent divergence between comment and configuration.

Verification: `bash scripts/tests/fuzz-budget-hard-halt.test.sh` passes and appears in `ci.yml`; removing either PR step's `fail` setting makes it fail locally; `GH_FUZZ_BUDGET_MINUTES=1 GH_FUZZ_BUDGET_CAP_MODE=fail scripts/check-fuzz-budget.sh` exits 1, and with `=warn` exits 0 with the warning line.

### Item 7: update declared smoke postures for newly seeded targets

Action: in `fuzz/tests/smoke.rs`, move targets that now have corpora AND an in-process entry point from `NO_CORPUS_SMOKE_TARGETS` (lines 39-52) to `CORPUS_SMOKE_TARGETS` (lines 23-37) and add the `<target>_smoke` test fn. Concretely: `eval_receipt_bundle` qualifies immediately (`chio_eval_receipt::verify_bundle` is directly callable, matching the pattern of the existing 13 smoke fns); `federation_trust_establishment` and `underwriting_policy_input` qualify if the owning crates expose (or gain) a `fuzz::` entry fn like the other smoked crates do; `revocation_oracle_merkle` stays in `NO_CORPUS_SMOKE_TARGETS` with a comment (its input is an `arbitrary`-encoded op stream, not meaningful to replay byte-wise outside libFuzzer), as do the merged targets from item 1 unless their crates expose entry fns. The declared-posture test (`all_matrix_targets_have_declared_smoke_posture`) forces this file to be updated whenever the matrix changes, which is exactly why item 3 must land.

Verification: `cd fuzz && cargo test --test smoke` green; the posture lists and corpus reality agree by construction of that test.

## Implementation plan

1. Phase 1 - corpus consolidation (items 1, 2, 7). Files to modify: `fuzz/corpus_metadata.toml`, `fuzz/tests/smoke.rs`; files to add: `fuzz/corpus/eval_receipt_bundle/*`, `fuzz/corpus/federation_trust_establishment/*`, `fuzz/corpus/underwriting_policy_input/*`, `fuzz/corpus/revocation_oracle_merkle/*`; files to remove: the three orphan dirs (contents moved via `git mv`).
2. Phase 2 - gates (items 4, 5). Files to modify: `.github/workflows/ci.yml` (one line in the structural-gates step), `fuzz/owners.toml`, `fuzz/tests/smoke.rs` (owners inventory test).
3. Phase 3 - CI wiring for the fuzz test lane (item 3). Files to add or modify: `.github/workflows/formal-pr-smoke.yml` (new path-scoped job) or `.github/workflows/fuzz-smoke.yml`; `.github/workflows/nightly.yml` (nightly `fuzz-smoke` job).
4. Phase 4 - budget posture (item 6). Files to modify: `.github/workflows/cflite_pr.yml`, `.github/workflows/mutants.yml` (PR budget steps gain explicit `fail`), `scripts/tests/fuzz-budget-hard-halt.test.sh` (require the explicit fail), `.github/workflows/ci.yml` (wire the contract test), `docs/fuzzing/continuous.md` (stale five-workflow sum note only). Scheduled lanes are untouched.
5. Phase 5 - close the loop: update `docs/formal/GAP_ANALYSIS.md` G6 status; record in `docs/fuzzing/continuous.md` that this checklist is the definition of done for new targets (FV-D4's `wasm_guard_smith`, FV-B3's ledger-ops target).

## CI and gating changes

- Required check job gains one cheap structural gate (`check-corpus-metadata.sh`), the only change to a required context in this document.
- New path-scoped PR job and nightly job for the fuzz workspace tests (advisory by virtue of not being ruleset-required; [FV-E5](FV-E5-lane-ratchets.md) can promote the PR job once stable).
- Both PR budget steps become genuinely fail-closed at the cap, matching their own documented contract and the fail-closed house rule; the four scheduled lanes keep their explicit advisory posture; the hardened contract test joins the required check job.
- No changes to fuzz execution lanes themselves (cflite build scripts, oss-fuzz mirrors) beyond corpus paths already handled by item 1's bookkeeping; `.clusterfuzzlite/build.sh` and `fuzz/oss-fuzz/build.sh` reference targets, not corpus dirs, and need no edit (re-verify during phase 1 per `target-map.toml:8-10`'s lockstep note).

## Acceptance criteria

- [ ] No directory under `fuzz/corpus/` fails to match a `[[bin]]` name in `fuzz/Cargo.toml` (item 1).
- [ ] All 25 matrix targets have a corpus dir with >= 3 seeds OR a documented posture exception in `smoke.rs` (items 2, 7; `revocation_oracle_merkle`'s minimized set may be smaller if cmin produces fewer, with a comment).
- [ ] `bash scripts/check-corpus-metadata.sh` runs in the required check job and passes (item 4).
- [ ] `cd fuzz && cargo test` runs in CI on fuzz-touching PRs and nightly; the inventory tests plus the new owners test are among them (items 3, 5).
- [ ] `fuzz/owners.toml` covers all 25 targets; `promote_fuzz_seed.sh` resolves each (item 5).
- [ ] Both PR budget steps set `GH_FUZZ_BUDGET_CAP_MODE: fail` explicitly; the four scheduled lanes keep their explicit `warn`; `scripts/tests/fuzz-budget-hard-halt.test.sh` requires the explicit fail settings and runs in the required check job (item 6).
- [ ] The three formerly orphaned seed sets (2 + 13 + 6 files) are loaded by their targets in a `-runs=0` replay (item 1 verification).
- [ ] G6 in `docs/formal/GAP_ANALYSIS.md` updated to point here with status.

## Risks and mitigations

- Moved seeds crash their targets (they were never actually run against current code). Mitigation: that is signal, not risk; triage as ordinary fuzz findings, and land the move even if some seeds get quarantined into `fuzz/corpus_quarantine/` with metadata (better than dead orphan dirs).
- The fuzz workspace test build is slow enough to annoy PR authors. Mitigation: path-scoped so only fuzz-touching PRs pay; `Swatinem/rust-cache` on the fuzz workspace; fallback python inventory check specified in item 3.
- Hard-halting the PR budget gates means an over-cap trailing window (usually consumed by the scheduled lanes) blocks fuzz-scoped PRs until the window drains. Mitigation: this is the contract the repository already documents and tests for (`cflite_pr.yml:68-70`, `scripts/tests/fuzz-budget-hard-halt.test.sh`); the cap stays tunable via `GH_FUZZ_BUDGET_MINUTES`, the warn-mode scheduled lanes keep the dashboard alive, and if the trade proves too aggressive the escape is a deliberate one-PR contract revision (docs, comments, and contract test together), never a silent divergence between comment and configuration.
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
