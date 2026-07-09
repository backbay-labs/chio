# FV-E1: Mutation testing for the specs and proof lanes

Status: Proposed (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: M
Depends on: none to start (seeded by the 2 existing negative tests); substantially stronger after [FV-B2](FV-B2-regression-negative-tests.md)
Feeds: [FV-E5](FV-E5-lane-ratchets.md) (the spec-mutants lane gets a ratchet entry), [FV-C5](FV-C5-proof-coverage-map.md) (kill rates join the coverage map), [FV-B1](FV-B1-drop-guard-model.md) (the new drop-guard spec joins the mutation set)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G5), [FV-B2](FV-B2-regression-negative-tests.md), [FV-A3](FV-A3-creusot-dedup.md), `formal/apalache/_negative_tests/README.md`, `docs/fuzzing/mutants.md`

## Summary

The mutation-testing estate scores production code against the unit suite, but deliberately excludes the formal files: `crates/kernel/chio-kernel-core/mutants.toml` (lines 29-32) skips `formal_aeneas.rs`, `formal_core.rs`, and both Kani harness files with the rationale "covered by the proof lane", and nothing ever measures whether the proof lane would actually kill mutants there (gap G5). This document proposes co-coverage for proofs, directly analogous to the in-repo cross-oracle precedent `scripts/mutants-fuzz-cocoverage.sh` (which replays the fuzz corpus against surviving cargo-mutants mutants nightly): mutate the spec and proof-owned artifacts, run the proof lane as the killer, and report a kill rate. Three sub-lanes: TLA action mutation checked by Apalache, cargo-mutants over the excluded formal Rust files with the Kani lane as the test oracle, and (stretch) a Lean model-sensitivity pilot. A surviving mutant is a vacuous proof lead: a guard, comparison, or definition that no invariant, harness, or theorem actually constrains.

## Motivation and evidence

- The exclusion is explicit and unmeasured. `crates/kernel/chio-kernel-core/mutants.toml:29-32` excludes the four formal files with "covered by the proof lane"; the workspace config `.cargo/mutants.toml:180-183` repeats the exclusion. The claim that the proof lane covers them has never been tested by mutation ([../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), G5).
- The repo already knows this failure mode. `formal/apalache/_negative_tests/README.md` exists precisely because "a real bug must produce a real counterexample": two hand-written broken spec variants (`ReceiptBeforeAllowBroken.tla`, `RevocationCutCompletenessBroken.tla`) demonstrate non-tautology for 2 of the 6 model-checked specs. They are manual, local-only, and cover a fixed pair of mutations. FV-E1 lane 1 is the mechanical generalization of that discipline.
- The precedent for "second oracle kills survivors" is in-tree and running nightly: `scripts/mutants-fuzz-cocoverage.sh` re-shells `cargo mutants` per survivor with `--file <path> --line <n>` and a custom `--test-tool` wrapper that runs the fuzz corpus against the mutated tree (lines 268-277), for 4 crates with a default of 200000 replay runs (`.github/workflows/mutants-fuzz-cocoverage.yml`). Lane 2 below reuses the exact same cargo-mutants machinery with Kani as the oracle.
- The broader mutation estate is weak enough that proof-lane vacuity would hide indefinitely: the trust-boundary baseline of 2026-04-29 measured a 30.7% kill rate (excluding unviable) against an 80% activation target (`docs/fuzzing/trust-boundary-mutants-baseline.toml`), and the gate is advisory (`releases.toml` has `observed_consecutive_nightly_successes = 0` and an empty `cycle_end_tag`, so `scripts/mutants-gate.sh` exits 0).

## Current state

- Specs: 6 production model-checked specs run in `.github/workflows/apalache-safety.yml` (matrix at lines 66-73, `--length=6`): `MonotoneLogApalache`, `RevocationCutCompleteness`, `ReceiptBeforeAllow`, `KernelTransitionCancelSafe` under `formal/apalache/`, plus `RevocationPropagation` and `DelegationDepthBound` under `formal/tla/`. `formal/apalache/README.md` states a 30-minute per-invariant timeout in CI (line 18).
- Negative tests: 2 broken variants under `formal/apalache/_negative_tests/`, run by hand. [FV-B2](FV-B2-regression-negative-tests.md) proposes the fail-unless-violation wrapper that makes an expected-counterexample run CI-safe; lane 1 reuses that wrapper shape.
- Proof-owned Rust files in chio-kernel-core: `formal_core.rs` (15+ pure `pub fn` helpers), `formal_aeneas.rs` (15 fns), `kani_harnesses.rs` (12 `#[kani::proof]` harnesses), `kani_public_harnesses.rs` (20 harnesses). `scripts/check-kani-core.sh` runs all 32 harnesses via `cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks` (line 11).
- cargo-mutants is pinned to the 25.x line (`.github/workflows/mutants.yml:118-123`). Config surface verified this session: `additional_cargo_test_args` exists in `.cargo/mutants.toml:43`; `--config <file>` is how the mutants-pr job loads a focused per-crate config (`mutants.yml:184`); `--test-tool <cmd>` is used in production by `scripts/mutants-fuzz-cocoverage.sh:268-277`, whose header (lines 37-39) records that `--test-tool` is documented in cargo-mutants 25.x as the substitution point for non-`cargo test` workflows. A custom test command is therefore natively available in the pinned tool; no wrapper hack is required.
- Lean: 22 `.lean` modules under `formal/lean4/Chio` (no mathlib dependency), built by `scripts/check-formal-proofs.sh` (lake build + sorry scan + manifest cross-ref).

## Design

### Rule zero: never mutate the checked property

All three lanes mutate the system under verification (actions, model definitions, mirrored helpers), never the property being checked. Mutating an invariant definition, a `#[kani::proof]` assertion, or a theorem statement is meaningless: the run would then check a different property, telling us nothing about the sensitivity of the real one. Concretely: in TLA, only action definitions reachable from `Next` are mutable; `Init` and every operator named in the cfg's `INVARIANT`/`TEMPORAL` lines (and their transitive definitions) are off-limits for the pilot. In Rust, the mutable set is the model/helper functions; `assert!`/`kani::assume` lines inside harness bodies are excluded by operator choice (see lane 2). The mutator enforces this with an explicit per-spec allowlist, fail-closed: an action name not on the allowlist is never touched.

### Lane 1: TLA action mutation (Apalache as killer)

New script `scripts/spec-mutants.py` (python3, stdlib only, same conventions as `scripts/check-apalache-formal-slice.py`).

- Mutant generation is line-based and operator-driven, applied only inside allowlisted action definitions:
  1. delete one conjunct from an action guard (a line beginning `/\ ` that is not a primed assignment),
  2. flip one comparison operator (`<` <-> `<=`, `>` <-> `>=`, `=` <-> `/=`),
  3. swap `TRUE`/`FALSE` where either literal appears in an action definition.
- Per-spec allowlist lives in a small TOML block at the top of the script or in `formal/apalache/spec-mutants-allowlist.toml` (preferred; reviewable next to the specs), listing `spec -> [action names]`. Seeding: the two hand-written negative tests tell us which mutation classes must be killable for `ReceiptBeforeAllow` and `RevocationCutCompleteness`; the generated set must subsume them (acceptance criterion below).
- Worked example of the three operators against a schematic action (illustrative shape, not a quote from a spec):

  ```tla
  \* original
  Revoke(a, c) ==
    /\ rev_epoch[a][c] = 0            \* site for operator 2: flip = to /=
    /\ c \in granted[a]               \* site for operator 1: delete this conjunct
    /\ rev_epoch' = [rev_epoch EXCEPT ![a][c] = epoch + 1]
    /\ UNCHANGED <<granted>>

  \* mutant (operator 1, guard-conjunct deletion): Revoke fires even for
  \* capabilities never granted; a sound completeness invariant must notice.
  ```

  Operator 3 (TRUE/FALSE swap) applies wherever an action definition uses a boolean literal, e.g. a `cancel_pending' = FALSE` reset becoming `TRUE`.
- Execution: for each sampled mutant, write the mutated module to a temp dir together with the untouched cfg and `Common.tla`, then run `apalache-mc check --length=4 --config=<cfg> <mutated.tla>` with a hard per-mutant wall cap (default 300 s). Expected outcome is a violation (non-zero exit with a counterexample). Verdicts:
  - `killed`: Apalache reports an invariant violation or deadlock attributable to the mutation,
  - `unviable`: the type checker or parser rejects the mutant (excluded from the denominator, mirroring cargo-mutants' Unviable),
  - `survived`: the check passes clean; the invariant does not depend on the mutated guard. This is the vacuity signal.
  - `timeout`: counted separately, not in the kill denominator, logged for bound tuning.
- Deterministic sampling, no wall-clock randomness: the full mutant set is enumerated exhaustively and ordered; the nightly sample of K mutants is chosen by `random.Random(int(git_head_sha[:16], 16))`. The same commit always yields the same sample, so a red night is reproducible locally with `scripts/spec-mutants.py --sample-from-head`.
- Report: `target/formal/spec-mutants-report.json`, schema `chio.spec-mutants-report.v1`, uploaded as a workflow artifact. Shape:

  ```json
  {
    "schema": "chio.spec-mutants-report.v1",
    "sample_seed": "dbb4639e1c0ffee0",
    "mutants": [
      {"spec": "ReceiptBeforeAllow", "action": "Allow", "operator": "delete_conjunct",
       "line": 41, "verdict": "killed", "apalache_exit": 12, "wall_secs": 74}
    ],
    "aggregate": {"sampled": 16, "killed": 14, "survived": 1, "unviable": 1,
                   "timeout": 0, "kill_rate_excluding_unviable": 93.3}
  }
  ```
- Budget math (estimates, to be re-measured in phase 1): 6 specs, roughly 20-30 allowlisted actions total, about 3 mutation sites per action, so an estimated 60-100 mutants in the full set. At `--length=4` a per-check run is expected well under the 300 s cap for these small state spaces (the production checks run at `--length=6` inside a 180-minute job for all 6 specs). A nightly sample of K=16 mutants at a worst-case 5 minutes each is 80 minutes plus a 2-minute Apalache install, which fits inside the existing 180-minute nightly envelope as a separate job scheduled off the 07:23 UTC apalache-safety cron. The full set cycles in 4-6 nights.

### Lane 2: proof-lane mutation of the excluded formal files (Kani as killer)

Primary path (native custom test command):

- New config `formal/rust-verification/formal-mutants.toml` with `examine_globs` listing exactly `crates/kernel/chio-kernel-core/src/formal_core.rs` and `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` (workspace-rooted, per the discovery rules documented in `.cargo/mutants.toml:3-9`), and no exclusion of them. Loading it via `--config` follows the exact mechanism `mutants.yml:184` already uses.
- New wrapper `scripts/kani-mutant-killer.sh`: runs the `scripts/check-kani-core.sh` invocation (`cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks`, all 32 harnesses). Invocation:

  ```bash
  cargo mutants \
    --config formal/rust-verification/formal-mutants.toml \
    --package chio-kernel-core \
    --test-tool scripts/kani-mutant-killer.sh \
    --no-shuffle --jobs 1 \
    --output target/formal/proof-mutants --json
  ```

- cargo-mutants runs its baseline first (the wrapper against the unmutated tree). Keep the baseline: a red Kani lane on the clean tree must abort the run rather than mis-score every mutant as caught. Fail-closed.
- The harness files themselves (`kani_harnesses.rs`, `kani_public_harnesses.rs`) join `examine_globs` in a second phase, with assertion-line mutations filtered out per rule zero (mutating a harness body's setup code is meaningful; mutating its `assert!` is not). Phase 1 covers only the two model files, where every mutation is meaningful.
- Fallback path, explicitly marked as fallback: if the pinned 25.x build rejects the `--config` + `--test-tool` combination for this scope (settled by the phase-1 smoke below), enumerate with `cargo mutants --list --diff --config formal/rust-verification/formal-mutants.toml --package chio-kernel-core`, apply each printed diff in a scratch worktree, run `scripts/check-kani-core.sh`, and record the kill in the same report schema. Slower to implement and loses cargo-mutants' outcomes.json, so it is not the plan of record.
- Budget math (estimates): 30 functions across the two files, several mutants per function, so an estimated 100-200 mutants. One full-lib Kani run per mutant at an estimated 3-6 minutes (the 20 public harnesses alone are about 2.2 minutes locally per the note in `formal/rust-verification/kani-public-harnesses.toml:51-53`) puts the full set at 5-20 hours: too big for one night. Nightly runs a sha-seeded sample of K=15 (same sampling function as lane 1), roughly 60-90 minutes, cycling the full set in about 10 nights.
- Why cargo test cannot be the killer here: the Kani harness files are `#[cfg(kani)]`-gated and never compile under `cargo test`; `formal_core.rs` carries `#![allow(dead_code)]` and much of it is unreferenced by production code (gap G2). The proof lane is the only oracle that even builds this code, which is exactly why measuring it matters.
- Creusot stretch: same trick over `formal/rust-verification/creusot-core/src/lib.rs` (7 contract functions) with `scripts/check-creusot-core.sh` as the `--test-tool`. Gated behind the nightly formal-qualification job because the Creusot toolchain install (git clone + opam + `./INSTALL`, `nightly.yml:277-286`) dominates cost; weekly cadence is enough for 7 functions.

Success metric for lane 2: proof-lane kill rate on the formal files >= 90% (excluding unviable). Every survivor is triaged as a vacuous-proof lead: either a helper nobody proves anything about (candidate for deletion or for a new harness) or a harness whose assumptions are too strong.

### Lane 3 (stretch): Lean model sensitivity

Scope honestly: Lean mutation tooling does not exist off the shelf, and building a term-level mutator is out of scope. The pilot is a small python mutator over a whitelist of `def` sites in `formal/lean4/Chio/Chio/Core/*.lean` (computable model definitions only, never `theorem`/`lemma`/`axiom` per rule zero): flip a comparison in a def body, swap `&&`/`||`, swap `true`/`false`. Kill condition: `lake build` fails somewhere (a theorem depending on the def no longer elaborates). A mutant that still builds means no theorem constrains that definition, which is a model-sensitivity gap worth a manual look. Runs inside the nightly formal-qualification job where elan/lake are already installed and cached; sample K=5 per night. Deliverable is a pilot report appended to `target/formal/spec-mutants-report.json` under a `lean` key, not a ratchet.

## Implementation plan

1. Phase 1 - TLA lane pilot (files to add: `scripts/spec-mutants.py`, `formal/apalache/spec-mutants-allowlist.toml`, `scripts/tests/spec-mutants.test.sh`).
   - Implement enumeration + sampling + verdicts + report writer.
   - Allowlist the 4 `formal/apalache/` specs first; require that the generated set subsumes the two `_negative_tests` mutations (assert in the self-test by generating and matching).
   - Measure real per-mutant wall time at `--length=4`; tune K.
2. Phase 2 - wire the TLA lane into nightly (files to modify: `.github/workflows/apalache-safety.yml` gains a `spec-mutants` job on the schedule trigger only, advisory, uploading the report artifact; alternatively a new `.github/workflows/spec-mutants.yml` if the job list gets crowded; recommendation: same file, since it shares the Apalache install steps).
3. Phase 3 - Kani co-coverage lane (files to add: `formal/rust-verification/formal-mutants.toml`, `scripts/kani-mutant-killer.sh`, `scripts/proof-mutants.sh` orchestrator that does the sampling and report merge; files to modify: `.github/workflows/nightly.yml` gains a `proof-mutants` job, advisory, reusing the kani install steps from `kani-public-nightly`).
   - First CI step is the settle-the-path smoke: `cargo mutants --config formal/rust-verification/formal-mutants.toml --package chio-kernel-core --list` must enumerate more than zero mutants in `formal_core.rs`; if config precedence over `.cargo/mutants.toml` misbehaves, fall back per the fallback path and record which path is live in the report.
4. Phase 4 - extend lane 2 to the two harness files with assertion-line filtering; add the 2 `formal/tla/` specs to lane 1's allowlist.
5. Phase 5 (stretch) - Creusot killer wrapper (`scripts/creusot-mutant-killer.sh`) weekly; Lean pilot (`scripts/lean-mutants.py`) with a whitelist of Core defs.
6. Phase 6 - hand the lane to [FV-E5](FV-E5-lane-ratchets.md): add `[gates.spec-mutants]` to `releases.toml` with `activation_target = 90` once two full cycles of measurements exist.

## CI and gating changes

- New nightly jobs, both advisory at introduction: `spec-mutants` (Apalache killer, schedule-only, in `apalache-safety.yml`) and `proof-mutants` (Kani killer, in `nightly.yml`). Neither touches the PR tier; per-PR mutation of specs would be both slow and noisy.
- Artifacts: `target/formal/spec-mutants-report.json` and the cargo-mutants `outcomes.json` uploaded with 30-day retention, mirroring `mutants-nightly`.
- Budget: these lanes do not share the fuzz/mutants 1800 min/30d envelope by default because `scripts/check-fuzz-budget.sh:29` enumerates workflows explicitly; decide in phase 2 whether to add them to that list (recommended: yes for `proof-mutants`, since it is cargo-mutants compute; no for `spec-mutants`, which is JVM/Apalache time). Set `GH_FUZZ_BUDGET_CAP_MODE` explicitly per the [FV-E4](FV-E4-fuzz-plumbing-repair.md) policy if added.
- Promotion to a gated posture goes through [FV-E5](FV-E5-lane-ratchets.md) (streak-based ratchet), never by editing this lane directly.

## Acceptance criteria

- [ ] `scripts/spec-mutants.py --list` enumerates the full mutant set deterministically; two runs at the same commit produce byte-identical output.
- [ ] The generated TLA mutant set subsumes both `_negative_tests` mutations, and both are reported `killed` in a full local run.
- [ ] Rule zero is enforced by construction: no mutant ever modifies a line inside an invariant/temporal definition or a non-allowlisted operator (self-test asserts this on a synthetic spec).
- [ ] Nightly `spec-mutants` job produces `target/formal/spec-mutants-report.json` with a kill matrix for a sha-seeded sample of at least K=16 mutants, within its budget.
- [ ] `cargo mutants --config formal/rust-verification/formal-mutants.toml --package chio-kernel-core --list` enumerates mutants in `formal_core.rs` and `formal_aeneas.rs` (settles the primary-vs-fallback path).
- [ ] Nightly `proof-mutants` job scores a sample with the Kani lane as `--test-tool`, keeps the baseline run, and uploads outcomes.
- [ ] Full-cycle kill rate on the two formal model files measured and recorded; survivors filed as issues; target >= 90% excluding unviable.
- [ ] The `.cargo/mutants.toml` and per-crate rationale comments are updated to say "covered by the proof lane, measured by the proof-mutants co-coverage lane" once the first full cycle completes.
- [ ] (Stretch) Lean pilot report exists for one sampled night; each surviving Lean mutant has a written disposition.

## Risks and mitigations

- Apalache flakiness or slow mutants blow the nightly budget. Mitigation: hard 300 s per-mutant cap, timeout verdict class, K tunable by one constant, and `--length=4` (shorter than the production 6) since mutants that only violate at depth 5+ still count as survivors for this measurement and will be caught as the bound is raised in later cycles.
- The `--config`/`--test-tool` combination behaves differently than the cocoverage precedent when scoping to excluded-by-workspace-config files. Mitigation: the phase-3 `--list` smoke settles it before any budget is spent; the worktree fallback is specified and produces the same report schema.
- Kani-as-killer is expensive per mutant. Mitigation: sha-seeded sampling with a documented full-cycle length; if 10 nights proves too slow, restrict the killer to the harness subset that references the mutated function (a static grep of `formal_core::<fn>` in the two harness files), trading soundness of "killed" for speed only with the mapping recorded in the report.
- Survivors get ignored. Mitigation: the report is an FV-E5 ratchet input; survivors above the activation target block posture promotion, and each survivor requires a filed issue before the count is rebaselined.
- Mutating specs in a temp dir can drift from how CI invokes Apalache. Mitigation: the runner copies the cfg untouched and reuses the exact `apalache-mc check` argument shape from `apalache-safety.yml:61-73`.

## Open questions

- Should `unviable` TLA mutants (type-checker rejects) count as weak kills? cargo-mutants excludes them from the denominator; the pilot mirrors that, but a type-level rejection is still evidence the spec is sensitive to the site. Revisit after the first cycle's numbers.
- Per-harness killer mapping (grep-based) vs full-lib Kani run: is the speedup worth the mapping-maintenance cost? Defer until measured.
- Does lane 1 extend to the `_negative_tests` `Common.tla` fork or share the production `Common.tla`? Pilot shares production; revisit if constant pinning (its `ASSUME`) blocks a useful mutation class.
- Where does the Lean pilot's whitelist live: in-script or `formal/lean4/lean-mutants-allowlist.toml`? Decide at phase 5.

## Manifest and registry updates

- `releases.toml`: add `[gates.spec-mutants]` and `[gates.proof-mutants]` entries (posture `advisory`, `activation_target = 90` for proof-mutants) when [FV-E5](FV-E5-lane-ratchets.md) lands the generic gate.
- `docs/fuzzing/mutants.md`: new section "Proof-lane co-coverage" describing both lanes and linking here; update the exclusion-rationale paragraph.
- `.cargo/mutants.toml` and `crates/kernel/chio-kernel-core/mutants.toml`: rationale comments updated to cite the measuring lane (exclusions themselves stay; the unit suite is still the wrong killer for these files).
- `formal/apalache/_negative_tests/README.md`: add a pointer that the mechanical generalization lives in `scripts/spec-mutants.py` and that new negative tests should also be added to the allowlist subsumption check.
- No changes to `formal/proof-manifest.toml` gate_commands: these lanes measure the gates, they are not gates themselves until FV-E5 promotes them.
