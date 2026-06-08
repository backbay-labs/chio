# Chio `scripts/` Audit and CI/CD CLI Consolidation Proposal

Scope: audit of `/Users/connor/Medica/backbay/standalone/arc/scripts/`. Read-only
research; no source, scripts, workflows, or configs were modified.

## 0. Summary

`scripts/` holds **163 files / 132 top-level executables** (146 `.sh`, 10 `.py`,
1 `.bats`, 1 `.txt` data file) totalling **~22,000 LOC** at top level plus
**~4,200 LOC** across the `smoke/` and `tests/` subdirs. The directory is
dominated by single-purpose CI verification gates ("assert that X holds"). It
shows clear signs of agent-driven sprawl: large families of near-identical
scripts (the 15-script `check-chio-pheromone-*` cluster wired 1:1 to 15
dedicated workflows is the worst offender), a handful of genuinely dead scripts,
and a partially-completed consolidation precedent (`check-sdk-release.sh` with 7
thin dispatch shims) that should be extended directory-wide.

The good news: the underlying *work* is mostly legitimate (schema validation,
`cargo test`, golden diffs against a shared `chio-spec-validate` crate). The
problem is **packaging**: hundreds of bespoke bash skeletons instead of a few
data-driven CLI subcommands.

## 1. Inventory by family

| Family (prefix) | Count | What it is |
|---|---|---|
| `check-chio-pheromone-*` | 15 | Pheromone relay/runtime/transit fixture+schema+`cargo test` gates. 1:1 with 15 workflows. ~3,444 LOC. |
| `check-chio-runtime-*` | 6 | Runtime spine/policy/orchestration/proof-parity fixture gates. |
| `check-chio-*` (other) | 19 | SDK release (`cpp/go/py/ts/drogon/...`), treaty/authority/proof-package gates. |
| `check-*` other `.sh` | 41 | Cross-cutting gates: egress, redaction, mutants-rationale, transitive-surface, workspace-layering, formal-proofs, dudect, fuzz-budget, etc. |
| `check-*.py` | 9 | Python gates: rust-public-surface (511 LOC), stub-surfaces (707), rust-file-hygiene (398), review-slices, architecture-docs, cargo-vet/deny, wildcard-deps, apalache-formal-slice. |
| `qualify-*` | 17 | Release/profile qualification (web3 x6, comptroller x4, bounded/mobile/browser/trust/universal-control-plane, release). ~2,099 LOC. |
| `mutants-*` | 4 | Mutation-testing gate, comment, autofile-issue, fuzz-cocoverage. |
| kani / aeneas / creusot | 5 / 3 / 2 | Formal-method harness runners + smoke/core variants. |
| fuzz / seed / corpus | ~6 | `promote_fuzz_seed.sh` (539), `pull_tee_corpus.py` (430), corpus-metadata, fuzz-budget. |
| `build-*` | 2 | `build-android-aar.sh`, `build-ios-framework.sh` (mobile SDK build helpers). |
| proof / threat | 5 / 4 | Proof-report generation, threat-coverage (+mutants), triage-threat-rows, adversarial-threat-link. |
| release / misc | ~12 | `qualify-release`, `stage-web3-release-artifacts` (353), `bless-replay-goldens` (224), `criterion-compare`, `seal-bless-audit`, `ci-workspace`, `cargo-lock-merge`, `setup-git-merge-drivers`, `tuf-rebake`, `rebuild-from-source`, `run-coverage`. |

### Largest scripts (consolidation/refactor weight)

```
882  check-sdk-release.sh            (already a multi-lang dispatcher)
707  check-stub-surfaces.py
539  promote_fuzz_seed.sh
511  check-rust-public-surface.py
481  check-chio-pheromone-relay-alert-assurance-archive-package.sh
475  check-chio-treaty-bound-provenance.sh
430  pull_tee_corpus.py
427  check-chio-runtime-orchestration.sh
407  mutants-fuzz-cocoverage.sh
405  kani-changed-harnesses.sh
403  check-formal-proofs.sh
398  check-rust-file-hygiene.py
```

### Smallest scripts (4-line shims - the consolidation pattern already in use)

The 7 `check-chio-<lang>-release.sh` files are 4-line `exec` shims that all
dispatch to one driver:

```bash
#!/usr/bin/env bash
# Thin wrapper preserved for CI compatibility. Dispatches to the unified
# SDK release driver.
exec "$(dirname "$0")/check-sdk-release.sh" cpp "$@"
```

This is the model to generalize. The repo already discovered that 7 scripts
collapse to 1 driver + thin shims; the same logic applies to the pheromone and
runtime clusters.

## 2. Usage buckets (with counts)

Reference surfaces grepped per basename: `.github/workflows/*.yml` (72
workflows), cross-references in other `scripts/`, `xtask/`, `docs/` + `AGENTS.md`
+ `README.md`, and `Makefile`. Note: the `Makefile` references **zero** scripts
(it is a codegen/knowledge-base orchestrator that shells to `cargo xtask`); the
`xtask` crate references **zero** scripts (it owns codegen, not gating). So the
only real wiring is workflows + docs + script-to-script.

| Bucket | Count | Definition |
|---|---|---|
| **ESSENTIAL** | ~92 | Referenced by >=1 workflow, OR referenced by docs/SDK READMEs as a documented gate, OR a real driver invoked by other scripts. |
| **CONSOLIDATABLE** | ~28 | Referenced, but trivial/duplicative - thin shims or members of a near-identical cluster that should become CLI subcommands. |
| **ORPHAN (dead)** | 6 | Zero references anywhere in the repo (workflows, scripts, xtask, docs, SDKs, evidence). Deletion candidates. |
| meta-tests | 25 | `scripts/tests/*.test.sh` + 1 `.bats`: harnesses that test the gate scripts. 10 are wired into CI workflows; the rest run via a test runner. Legitimate, keep. |
| junk | 5 | `scripts/__pycache__/*.pyc` (see section 6). |

### 2a. CONSOLIDATABLE detail (referenced but redundant packaging)

- **7 SDK release shims** (`check-chio-{cpp,cpp-kernel,guard-cpp,drogon,go,py,ts}-release.sh`)
  - already 4-line `exec` dispatchers to `check-sdk-release.sh`. Keep as
    compatibility shims or fold into a single `chio-ci sdk-release <lang>`.
- **15 `check-chio-pheromone-*` scripts** - share one skeleton (resolve ROOT,
  parse `--schema-only|--negative-only`, embed a `python3 - <<'PY'` heredoc
  validating fixtures in `examples/chio-3vendor/fixtures/pheromone/relay`
  against `spec/schemas/chio-pheromone/v1`, then `cargo run -p
  chio-spec-validate` + `cargo test -p chio-pheromone-relay <facet>`). They
  differ only by facet name, schema id list, and fixture filenames.
- **6 `check-chio-runtime-*` scripts** - same fixture+schema+cargo-test shape,
  different facet.
- **6 `qualify-web3-*` + 4 `qualify-comptroller-*`** - profile-qualification
  variants; 6 of the 17 `qualify-*` do nothing but grep docs/files (no `cargo`),
  which is exactly the "prove a doc claim exists" agent pattern.

### 2b. ORPHAN list (explicit - zero references repo-wide)

These six have **no** reference in any workflow, script, xtask, doc, SDK README,
or evidence file. They are deletion candidates (verify once more at delete time):

1. `scripts/check-adversarial-threat-link.sh` (94 LOC)
2. `scripts/check-chio-attest-buyer-fixtures.sh` (24 LOC)
3. `scripts/check-docker-deployable-experience.sh` (66 LOC)
4. `scripts/check-framework-integration-examples.sh` (178 LOC)
5. `scripts/check-tool-server-async.sh` (65 LOC)
6. `scripts/measure_chio_core_rebuild.sh` (81 LOC)

**Near-orphans** (self-only or single weak reference - investigate, likely
fold or retire):

- `scripts/kani-changed-harnesses.sh` (405 LOC) - only self-reference found; not
  invoked by `run-kani-manifest.sh` or any workflow. High-LOC dead weight if
  truly unwired; confirm before deleting.
- `scripts/rebuild-from-source.sh` (107 LOC) - self-only.
- `scripts/check-corpus-metadata.sh` (210 LOC) - referenced only by the data
  file `fuzz/corpus_metadata.toml` (not executed by CI).
- `scripts/triage-threat-rows.sh` (145 LOC) - referenced only by an evidence
  markdown (`audits/evidence/threat-row-triage/per-row-triage.md`), not CI.
- `scripts/check-mapping.sh` (202 LOC) - referenced by `formal/MAPPING.md` and
  compliance narratives as documentation, not wired to a workflow.
- `scripts/build-android-aar.sh`, `scripts/build-ios-framework.sh` - referenced
  only from SDK READMEs (`sdks/jvm/...`, `sdks/swift/...`) as manual build
  helpers, not CI gates. Keep but relocate (see recommendations).
- `scripts/check-sdk-publication-examples.sh` - referenced from SDK
  RELEASING/README docs only.

## 3. What the scripts actually do (high level)

Of the `check-*.sh` gates: **27 invoke `cargo run`**, **29 invoke `cargo
test`**, **26 invoke the shared `chio-spec-validate` crate**, **23 do golden /
snapshot / diff comparisons**, **13 compute `sha256` digests**. So the dominant
gate shape is:

> resolve repo root -> (optionally) run an embedded Python fixture validator ->
> validate JSON fixtures against `spec/schemas/.../v1` via `cargo run -p
> chio-spec-validate` -> run a scoped `cargo test -p <crate> <facet>` ->
> optionally diff output against a committed golden / compute a digest.

This is real CI value, but it is **the same five steps re-typed in bash 30+
times**, with the variation captured in string literals (crate name, schema ids,
fixture dir, facet). That variation is *data*, not *logic*, which is precisely
what makes a data-driven CLI the right consolidation.

The `qualify-*` family is split: 11 run `cargo`, but 6 only grep docs/files for
the presence of claims - the classic "agent writes a script to prove its own
change landed" artifact. Those 6 are the lowest-value scripts in the directory.

## 4. Duplication clusters

1. **Pheromone relay cluster (worst): 15 scripts (3,444 LOC) <-> 15 workflows.**
   Every `chio-pheromone-*.yml` is a 33-55 line wrapper that does `bash
   scripts/check-chio-pheromone-<facet>.sh`. The scripts are structurally
   identical (verified: shared ROOT idiom, shared `--schema-only/--negative-only`
   flag parsing, shared `python3 <<'PY'` validator block, shared
   `chio-spec-validate` + `cargo test -p chio-pheromone-relay` backend). This is
   one parameterized gate masquerading as 15.
2. **Runtime cluster: 6 `check-chio-runtime-*` scripts** - same skeleton,
   different facet.
3. **SDK release: already consolidated** into `check-sdk-release.sh` (882 LOC,
   `case "$lang" in cpp|cpp-kernel|guard-cpp|drogon|go|py|ts)`) with 7 4-line
   shims. Proof that the pattern works in this repo.
4. **Formal-method runners**: kani (`check-kani-{core,public-core,smoke}.sh`,
   `run-kani-manifest.sh`, `kani-changed-harnesses.sh`), aeneas
   (`{equivalence,pilot,production}`), creusot (`{core,smoke}`) - 10 scripts
   that are mostly thin profile variants of "run prover with profile X".
5. **web3 qualify (6) + comptroller qualify (4)** - profile variants of one
   qualification routine.

## 5. `smoke/` and `tests/` subdirs

- `scripts/smoke/chio-cli-smoke.sh` (1,088 LOC) - single end-to-end CLI smoke
  test. Legitimate, but a 1,000-line bash smoke test is itself a refactor
  candidate (could become `cargo test`-driven or a CLI `selftest` subcommand).
- `scripts/tests/` - **25 `*.test.sh` + 1 `.bats`** harnesses that test the gate
  scripts themselves (e.g. `check-threat-coverage.test.sh`,
  `check-rust-public-surface.test.sh`,
  `promote_fuzz_seed_adversarial.bats`). **10 are referenced by workflows**, so
  they run in CI; the rest run via a test runner. These are legitimate meta-tests
  - NOT junk - and validate that the consolidation must preserve behavior. Keep
  them, and point them at the new CLI subcommands after consolidation.

## 6. Junk

- `scripts/__pycache__/` - 5 `.pyc` files (cpython-311 and cpython-314 mixed,
  ~87 KB). **Confirmed gitignored and NOT git-tracked** (`git ls-files` returns
  nothing; `git check-ignore` matches). This is local build residue that should
  simply not exist in the working tree; harmless but should be cleaned and the
  ignore rule kept. No action needed in-repo beyond a local `rm`.
- `scripts/cargo-deny-duplicate-baseline.txt` - data file, not a script;
  consumed by `check-cargo-deny-duplicate-baseline.py`. Keep, but it belongs
  beside other gate data, not in the scripts root.

## 7. Recommendation: a single `chio-ci` CLI tool

### 7.1 Target shape

Introduce one Rust binary (extend `xtask`, or a new `chio-ci` crate) that
exposes the gates as subcommands driven by a declarative manifest, replacing the
bespoke bash skeletons. The repo already has the backend crate
(`chio-spec-validate`) and the dispatcher precedent (`check-sdk-release.sh`).

```
chio-ci check fixtures <profile>     # pheromone/runtime/treaty fixture+schema gates
chio-ci check surface <kind>         # rust-public-surface, transitive, stub, hygiene
chio-ci check policy <kind>          # egress, redaction, workspace-layering, deps
chio-ci qualify <profile>            # web3 / comptroller / bounded / mobile / browser
chio-ci sdk-release <lang>           # = current check-sdk-release.sh
chio-ci formal <tool> [profile]      # kani / aeneas / creusot
chio-ci mutants <op>                 # gate / comment / autofile-issue / cocoverage
chio-ci selftest                     # = scripts/smoke/chio-cli-smoke.sh
```

A `ci-gates.toml` manifest captures the per-gate *data* (crate, schema ids,
fixture dir, facet, golden path) that is currently hardcoded across 30+ scripts.
Workflows then call `chio-ci check fixtures pheromone-relay-observability`
instead of `bash scripts/check-chio-pheromone-relay-observability.sh`.

### 7.2 Phased plan (fail-closed: never widen or drop a gate silently)

1. **Delete the 6 confirmed orphans** (section 2b) after a final repo-wide grep.
   No behavior change - they run nowhere.
2. **Triage the near-orphans** (section 2b) with the owner: `kani-changed-harnesses.sh`
   (405 LOC) is the biggest unwired script and warrants a keep/delete decision.
3. **Collapse the pheromone cluster (15 -> 1 parameterized gate + manifest).**
   Biggest single win: ~3,400 LOC and 15 workflows become 1 reusable workflow
   matrix + 1 subcommand. Keep the 15 `*.test.sh` meta-tests pointed at the new
   subcommand to prove parity before deleting the old scripts.
4. **Collapse the runtime cluster (6 -> 1)** by the same recipe.
5. **Fold `qualify-*` profiles into `chio-ci qualify <profile>`**, and either
   delete or convert the 6 doc-grep-only `qualify-*` scripts into proper
   assertions (a markdown-claim grep is not a qualification gate).
6. **Move the 7 SDK release shims behind `chio-ci sdk-release <lang>`** (the
   driver is already written).
7. **Relocate non-gate helpers**: `build-android-aar.sh`/`build-ios-framework.sh`
   belong with their SDKs (`sdks/jvm`, `sdks/swift`); merge-driver/git setup
   (`setup-git-merge-drivers.sh`, `cargo-lock-merge.sh`) belong in a
   `scripts/git/` or developer-setup area.

### 7.3 Expected outcome

- ~132 top-level scripts -> on the order of ~25-40 (the 9 Python gates and a few
  genuinely unique bash drivers may stay as bash initially), with the
  high-duplication clusters (pheromone 15, runtime 6, sdk-release 7, qualify 17)
  collapsing to single subcommands + a manifest.
- Workflows shrink from per-script wrappers to a small set of matrix jobs.
- One discoverable entrypoint (`chio-ci --help`) instead of 132 ad-hoc files.
- `unwrap_used`/`expect_used` clippy enforcement and Rust typing apply to gate
  logic that is currently untyped bash/heredoc-Python.

### 7.4 Guardrails (house rules)

- Fail-closed: the manifest must enumerate every gate; an unknown/missing gate is
  an error, not a skip. Migrate one cluster at a time and keep the `*.test.sh`
  meta-tests green at each step to guarantee no gate is silently dropped.
- No em dashes in any new code/docs (hyphens/parentheses only).
- Preserve CI-compatibility shims (like the existing 4-line release wrappers) for
  one release cycle so workflow edits and script removal can land separately.
