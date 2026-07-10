# Continuous Fuzzing Runbook

This is the operational runbook for Chio's continuous-fuzzing program. Chio
runs a layered strategy: an in-tree `cargo +nightly fuzz` matrix on a nightly
cron, a ClusterFuzzLite bridge for PR-time and nightly soak coverage, and
OSS-Fuzz as the long-running primary once acceptance lands. The three lanes
overlap on purpose so no single failure mode (a flaky workflow, an OSS-Fuzz
acceptance lag, a budget cap-out) leaves the trust-boundary surface unfuzzed.

## Decision: OSS-Fuzz primary, ClusterFuzzLite bridge

Locked decision (`id=continuous-fuzzing-path`):

- OSS-Fuzz is the primary continuous-fuzzing host once accepted.
- ClusterFuzzLite on GitHub Actions hosted runners is the bridge that carries
  coverage through the OSS-Fuzz acceptance window (typically 2-6 weeks) and
  remains the documented permanent fallback.
- Budget cap: 2,000 GHA runner-minutes per month for ClusterFuzzLite, with a
  hard halt at 1,800 min/30d to leave 200 min/month headroom inside the
  public-repo free tier. Enforced by `scripts/check-fuzz-budget.sh`.

OSS-Fuzz post-acceptance is free CPU on Google's hosts and the route to
sustained continuous fuzzing without burning the GHA cap. The bridge keeps
PR-time smoke coverage running indefinitely (it does not turn off when
OSS-Fuzz lands), so a PR diff that touches a fuzz target still gets a quick
verdict before it reaches the long-running OSS-Fuzz soak.

## GHA budget

The public-repo GitHub Actions free tier is 2,000 runner-minutes per month.
The continuous-fuzzing program self-caps at 1,800 min/30d for fuzz-related
runs (200 min/month headroom for everything else). Enforcement:

- `scripts/check-fuzz-budget.sh` queries the trailing-30d billed-second
  total for `cflite_pr.yml`, `cflite_batch.yml`, `fuzz.yml`,
  `mutants.yml`, and `mutants-fuzz-cocoverage.yml`, sums them, and exits
  non-zero when the sum crosses the cap unless a lane explicitly opts into
  `GH_FUZZ_BUDGET_CAP_MODE=warn`.
- PR-time CFLite budget checks are advisory when the shared trailing window is
  already over cap. The PR still runs changed-target sampling, but shared
  budget exhaustion does not block unrelated merge readiness.
- PR-time mutation gates hard halt when the cap is crossed. These gates are
  release qualification signals and must not run warn-only.
- Scheduled measurement lanes may use `GH_FUZZ_BUDGET_CAP_MODE=warn` to keep
  producing dashboard evidence after the trailing window is already over cap;
  those workflows must document the advisory posture in the step comment.
- Override during incident triage: `GH_FUZZ_BUDGET_MINUTES=900` (or any
  lower value) in the workflow env. Do not raise the cap above 1,800
  without re-opening the locked decision.

Sizing intent (steady state, 18-target inventory):

| Lane              | Cadence             | Per-run cost         | 30-day cost (est.) |
|-------------------|---------------------|----------------------|--------------------|
| `cflite_pr`       | per PR (sampled)    | ~3 targets x 60-120s | ~300 min/month     |
| `cflite_batch`    | nightly rotation    | 1 target x 30 min    | ~900 min/month     |
| `fuzz` (in-tree)  | nightly matrix      | parallel, 30 min/job | runner-time only   |
| OSS-Fuzz          | continuous, free    | n/a (Google CPU)     | 0 GHA min          |

The in-tree `fuzz.yml` matrix runs on the GitHub-hosted pool but bills
against the same free tier; nightly wall-clock is bounded by the longest
single target rather than the sum because the matrix runs jobs in parallel.
The cap-check script counts only `cflite_*` minutes today; if
`fuzz.yml` minutes start crowding the cap, extend the script's workflow
filter rather than raising the cap.

## Workflow inventory

Current inventory.

| Workflow                                     | Owner | Trigger                                  | Per-run wall-time          |
|----------------------------------------------|-------|------------------------------------------|----------------------------|
| `.github/workflows/cflite_pr.yml`            | core  | PR (changed-target sampling)             | 60-120s per selected target|
| `.github/workflows/cflite_batch.yml`         | core  | nightly cron `17 2 * * *` UTC            | 1 target x 1,800s          |
| `.github/workflows/fuzz.yml`                 | core  | nightly cron `23 3 * * *` UTC + dispatch | matrix, 1,800s/target ASan |
| `.github/workflows/mutants.yml`              | core  | nightly + PR diff (advisory)             | 4-hour budget per crate    |

Notes:

- `cflite_pr.yml` defaults to changed-target sampling per `fuzz/target-map.toml`
  (1-6 targets per PR). Opt-in `fuzz: full` PR label promotes the run to a
  full-corpus sweep at 120s per target (release-cut PRs and trust-boundary
  edits). The workflow listens to the `labeled` activity type, so adding the
  label to an already-open PR triggers a fresh run rather than waiting for
  the next commit.
- `cflite_batch.yml` rotates one target per night across an 18-day full sweep.
- `fuzz.yml` is the in-tree `cargo +nightly fuzz` matrix authored in
  It complements rather than replaces ClusterFuzzLite by running
  every target every night with ASan.
- `mutants.yml` is advisory for one release cycle per
  decision 12; see `docs/fuzzing/mutants.md` when it
  exists.

## Target inventory

The in-tree matrix in `fuzz.yml` enumerates
every target below; ClusterFuzzLite picks per-PR or per-night rotations
from `fuzz/target-map.toml`.

PR #13 baseline (seven targets):

| Target                     | Source                                                |
|----------------------------|-------------------------------------------------------|
| `canonical_json_roundtrip` | canonical-JSON serializer round-trip                  |
| `manifest_decode`          | tool-manifest decode                                  |
| `receipt_decode`           | signed-receipt decode                                 |
| `capability_decode`        | capability-token decode                               |
| `scope_decode`             | scope-string decode                                   |
| `policy_decision_decode`   | policy-decision decode                                |
| `signing_envelope_decode`  | signing-envelope decode                               |

Supply-chain (one target):

| Target          | Source                                          |
|-----------------|-------------------------------------------------|
| `attest_verify` | supply-chain attestation parser      |

Target expansion (twelve targets, T8 included):

| Target                          | Source                                                                |
|---------------------------------|-----------------------------------------------------------------------|
| `jwt_vc_verify`                 | JWT VC verifier                                          |
| `oid4vp_presentation`           | OID4VP holder response                                   |
| `did_resolve`                   | chio-did parser plus resolver                            |
| `anchor_bundle_verify`          | anchor proof bundle plus checkpoint records                |
| `mcp_envelope_decode`           | MCP NDJSON decode plus edge dispatch                     |
| `a2a_envelope_decode`           | A2A SSE parse plus per-event fan-out                     |
| `acp_envelope_decode`           | ACP-Client NDJSON plus handle_jsonrpc dispatch                  |
| `wasm_preinstantiate_validate`  | ComponentBackend, WasmtimeBackend, format detect         |
| `wit_host_call_boundary`        | GuardRequest/Verdict serde deserialization               |
| `chio_yaml_parse`               | chio-config YAML loader                                  |
| `openapi_ingest`                | OpenApiMcpBridge::from_spec                              |
| `receipt_log_replay`            | pre-included slot in fuzz.yml; binary lands in T8          |

Total: 7 (PR #13) + 1 + 12 = 20 targets.
The success-criteria floor is 11 new targets (7 baseline + 11 new =
18 in the matrix exit-test count); T8 lifts the count from 11 to 12 and the
total to 20.

## ClusterFuzzLite bridge

Two GitHub-Actions workflows pair libFuzzer's PR-time and nightly-cron
coverage into the bridge that carries Chio through the OSS-Fuzz acceptance
window and remains the documented permanent fallback after acceptance lands:

- `.github/workflows/cflite_pr.yml` -- changed-target sampling per
  `fuzz/target-map.toml`. Default per-target wall budget is 60s (1-6 targets
  per PR after the glob match). Opt-in `fuzz: full` PR label promotes the
  run to a full-corpus sweep across all sixteen targets at 120s each
  (release-cut PRs and trust-boundary edits).
- `.github/workflows/cflite_batch.yml` -- sampled nightly cron at
  `17 2 * * *` UTC. Rotates one target per night across the sixteen-target
  inventory (`day-of-epoch mod 16`), 30 minutes per run. The `cflite_cron`
  workflow that the source-doc earlier described is intentionally absent;
  the weekly-soak Tier-A plan was dropped along with Tier A, and OSS-Fuzz
  is the post-acceptance soak path.

PR-time fuzz and mutation workflows invoke `scripts/check-fuzz-budget.sh`
before any fuzz or mutation step so the 1,800 GHA min/30d cap is visible in
the run logs. PR-time CFLite budget checks are advisory because the trailing
window is shared across unrelated PRs, while PR-time mutation remains a hard
halt. Scheduled fuzz, CFLite rotation, mutants nightly, and mutants
fuzz-cocoverage lanes may stay warning-only when their purpose is measurement
continuity rather than PR or release qualification.

The CFLite builder image lives under `.clusterfuzzlite/`:

- `.clusterfuzzlite/Dockerfile` -- `FROM gcr.io/oss-fuzz-base/base-builder-rust`
  with the rustls/openssl build deps plus `zip`. Mirrors the OSS-Fuzz
  scaffold under `fuzz/oss-fuzz/` so the in-tree CFLite image and the
  OSS-Fuzz image stay behaviourally identical.
- `.clusterfuzzlite/build.sh` -- enumerates all sixteen fuzz targets and
  runs `cargo +nightly fuzz build <target> --release --sanitizer
  "$SANITIZER"` per target. The OSS-Fuzz copy at `fuzz/oss-fuzz/build.sh`
  is the source-of-truth; any new fuzz target lands in both files in the
  same change set.
- `.clusterfuzzlite/project.yaml` -- declares `language: rust`, the primary
  contact, the address+undefined sanitizer pair, the `x86_64` architecture,
  and the `libfuzzer` engine. The `report_to_oss_fuzz` flag stays `false`
  until OSS-Fuzz acceptance lands. The corpus `storage-repo` is wired as
  a `FUZZ_CORPUS_PAT`-backed action input on the `run_fuzzers` step in
  `.github/workflows/cflite_pr.yml` and `.github/workflows/cflite_batch.yml`
  per ClusterFuzzLite's published schema (it is not a `project.yaml` field).

Storage backend: `backbay-labs/chio-fuzz-corpus` (sibling private repo). The
repo is created out-of-band before the first `cflite_batch.yml` run; until
it exists, ClusterFuzzLite falls back to per-run artifact storage and the
rotation still passes its crash-search criterion. Keeping corpus storage in
the GitHub control plane avoids new cloud-billing surfaces and keeps the
1,800 min/30d cap legible. Cross-repo writes require the repository secret
`FUZZ_CORPUS_PAT`; `GITHUB_TOKEN` cannot push to the sibling private repo.
Fork-origin PRs and batch rotations run without corpus storage when that
secret is unavailable.

## OSS-Fuzz application status

- Target submission window: during OSS-Fuzz onboarding.
- Status: pending.
- Infrastructure scaffolding lands under `fuzz/oss-fuzz/` in the OSS-Fuzz integration package
  (`project.yaml`, `Dockerfile`, `build.sh`).
- Acceptance lag: typically 2-6 weeks. ClusterFuzzLite carries coverage
  through the lag.
- Contacts: primary `security@backbay.io`, backup `fuzzing@backbay.io`.
- On acceptance: repoint the bug-tracker integration in
  `.clusterfuzzlite/project.yaml` (`report_to_oss_fuzz: true`); keep
  ClusterFuzzLite running as the documented fallback.
- Triage SLO commitment to OSS-Fuzz upstream: 24h acknowledgement, 7d
  fix-or-defer for `Critical`, 30d for `High`. Tracked in
  `docs/fuzzing/triage.md`.

## OSS-Fuzz integration

Chio is in the OSS-Fuzz application pipeline. Integration
files live under `fuzz/oss-fuzz/` and are mirrored into the upstream
`google/oss-fuzz` repo as a dedicated upstream PR:

- `fuzz/oss-fuzz/project.yaml` declares `language: rust`, the primary
  contact (`security@backbay.io`), backup contact (`fuzzing@backbay.io`),
  the `address` plus `undefined` sanitizer pair, the `x86_64` architecture,
  and the `libfuzzer` engine.
- `fuzz/oss-fuzz/Dockerfile` is based on
  `gcr.io/oss-fuzz-base/base-builder-rust`, installs the rustls/openssl
  build deps plus `zip` for seed-corpus packing, and clones the repo at
  `/src/chio`.
- `fuzz/oss-fuzz/build.sh` enumerates all sixteen fuzz targets
  (`attest_verify`, `jwt_vc_verify`, `oid4vp_presentation`,
  `did_resolve`, `anchor_bundle_verify`, `mcp_envelope_decode`,
  `a2a_envelope_decode`, `acp_envelope_decode`,
  `wasm_preinstantiate_validate`, `wit_host_call_boundary`,
  `chio_yaml_parse`, `openapi_ingest`, `receipt_log_replay`,
  `canonical_json`, `capability_receipt`, `manifest_roundtrip`),
  invokes `cargo +nightly fuzz build <target> --release --sanitizer
  "$SANITIZER"` for each, copies the resulting binary into `$OUT/`,
  and packs `fuzz/corpus/<target>/` into
  `$OUT/<target>_seed_corpus.zip` when a corpus directory exists.

The upstream PR opens against
`https://github.com/google/oss-fuzz/tree/master/projects/chio` once
these in-tree files merge. The OSS-Fuzz README requires the same
three files at that path, so the in-tree copy under `fuzz/oss-fuzz/`
is the source-of-truth and the upstream PR lifts the directory
verbatim.

Acceptance lag is typically 2-6 weeks. ClusterFuzzLite (in
`.github/workflows/cflite_pr.yml` and `.github/workflows/cflite_batch.yml`)
plus the in-tree `.github/workflows/fuzz.yml` carry continuous coverage
through the OSS-Fuzz acceptance window and remain the documented
permanent fallback after acceptance lands.

## Local development workflow

Run a single target locally against the in-tree corpus:

```bash
cd fuzz
cargo +nightly fuzz run <target> -- -runs=10000 -max_total_time=60
```

Smoke-test only the corpus seeds (no fuzzing, fast feedback during target
authoring). The `cd fuzz` is required because `fuzz/Cargo.toml` defines
its own workspace; the root `Cargo.toml` does not include `fuzz`, so
running this from the repo root will not find the `smoke` test target:

```bash
cd fuzz
cargo test --test smoke <target>_smoke
```

Reproduce a known crash from a minimized input:

```bash
cd fuzz
cargo +nightly fuzz run <target> path/to/crash-<sha>.bin
```

Build all target binaries without running them (CI parity check):

```bash
cd fuzz
cargo +nightly fuzz build --release
```

### macOS arm64 environmental note

`cargo +nightly fuzz run -- -runs=0` may hang in libFuzzer/ASan
initialization on macOS arm64. The hang is in the empty-run init path and
not a Chio bug. Workaround for local development: run with `-runs=N` for
N>0 (any positive value bypasses the affected init path). The authoritative
gate is CI on Linux x86_64; macOS is for fast local iteration only.

## Triage

Crash artifacts from CI:

- ClusterFuzzLite (`cflite_pr`, `cflite_batch`) writes crash artifacts
  into the workflow's GitHub Actions artifact store and (when OSS-Fuzz
  reporting is enabled post-acceptance) opens issues labelled `fuzz-crash`
  on `backbay-labs/chio`.
- The in-tree `fuzz.yml` matrix uploads the libFuzzer crash file plus the
  raw stderr as a workflow artifact named `fuzz-crash-<target>-<run-id>`.

Pull a crash artifact and reproduce locally:

```bash
# List recent fuzz workflow runs
gh run list --workflow fuzz.yml --limit 10

# Download all artifacts from a specific run
gh run download <run-id> --dir /tmp/fuzz-crash

# Reproduce against the failing target
cd fuzz
cargo +nightly fuzz run <target> /tmp/fuzz-crash/<artifact>/crash-<sha>.bin
```

Minimize a crash for issue attachment:

```bash
cd fuzz
cargo +nightly fuzz tmin <target> /tmp/fuzz-crash/<artifact>/crash-<sha>.bin
```

Crash-to-issue automation, dedupe-by-input-hash, severity bands, and
seed-promotion-to-regression-test land in the triage runbook
(`.github/workflows/fuzz_crash_triage.yml`, `scripts/promote_fuzz_seed.sh`,
`docs/fuzzing/triage.md`).

## Timing-leak detection (dudect)

The `dudect` Cargo feature gates a set of `dudect-bencher`
0.7-driven timing harnesses that statistically detect data-dependent
timing leaks in the trust-boundary primitives that sit on the verdict
hot path. The harnesses are off by default so `cargo test` stays fast
and deterministic; they are opt-in via a per-target `--features dudect`
build, and the standalone test binary's `main` is provided by
`dudect_bencher::ctbench_main!`.

Each harness defines two input classes (`Class::Left` and `Class::Right`)
that should produce the same verdict but might take a different amount of
time on a leaky implementation. The dudect runner times both classes
many times, then runs Welch's t-test on the runtime distributions; a
`max_t` value above the documented 4.5 threshold in two consecutive
runs is the failure criterion.

Inventory:

| Crate              | Harness                                                            | Target surface                                                                     |
|--------------------|--------------------------------------------------------------------|------------------------------------------------------------------------------------|
| `chio-credentials` | `crates/trust/chio-credentials/tests/dudect/jwt_verify.rs`               | `verify_chio_passport_jwt_vc_json` parse-and-fail path                             |
| `chio-kernel-core` | `crates/kernel/chio-kernel-core/tests/dudect/mac_eq.rs`                   | `chio_core_types::crypto::Signature` byte-equality compare (the MAC-eq surface)    |
| `chio-kernel-core` | `crates/kernel/chio-kernel-core/tests/dudect/scope_subset.rs`             | `NormalizedScope::is_subset_of` capability-algebra subset check                    |

Run locally. Use `--test <binary>` to select a specific dudect harness
target rather than a positional `TESTNAME` filter; the harnesses are
`harness = false` test binaries (each provides its own `main` via
`dudect_bencher::ctbench_main!`), and the positional argument is a
test-name filter that does not isolate a single binary, so a positional
form like `... mac_eq` can still execute multiple dudect binaries and
conflate runtime / output parsing.

```bash
cargo test -p chio-credentials --features dudect --release --test dudect_jwt_verify
cargo test -p chio-kernel-core --features dudect --release --test dudect_mac_eq
cargo test -p chio-kernel-core --features dudect --release --test dudect_scope_subset
```

The release-mode build is required: dudect's t-test is sensitive to the
optimization level, and unoptimized builds produce noise that overwhelms
the signal. Each harness collects ~100,000 input pairs per invocation,
and the runner re-invokes the closure many times per pair, so a single
local run of any one harness takes a few minutes.

Pass criterion:

- `max_t < 4.5` in two consecutive runs of the same harness on the same
  target surface. A single `max_t > 4.5` is treated as advisory; a
  reproduced failure is a regression and blocks the change set.
- Below the 4.5 threshold the t-test cannot distinguish the two input
  classes' runtime distributions at a level that survives multiple
  testing correction across the ~100 t-tests dudect runs internally.

CI lane: `.github/workflows/dudect.yml` wires these three
harnesses into nightly + PR-time runs and applies the
two-consecutive-runs `t < 4.5` pass rule.

## Cross-references

- Workflows: [`.github/workflows/cflite_pr.yml`](../../.github/workflows/cflite_pr.yml),
  [`.github/workflows/cflite_batch.yml`](../../.github/workflows/cflite_batch.yml),
  [`.github/workflows/fuzz.yml`](../../.github/workflows/fuzz.yml),
  [`.github/workflows/mutants.yml`](../../.github/workflows/mutants.yml)
- Budget enforcement: [`scripts/check-fuzz-budget.sh`](../../scripts/check-fuzz-budget.sh)
- Target-to-source mapping: [`fuzz/target-map.toml`](../../fuzz/target-map.toml)
