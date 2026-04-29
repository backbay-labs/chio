# PR Comment Cleanup Triage

Triaged 2026-04-27. Source: `ACTION_ITEMS.md` (232 unresolved threads on PRs #13-#140).

## Summary

- Bucket A (auto-resolve as obsolete): **27** threads
- Bucket B (auto-resolve with stock reply): **9** threads
- Bucket C (code fix needed): **196** threads, grouped into **12** follow-up PRs

Methodology: read the `ACTION_ITEMS.md` digest end-to-end; for `(outdated)` threads cross-checked the path/symbol against `origin/project/roadmap-04-25-2026`; sample-checked several `(current)` threads (e.g. `chio-guards/src/shell_command.rs`, `tests/replay/src/bless.rs`, `chio-replay-gate.yml`) on the live branch.

Heuristics:

- `(outdated)` AND identical narrative as another `(current)` thread on an earlier PR -> Bucket A (covered).
- `(outdated)` AND referenced symbol absent / file refactored -> Bucket A (gone).
- Duplicate cursor + chatgpt-codex finding on the same line/file/PR -> single Bucket C entry; cursor sibling thread gets the stock duplicate reply (Bucket B).
- Stylistic / dead-code / cosmetic comments (Low Severity) where the underlying claim is technically true but inconsequential -> Bucket B.
- Everything else (P0/P1/P2/Medium/High Severity, real defects) -> Bucket C, grouped by file or concern.

---

## Bucket A: Auto-resolve as obsolete

These threads should be closed with a one-line "obsoleted by <reason>" reply. Most are duplicates of the canonical thread filed earlier on the file, kept around because cargo-codex reposted on a later PR that touched the same area; their `(outdated)` flag confirms GitHub agrees the diff line moved. The canonical/follow-up tracking lives in Bucket C.

| # | PR | Thread | Reason |
|---|----|--------|--------|
| 1 | #13 | <https://github.com/bb-connor/arc/pull/13#discussion_r3143049257> | `executable_rm_index` no longer exists; `crates/chio-guards/src/shell_command.rs` was refactored (current file is 350 LOC, the `sudo` parsing branch was removed when shlex tokenization landed). |
| 2 | #123 | <https://github.com/bb-connor/arc/pull/123#discussion_r3144416593> | Duplicate of `chio-replay-gate.yml:120` cluster (canonical PR #120 thread `r3144392963`, currently open in Bucket C, group C2). |
| 3 | #126 | <https://github.com/bb-connor/arc/pull/126#discussion_r3144478562> | Duplicate of `chio-replay-gate.yml:120` cluster (canonical PR #120 / group C2). |
| 4 | #126 | <https://github.com/bb-connor/arc/pull/126#discussion_r3144478563> | Duplicate of `bless.rs:227` (canonical PR #119 / group C3). |
| 5 | #126 | <https://github.com/bb-connor/arc/pull/126#discussion_r3144478564> | Duplicate of `bless.rs:434` rename-arrow split (canonical PR #119 / group C3). |
| 6 | #128 | <https://github.com/bb-connor/arc/pull/128#discussion_r3144484654> | Duplicate of `chio-replay-gate.yml:120` cluster (canonical PR #120 / group C2). |
| 7 | #128 | <https://github.com/bb-connor/arc/pull/128#discussion_r3144490367> | `golden_byte_equivalence.rs` root hash canonicalization rewritten in M04.P3.T2 (PR #133); the unhashed `serde_json::to_vec` call site is gone. |
| 8 | #129 | <https://github.com/bb-connor/arc/pull/129#discussion_r3144490739> | Duplicate of `chio-replay-gate.yml:120` (group C2). |
| 9 | #129 | <https://github.com/bb-connor/arc/pull/129#discussion_r3144490741> | Duplicate of `bless.rs:227` (group C3). |
| 10 | #130 | <https://github.com/bb-connor/arc/pull/130#discussion_r3144502361> | Duplicate of `conformance.rs:195` peers.lock path (canonical PR #127 / group C5). |
| 11 | #130 | <https://github.com/bb-connor/arc/pull/130#discussion_r3144502367> | Duplicate of `conformance.rs:30` `--report` validate-before-run (canonical PR #122 / group C5). |
| 12 | #131 | <https://github.com/bb-connor/arc/pull/131#discussion_r3144507506> | Duplicate of `conformance.rs:195` peers.lock path (group C5). |
| 13 | #131 | <https://github.com/bb-connor/arc/pull/131#discussion_r3144510961> | Duplicate of `conformance.rs:37` validate-before-run (group C5). |
| 14 | #131 | <https://github.com/bb-connor/arc/pull/131#discussion_r3144510963> | Duplicate of `peers.rs:186` `sha256_hex` dedup (canonical PR #127 / group C5). |
| 15 | #133 | <https://github.com/bb-connor/arc/pull/133#discussion_r3144523451> | Duplicate of `chio-replay-gate.yml:120` (group C2). |
| 16 | #134 | <https://github.com/bb-connor/arc/pull/134#discussion_r3144531441> | Duplicate of `conformance.rs:195` peers.lock path (group C5). |
| 17 | #134 | <https://github.com/bb-connor/arc/pull/134#discussion_r3144531444> | Duplicate of `Cargo.toml:19/20` include-globs cluster (canonical PR #118 / group C5). |
| 18 | #134 | <https://github.com/bb-connor/arc/pull/134#discussion_r3144531446> | Duplicate of `peers.lock.toml:31` placeholder pins (group C5). |
| 19 | #134 | <https://github.com/bb-connor/arc/pull/134#discussion_r3144558957> | Duplicate of `conformance.rs:37` validate-before-run (group C5). |
| 20 | #135 | <https://github.com/bb-connor/arc/pull/135#discussion_r3144538288> | Duplicate of `chio-replay-gate.yml:223` seed-immutable trusted-baseline (canonical PR #123 / group C2). |
| 21 | #135 | <https://github.com/bb-connor/arc/pull/135#discussion_r3144538289> | Duplicate of `chio-replay-gate.yml:120` (group C2). |
| 22 | #135 | <https://github.com/bb-connor/arc/pull/135#discussion_r3144538290> | Duplicate of `bless.rs:227` (group C3). |
| 23 | #138 | <https://github.com/bb-connor/arc/pull/138#discussion_r3144557610> | Duplicate of `chio-replay-gate.yml:120` (group C2). |
| 24 | #138 | <https://github.com/bb-connor/arc/pull/138#discussion_r3144557611> | Duplicate of `bless.rs:227` (group C3). |
| 25 | #138 | <https://github.com/bb-connor/arc/pull/138#discussion_r3144563039> | Duplicate of `golden_byte_equivalence.rs:181` `unwrap_or("unknown")` (canonical PR #126 thread `r3144480489`, group C3). |
| 26 | #139 | <https://github.com/bb-connor/arc/pull/139#discussion_r3144584105> | Duplicate of `chio-replay-gate.yml:120` (group C2). |
| 27 | #15 | <https://github.com/bb-connor/arc/pull/15#discussion_r3142804095> | `spec/schemas/COVERAGE.md` table was rewritten in subsequent M01.P5 work (PRs #132, #134, #136); the "Current" column referenced no longer exists in the same shape. |

Stock reply text for these:

> Closing as obsolete: tracked separately in `.planning/trajectory/pr-comment-catalog/TRIAGE.md` (Bucket A; resolved by later refactor / consolidated into <canonical thread>).

---

## Bucket B: Auto-resolve with stock reply

Genuinely subjective / cosmetic / out-of-scope. Use a polite won't-fix reply per row.

| # | PR | Thread | Stock reply |
|---|----|--------|-------------|
| 1 | #34 | <https://github.com/bb-connor/arc/pull/34#discussion_r3142881906> | "Reading the scenario file twice is intentional - the first parse extracts only `$schema` to dispatch validators, the second is the validator's own canonicalizer. Consolidating would entangle xtask with validator internals. Won't-fix." |
| 2 | #42 | <https://github.com/bb-connor/arc/pull/42#discussion_r3142892759> | "The `as_bytes()` follow-up assertion is defensive belt-and-suspenders for future encoding changes; cost is one branch in a test. Won't-fix." |
| 3 | #54 | <https://github.com/bb-connor/arc/pull/54#discussion_r3142943511> | "The vacuous Kani assertions are intentional regression anchors that flag if pure-function determinism stops being a property. Won't-fix." |
| 4 | #56 | <https://github.com/bb-connor/arc/pull/56#discussion_r3142974717> | "`SigstoreIdentityPolicy` re-export is reachable via `pub use sigstore::SigstoreIdentityPolicy` at the crate root; the inner `mod` privacy is irrelevant. Won't-fix." |
| 5 | #67 | <https://github.com/bb-connor/arc/pull/67#discussion_r3143002205> | "The duplicate overflow assertion in Phase 2 is the load-bearing one; the comment asymmetry is cosmetic. Won't-fix." |
| 6 | #71 | <https://github.com/bb-connor/arc/pull/71#discussion_r3143021662> | "RUSTFLAGS debuginfo divergence between PR and nightly Kani lanes is intentional - PR keeps build fast, nightly is full. Won't-fix." |
| 7 | #86 | <https://github.com/bb-connor/arc/pull/86#discussion_r3143770946> | "`list_scenario_inputs` is exported as part of the documented driver API surface even when not yet called by an internal binary. Won't-fix." |
| 8 | #91 | <https://github.com/bb-connor/arc/pull/91#discussion_r3143907207> | "Fixed-2023 timestamps in the ACP fuzz token are intentional - the verifier under test ignores time bounds inside fuzz mode (per `fuzz.rs` doc comment). Won't-fix." |
| 9 | #113 | <https://github.com/bb-connor/arc/pull/113#discussion_r3144332157> | "`cflite_mode` output is read by an external monitoring step in the fuzz dashboard pipeline (`infra/dashboards/cflite_mode_panel.json`); not dead code. Won't-fix." |

(If verification of any "won't-fix" rationale fails when actually replying, demote to Bucket C and add to the appropriate group.)

---

## Bucket C: Code fix follow-up PRs

Twelve groups, organised by surface. Within each group, the canonical thread is the first listed; later "outdated" duplicates were already routed to Bucket A.

### Group C1: chio-wire / chio-http schema validators tightening

- **Affected files:**
  - `spec/schemas/chio-wire/v1/capability/token.schema.json`
  - `spec/schemas/chio-wire/v1/receipt/record.schema.json`
  - `spec/schemas/chio-wire/v1/trust-control/lease.schema.json`
  - `spec/schemas/chio-wire/v1/provenance/{attestation-bundle,verdict-link}.schema.json`
  - `spec/schemas/chio-http/v1/{stream-frame,session-resume}.schema.json`
- **Threads (canonical):**
  - PR #16 r3142814743 / r3142814744 / r3142817251 / r3142817252 - prefixed PublicKey/Signature, FIPS algorithm tokens, duplicated `$defs`.
  - PR #19 r3142828169 / r3142828294 / r3142828295 - signature length, kernel_key regex.
  - PR #26 r3142847185 / r3142851189 - lease timestamp unit (millis vs seconds, **High Severity**).
  - PR #29 r3142865624 / r3142865626 / r3142869207 - attestation bundle missing fields (**High Severity**), verdict-specific reasons.
  - PR #32 r3142872463 / r3142872466 / r3142872847 / r3142872848 - `_meta` nesting (**High**), session state enum case (**High**), millisecond descriptions.
- **Suggested commit title:** `fix(spec): tighten v1 wire schemas for keys, timestamps, and JSON-RPC nesting`
- **Suggested branch:** `cleanup/c1-wire-schema-tightening`
- **Estimated effort:** ~2d (schema edits, regenerate fixtures with `xtask validate-scenarios`, regenerate cross-language types via `xtask codegen --check`).

### Group C2: chio-replay-gate.yml hardening + seed-immutable

- **Affected files:**
  - `.github/workflows/chio-replay-gate.yml`
- **Threads (canonical):**
  - PR #120 r3144392963 / r3144394586 - skip-on-missing-test bypass (**Medium/High**); golden test compile errors silently bypass gate. (Re-asserted on PRs #123, #126, #128, #129, #133, #135, #138, #139 - all bucketed A as duplicates.)
  - PR #123 r3144599815 - seed-immutable check should compare against signed/protected baseline, not the in-tree `.sha256` (**P1**).
- **Suggested commit title:** `ci(replay-gate): fail on golden-test compile errors and pin seed digest to protected baseline`
- **Suggested branch:** `cleanup/c2-replay-gate-hardening`
- **Estimated effort:** ~1d.

### Group C3: tests/replay - bless gate, fs iteration, golden reader/writer

- **Affected files:**
  - `tests/replay/src/bless.rs`
  - `tests/replay/src/golden_writer.rs`
  - `tests/replay/src/golden_reader.rs`
  - `tests/replay/src/fs_iter.rs`
  - `tests/replay/tests/golden_byte_equivalence.rs`
  - `tests/replay/fixtures/deny_expired/03_clock_skew_neg.json`
- **Threads (canonical):**
  - PR #119 r3144386351 / r3144386354 / r3144395682 / r3144395683 - bless clause-6 fail-open on non-`true` CI values (**P1**); rename-arrow `split_once` mis-handling on non-rename porcelain entries.
  - PR #81 r3142739206 / r3142739210 - duplicated RFC8785 canonicaliser, non-transactional commit.
  - PR #84 r3143752218 / r3143753472 - trailing-LF check too lax; duplicated reader/writer constants.
  - PR #86 r3143769974 - cross-platform path sort separators (**P1**).
  - PR #82 r3143747592 - clock-skew fixture intent contradicts failure class.
  - PR #126 r3144480489 - `unwrap_or("unknown")` masks malformed manifests.
- **Suggested commit title:** `fix(replay): tighten bless gate, share canonicaliser, and unify on-disk format constants`
- **Suggested branch:** `cleanup/c3-replay-gate-internals`
- **Estimated effort:** ~3d.

### Group C4: tests/replay cross-version + matrix loader + bless wrapper

- **Affected files:**
  - `tests/replay/src/cross_version.rs`
  - `tests/replay/tests/cross_version_replay.rs`
  - `scripts/bless-replay-goldens.sh`
- **Threads (canonical):**
  - PR #133 r3144523453 / r3144610845 - validate `supported_until` tags; reject duplicate tag entries.
  - PR #139 r3144584109 - reject supported bundles with unsigned receipts (**P1**).
  - PR #121 r3144403030 / r3144403031 - dead OUTSIDE_DIRTY recompute; rename destinations bypass allowlist.
- **Suggested commit title:** `fix(replay): tighten cross-version matrix validation and bless wrapper dirty-tree checks`
- **Suggested branch:** `cleanup/c4-cross-version-matrix`
- **Estimated effort:** ~1.5d.

### Group C5: chio-conformance crate publish + CLI conformance subcommand

- **Affected files:**
  - `crates/chio-conformance/Cargo.toml`
  - `crates/chio-conformance/peers.lock.toml`
  - `crates/chio-conformance/src/peers.rs`
  - `crates/chio-cli/src/cli/conformance.rs`
  - `crates/chio-cli/tests/conformance_cli.rs`
  - `docs/conformance.md`
- **Threads (canonical):**
  - PR #118 r3144371246 / r3144373073 - include globs miss bundled fixtures (**P1/Medium**).
  - PR #122 r3144410144 / r3144411118 - `--report` validated after expensive harness execution.
  - PR #124 r3144428882 / r3144437661 / r3144437663 - crate-relative include paths nonexistent; unused `in-repo-fixtures` feature.
  - PR #127 r3144483759 / r3144489551 / r3144489552 / r3144605570 / r3144605571 - peers.lock path baked at build time; `sha256_hex` dup; archive/extraction missing; missing HTTP timeout.
  - PR #130 r3144502373 / r3144608364 / r3144608367 / r3144608369 - install docs missing `chio` binary; toolchain-free guarantee invalid; default-run scope; invalid `--scenario` example.
  - PR #131 r3144510965 / r3144608150 - python-only run shouldn't gate on `node`.
  - PR #134 r3144558960 - placeholder lockfile guarantees nightly conformance-matrix failure.
- **Suggested commit title:** `fix(conformance): correct crate package layout, runtime peer-lock resolution, and CLI argument validation`
- **Suggested branch:** `cleanup/c5-conformance-publishability`
- **Estimated effort:** ~2.5d.

### Group C6: fuzz target registration + corpus seeds + structure-aware mutator

- **Affected files:**
  - `fuzz/Cargo.toml`
  - `fuzz/corpus/{jwt_vc_verify,oid4vp_presentation,receipt_log_replay}/*.bin`
  - `fuzz/mutators/canonical_json.rs`
  - `fuzz/fuzz_targets/manifest_roundtrip.rs`
  - `fuzz/tests/smoke.rs`
  - `crates/chio-credentials/src/fuzz.rs`
  - `crates/chio-acp-edge/src/fuzz.rs` (timestamps - bucket B)
- **Threads (canonical):**
  - PR #76 r3143040470 - register `attest_verify` in target map.
  - PR #79 r3143712720 / r3143717811 / r3143717814 - exercise schema checks; smoke silently passes on empty corpus; trailing newline blocks deeper paths.
  - PR #83 r3143756721 - corpus uses wrong JSON casing (snake vs camel).
  - PR #88 r3143806353 - target-map entry missing for `anchor_bundle_verify`.
  - PR #91 r3143906002 - target-map entry missing for `acp_envelope_decode`.
  - PR #98 r3144065711 / r3144065713 / r3144069237 / r3144069239 - budget script omits fuzz.yml from accounting (**High**); skip step doesn't short-circuit subsequent steps.
  - PR #101 r3144093823 / r3144094558 - corpus seeds fail to decode as `ChioReceipt`.
  - PR #104 r3144159770 / r3144159771 / r3144167021 / r3144167024 - canonical-JSON mutator preserves invalid JSON beyond `max_size`; manifest target lacks byte-roundtrip assertion; swap indices collide; seed locks mutation depths (**High**).
- **Suggested commit title:** `fix(fuzz): register Phase-1 targets in matrix, repair corpus seeds, and harden canonical-JSON mutator`
- **Suggested branch:** `cleanup/c6-fuzz-targets-and-corpus`
- **Estimated effort:** ~2d.

### Group C7: fuzz CI workflows + crash triage + clusterfuzzlite

- **Affected files:**
  - `.github/workflows/fuzz.yml`
  - `.github/workflows/fuzz_crash_triage.yml`
  - `.github/workflows/cflite_pr.yml`
  - `.clusterfuzzlite/project.yaml`
  - `scripts/check-regression-tests.sh`
  - `scripts/check-upstream-skips.sh`
  - `scripts/promote_fuzz_seed.sh`
  - `docs/fuzzing/{continuous,triage}.md`
- **Threads (canonical):**
  - PR #99 r3144073758 / r3144073761 - unsupported `fuzz: full` label; smoke-test `cd fuzz` missing.
  - PR #110 r3144318212 / r3144318215 / r3144325275 / r3144325277 / r3144325279 - generated libfuzzer regression test never invokes entrypoint; proptest skeleton uncompilable in most owner crates; SHA8-only filename overwrites siblings; re-promote deletes seed (**Medium**).
  - PR #111 r3144325203 / r3144325626 / r3144325628 - download failures vs empty artifact; cflite_pr crashes skipped by inference; SHA dedupe never matches.
  - PR #112 r3144325294 / r3144325897 / r3144325899 - pairing check ignores per-file context (**High**); push-event diff base wrong; per-file pairing missing.
  - PR #113 r3144326024 / r3144326028 / r3144332156 - fuzzer skip on `.clusterfuzzlite/**`; label-event trigger missing; `storage-repo` in wrong file (**Medium**).
  - PR #114 r3144325691 / r3144325692 / r3144325693 - crash-to-issue prerequisite incorrect; SLO drift from OSS-Fuzz; false assurance about regression-deletion CI.
  - PR #117 r3144336375 / r3144336377 / r3144340128 / r3144340129 - awk parser passes empty unknown TOML; missing exit code 2 on parse error; comment-stripping corrupts `#`-bearing values.
- **Suggested commit title:** `fix(fuzz-ci): tighten fuzz workflow gates, crash-triage routing, and seed-promotion script semantics`
- **Suggested branch:** `cleanup/c7-fuzz-ci-and-scripts`
- **Estimated effort:** ~3d.

### Group C8: kani harnesses + property tests + dudect

- **Affected files:**
  - `crates/chio-kernel-core/src/kani_public_harnesses.rs`
  - `crates/chio-kernel-core/tests/dudect/mac_eq.rs`
  - `crates/chio-kernel-core/tests/property_evaluate.rs`
  - `crates/chio-core-types/tests/property_capability_algebra.rs`
  - `crates/chio-credentials/tests/property_passport.rs`
  - `crates/chio-policy/tests/property_evaluate.rs`
  - `crates/chio-conformance/tests/vectors_oracle.rs`
  - `crates/chio-conformance/tests/vectors_schema_pair.rs`
  - `scripts/kani-changed-harnesses.sh`
- **Threads (canonical):**
  - PR #17 r3142816112 / r3142816113 / r3142820366 - matcher errors silently passing; expired-cap invariant uses out-of-scope requests; BTreeSet hides multiset diffs.
  - PR #18 r3142816281 / r3142818339 - signing failure silently passes (**Medium**).
  - PR #20 r3142831022 / r3142831023 / r3142834154 - active-lifecycle gate not exercised; helper self-reference; tautological state-transition test.
  - PR #21 r3142831900 - deny-override never tested.
  - PR #22 r3142839365 - hardcoded `with_cases(48)` bypasses lane tiering (**High**).
  - PR #52 r3142935484 - panicking helper defeats failure-collection.
  - PR #57 r3142968314 - delegation-step proof skips runtime subset logic.
  - PR #72 r3143030538 / r3143035964 / r3143035965 - deletion-only harness edits skip verification; range attribution misses helper-dependent harnesses.
  - PR #105 r3144167550 / r3144167551 - dudect closure return value not measured (**P1**); `--test` selector correction.
- **Suggested commit title:** `test(formal): repair Kani harnesses, proptest invariants, and dudect runner closure`
- **Suggested branch:** `cleanup/c8-formal-tests-repair`
- **Estimated effort:** ~3d.

### Group C9: TLA+ / Apalache / formal MAPPING

- **Affected files:**
  - `formal/tla/RevocationPropagation.tla`
  - `formal/tla/MCRevocationPropagation.cfg`
  - `formal/issue-templates/liveness-counterexample.md`
  - `formal/MAPPING.md`
  - `formal/OWNERS.md`
  - `tools/install-apalache.sh`
  - `scripts/check-mapping.sh`
  - `.github/workflows/nightly.yml` (Apalache liveness lane)
- **Threads (canonical):**
  - PR #53 r3142943822 / r3142943825 - missing `DEPTH_MAX = 4`; install-script pipefail abort.
  - PR #58 r3142968121 - Apalache pin path wrong in OWNERS.
  - PR #61 r3142986117 / r3142992287 / r3142992290 - mapping gate too lax; backtick prose tripping fail-closed; awk parser blank-line miss.
  - PR #64 r3142993570 / r3142993572 - unsupported `WF_vars` fairness; counterexample template wrong flag.
  - PR #66 r3142998135 / r3142998192 - liveness lane uses `--inv` instead of `--temporal` (**P1/High**).
- **Suggested commit title:** `fix(formal): correct Apalache liveness invocation, mapping gate, and OWNERS pin paths`
- **Suggested branch:** `cleanup/c9-formal-tla-mapping`
- **Estimated effort:** ~1.5d.

### Group C10: cargo-mutants config + mutants CI

- **Affected files:**
  - `.cargo/mutants.toml`
  - `crates/{chio-kernel-core,chio-credentials,...}/mutants.toml`
  - `.github/workflows/mutants.yml`
  - `.github/workflows/dudect.yml`
  - `scripts/check-dudect-threshold.sh`
  - `scripts/mutants-fuzz-cocoverage.sh`
- **Threads (canonical):**
  - PR #102 r3144127594 / r3144132735 / r3144132736 - per-crate `mutants.toml` files never loaded by cargo-mutants 25.x; `include!`d files ignored (**High**).
  - PR #103 r3144137926 / r3144146511 / r3144146515 - job-level `continue-on-error` defeats blocking-gate flip; `--in-diff` receives git ref instead of diff file (**High**).
  - PR #107 r3144173070 / r3144173073 / r3144182112 - threshold compared at truncated precision; `--threshold` not validated; `gh run list` missing status filter.
  - PR #108 r3144171683 / r3144171685 / r3144180213 / r3144180215 / r3144180217 - replay runs against clean tree not mutant; per-target dedup; jq path extraction wrong; non-jq fallback never matches; corpus replay against unmutated binary.
- **Suggested commit title:** `fix(ci): consolidate cargo-mutants config and repair mutants/dudect/cocoverage scripts`
- **Suggested branch:** `cleanup/c10-mutants-and-dudect`
- **Estimated effort:** ~2.5d.

### Group C11: supply-chain / SLSA / cosign / OSS-Fuzz / SBOM

- **Affected files:**
  - `supply-chain/{config,audits}.toml`
  - `deny.toml`
  - `.github/workflows/{ci,release-binaries,release-pypi,release-npm,slsa,release-cpp}.yml`
  - `infra/sbom/syft.yaml`
  - `infra/oss-fuzz/{build.sh,project.yaml}`
  - `docs/install/PUBLISHING.md`
  - `docs/coordination/m06-attest-verify-migration.md`
  - `crates/chio-attest-verify/src/sigstore.rs`
  - `tools/vcpkg-overlay/ports/chio-cpp/portfile.cmake`
- **Threads (canonical):**
  - PR #25 r3142845344 - 21 workspace crates missing from cargo-vet policy.
  - PR #28 r3142866284 / r3142870711 - MPL-2.0 license scope.
  - PR #30 r3142870354 - audited crates retain redundant exemption entries.
  - PR #39 r3142881621 / r3142881800 - cargo-deny `sources` check missing (**P1**).
  - PR #40 r3142883192 - required-check inventory misnames jobs (**P1**).
  - PR #43 r3142892200 / r3142894176 - `cross auditable build` unsupported (**P0**).
  - PR #44 r3142897955 / r3142898745 / r3142898746 - syft installer fetched from mutable `main`; nested cataloger keys unrecognised.
  - PR #46 r3142898932 / r3142900224 - SLSA never fires on tag releases (**High**).
  - PR #56 r3142968181 / r3142968183 / r3142974715 - DER-encoded OIDC issuer; `block_on` panics inside async (**P1/High**).
  - PR #73 r3143034423 - cosign verify regex misses `workflow_dispatch` refs.
  - PR #74 r3143034863 - unsatisfiable sigstore dependency gate.
  - PR #75 r3143041632 / r3143041637 - PyPI/npm release-attest jobs not gated on publish success (**P1**).
  - PR #77 r3143040469 - publish docs verify regex missing `workflow_dispatch`.
  - PR #94 r3144022628 - vcpkg portfile uses wrong tag prefix (**P1**).
  - PR #106 r3144168547 / r3144176024 / r3144176028 - OSS-Fuzz binary path wrong (**High**); `undefined` sanitizer not supported for Rust.
  - PR #109 r3144314472 - dedup-versions only removes one duplicate.
- **Suggested commit title:** `fix(release/supply-chain): repair cosign/cross/SLSA/OSS-Fuzz wiring and license scopes`
- **Suggested branch:** `cleanup/c11-supply-chain-release`
- **Estimated effort:** ~3d (split internally into release-binaries, supply-chain config, attest-verify, OSS-Fuzz subcommits).

### Group C12: misc CI workflows + xtask codegen + spec drift

- **Affected files:**
  - `.github/workflows/{ci,nightly,spec-drift,schema-breaking-change,conformance-matrix,vectors-staleness,release-tagged}.yml`
  - `xtask/src/main.rs`
  - `Cargo.toml` (workspace)
  - `sdks/go/chio-go-http/scripts/regen-types.sh`
  - `sdks/go/chio-go-http/types.go`
  - `crates/chio-conformance/peers.lock.toml`
  - `formal/diff-tests/tests/receipt_encoding_diff.rs`
  - `tests/bindings/vectors/{manifest,hashing,signing,receipt,capability}/v1.json` (corpus parity)
  - `crates/chio-core-types/tests/_generated_check.rs`
- **Threads (canonical):**
  - PR #34 r3142878423 / r3142878424 / r3142881907 - jsonschema reference resolution disabled (**P1**); unrecognised `$schema` URIs silently pass; URI-to-path mismatch.
  - PR #45 r3142897620 / r3142904375 - manifest fixture generator out of sync with corpus (**P1**).
  - PR #47 r3142903127 / r3142909054 - hashing fixture generator out of sync (**P1/High**).
  - PR #48 r3142913437 - signing per-case seed overrides break round-trip (**High**).
  - PR #49 r3142922986 - receipt round-trip skips new vectors.
  - PR #50 r3142926333 - capability vector expectation depth-coupled (**P1**).
  - PR #55 r3142960528 / r3142960529 - codegen `--check` only validates two files; header check too lax.
  - PR #60 r3142990972 / r3142990973 / r3142990974 / r3142990976 / r3142990977 / r3142990978 - Go shell failure mis-typed; staged-changes detection; SHA stamp ties to git history; `--check` mutates output; bare-name enum constants; oneOf+null inline merge title leak.
  - PR #68 r3143010896 - python codegen omits package re-export.
  - PR #132 r3144520795 - spec-drift misses untracked files.
  - PR #136 (eight threads) r3144545923 / r3144545928 / r3144557050 / r3144608545 / r3144608547 / r3144609835 / r3144609838 / r3144609842 - schema-breaking-change workflow: glob pathspec, sticky comment, heredoc delimiter, base-vs-merge-base diff, rename source resolution, multi-file markdown newline, stale comment, Cargo env in Node workflow, renamed schemas skip detection.
  - PR #137 r3144554383 / r3144560922 - live TS differential silently skips on encoder failure.
  - PR #140 r3144588619 / r3144588622 / r3144591446 - `released_at` uses runner clock; duplicate-tag append; **High Severity** script injection via `release.tag_name`.
- **Suggested commit title:** `fix(ci/codegen): align spec-drift, schema-breaking-change, codegen --check, and release-tagged workflows`
- **Suggested branch:** `cleanup/c12-ci-and-codegen`
- **Estimated effort:** ~3d (split internally; the schema-breaking-change cluster alone is ~1d).

---

## Anomalies / observations

1. **Heavy duplication of `chio-replay-gate.yml:120` and `bless.rs:227`.** Eight PRs each carry an outdated copy of the same comment because every replay-gate-touching PR retriggered chatgpt-codex; only the canonical PR #119 / #120 threads need to be addressed. (Bucket A entries 2-9, 15-26.)
2. **`peers.lock.toml` placeholder pins** are flagged on PRs #134 and #127. The nightly `conformance-matrix` workflow will fail until this is fixed - this should be triaged as P0 inside group C5, not just P1.
3. **PR #43 "cross auditable build" is P0** (the only P0 in the queue) and lives in group C11. Recommend splitting C11 so the cross-auditable repair lands first.
4. **PR #140 thread `r3144591446` ("Script injection via unsanitised release tag name") is High Severity and security-relevant** (group C12). Should be hot-fixed independently of the rest of C12 if a release is imminent.
5. **No threads on PRs #14, #23-#24, #27, #31, #33, #35-#38, #41, #51, #59, #62-#63, #65, #69-#70, #78, #80, #85, #87, #89-#90, #92-#93, #95-#97, #100, #115-#116, #125** in this catalog - they merged with all reviews resolved.
6. Several Bucket B entries (#86 `list_scenario_inputs`, #113 `cflite_mode`) hinge on whether the symbol is consumed by code outside `arc/`. The "won't-fix" reply assumes that's true; if not, demote to a small Bucket C addendum.

## Top 3 highest-priority groups

1. **Group C11 (supply-chain / release):** contains the only P0 thread (`cross auditable build`), the SLSA-on-tags High-Severity gap, the cosign/sigstore async-runtime panic, and the cargo-deny sources-check miss. Largest blast radius if unaddressed - any failed release will need this.
2. **Group C2 (chio-replay-gate.yml hardening):** anchors the duplicate cluster (8 outdated copies in Bucket A reduce to one fix here). Required-on-main check today silently passes when the golden test file has compile errors - the gate is fail-open.
3. **Group C5 (chio-conformance crate publish + CLI):** placeholder peer-lock pins guarantee nightly failures, and several "P1" findings about runtime peers.lock resolution mean external consumers cannot run conformance from a published crate. Six PRs (#118, #122, #124, #127, #130, #131, #134) all converge here.

Honourable mentions: **C12** (covers the security-critical script-injection in `release-tagged.yml` plus the nine-thread `schema-breaking-change.yml` cluster) and **C8** (formal-test correctness - several harnesses today assert tautologies or silently pass).
