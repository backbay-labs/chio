# Validation appendix: moving crates/chio-* into crates/<group>/chio-*

Read-only adversarial validation of the planned step:

> move crates/chio-* into crates/<group>/chio-* (11 functional folders) AFTER centralizing internal deps via [workspace.dependencies].

Repo: /Users/connor/Medica/backbay/standalone/arc (branch codex/chio-next-10-remediation).
No files were modified. Evidence is file:line. House rule honored: no em dashes.

## Verdict

safe-with-edits, BUT only if the centralization step is done correctly AND the four standalone (own-`[workspace]`) crates plus the path-literal CI gates are repaired in the same commit. The dominant risk is NOT compile breakage (cargo errors loudly); it is the large set of fail-closed CI gates and `paths:`/CODEOWNERS filters that key on literal `crates/chio-x/...` strings. After a move those go silently dark: the gate stops finding files, reports nothing to enforce, and CI stays green while the protection is gone. That is the exact failure mode being guarded against.

Recommend EXPLICIT enumeration for the workspace `members` list, not a glob. Reasoning under "Blocker / members glob".

## 1. Centralization feasibility (the 447 / 451 figure)

- `crates/` path-dep lines referencing an internal chio crate: 450 total.
  - 447 single-level `path = "../chio-..."`  (grep `path *= *"\.\./chio-` over `crates/**/Cargo.toml`).
  - 3 double-level `path = "../../chio-..."` (all in `crates/chio-conformance/verdict_matrix/Cargo.toml:33-35`).
  - 0 triple-level.
- 91 distinct internal chio crates are consumed by path.
- 32 of the 447 carry a `package = "..."` rename (key != package). Dominant case is `chio-core = { package = "chio-core-types", path = "../chio-core-types" }` (e.g. crates/chio-tee/Cargo.toml:26, crates/chio-a2a-adapter/Cargo.toml:17, crates/chio-mcp-adapter/Cargo.toml:20, and 29 more).
- 25 of the 447 carry `features = [...]`.

Centralization to `[workspace.dependencies]` is mechanically sound for all 450:
- Plain dep -> key on the package name: `chio-core = { path = "crates/<group>/chio-core" }`, consumer writes `chio-core = { workspace = true }`.
- Rename dep -> key on the real package name: `chio-core-types = { path = "crates/<group>/chio-core-types" }`, consumer writes `chio-core = { package = "chio-core-types", workspace = true }`.
- Feature dep -> `features` is allowed alongside `workspace = true`: `chio-x = { workspace = true, features = ["fuzz"] }`.

Only ONE internal crate is centralized today: `chio-metrics-spec = { path = "crates/chio-metrics-spec" }` at Cargo.toml:320. The remaining 90 must be added to `[workspace.dependencies]` in the centralization step, with paths already pointing at the post-move `crates/<group>/...` location so the subsequent folder move only edits the single `[workspace.dependencies]` block, not 447 member manifests.

Key correctness point for the move: because `[workspace.dependencies]` declares the path ONCE in the root, the 447 member-manifest lines become `{ workspace = true }` and are location-independent. That is the entire value of doing centralization first. It does NOT, however, help the four standalone workspaces below (they do not inherit the root `[workspace.dependencies]`).

## 2. Nested sub-crates using deeper paths

- `crates/chio-conformance/verdict_matrix/Cargo.toml` declares its OWN `[workspace]` (line 30) and is intentionally NOT a root member. It uses three `../../chio-*` deps:
  - line 33 `chio-core = { package = "chio-core-types", path = "../../chio-core-types" }`
  - line 34 `chio-kernel = { path = "../../chio-kernel" }`
  - line 35 `chio-kernel-browser = { path = "../../chio-kernel-browser" }`
  These do NOT see root `[workspace.dependencies]`. If chio-conformance moves to `crates/<groupA>/chio-conformance` AND its dep targets move to `crates/<groupB>/...`, the `../../` depth is no longer correct (the relative jump now lands in the wrong group). These three must be hand-rewritten to the new relative paths (likely `../../../<groupB>/chio-core-types` etc., depending on group nesting depth).
- `crates/chio-eval-receipt/py/Cargo.toml:17` uses `chio-eval-receipt = { path = ".." }`. This is relative to its own parent, so it survives the move as long as `py/` stays a child of `chio-eval-receipt/` (it does). The root `exclude` entry (below) still needs the path updated.
- `crates/chio-conformance/verdict_matrix/drivers/lambda/Cargo.toml` is a root member (Cargo.toml:133) but uses only `workspace = true` deps (no chio path deps). Its member path line must be updated on the move.
- `crates/chio-data-guards/redactors/default/Cargo.toml` is a root member (Cargo.toml:20), no chio path deps; member path line must be updated.

## 3. The two non-member nested manifests + chio-openai mismatch (confirmed)

- Confirmed: `crates/chio-conformance/verdict_matrix/Cargo.toml` (own `[workspace]`, line 30) is NOT in root members; only its `drivers/lambda` child is (Cargo.toml:133).
- Confirmed: `crates/chio-eval-receipt/py/Cargo.toml` is in the root `exclude` list (Cargo.toml:167 `"crates/chio-eval-receipt/py"`), not a member.
- Confirmed chio-openai dir vs package mismatch:
  - directory `crates/chio-openai/` but `[package] name = "chio-openai-adapter"` (crates/chio-openai/Cargo.toml:2).
  - Only consumer: crates/chio-provider-conformance/Cargo.toml:21 `chio-openai = { package = "chio-openai-adapter", path = "../chio-openai", features = ["provider-adapter"], optional = true }`.
  - Centralization key must be the package name `chio-openai-adapter` pointing at the directory `crates/<group>/chio-openai`; consumer becomes `chio-openai = { package = "chio-openai-adapter", workspace = true }`. The directory/package name mismatch is harmless to cargo (path is explicit), but it WILL trip any tooling that assumes dir-name == package-name.

## 4. supply-chain/ and deny.toml: SAFE (no path coupling)

- `supply-chain/config.toml` and `supply-chain/audits.toml` (cargo-vet) key everything by package NAME, e.g. `[policy.chio-a2a-adapter]` (config.toml:19), `[[audits.chio-mcp-remote]]` (audits.toml:460). cargo-vet resolves the dependency graph by crate name, not filesystem path. Zero literal `crates/chio-x` paths in supply-chain/ (grep returned none).
- `deny.toml`: 0 occurrences of `crates/chio` (grep `-c` = 0). cargo-deny is name/graph based. SAFE.
- `osv-scanner.toml`, `releases.toml`, `Makefile`: 0 occurrences each. `releases.toml` `trust_boundary_crates` (line 88+) lists crate NAMES (`"chio-policy"`), not paths. SAFE.

## 5. scripts/ and .github/ hard-coded paths: the blast radius

### .github/ (37 workflow yml + CODEOWNERS, 346 refs)

The most dangerous category. Three sub-kinds:

- `paths:` trigger filters: 239 literal `- "crates/chio-x/**"` lines across 28 workflows. After the move these patterns match nothing, so the workflow STOPS triggering on changes under those crates. Silent go-dark; CI stays green. Representative: .github/workflows/transitive-surface.yml:10-24 (44 such lines), provider-conformance.yml, chio-runtime.yml, conformance-matrix.yml, threat-model-coverage.yml.
- `working-directory: crates/chio-cli/dashboard`: 5 occurrences (e.g. .github/workflows/chio-pheromone-relay-alert-assurance.yml:48, chio-pheromone-relay-observability.yml:47, chio-pheromone-relay-alert-handoff.yml:52, chio-pheromone-relay-alert-routing.yml:50, chio-pheromone-relay-alert-delivery.yml:50). These hard-break (step fails) on the move.
- Literal path args to scripts: e.g. .github/workflows/bench-regression.yml:104,154 pipe `crates/chio-kernel/Cargo.toml` into a script.
- `.github/CODEOWNERS`: 23 literal `crates/chio-x/**` patterns (e.g. lines 14-23). On the move these silently stop matching, so trust-boundary files lose their required `@backbay-labs/chio-maintainers` reviewers. Security-relevant silent regression.

MOVE-SAFE within .github: any step using `cargo -p <crate-name>` (package selector) survives. Examples: verdict-matrix.yml:77-83 `cargo test -p chio-conformance ...`, bench-regression.yml:111 `cargo bench -p chio-kernel`, nightly.yml:55-58, chio-cpp.yml:72-73. These need no edit.

### scripts/ (41 .sh + 3 .py + 1 .bats, 465 refs)

All consume literal `crates/chio-x/...` rooted at `Path(__file__).parents[1]` or `$REPO_ROOT`. The heavy / fail-closed ones:

- scripts/check-review-slices.py (95): literal `crates/chio-x/**` ownership-slice globs (lines 42+). Breaks silently.
- scripts/check-stub-surfaces.py (92): dict keyed by exact file path, e.g. `"crates/chio-anchor/src/witness.rs": allow(...)` (lines 40+). On move the allow-list entries no longer match any file; stub gate either errors or stops enforcing.
- scripts/check-workspace-layering.sh (8): literal `"crates/chio-core/Cargo.toml"` list (lines 7-14).
- scripts/check-adapter-no-bypass.sh (7): literal `"crates/chio-mcp-edge/src/runtime/tool_calls.rs"` etc (lines 11+).
- scripts/triage-threat-rows.sh (20): pipe-delimited rows embedding `crates/chio-guards/src/...` and `crates/chio-conformance/tests/threats/...` (lines 13+).
- scripts/check-threat-coverage.sh: reads spec/security/chio-threat-model.v1.json and asserts test files exist at literal `crates/chio-conformance/tests/threats/<id>.rs` (lines 6-19, THREAT_MODEL at line 49). Fail-closed gate; breaks when chio-conformance moves.
- scripts/check-rust-file-hygiene.py (19), check-proptest-coverage.sh (18), check-sre-metrics-registry.sh (13), check-anchor-batch-async-witness.sh (7), bless-replay-goldens.sh, check-http-egress-contract.sh, qualify-portable-browser.sh, measure_chio_core_rebuild.sh, kani-changed-harnesses.sh, check-mapping.sh, check-log-redaction.sh, check-aeneas-equivalence.sh, qualify-release.sh, promote_fuzz_seed.sh, smoke/chio-cli-smoke.sh, check-chio-cpp.sh, plus scripts/tests/*.test.sh fixtures that hardcode expected paths.
- scripts/qualify-bounded-chio.sh: consumes docs/standards/*.json whose `crate_path` fields embed literal `crates/chio-x/...::Symbol` (see below).

## Additional fail-closed gates OUTSIDE the requested dirs (found while validating; must not be missed)

These were not in the original dir list but are the same silent-go-dark class:

- .cargo/mutants.toml: ~70+ literal `crates/chio-x/src/*.rs` entries in mutation include/exclude lists (lines 88-201). cargo-mutants finds zero files at stale paths and the mutation gate passes with nothing tested. SILENT.
- .kani/harnesses.toml: source-path references like `crates/chio-anchor/src/kani_public_harnesses.rs` (lines 239,243,267,294,299; also chio-attest-verify, chio-weights). Proof harness manifest.
- audits/mutation/per-crate-configs/*.toml (7 files: chio-anchor.toml, chio-attest-verify.toml, chio-guards.toml, chio-kernel-core.toml, chio-policy.toml, chio-weights.toml, chio-guards-2026-05-08-subset.toml): literal `examine_globs` source paths (e.g. chio-anchor.toml:36-55).
- spec/security/coverage.yaml: literal `crates/chio-custody-hw/src/*.rs` coverage entries (lines 26-40).
- spec/security/chio-threat-model.v1.json: threat rows embed impl paths consumed by check-threat-coverage.sh.
- contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json: lines 20-21 hardcode `crates/chio-web3-bindings/src/interfaces.rs` and `.../lib.rs` (release-contract manifest).
- docs/standards/*.json (12 qualification matrices, e.g. CHIO_OFFICIAL_STACK.json:13,22,31): `crate_path` fields like `crates/chio-kernel/src/authority.rs::LocalCapabilityAuthority`, consumed by scripts/qualify-bounded-chio.sh and parity tests.
- formal/proof-manifest.toml (11 lines: covered source files at lines 51-57), formal/aeneas/production.toml:4 (`source = "crates/chio-kernel-core/src/formal_aeneas.rs"`), formal/theorem-inventory.json (2). Proof-coverage gates.
- .github/ISSUE_TEMPLATE/mutants_survivor.yml: literal path references.

Lower priority (prose mirrors / not filesystem lookups, cosmetic drift only):
- spec/schemas/chio-wire/**.schema.json: `crates/chio-...` appears only inside `description` text, not as a path consumed by the validator. The `chio-wire/v1/...` tokens are schema $id namespaces, not crate dirs.
- sdks/go/chio-go-http/types.go and sdks/python/.../_generated/*.py: generated doc-comment "Mirrors crates/chio-x/src/...rs" strings (hundreds of lines). Stale comments only.
- Most of docs/, ops/knowledge-base/, .codex/pr-cleanup/ (PR-history JSON), audits/evidence/threats|mutants/*.json (dated evidence snapshots).

## Standalone (own-[workspace]) crates that centralization CANNOT reach

These four declare their own `[workspace]` so they do NOT inherit root `[workspace.dependencies]`. Their chio path deps must be hand-edited on the move (31 lines total):

- fuzz/Cargo.toml (own `[workspace]` at line 25): 23 `path = "../crates/chio-*"` deps (lines 28-53). PLUS fuzz/owners.toml (20 literal `path = "crates/chio-*"`, lines 17-93) and fuzz/target-map.toml (34 literal `crates/chio-x/**` coverage globs).
- crates/chio-conformance/verdict_matrix/Cargo.toml (own `[workspace]` line 30): 3 `../../chio-*` deps (lines 33-35).
- sdks/rust/chio-guard-sdk-compat/Cargo.toml (own `[workspace]` line 20): 1 dep `../../../crates/chio-guard-sdk` (line 14).
- sdks/lambda/chio-lambda-extension/Cargo.toml (own `[workspace]` line 15): 4 deps `../../../crates/chio-*` (lines 22-25).

xtask also has RUNTIME path constants in Rust source (not deps) that break on move:
- xtask/src/main.rs:450 `const CHIO_WIRE_V1_RUST_OUT: &str = "crates/chio-core-types/src/_generated";` (codegen writes here).
- xtask/src/eval_receipt_regen.rs:61,72,83 `"../../crates/chio-eval-receipt/tests/fixtures/..."`.

Consumers that ARE root members (so their 447-style path deps become `{ workspace = true }` for free): examples/* (36 lines across 10 manifests, including guards/* at `../../../`), tests/e2e (4), tests/replay (1), xtask (3 deps), formal/diff-tests (3), integrations/mcp-adapter (1). These need only the per-line `{ workspace = true }` rewrite that the centralization step already performs; no path math.

Non-dep runtime/test path literals in member code that still break:
- tests/replay/src/bless.rs:859,864 stub git path `crates/chio-kernel/src/lib.rs`.
- tests/ci_guards/regression_deletion_test.sh:51-128 creates/removes `crates/chio-kernel-core/tests/regression_deadbeef.rs`.
- sdks/go/chio-go-http/verdict_matrix_test.go:14,18 and sdks/python/chio-sdk-python/tests/test_verdict_matrix.py:12,21,37 resolve `crates/chio-conformance/verdict_matrix/...` at test time.
- examples/eval-receipt-ingest/metr/ingest.py:10,68 fixture path lookups.
- Dockerfile:23-61 (8 lines) `COPY crates/chio-cli/dashboard/...` build steps. Hard break.

## Root Cargo.toml edits required on the move

- 111 member lines `"crates/chio-..."` (Cargo.toml:5-136) repath to `"crates/<group>/chio-..."`. Includes the three nested member lines:
  - line 20 `"crates/chio-data-guards/redactors/default"`
  - line 133 `"crates/chio-conformance/verdict_matrix/drivers/lambda"`
- exclude line 167 `"crates/chio-eval-receipt/py"` repath.
- [workspace.dependencies] line 320 `chio-metrics-spec` path repath, plus the 90 new centralized entries.

## requiredEdits summary (grouped checklist)

1. Centralize first (done before move): add all 90 missing internal crates to root `[workspace.dependencies]` keyed by package name; flip the 447 member-manifest path deps to `{ workspace = true }` (preserve `package =` rename on 32, `features` on 25, `optional`).
2. Root Cargo.toml: repath 111 member lines + 1 exclude line + the centralized `[workspace.dependencies]` paths to `crates/<group>/...`.
3. Four standalone workspaces (NOT reached by centralization): hand-edit 31 path-dep lines + fuzz/owners.toml (20) + fuzz/target-map.toml (34).
4. .github: rewrite 239 `paths:` glob lines (28 workflows), 5 `working-directory:` lines, literal script-arg paths; rewrite 23 CODEOWNERS patterns. Leave `cargo -p` steps untouched.
5. scripts/: rewrite literal `crates/chio-x` in 41 .sh + 3 .py + 1 .bats (check-review-slices.py, check-stub-surfaces.py, check-workspace-layering.sh, check-adapter-no-bypass.sh, triage-threat-rows.sh, check-threat-coverage.sh, etc.).
6. Out-of-band fail-closed configs: .cargo/mutants.toml, .kani/harnesses.toml, audits/mutation/per-crate-configs/*.toml (7), spec/security/coverage.yaml, spec/security/chio-threat-model.v1.json, formal/proof-manifest.toml, formal/aeneas/production.toml, formal/theorem-inventory.json, contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json, docs/standards/*.json (12), .github/ISSUE_TEMPLATE/mutants_survivor.yml.
7. Runtime/build literals: xtask/src/main.rs:450, xtask/src/eval_receipt_regen.rs:61/72/83, Dockerfile:23-61, tests/replay/src/bless.rs:859/864, tests/ci_guards/regression_deletion_test.sh, sdks verdict_matrix tests, examples/eval-receipt-ingest/metr/ingest.py.

## Blocker / members glob recommendation

Recommend EXPLICIT enumeration, not a glob (`crates/*/chio-*` or `crates/**`), for the `members` list:

- Fail-closed reasoning: the repo deliberately has multiple in-tree crates that are NOT members (own `[workspace]`): crates/chio-conformance/verdict_matrix, plus py exclude, plus the four standalone workspaces. A broad glob like `crates/*` or `crates/**` would try to ADOPT crates/chio-conformance/verdict_matrix and crates/chio-eval-receipt/py into the root workspace, which is an error (a crate cannot belong to two workspaces) and would fail the build, OR worse, silently pull excluded crates into `--workspace` gates. The current explicit list encodes intent that a glob cannot express.
- A glob also cannot encode the deliberate inclusion of only `verdict_matrix/drivers/lambda` while excluding its parent `verdict_matrix`. That asymmetry (member child under a non-member parent) is impossible to express with a single glob and is exactly why the explicit list exists today.
- Globs hide membership: a new crate dropped into a group folder would be silently adopted with no review, defeating the public-entrypoint and supply-chain gating that keys on the curated member set (workspace.metadata.chio.rust_public_entrypoints at Cargo.toml:177+).
- Net: keep explicit members; the move only rewrites the path prefix of each existing line. Pair the move with a `cargo metadata --no-deps` member-count assertion (expect the same N members before and after) as a fail-closed check that no crate was accidentally dropped or adopted.
