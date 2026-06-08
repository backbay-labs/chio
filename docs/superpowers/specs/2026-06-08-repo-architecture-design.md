# Chio Repository Architecture Redesign

Design spec. Date: 2026-06-08. Status: proposed (awaiting owner approval).

This document defines the target file/folder architecture for the Chio repository
and a phased, fail-closed migration roadmap. It covers five fronts: the `crates/`
taxonomy, a unified `cargo xtask` CI/CD CLI, the GitHub Actions workflow
architecture, root-level consolidation, and the README rewrite.

It is the synthesis of two research waves recorded in `docs/superpowers/research/`:
wave 1 (inventory and proposals) and wave 2 (read-only adversarial validation of
every load-bearing migration step, with `file:line` evidence). Where wave 2
contradicted a wave 1 assumption, wave 2 wins and the spec says so.

House rules honored throughout: no em dashes; fail-closed (errors deny, invalid
input rejects at load); `unwrap_used`/`expect_used` denied in new Rust.

---

## 1. Goals and non-goals

### Goals

1. Give a newcomer an immediate mental model: every crate, script, workflow, and
   root entry has one obvious home.
2. Replace the 22k-line bash gate pile with one typed, testable, discoverable
   `cargo xtask` CLI so gate logic lives in Rust, not in copy-pasted YAML.
3. Rebuild CI from first principles: thin entry workflows composing reusable
   workflows and composite actions, with a merge queue and a single aggregate
   required check.
4. Remove root-level cruft and consolidate overlapping directories.
5. Rewrite the README value-first with a real quickstart.

### Non-goals

- No protocol, wire, or schema changes. This is purely structural.
- No change to what the gates assert. Consolidation must preserve every gate's
  behavior exactly (proven by dual-run parity), never widen or silently drop one.
- No docs-tree content rewrite beyond the README and the moved files. The
  `docs/` reorganization (320 markdown files) is a separate later effort.
- No new third-party dependencies beyond `clap` (already pinned per-crate at 4.x in 5 crates and vetted; this phase reuses it, not a new dependency surface).

### The overarching risk this spec is built around

The dominant failure mode is not compile breakage (Cargo fails loudly). It is
**silent go-dark**: a path literal in a `paths:` filter, a CODEOWNERS pattern, a
mutation/kani/threat-coverage config, or a cargo-vet trigger that, after a move,
matches nothing. The gate then enforces nothing, the required reviewer is no
longer required, and CI stays green. Every phase below is sequenced and gated to
make that failure mode impossible, primarily via a new `xtask` guard that asserts
every `crates/chio-*` path literal in the repo resolves to a real file.

---

## 2. Target architecture

### 2.1 Crate taxonomy: 11 functional folders

`crates/` moves from 107 flat directories to 11 functional subfolders that mirror
the comment-group headers already in the root `Cargo.toml`. The folders are
navigation/documentation aids, not build-layer enforcement (Cargo does not
enforce layering by directory, and the real graph has economy-contract crates
sitting below core/kernel).

Top-level folders under `crates/`:
`core`, `kernel`, `guards`, `protocol`, `economy`, `trust`, `observability`,
`platform`, `products`, `sdk`, `tooling`.

Full assignment (107 top-level crates + 4 nested):

| Group | Crates |
| --- | --- |
| `core` (5) | chio-core, chio-core-types, chio-errors, chio-adversarial-suite, chio-arena |
| `kernel` (7) | chio-kernel, chio-kernel-core, chio-kernel-browser, chio-kernel-mobile, chio-runtime, chio-runtime-core, chio-runtime-harness |
| `guards` (6) | chio-data-guards (+ nested redactors/default), chio-external-guards, chio-guard-registry, chio-guards, chio-policy, chio-wasm-guards |
| `protocol` (27) | chio-a2a-adapter, chio-a2a-edge, chio-acp-edge, chio-acp-proxy, chio-ag-ui-proxy, chio-anthropic-tools-adapter, chio-bedrock-converse-adapter, chio-cohere-tools-adapter, chio-cross-protocol, chio-edge-metrics, chio-egress-contract, chio-envoy-ext-authz, chio-gemini-tools-adapter, chio-groq-tools-adapter, chio-mcp-adapter, chio-mcp-edge, chio-mcp-remote, chio-mistral-tools-adapter, chio-ollama-tools-adapter, chio-openai (-> rename dir to chio-openai-adapter), chio-openapi, chio-openapi-mcp-bridge, chio-provider-adapter-core, chio-provider-conformance, chio-tool-call-fabric, chio-tower, chio-hosted-mcp |
| `economy` (13) | chio-anchor, chio-appraisal, chio-autonomy, chio-credit, chio-link, chio-listing, chio-market, chio-open-market, chio-settle, chio-underwriting, chio-web3, chio-web3-bindings, chio-metering |
| `trust` (20) | chio-replay-corpus, chio-attest-buyer, chio-attest-buyer-core, chio-attest-verify, chio-attest-loopback, chio-custody-hw, chio-weights, chio-tee, chio-tee-frame, chio-credentials, chio-did, chio-federation, chio-federation-authority, chio-governance, chio-pheromone, chio-pheromone-relay, chio-pheromone-runtime, chio-revocation-oracle, chio-reputation, chio-selective-disclosure |
| `observability` (5) | chio-lineage, chio-log-redact, chio-metrics-spec, chio-otel-receipt-exporter, chio-siem |
| `platform` (7) | chio-config, chio-control-plane, chio-manifest, chio-store-sqlite, chio-workflow, chio-http-core, chio-http-session |
| `products` (6) | chio-api-protect, chio-cli, chio-mercury, chio-mercury-core, chio-wall, chio-wall-core |
| `sdk` (6) | chio-binding-helpers, chio-bindings-ffi, chio-cpp-kernel-ffi, chio-eval-receipt (+ nested py), chio-guard-sdk, chio-guard-sdk-macros |
| `tooling` (5) | chio-lsp, chio-conformance (+ nested verdict_matrix, verdict_matrix/drivers/lambda), chio-spec-codegen, chio-spec-validate, chio-test-support |

Resolved placement calls (defaults; owner can override):
- `chio-metering` -> economy (cohesion with credit/settle/billing), not observability.
- `chio-appraisal` -> economy (core/kernel consume it as an economic contract),
  though it straddles trust.
- `chio-guard-sdk` / `chio-guard-sdk-macros` -> sdk (keeps `guards/` as the runtime
  enforcement surface; the SDK is for authoring guards). Alternative: `guards/`.
- `trust/` stays one folder (20 crates is cohesive). Documented sub-areas
  (identity, attestation, pheromone substrate) live in a `crates/trust/README.md`,
  not as nested folders. Consistent with the chosen 11-folder depth.

Members declaration: **explicit enumeration, grouped by folder with comment
headers, NOT a glob.** Wave 2 confirmed a glob (`crates/*` or `crates/**`) would
try to adopt the deliberately-non-member nested crates
(`chio-conformance/verdict_matrix` has its own `[workspace]`; `chio-eval-receipt/py`
is in `exclude`), which is a build error, and cannot express the deliberate
asymmetry of including only `verdict_matrix/drivers/lambda` while excluding its
parent. Globs also silently adopt any future crate with no review, defeating the
curated `rust_public_entrypoints` and supply-chain gating. The move only rewrites
the path prefix of each existing member line.

### 2.2 Unified CI/CD CLI: grow `cargo xtask`

`xtask` becomes the single entry point for artifact generation, verification
gates, qualification, formal-method runs, fuzz/mutation orchestration, release
steps, supply-chain checks, and tool-version management. Gate logic moves from
bash into typed, unit-tested Rust. Only thin external-tool wrappers and imperative
installers stay as shell.

`xtask` is converted from its hand-rolled `match` dispatcher (1,981 lines) to a
derive-based `clap` CLI (`clap` is already pinned at 4.x in 5 crates - chio-cli,
chio-control-plane, chio-wall, chio-mercury, chio-provider-conformance - so adopting
it in xtask reuses an already-vetted dependency rather than adding a new one; note
it is pinned per-crate, not yet in `[workspace.dependencies]`). Generated `--help`
replaces the hand-maintained `println!` help block.

Subcommand tree (noun-verb; every leaf maps to one CI job step):

```
cargo xtask
  gen        codegen --lang {rust,ts,go,python} [--check] | errors | snippets |
             eval-receipt | freeze-vectors | proof-report | bless-goldens
  check      hygiene | layering | egress | redaction | surface | threat |
             release-inputs | schema-registry | metrics | crate-paths | all
  qualify    release | bounded | trust-control | mobile-kernel | portable-browser |
             cross-protocol | universal-control-plane | comptroller <facet> | web3 <stage>
  verify     formal | kani [--scope ...] | apalache [--mode ...] | creusot |
             aeneas | dudect | coverage | proptest | proof-report
  fuzz       run | budget | promote-seed | cocoverage
  mutants    gate | rationale | banner | comment
  release    inputs | qualify | stage-web3 | tuf-rebake | seal-audit | sbom | binaries
  supply-chain  vet | deny | wildcard-deps | upstream-skips
  tools      doctor | install <tool> | versions
```

Two design points specific to this repo:
- `check crate-paths` is new and load-bearing: it parses every config that
  embeds a `crates/chio-*` path literal (workflow `paths:` filters, CODEOWNERS,
  `.cargo/mutants.toml`, `.kani/harnesses.toml`, `audits/mutation/per-crate-configs/*`,
  `spec/security/coverage.yaml`, `spec/security/chio-threat-model.v1.json`,
  `formal/proof-manifest.toml`, `contracts/release/*.json`, `docs/standards/*.json`)
  and fails if any literal does not resolve to an existing file. This is the guard
  that makes the crate move (and the assurance consolidation) fail-closed instead
  of silently going dark. It is built BEFORE any move.
- `--check` drift semantics are preserved exactly for every `gen` leaf (the
  contract `spec-drift` CI depends on).

CI integration: each workflow step becomes one `cargo xtask ...` line. The
monolithic `ci.yml` check job (currently ~20 inlined script calls in a `run: |`
block) becomes `run: cargo xtask check all`. Local == CI: a contributor runs the
identical command CI runs. The Makefile keeps only one-line delegations (or is
dropped once xtask covers its surface); no logic ever lands in make.

Script disposition (validated counts):
- DELETE (8, zero operational references confirmed in wave 2):
  `check-adversarial-threat-link.sh`, `check-chio-attest-buyer-fixtures.sh`,
  `check-docker-deployable-experience.sh`, `check-framework-integration-examples.sh`,
  `check-tool-server-async.sh`, `measure_chio_core_rebuild.sh`,
  `kani-changed-harnesses.sh`, `rebuild-from-source.sh`. Plus `rm -rf scripts/__pycache__`
  (gitignored cache).
- COLLAPSE into xtask subcommands: pheromone cluster (15 -> 1 parameterized gate),
  runtime cluster (6 -> 1), qualify family (17), SDK-release (already 1 driver +
  7 shims). The 25 `scripts/tests/*.test.sh` become Rust `#[cfg(test)]` tests as
  their target gate migrates.
- KEEP as thin shell: imperative installers (`tools/install-apalache.sh`), git
  plumbing (`setup-git-merge-drivers.sh`, `cargo-lock-merge.sh`), and pure
  external-tool passthroughs where the tool's own CLI is the real interface.
- OWNER DECISION (do not blind-delete, wave 2 flagged as doc-contract enforcement):
  `check-mapping.sh` (named by `formal/MAPPING.md` + HITRUST narrative),
  `triage-threat-rows.sh` (named by audit evidence), `check-corpus-metadata.sh`
  (named in `fuzz/corpus_metadata.toml`). Default: keep and fold into xtask.
- RELOCATE to their SDK (update the readme/manifest refs atomically):
  `build-android-aar.sh` -> `sdks/jvm/...`, `build-ios-framework.sh` -> `sdks/swift/`,
  `check-sdk-publication-examples.sh` -> beside the TS/Python SDK docs.

### 2.3 CI workflow architecture (first-principles rebuild)

From ~73 flat files (zero reusable workflows, zero composite actions, 51 copies
of the same Rust setup) to a composed architecture:

```
.github/
  actions/
    setup-rust/action.yml      # checkout + toolchain + rust-cache (inputs)
    setup-node/action.yml      # node + install (input: version)
  workflows/
    pr.yml                     # on: pull_request, merge_group -> fan-out to reusable
    ci.yml                     # on: push main -> reusable build/test + post-merge
    nightly.yml                # on: schedule + dispatch -> fuzz/mutants/bench/formal fan-out
    release.yml                # on: tags/release -> per-artifact reusable release jobs
    security.yml               # on: schedule + dispatch + PR(paths) -> vet/deny/cve/sbom/slsa
    pages.yml                  # on: push main -> demo-pages + docs
    _rust-build.yml            # reusable: build/test/clippy/fmt matrix
    _script-gate.yml           # reusable: one gate (inputs: xtask-cmd, needs-node, node-version)
    _conformance.yml           # reusable: vectors-byte-stable + parity
    _release-artifact.yml      # reusable: plan/build/publish/attest (input: registry)
    _sdk-{jvm,web,cpp}.yml      # reusable per-SDK
    _tee.yml _image.yml _replay-gate.yml _reproducible-build.yml _fuzz.yml
```

Design rules:
1. Entry workflows are thin: triggers, `concurrency` with `cancel-in-progress`,
   top-level `permissions: {}`, and calls to reusable workflows.
2. One `setup-rust` composite replaces the 51 copied setups; SHA bumps and cache
   policy change in one place.
3. `_script-gate.yml` absorbs the 18 thin one-script gates (15 pheromone + 3
   treaty/proof). The shape A/B/C/D differences (permissions, node version, cache)
   become explicit reusable-workflow inputs. Per-entry path filtering moves to a
   `paths-filter` dispatch job in `pr.yml`, which answers the existing
   `.github/workflows/README.md` objection without weakening fail-closed posture
   (every gate gets `contents: read`, tightening not loosening).
4. One aggregate `ci-required` job `needs:` all gate jobs; branch protection
   requires only `ci-required`, so adding/renaming a gate never touches GitHub
   ruleset config. (Requires a one-time branch-protection settings change: owner
   action, outside the repo.)
5. `merge_group` trigger + merge queue; heavy gates run once in the queue.
6. Least privilege: top-level `permissions: {}`, per-job opt-in; `id-token: write`
   only on SLSA/SBOM/attestation jobs. Fix the 1 unpinned action (`setup-dotnet@v4`).
7. `nightly.yml` fans out to reusable jobs, eliminating ~18 independent scheduled
   cold starts.

Result: ~18-20 files down from 73; per-PR required-check surface collapses from
25-30 separate checks to one `ci-required`.

### 2.4 Root-level layout

Wave 2 verified which root entries are pinned by tooling/governance and must NOT
move. The safe cleanup is documents, assets, Dockerfiles, packaging, and the
mislabeled `ops/` dir.

KEEP AT ROOT (verified pinned, moving risks fail-open or hard break):
- Standard OSS files: `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `AGENTS.md`, `CLAUDE.md`.
- Build/toolchain: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
  `.cargo/` (holds the `xtask` alias), `.gitignore`, `.gitattributes`,
  `.dockerignore` (build context stays repo root).
- `deny.toml` (cargo-deny reads from cwd; CODEOWNERS-pinned; cve-monitor trigger).
- `supply-chain/` (cargo-vet runs bare from root; moving needs a `store.path` edit
  plus rewrites to checksum/sbom write-contracts and a fail-open trigger risk).
- `releases.toml` (governance-pinned mutation-gate state file; a missing-file
  fail-closed guard in `release-binaries.yml`; documented as permanent root path).
- `.kani/`, `.clusterfuzzlite/` (tool-mandated root paths).
- `package.json` + `bun.lock` (root-constrained Bun workspace globs reach
  `docs/demo` and `sdks/typescript/*`; document why a Rust repo has them).

MOVE (low risk, with the exact edits wave 2 enumerated):
- `Dockerfile`, `Dockerfile.sidecar`, `Dockerfile.tee` -> `deploy/docker/`. Keep
  `.dockerignore` at root. Edit in the SAME commit: `sidecar-image.yml:106`,
  `chio-tee-image.yml:50` and its `paths:` triggers (`:6`, `:20`, else fail-open),
  `examples/docker/compose.yaml:8,27`, `examples/tee-sidecar/docker-compose.yml:5`,
  `scripts/tests/check-sidecar-docker-context.test.sh:5`, plus doc mentions.
- `Homebrew/chio.rb.tmpl` -> `packaging/homebrew/`.
- `papers/` -> `docs/papers/`; `assets/` -> `docs/assets/`;
  `RELEASE_AUDIT.md` -> `docs/release/`.
- `editors/` -> `integrations/editors/`.
- `ops/knowledge-base/` -> `tools/knowledge-base/` (`ops/` is not deployment ops;
  it is one Python tool). Removes the misleading `ops/` root dir.
- `infra/` folds into `deploy/` (grafana/compose) and `fuzz/oss-fuzz/` (oss-fuzz),
  with sbom config going to the assurance cluster.
- `coverage/` -> gitignore the whole dir; move its lone tracked README to
  `docs/operations/coverage.md`.
- `playwright.config.ts` -> drop the shim; CI invokes
  `--config docs/demo/playwright.config.ts`.

CONSOLIDATE (medium risk, gated by `check crate-paths` generalized to all path
literals): introduce `assurance/` to absorb `audits/` evidence, root `compliance/`,
`docs/compliance/`, and `infra/sbom`. NOTE: `supply-chain/` (the cargo-vet store)
stays at root; only the evidence/compliance siblings merge.

DEFER (low value, high churn): `.tooling/*.version` merge. Wave 2 found 14 workflow
lines + 2 SDK scripts + 3 exact-string test guards + a tar manifest read these
one-line files via `cat`; reformatting to TOML forces every reader to a parser and
breaks the string-literal guards. If done at all, move the three files under
`tools/versions/` keeping the one-line format, not into `tools/versions.toml`.
`osv-scanner.toml` -> `supply-chain/` is a clean 2-edit move but marginal; default
leave at root.

Target root: standard OSS files + the pinned configs + ~16 top-level dirs
(`crates`, `examples`, `tests`, `benches`, `fuzz`, `xtask`, `spec`, `docs`,
`formal`, `assurance`, `deploy`, `integrations`, `sdks`, `contracts`, `tools`,
`scripts`, `packaging`, `wit`, `arena` + tool dotdirs). Root drops from ~67 entries
toward ~38.

### 2.5 README and top-level docs

Rewrite the README (currently 134 lines, link-heavy, no quickstart, leads with
release-gating jargon) value-first, ~150-220 lines:

1. Header: hero image, name, tagline ("Governed tool access for AI systems"),
   subtitle (capability validation, fail-closed policy, budgets, signed receipts),
   badges (License, MSRV 1.93, CI status, docs), short nav row.
2. What is Chio (3-5 sentences, no jargon): the kernel-between-agent-and-tools
   framing + "MCP tells agents how to call tools; Chio proves what they were
   allowed to do, what it cost, and what happened." Core primitive: a signed,
   capability-bound receipt per decision.
3. Why Chio (3-4 bullets): no identity/delegation/budget/receipt at the tool-call
   layer today; fail-closed; native policy (HushSpec) and guards, no external
   engine; wraps MCP/A2A/ACP/OpenAPI rather than replacing them.
4. Quickstart (the critical missing piece): one install line + one runnable
   end-to-end example (one deny, one allow, one receipt) inline. Status note:
   "0.1.0, pre-release, APIs may change, not yet on crates.io."
5. Choose your path (3 bullets): MCP migration / web backend / native tool server.
6. Architecture overview: the five components (Agent, Runtime Kernel/TCB, Tool
   Servers, Capability Authority, Receipt Log) + pointer to `docs/architecture/`
   and `AGENTS.md`. Name only the handful of crates a user touches.
7. Integrations and SDKs: protocols one-liner + the three real SDKs (TS
   `@chio-protocol/sdk`, Python `chio-sdk`, Go `chio-go`); other languages in
   progress.
8. Security and trust posture: fail-closed summary, TCB boundary, canonical JSON
   (RFC 8785); link `SECURITY.md` + threat model.
9. Examples pointer; 10. Project status (honest 0.1.0 paragraph); 11. Contributing
   (link + the four-command gate); 12. License.

Keep out of the README: the large status table (lives in `docs/README.md`),
comptroller/web3/pheromone runbook links, internal milestone version history,
artifact counts, market-size claims. Per owner preference, describe what IS.

Top-level doc set is already good (`LICENSE`, `NOTICE`, `CONTRIBUTING`,
`CODE_OF_CONDUCT`, `SECURITY`, `CHANGELOG`, `AGENTS`). Optional adds: a `SUPPORT.md`
or "Getting help" section; confirm `.github/ISSUE_TEMPLATE` + PR template presence.

---

## 3. Migration roadmap (phased, safe-first)

Each phase ends green on the full local gate
(`cargo build --workspace && cargo test --workspace && cargo clippy --workspace --
-D warnings && cargo fmt --all -- --check`) plus `cargo-deny` and `cargo-vet`, and
each phase is independently revertable. Risk rises monotonically; the highest
blast-radius work is last and sits behind the `check crate-paths` guard.

- **Phase 0 - quick wins (near-zero risk).** Delete the 8 confirmed-orphan scripts
  + `rm -rf scripts/__pycache__`. Rewrite the README. Add `.codex/` to
  `.gitignore`; gitignore `coverage/` and move its README to `docs/`. No
  structural moves.

- **Phase 1 - xtask foundation (no behavior change).** Add `clap`; convert the
  dispatcher to a derive parser; keep the 6 existing subcommand names as aliases.
  Introduce the noun groups as parents. Land the shared `external_tool()` preflight
  helper. Build and wire `cargo xtask check crate-paths` (the go-dark guard) and
  add it to `ci.yml`. This guard is a prerequisite for Phases 5 and 6.

- **Phase 2 - `[workspace.dependencies]` centralization (no moves).** Add the 97
  missing internal crates to the root table keyed by package name (paths still
  pointing at current `crates/chio-x`); flip the ~415 plain member path deps to
  `{ workspace = true }`, preserving `features` (25) and `optional`. Important
  correction (verified): the 32 `package =` rename lines (31
  `chio-core = { package = "chio-core-types" }` + 1
  `chio-openai = { package = "chio-openai-adapter" }`) CANNOT be centralized via
  member-side `package = ... , workspace = true`, because Cargo inherits workspace
  deps by the dependency KEY, not the package name (the alias would rebind to the
  wrong crate or fail to resolve). Those 32 stay path-based in this phase; fully
  centralizing them needs a source change (`use chio_core` -> `use chio_core_types`)
  that is out of scope here. Note: the 4 standalone workspaces (`fuzz/`,
  `verdict_matrix`, `sdks/rust/chio-guard-sdk-compat`,
  `sdks/lambda/chio-lambda-extension`) do not inherit the root table and are handled
  in Phase 6. Independently valuable: one source of truth for internal versions.

- **Phase 3 - script consolidation into xtask (waves).** Port pure-logic gates
  first; collapse the pheromone (15->1) and runtime (6->1) clusters; fold the
  qualify family; port each `scripts/tests/*.test.sh` into a Rust `#[cfg(test)]`
  test. Flip CI to `cargo xtask ...` only after a dual-run shows identical
  pass/fail, then delete the migrated script + its meta-test in the same PR. Keep
  external-tool wrappers thin.

- **Phase 4 - CI workflow rebuild.** Extract `setup-rust`/`setup-node` composites;
  introduce the reusable workflows; collapse to the 6 entry workflows; add
  `concurrency` cancel-in-progress and `permissions: {}` everywhere; add
  `merge_group` + the aggregate `ci-required` check; fix the unpinned action. Pair
  with the one-time branch-protection settings change (owner). This phase is
  behavior-bearing for token scope, node version, and required-check names; verify
  with Actions actually running on a branch.

- **Phase 5 - root consolidation (low/medium risk).** Move Dockerfiles (+ the 7
  verified edits, same commit), `Homebrew`, `papers`, `assets`, `editors`,
  `RELEASE_AUDIT.md`, `ops/knowledge-base`, and fold `infra/`. Then the `assurance/`
  consolidation, gated by `check crate-paths` extended to all moved path literals.
  Leave the pinned root configs untouched.

- **Phase 6 - crate folder move (highest blast radius, LAST, single atomic
  change + full gate).** Move `crates/chio-*` -> `crates/<group>/chio-*` with
  explicit grouped members. Rewrite, in lockstep:
  - root `Cargo.toml`: 111 member lines + 1 exclude + the centralized
    `[workspace.dependencies]` paths;
  - the 4 standalone workspaces: 31 path-dep lines + `fuzz/owners.toml` (20) +
    `fuzz/target-map.toml` (34);
  - `.github/`: 239 `paths:` glob lines across 28 workflows, 5 `working-directory:`
    lines, literal script-arg paths, and 23 CODEOWNERS patterns (leave `cargo -p`
    steps untouched);
  - scripts literals (41 `.sh` + 3 `.py` + 1 `.bats`);
  - out-of-band fail-closed configs: `.cargo/mutants.toml`, `.kani/harnesses.toml`,
    `audits/mutation/per-crate-configs/*` (7), `spec/security/coverage.yaml`,
    `spec/security/chio-threat-model.v1.json`, `formal/proof-manifest.toml`,
    `formal/aeneas/production.toml`, `formal/theorem-inventory.json`,
    `contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json`, `docs/standards/*.json` (12),
    `.github/ISSUE_TEMPLATE/mutants_survivor.yml`;
  - runtime/build literals: `xtask/src/main.rs:450`,
    `xtask/src/eval_receipt_regen.rs:61/72/83`, `deploy/docker/Dockerfile` COPY
    lines, `tests/replay/src/bless.rs`, `tests/ci_guards/regression_deletion_test.sh`,
    the SDK `verdict_matrix` tests, `examples/eval-receipt-ingest/metr/ingest.py`.
  - Rename `crates/.../chio-openai` dir to `chio-openai-adapter` (matches its
    package name) while paths are already churning.
  Fail-closed exit criteria: `cargo metadata --no-deps` reports the same member
  count before and after; `cargo xtask check crate-paths` passes (every literal
  resolves); a grep confirms no stale top-level `crates/chio-x` literal survives;
  CI confirms `paths:` filters and CODEOWNERS still match (no go-dark).

---

## 4. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Silent go-dark on the crate move (paths:/CODEOWNERS/mutants/kani/threat configs stop matching) | `cargo xtask check crate-paths` built in Phase 1, run in CI, asserts every literal resolves; member-count assertion; explicit (non-glob) members |
| cargo-vet/cargo-deny break if `supply-chain/`/`deny.toml` move | They do not move (verified pinned); spec keeps them at root |
| `releases.toml` move breaks the mutation gate and a fail-closed release guard | It does not move (verified governance-pinned) |
| Dockerfile move silently changes build context or stops triggering rebuilds | Keep `.dockerignore` at root; update all 7 refs incl. `chio-tee-image.yml` `paths:` triggers in the same commit |
| Gate consolidation silently drops a check | Dual-run parity per gate; `scripts/tests/*.test.sh` ported to Rust tests prove behavior before deletion; fail-closed (unknown gate name is an error) |
| Required checks break when job names disappear | Aggregate `ci-required` job + branch-protection requires only it |
| `.tooling` TOML reformat breaks string-literal test guards | Deferred; if done, keep one-line format under `tools/versions/` |

---

## 5. Verification strategy

- Per-phase: the four-command workspace gate + `cargo-deny` + `cargo-vet`, run
  locally (CI logs truncate; reproduce gates locally per project memory).
- Phase 3: dual-run each migrated gate (old script + new xtask leaf) and assert
  identical pass/fail before flipping the caller.
- Phase 4: verify on a live branch with Actions running (token scope, node
  version, required-check names are behavior-bearing).
- Phase 6: member-count invariant + `check crate-paths` + go-dark check on
  `paths:`/CODEOWNERS, as a single atomic PR.

---

## 6. Open decisions for the owner

These have spec defaults; flag any you want changed before planning:

1. `trust/` stays one folder (default) vs split into identity/attestation/substrate.
2. `chio-guard-sdk*` in `sdk/` (default) vs `guards/`.
3. The 3 doc-contract scripts (`check-mapping`, `triage-threat-rows`,
   `check-corpus-metadata`): keep and fold into xtask (default) vs retire the doc
   claim too.
4. `.tooling` merge: defer (default) vs move to `tools/versions/` now.
5. `osv-scanner.toml`: leave at root (default) vs move into `supply-chain/`.
6. `assurance/` consolidation scope (Phase 5): include `docs/compliance/` in the
   merge (default) vs leave docs/compliance where it is.
7. Phase ordering: ship Phases 0-5 and treat Phase 6 (crate move) as a separate
   go/no-go after the guard has lived in CI for a while (default), vs run straight
   through 0-6.
