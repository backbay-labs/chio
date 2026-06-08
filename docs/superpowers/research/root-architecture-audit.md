# Chio Root-Level Architecture Audit

Audit of every root-level file and directory in the Chio workspace
(`/Users/connor/Medica/backbay/standalone/arc`), with consolidation verdicts and a
proposed target layout. Scope: redesign the root for a professional, open-source,
production-ready Rust project. No source/config/script was modified during this audit.

## Method and headline numbers

- `ls -A` reports 67 root entries (the brief's "52" undercounted; dotfiles and
  several dirs were added since). Tracked top-level entries: 57.
- Largest tracked dirs by disk: `crates` 4.2G build residue aside, `sdks` 5.0G,
  `examples` 737M, `contracts` 212M, `formal` 96M. Largest UNTRACKED local-only:
  `target` 130G, `.worktrees` 3.3G, `.codex` 3.4M, `.planning` 1.1M, `_apalache-out` 188K.
- The Rust workspace has 110 `crates/*` members plus ~30 `examples/*` members and `xtask`.

## Per-entry verdict table

Legend for "Tracked": Y = in git, N = untracked, IGN = matched by .gitignore.

### Root files

| Entry | What it is | Size | Tracked | Verdict | Notes |
|---|---|---|---|---|---|
| `LICENSE` | Apache-2.0 text | 10K | Y | KEEP-AT-ROOT | OSS convention; tooling (GitHub, crates.io) expects root. |
| `NOTICE` | Apache NOTICE | 515B | Y | KEEP-AT-ROOT | Pairs with Apache LICENSE. |
| `README.md` | Project front page | 5K | Y | KEEP-AT-ROOT | Required. |
| `CHANGELOG.md` | Keep-a-changelog | 1.7K | Y | KEEP-AT-ROOT | Convention. |
| `CONTRIBUTING.md` | Contributor guide | 4.5K | Y | KEEP-AT-ROOT | GitHub surfaces it from root or `.github/`. |
| `CODE_OF_CONDUCT.md` | CoC | 1.8K | Y | KEEP-AT-ROOT (or `.github/`) | Acceptable at root or `.github/`. |
| `SECURITY.md` | Security policy | 3.3K | Y | KEEP-AT-ROOT (or `.github/`) | GitHub auto-detects in either. |
| `Cargo.toml` | Workspace manifest (110 crate members) | 10K | Y | KEEP-AT-ROOT | Required by Cargo. |
| `Cargo.lock` | Lockfile | 314K | Y | KEEP-AT-ROOT | Required; commit for a bin/workspace. |
| `rust-toolchain.toml` | Pinned toolchain | 86B | Y | KEEP-AT-ROOT | Required by rustup at root. |
| `AGENTS.md` | Canonical agent guide | 4.2K | Y | KEEP-AT-ROOT | Project's stated source of truth; agent-tool convention is root. |
| `CLAUDE.md` | Claude entry point | 1.3K | Y | KEEP-AT-ROOT | Tool convention. Consider making it a thin pointer to AGENTS.md. |
| `Makefile` | Dev task aliases | 4.1K | Y | KEEP-AT-ROOT (assess vs xtask) | Overlaps `xtask` + `scripts`; see redundant clusters. |
| `RELEASE_AUDIT.md` | Release-gate audit doc | 1.5K | Y | MOVE-TO-`docs/release/` | Not a standard root file; it is project doc. `docs/release/` already exists. |
| `Dockerfile` | Main image | 3.6K | Y | MOVE-TO-`deploy/docker/` | See Dockerfile cluster below. |
| `Dockerfile.sidecar` | Sidecar image | 5.7K | Y | MOVE-TO-`deploy/docker/` | `deploy/sidecar/` already exists. |
| `Dockerfile.tee` | TEE image | 2.6K | Y | MOVE-TO-`deploy/docker/` | TEE workflows can point at new path. |
| `.dockerignore` | Docker ignore | 129B | Y | KEEP-AT-ROOT (or move w/ Dockerfiles) | Docker build context is repo root, so it must stay at root if build context is root; revisit if Dockerfiles move and context changes. |
| `deny.toml` | cargo-deny config | 16K | Y | KEEP-AT-ROOT | cargo-deny resolves from cwd/root by default. |
| `osv-scanner.toml` | osv-scanner config | 2.1K | Y | KEEP-AT-ROOT or MOVE-TO-`supply-chain/` | Scanner accepts `--config`; could live with other supply-chain config. |
| `releases.toml` | Release channel/version manifest | 8K | Y | KEEP-AT-ROOT or MOVE-TO-`docs/release/` | Custom file; check what reads it before moving. |
| `package.json` | JS workspace root (docs demo + TS SDKs) | 629B | Y | KEEP-AT-ROOT (constrained) | Bun/npm workspaces must root the manifest where `workspaces` globs resolve; see JS analysis. |
| `bun.lock` | Bun lockfile | 32K | Y | KEEP-AT-ROOT | Pairs with package.json; must sit beside it. |
| `playwright.config.ts` | Re-exports `docs/demo` PW config | 404B | Y | CONSOLIDATE / MOVE-TO-`docs/demo/` | Pure convenience shim; only one PW suite exists; see JS analysis. |
| `.gitignore` | git ignore | 3.6K | Y | KEEP-AT-ROOT | Required. |
| `.gitattributes` | git attributes | 641B | Y | KEEP-AT-ROOT | Required. |
| `.env` | Local secrets/env | 291B | IGN | KEEP (local, ignored) | Correctly gitignored; never commit. Provide `.env.example` (one exists under `ops/`). |
| `.DS_Store` | macOS cruft | 10K | IGN | DELETE (local) | Gitignored; safe to remove locally, harmless. |

### Root directories

| Entry | What it is | Size | Tracked files | Verdict | Notes |
|---|---|---|---|---|---|
| `crates/` | 110 workspace crates | 4.2G* | many | KEEP-AT-ROOT | Core. (*Disk incl. nested build output.) |
| `examples/` | ~30 example crates (workspace members) | 737M | many | KEEP-AT-ROOT | Workspace members; Cargo convention. Disk is bloated by ignored `artifacts/`. |
| `tests/` | Cross-cutting test suites (abi, conformance, e2e, replay, corpora) | - | 330 | KEEP-AT-ROOT | Standard Rust integration-test location. |
| `xtask/` | Cargo xtask runner | 116K | 6 | KEEP-AT-ROOT | Standard xtask pattern. |
| `benches`/`bench/` | `bench/` holds 2 bench harnesses (healthcare-pilot-capacity, ttfrh) | 124K | 20 | KEEP-AT-ROOT or RENAME `benches/` | Cargo convention dir is `benches/`; `bench/` is non-standard but tracked. Low priority. |
| `fuzz/` | cargo-fuzz targets | - | many | KEEP-AT-ROOT | cargo-fuzz convention. |
| `spec/` | Normative protocol spec (PROTOCOL.md etc.) | 1.7M | many | KEEP-AT-ROOT | Stated source of truth; fine at root. |
| `docs/` | Documentation set (39 subdirs incl. adr, architecture, compliance, release) | 5.5M | many | KEEP-AT-ROOT | Standard. Should ABSORB several siblings (papers, RELEASE_AUDIT, parts of audits). |
| `wit/` | WASM Interface Types (2 worlds) | 8K | 2 | KEEP-AT-ROOT or MOVE-TO-`crates/.../wit` | Tiny; convention varies. Could colocate with the WASM guard crate that consumes it. |
| `sdks/` | Polyglot SDKs (cpp, dotnet, go, guard, jvm, k8s, lambda, python, rust, swift, typescript) | 5.0G | 936 | KEEP-AT-ROOT | Consolidated SDK root (per MEMORY). Disk dominated by ignored deps. |
| `contracts/` | Solidity web3 contracts (Foundry/pnpm project) + tracked `node_modules` | 212M | 64 | KEEP-AT-ROOT (audit node_modules) | Self-contained sub-project. `node_modules` is NOT tracked (good); 212M is local install. |
| `integrations/` | Adapters: aws-bedrock, mcp-adapter | 192K | 44 | KEEP-AT-ROOT or MERGE into `crates/`/`sdks/` | Overlaps adapter crates already under `crates/`. Evaluate folding in. |
| `formal/` | Formal methods (apalache, tla, lean4, aeneas, rust-verification, proofs) | 96M | 77 | KEEP-AT-ROOT | Legit; large but real. Single home for verification source. |
| `arena/` | Adversarial scenario fixtures (TOML + schema) | 40K | 9 | KEEP-AT-ROOT or MOVE-TO-`tests/arena/` | Data for `chio-arena` crate; could move under tests/ or crate fixtures. |
| `papers/` | 6 research papers (LaTeX/markdown) | 4.4M | 122 | MOVE-TO-`docs/papers/` | Research prose; belongs under docs. Removes a root dir. |
| `assets/` | hero.png + icons | 1.7M | 21 | MOVE-TO-`docs/assets/` or `.github/assets/` | Branding/readme images; not a top-level concern. |
| `editors/` | Editor integrations (vscode-chio, zed-chio, snippets) | 180K | 25 | MOVE-TO-`integrations/editors/` or `tools/editors/` | Editor plugins are integrations/tooling, not a root concern. |
| `audits/` | Evidence: mutants, formal, threats, kani, mutation configs | 564K | 84 | CONSOLIDATE (see cluster) | Heavy overlap with `compliance/` + `formal/` + `supply-chain/`. |
| `compliance/` | HITRUST readiness package only | 128K | 30 | CONSOLIDATE (see cluster) | Single framework; overlaps `docs/compliance/` and `audits/`. |
| `supply-chain/` | cargo-vet config, audits.toml, checksums, sbom config | 208K | 5 | CONSOLIDATE (see cluster) | Provenance/attestation; overlaps `infra/sbom`, `audits/`. |
| `infra/` | grafana, oss-fuzz, sbom (syft), streaming compose files | 36K | 7 | CONSOLIDATE (see cluster) | Overlaps `deploy/` (runtime infra) and `.clusterfuzzlite`/`fuzz` (oss-fuzz). |
| `deploy/` | azure, cloud-run, ecs, sidecar, prometheus, dashboards, guides | 132K | 18 | KEEP-AT-ROOT (absorb infra+Dockerfiles) | Best home for all deployment artifacts. |
| `ops/` | knowledge-base only (Python cocoindex tool) | 888K | 32 | MOVE/RENAME | Single sub-project mislabeled as "ops"; not deployment ops. |
| `tools/` | install-apalache.sh, vcpkg-overlay, versions.toml | 48K | 11 | CONSOLIDATE (see cluster) | Overlaps `scripts/`, `.tooling/`, `xtask/`. |
| `scripts/` | 146 shell + 10 py gate/CI scripts | 1.4M | 158 | KEEP-AT-ROOT (organize) | Large but legit CI/gate glue. Needs internal subfoldering, not relocation. |
| `wit/` | (listed above) | | | | |
| `.cargo/` | config.toml + mutants.toml | 16K | 2 | KEEP-AT-ROOT | Cargo convention. |
| `.tooling/` | 3 version-pin files (cargo-ndk, wasm-bindgen, wasm-pack) | 12K | 3 | CONSOLIDATE-INTO `tools/versions.toml` | Three single-line version pins duplicate `tools/versions.toml` intent. |
| `.kani/` | harnesses.toml | 16K | 1 | KEEP-AT-ROOT | Kani convention (tool reads `.kani/`). |
| `.clusterfuzzlite/` | ClusterFuzzLite Dockerfile/build/project | 12K | 3 | KEEP-AT-ROOT | Tool convention; near-duplicate of `infra/oss-fuzz/` (see cluster). |
| `.github/` | workflows (90+) + templates | - | many | KEEP-AT-ROOT | Required. |
| `.claude/` | Claude local config | - | varies | KEEP (local) | Tool config. |
| `coverage/` | README.md tracked; html/ + tarpaulin.log untracked | 8K | 1 | GITIGNORE dir, keep README in docs | The only tracked thing is a README; `html/` and `tarpaulin.log` are build output. Either gitignore the whole dir and move README to `docs/`, or keep just README. |
| `target/` | Cargo build output | 130G | 0 | IGN (correct) | Gitignored. No action. |
| `_apalache-out/` | Apalache model-check output | 188K | 0 | IGN (correct) | Confirmed gitignored (`_apalache-out/`); local-only. No action; can delete locally. |
| `.codex/` | Codex agent local state | 3.4M | 0 | IGN/local | Untracked agent scratch; ensure it is gitignored (currently just untracked). |
| `.planning/` | Local planning/orchestration state | 1.1M | 0 | IGN (correct) | Gitignored. |
| `.worktrees/` | git worktrees (3.3G) | 3.3G | 0 | IGN (correct) | Gitignored. Local-only. |
| `Homebrew/` | Single `chio.rb.tmpl` formula template | - | 1 | MOVE-TO-`packaging/homebrew/` | One file; "Homebrew" as a top-level dir is heavy for a template. |

## JS tooling at the root of a Rust project

`package.json`, `bun.lock`, `playwright.config.ts` exist because the repo ships two
JS deliverables:

1. The GitHub Pages docs demo (`docs/demo`), built/tested via Playwright. Driven by
   `.github/workflows/demo-pages.yml`.
2. The polyglot TypeScript SDKs under `sdks/typescript/packages/{browser,workers,edge,deno}`,
   declared as Bun `workspaces` in the root `package.json`. Driven by `web-sdk.yml`,
   `release-npm.yml`, `sdk-parity.yml`, `cve-monitor.yml`.

Assessment:

- The root `package.json` + `bun.lock` are CONSTRAINED to root: Bun/npm resolve the
  `workspaces` globs relative to the manifest directory, and the globs reach into both
  `docs/demo` and `sdks/typescript/...`. Moving the manifest would require rewriting
  every workspace glob and the CI that runs `bun install` from root. Keep at root; it
  is a legitimate (if unusual) polyglot-monorepo pattern. Recommend a one-line README
  note explaining why a Rust repo has a root `package.json`.
- `playwright.config.ts` is a pure 3-line re-export of `docs/demo/playwright.config.ts`.
  It exists only so `bunx playwright test` can run from root. This is the one JS file
  that is safe to MOVE/CONSOLIDATE: drop the shim and have CI invoke
  `bunx playwright test --config docs/demo/playwright.config.ts`, or keep the shim but
  document it as the sole reason it is at root. Low-risk cleanup.

## The three Dockerfiles

`Dockerfile`, `Dockerfile.sidecar`, `Dockerfile.tee` are all tracked at root. A
`deploy/sidecar/` directory already exists, so deployment artifacts have a home.
Recommend MOVE-TO `deploy/docker/` (or `deploy/images/`):

- `deploy/docker/Dockerfile`
- `deploy/docker/Dockerfile.sidecar` (or fold into `deploy/sidecar/`)
- `deploy/docker/Dockerfile.tee`

Caveat (fail-closed): Docker build context defaults to the directory containing the
Dockerfile only when `-f` is not used. The workflows (`chio-tee-image.yml`,
`sidecar-image.yml`, etc.) almost certainly pass `-f Dockerfile.x .` with root as
context. Moving the files requires updating the `-f` paths in those workflows and the
`.dockerignore` stays at root (context root is the repo). Do the move and the workflow
edits together, or it will silently break image builds.

## Redundant-directory clusters

### Cluster A: evidence / assurance / compliance (audits vs compliance vs supply-chain vs formal)

- `formal/` = SOURCE of formal proofs (TLA+, Lean4, Apalache, Aeneas). Distinct purpose: keep.
- `audits/evidence/{formal,kani,mutants,threats}` = GENERATED evidence/snapshots from
  proofs, mutation, kani, threat triage.
- `compliance/hitrust/` = one compliance framework's readiness package.
- `docs/compliance/` = prose mappings for other frameworks (NIST AI RMF, ISO 42001,
  EU AI Act, OWASP LLM Top 10, PCI-DSS, Colorado SB-24-205).
- `supply-chain/` = cargo-vet config + checksums + sbom config.
- `infra/sbom/` = syft.yaml (sbom generation config) -- duplicates supply-chain's sbom intent.

Overlap: assurance/compliance evidence is scattered across four top-level dirs plus
`docs/compliance`. Recommendation: introduce a single `assurance/` (or `evidence/`)
top-level dir housing `assurance/formal-evidence/` (from audits/evidence/formal),
`assurance/mutation/`, `assurance/threats/`, `assurance/compliance/{hitrust,...}`
(merge root `compliance/` AND `docs/compliance/`), and `assurance/supply-chain/`
(merge `supply-chain/` + `infra/sbom`). Keep `formal/` separate as proof SOURCE. This
collapses 4-5 root dirs into 1. NOTE: cargo-vet expects `supply-chain/` at a known path;
verify the tool's `--manifest`/path override before relocating, or keep `supply-chain/`
where it is and only merge the doc/evidence siblings.

### Cluster B: ops vs infra vs deploy

- `deploy/` = cloud deployment manifests (azure, cloud-run, ecs, sidecar, prometheus, dashboards) -- the real deployment home.
- `infra/` = grafana dashboards, oss-fuzz config, sbom config, streaming compose files -- a grab-bag.
- `ops/` = ONLY `knowledge-base/` (a Python cocoindex tool); not operations at all.

Recommendation: collapse `infra/` into `deploy/` (grafana -> `deploy/dashboards/` next
to existing prometheus/dashboards; streaming compose -> `deploy/compose/`; sbom ->
assurance cluster; oss-fuzz -> next to `.clusterfuzzlite`/`fuzz`). Rename/relocate
`ops/knowledge-base` to its true nature -- it is a tool/sub-project, e.g.
`tools/knowledge-base/` -- eliminating the misleading `ops/` root dir entirely.

### Cluster C: tools vs .tooling vs xtask vs scripts

- `xtask/` = Rust task runner (build-time tasks). Keep (convention).
- `scripts/` = 146 shell + 10 py CI/gate scripts. Keep but organize internally.
- `tools/` = install-apalache.sh, vcpkg-overlay, versions.toml.
- `.tooling/` = 3 one-line version pins (cargo-ndk, wasm-bindgen, wasm-pack).

Recommendation: merge `.tooling/`'s three version pins into `tools/versions.toml` (or a
`tools/versions/` dir) and delete `.tooling/`. Consider whether `tools/` and `scripts/`
should unify, but they serve different roles (helper assets/overlays vs executable gate
scripts), so a merge is optional. The clear win is eliminating `.tooling/`.

### Cluster D: assets vs papers vs editors (and RELEASE_AUDIT)

- `papers/` (6 research papers) -> `docs/papers/`.
- `assets/` (hero image + icons) -> `docs/assets/` or `.github/assets/`.
- `editors/` (vscode/zed plugins, snippets) -> `integrations/editors/` (or `tools/editors/`).
- `RELEASE_AUDIT.md` -> `docs/release/`.

These are doc/integration content that does not warrant top-level dirs. Folding them
removes 3 root dirs + 1 root file.

### Cluster E: oss-fuzz fragmentation

`fuzz/` (cargo-fuzz), `.clusterfuzzlite/` (CFLite Dockerfile/build/project), and
`infra/oss-fuzz/` (near-identical Dockerfile/build/project) all relate to fuzzing.
`.clusterfuzzlite/` is a tool-mandated path (keep). `infra/oss-fuzz/` should move next
to fuzzing config (e.g. `fuzz/oss-fuzz/`) rather than living under `infra/`.

## Tracked build/output artifacts (fail-closed flags)

- `coverage/` -- only `coverage/README.md` is tracked; `html/` and `tarpaulin.log` are
  build output (untracked but present). RECOMMEND: gitignore the whole `coverage/` dir
  and relocate the README to `docs/` (or `docs/operations/coverage.md`). A `coverage/`
  root dir that exists only to host a README is cruft.
- `target/` (130G), `_apalache-out/` (188K), `.worktrees/` (3.3G), `.planning/` --
  all correctly gitignored; no tracked artifacts. `.DS_Store` correctly gitignored.
- `.codex/` (3.4M) -- untracked but NOT explicitly in `.gitignore` (it just is not
  added). RECOMMEND adding `.codex/` to `.gitignore` so it cannot be committed by
  accident (fail-closed).
- `contracts/node_modules` -- 212M on disk, 0 files tracked (correct). No action.

No genuinely committed build artifacts were found, which is good. The only structural
artifact problem is `coverage/` existing as a tracked root dir for one README.

## Proposed target root layout

Target after consolidation. Root files (standard OSS set only):

```
LICENSE  NOTICE  README.md  CHANGELOG.md
CONTRIBUTING.md  CODE_OF_CONDUCT.md  SECURITY.md   (CoC/SECURITY may instead live in .github/)
AGENTS.md  CLAUDE.md
Cargo.toml  Cargo.lock  rust-toolchain.toml
deny.toml
package.json  bun.lock                            (root-constrained polyglot workspace)
.gitignore  .gitattributes  .dockerignore
```

Moved off root: `Dockerfile*` -> `deploy/docker/`; `RELEASE_AUDIT.md` -> `docs/release/`;
`releases.toml` -> `docs/release/` (or keep if a tool reads it from root);
`osv-scanner.toml` -> `supply-chain/`/assurance (or keep);
`playwright.config.ts` -> dropped/consolidated into `docs/demo/`.

Target top-level directories:

```
crates/         # 110 Rust workspace members (core)
examples/       # example crates (workspace members)
tests/          # cross-cutting integration/conformance/e2e/replay suites
benches/        # rename of bench/
fuzz/           # cargo-fuzz + fuzz/oss-fuzz/ (absorbs infra/oss-fuzz)
xtask/          # task runner
spec/           # normative protocol spec
docs/           # all prose: + docs/papers (from papers/), docs/assets (from assets/),
                #   docs/release/RELEASE_AUDIT.md, docs/compliance (merged)
formal/         # formal-proof SOURCE (TLA+, Lean4, Apalache, Aeneas)
assurance/      # NEW: merged audits/ evidence + compliance/ + supply-chain/ + infra/sbom
deploy/         # cloud manifests + deploy/docker/ (Dockerfiles) + infra/ (grafana, compose)
integrations/   # adapters + integrations/editors (from editors/)
sdks/           # polyglot SDKs
contracts/      # solidity sub-project
tools/          # helper assets + versions (absorbs .tooling/) + tools/knowledge-base (from ops/)
scripts/        # CI/gate scripts (organized into subfolders)
packaging/      # NEW: packaging/homebrew/chio.rb.tmpl (from Homebrew/)
wit/            # WIT worlds (or relocate beside consuming crate)
arena/          # scenario fixtures (or move under tests/)
.cargo/ .kani/ .clusterfuzzlite/ .github/   # tool-mandated dotdirs (keep)
```

Net effect: removes/relocates ~10 root directories (`papers`, `assets`, `editors`,
`ops`, `infra`, `compliance`, `supply-chain` or `audits`, `.tooling`, `Homebrew`,
`coverage`) and ~5 root files (3 Dockerfiles, RELEASE_AUDIT, playwright shim), taking the
root from 67 entries toward roughly 35-40, with the remaining set being either OSS
conventions or tool-mandated.

## Caveats before executing any move (fail-closed)

1. cargo-vet reads `supply-chain/` from a conventional path; confirm override flags
   before relocating it.
2. Moving `Dockerfile*` requires editing every workflow that passes `-f <name>` and
   confirming the build context stays repo-root (keep `.dockerignore` at root).
3. The root `package.json` workspace globs and CI `bun install` cwd pin the JS manifest
   to root -- do not move it.
4. `releases.toml` / `osv-scanner.toml` may be read from fixed root paths by scripts or
   workflows; grep their readers before moving.
5. `scripts/` (158 files) are referenced by 90+ workflows; reorganizing into subfolders
   means updating workflow paths in lockstep.
6. Many gate scripts and CI jobs reference these paths; any relocation must be a single
   atomic change that updates `.github/workflows/`, `Makefile`, and `xtask` together,
   then runs the full local gate (`cargo build/test/clippy/fmt` + the gate scripts) to
   prove nothing broke.
