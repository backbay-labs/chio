# Phase 5 Root Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the low/medium-risk root-level files and directories (Dockerfiles, Homebrew template, papers, assets, RELEASE_AUDIT addendum, editors, ops/knowledge-base, and the infra fold) into their consolidated homes, each move landing in a single commit together with every reference edit so no gate, build, or path-trigger silently goes dark.

**Architecture:** Pure `git mv` relocations paired in-commit with their reference edits in workflows, Cargo manifest, xtask Rust constants, Makefile, scripts, Dockerfiles, and docs. The fail-closed contract is enforced two ways: every move is verified by a post-move grep that no stale literal survives at the old path, and the `cargo xtask check-crate-paths` go-dark guard (built in the keystone Phase 1 plan) plus the full four-command workspace gate run green after each commit. The crate folder move is explicitly out of scope (Phase 6).

**Tech Stack:** git, GitHub Actions YAML, Rust (`xtask`), Make, bash/Python gate scripts, Cargo workspace manifest.

---

## Scope and dependencies

This is the Phase 5 plan derived from
`docs/superpowers/specs/2026-06-08-repo-architecture-design.md` section 2.4 and 3
(Phase 5), validated against:
- `docs/superpowers/research/root-architecture-audit.md` (per-entry verdicts, clusters).
- `docs/superpowers/research/validation-dockerfile-move.md` (the exact Dockerfile edits + `.dockerignore`-stays-at-root rule + `chio-tee-image.yml` paths-trigger fail-open warning).
- `docs/superpowers/research/migration-validation-rootconfig-supplychain.md` (the verified KEEP-AT-ROOT list).

**Depends on the keystone plan** `docs/superpowers/plans/2026-06-08-phase-1-crate-paths-guard.md`:
- Task A there already handles Phase 0 (gitignore `coverage/`, move its README, gitignore `.codex/`, delete 8 orphans). This plan does NOT repeat that.
- Tasks 1-5 there ship `cargo xtask check-crate-paths`. This plan invokes that
  guard after moves that touch path-literal configs. If the keystone has not
  landed yet, the guard step is skipped (noted inline per task) and the grep +
  full-gate verification still apply.

**House rules:** no em dashes (use hyphens/parentheses); fail-closed (a move
without its reference edits is forbidden; a stale literal is an error not a
warning); `unwrap_used`/`expect_used` denied in Rust, so any test code matches on
`Err` and `panic!`s explicitly. The phase exit gate per commit is:
`cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

**Branch:** all work lands on a feature branch (e.g.
`codex/phase-5-root-consolidation`), never directly on `main` or the current
`codex/chio-next-10-remediation` branch. Create it first:
```bash
git checkout -b codex/phase-5-root-consolidation
```

---

## KEEP-AT-ROOT - DO NOT MOVE (non-task note for the executor)

Wave 2 verified these are pinned by tooling or governance; moving any of them
fail-opens a gate or hard-breaks a tool. They are OUT OF SCOPE for this plan and
must be left exactly where they are:

- `supply-chain/` - cargo-vet runs bare from repo root with no `--store-path`
  override; `[workspace.metadata.cargo-vet]` in `Cargo.toml` is empty. Moving needs
  a `store.path` edit plus rewrites to checksum/SBOM write-contracts and two
  `paths:` triggers (fail-open risk). KEEP.
- `releases.toml` - governance-pinned mutation-gate state file; CODEOWNERS pin at
  `.github/CODEOWNERS:66`; a missing-file fail-closed guard at
  `release-binaries.yml:920`; cwd-relative readers in `mutants-gate.sh`,
  `mutants-comment.sh`, `mutants.yml`. KEEP. (Note: `releases.toml:100`
  `release_gate: RELEASE_AUDIT` is a label string inside the `activation_evidence`
  multiline string of the `[release_audit]` table (the string opens at
  `activation_evidence = """` on line 98), not a `[release_audit]`-table key and not
  a path to the moved file; do not touch it.)
- `deny.toml` - cargo-deny reads from cwd with no `--config`; CODEOWNERS-pinned;
  cve-monitor `paths:` trigger. KEEP.
- `.cargo/` - holds the `xtask` alias; moving silently disables `cargo xtask`. KEEP.
- `.kani/` - `harnesses.toml` read cwd/root-relative by default. KEEP.
- `.clusterfuzzlite/` - tool-name IS the directory name; CFLite actions default to
  this root path. KEEP.
- `.dockerignore` - Docker build context stays repo root; the loader reads it from
  the context root, not beside the Dockerfile. KEEP AT ROOT (Task 1 depends on this).
- `osv-scanner.toml` - leave at root (spec default; marginal 2-edit move deferred).
- `.tooling/*.version` - DEFERRED (high-churn: 14 workflow lines + 2 SDK scripts +
  3 exact-string test guards + a tar manifest read these via `cat`). NOT in this plan.
- The standard OSS files (`LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `AGENTS.md`, `CLAUDE.md`),
  `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `package.json`, `bun.lock`,
  `.gitignore`, `.gitattributes`. KEEP.

The `assurance/` consolidation (merging `audits/`, root `compliance/`,
`docs/compliance/`, `infra/sbom`) is the medium-risk tail of spec Phase 5. It is
explicitly NOT in this plan: it requires the generalized `check-crate-paths` and
its own dual-run-style verification, and the brief scopes this plan to the file
moves only. `infra/sbom/syft.yaml` is therefore relocated to `deploy/sbom/` in
Task 6 (keeping it inside the `deploy/` fold the brief mandates) rather than into a
not-yet-existing `assurance/` tree.

---

## Task ordering rationale

1. **Dockerfiles first** (Task 1): the editors move (Task 5) edits the same
   Dockerfiles' `COPY editors` lines; doing Dockerfiles first means Task 5 edits the
   files at their final `deploy/docker/` path. Same for infra (Task 6) is independent.
2. **Homebrew, papers+assets+RELEASE_AUDIT, editors, ops, infra** follow; each is
   self-contained and independently revertable.

---

## Task 1: Move the three root Dockerfiles into deploy/docker/

**Files moved:** `Dockerfile`, `Dockerfile.sidecar`, `Dockerfile.tee` -> `deploy/docker/`.
**`.dockerignore` STAYS AT ROOT.**
**Reference edits (same commit):**
- `.github/workflows/sidecar-image.yml:106`
- `.github/workflows/chio-tee-image.yml:50`, `:6`, `:20`
- `examples/docker/compose.yaml:8`, `:27`
- `examples/tee-sidecar/docker-compose.yml:5`
- `scripts/tests/check-sidecar-docker-context.test.sh:5`
- docs: `deploy/SIDECAR_BUILD_GUIDE.md:5,17,28`, `docs/install/BINARY_DISTRIBUTION.md:27,45,120`, `docs/operations/ROADMAP.md:141`, `examples/tee-sidecar/README.md:5,42`, `examples/tee-sidecar/chio-tee.toml:5`

- [ ] **Step 1.1: Pre-move grep (capture every reference to the three root Dockerfiles)**

Run (from repo root):
```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'Dockerfile.sidecar' -e 'Dockerfile.tee' -e '\bDockerfile\b' . \
  | grep -vE '^\./deploy/sidecar/Dockerfile|^\./sdks/k8s/|^\./\.clusterfuzzlite/|^\./infra/oss-fuzz/|^\./ops/knowledge-base/Dockerfile.kb-mcp|^\./docs/.*Dockerfile.distroless'
```
Expected: the hits enumerated in the file list above, plus internal Dockerfile
comments (`Dockerfile:3`, `Dockerfile.tee:2`) and out-of-scope siblings already
filtered. Confirm no NEW reference appeared since validation (a new `docker build
-f Dockerfile` workflow). If a new live `docker build`/`build-push` reference to a
root Dockerfile exists, add its edit to Step 1.3 before proceeding.

- [ ] **Step 1.2: Move the files (keep .dockerignore at root)**

```bash
mkdir -p deploy/docker
git mv Dockerfile deploy/docker/Dockerfile
git mv Dockerfile.sidecar deploy/docker/Dockerfile.sidecar
git mv Dockerfile.tee deploy/docker/Dockerfile.tee
```
Do NOT move `.dockerignore`. Confirm it is still at root:
```bash
test -f .dockerignore && echo ".dockerignore stays at root: OK"
```
Expected: `.dockerignore stays at root: OK`.

- [ ] **Step 1.3: Edit the CI-blocking workflow references**

`.github/workflows/sidecar-image.yml:106` - change the `file:` value (leave
`context: .` at `:105` unchanged):
```yaml
          file: deploy/docker/Dockerfile.sidecar
```

`.github/workflows/chio-tee-image.yml:50` - change `-f` (leave trailing `.`):
```yaml
        run: docker build -f deploy/docker/Dockerfile.tee -t chio-tee:ci .
```

`.github/workflows/chio-tee-image.yml:6` and `:20` - both `paths:` trigger lists
have a line `      - Dockerfile.tee`. Change BOTH to:
```yaml
      - deploy/docker/Dockerfile.tee
```
(Failing to update these is a silent stale-image fail-open: edits to the moved
`Dockerfile.tee` would no longer trigger a rebuild.)

- [ ] **Step 1.4: Edit the compose references (dockerfile: is context-relative; context is `../..` = repo root)**

`examples/docker/compose.yaml:8` and `:27` - both read `dockerfile: Dockerfile`.
Change BOTH to:
```yaml
      dockerfile: deploy/docker/Dockerfile
```

`examples/tee-sidecar/docker-compose.yml:5` - reads `dockerfile: Dockerfile.tee`.
Change to:
```yaml
      dockerfile: deploy/docker/Dockerfile.tee
```

- [ ] **Step 1.5: Edit the script reference**

`scripts/tests/check-sidecar-docker-context.test.sh:5` - reads
`dockerfile="${repo_root}/Dockerfile.sidecar"`. Change to:
```bash
dockerfile="${repo_root}/deploy/docker/Dockerfile.sidecar"
```
(Line 11's `grep -Fxq "COPY ${source} ${destination}"` asserts file CONTENT and is
unchanged; only the path to the file changes.)

- [ ] **Step 1.6: Edit the documentation references (accuracy; non-blocking)**

- `deploy/SIDECAR_BUILD_GUIDE.md:17` - `docker build -f Dockerfile.sidecar -t chio-sidecar:local .` -> `-f deploy/docker/Dockerfile.sidecar` (keep trailing `.`). Lines `:5` and `:28` mention `Dockerfile.sidecar` in prose; update the bare name to `deploy/docker/Dockerfile.sidecar`.
- `docs/install/BINARY_DISTRIBUTION.md:27` and `:120` - `Homebrew/...` is handled in Task 2; here update the `Dockerfile.sidecar` mention at `:45` (`is built from \`Dockerfile.sidecar\``) to `deploy/docker/Dockerfile.sidecar`.
- `docs/operations/ROADMAP.md:141` - prose `Dockerfile.sidecar` -> `deploy/docker/Dockerfile.sidecar`.
- `examples/tee-sidecar/README.md:5` and `:42` - prose `Dockerfile.tee` -> `deploy/docker/Dockerfile.tee`.
- `examples/tee-sidecar/chio-tee.toml:5` - comment `# Runtime paths match Dockerfile.tee and docker-compose.yml.` -> `# Runtime paths match deploy/docker/Dockerfile.tee and docker-compose.yml.`

Do NOT edit the internal cross-reference comments at `deploy/docker/Dockerfile:3-4`
and `deploy/docker/Dockerfile.tee:2`: after the move the three files are still
siblings in `deploy/docker/`, so the bare names (`Dockerfile.sidecar`,
`Dockerfile.tee`) remain correct.

- [ ] **Step 1.7: Verify no stale top-level Dockerfile reference survives**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e '\bf Dockerfile' -e 'dockerfile: Dockerfile' -e 'file: Dockerfile' \
  -e '\- Dockerfile' . \
  | grep -vE 'deploy/docker/|deploy/sidecar/Dockerfile|sdks/k8s/'
```
Expected: no output (every `-f`, `dockerfile:`, `file:`, and `paths:` reference now
carries the `deploy/docker/` prefix). The two example composes and three workflows
no longer reference a bare root Dockerfile.

Then confirm the three files resolve at their new path and the test script points at
a real file:
```bash
test -f deploy/docker/Dockerfile && test -f deploy/docker/Dockerfile.sidecar \
  && test -f deploy/docker/Dockerfile.tee && echo "all three resolve: OK"
bash scripts/tests/check-sidecar-docker-context.test.sh
```
Expected: `all three resolve: OK`, then the sidecar context test prints
`sidecar Docker build context includes contract artifacts` (it now reads the moved
Dockerfile.sidecar and finds the `COPY contracts ./contracts` line).

- [ ] **Step 1.8: Optional docker dry check (if docker is available locally)**

```bash
if command -v docker >/dev/null 2>&1; then
  docker build -f deploy/docker/Dockerfile.tee --target '' -t chio-tee:planproof . --no-cache --pull=false 2>&1 | head -5 || true
else
  echo "docker not installed; rely on the resolves+grep verification above"
fi
```
Expected: docker begins reading the build context from repo root (proving context +
`.dockerignore`-at-root work) or, if docker is absent, the message. A full build is
not required; the goal is to confirm the `-f deploy/docker/...` path plus repo-root
context resolves. Abort the build after the context is sent.

- [ ] **Step 1.9: Commit**

```bash
git add -A
git commit -m "refactor: move root Dockerfiles to deploy/docker with reference edits"
```

- [ ] **Step 1.10: Full workspace gate**

```bash
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: all pass. (No Rust source references the Dockerfiles, so this is a
regression check that the move did not disturb the workspace.)

---

## Task 2: Move Homebrew/chio.rb.tmpl into packaging/homebrew/

**Files moved:** `Homebrew/chio.rb.tmpl` -> `packaging/homebrew/chio.rb.tmpl`
(removes the `Homebrew/` root dir).
**Reference edits (same commit):**
- `.github/workflows/release-binaries.yml:595` (CI-blocking: fail-closed guard reads `formula_src`)
- docs: `docs/install/BINARY_DISTRIBUTION.md:27,120`, `docs/install/homebrew.md:13`, `docs/operations/ROADMAP.md:140`

- [ ] **Step 2.1: Pre-move grep**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'Homebrew/chio.rb' -e 'Homebrew/' . | grep -v '^\./Homebrew/'
```
Expected: `release-binaries.yml:595` (`formula_src="Homebrew/chio.rb.tmpl"`), plus
the doc hits in the file list above. Other `Homebrew`/`brew install` mentions in
docs and workflows are about the Homebrew tool, not the `Homebrew/` directory; do
not edit those. Confirm no other literal `Homebrew/chio.rb.tmpl` path reader exists.

- [ ] **Step 2.2: Move the file**

```bash
mkdir -p packaging/homebrew
git mv Homebrew/chio.rb.tmpl packaging/homebrew/chio.rb.tmpl
```
Confirm the old dir is gone:
```bash
test ! -d Homebrew && echo "Homebrew/ removed: OK"
```
Expected: `Homebrew/ removed: OK`.

- [ ] **Step 2.3: Edit the CI-blocking reference**

`.github/workflows/release-binaries.yml:595` - the render step assigns
`formula_src="Homebrew/chio.rb.tmpl"` and the very next guard (`:597`) hard-exits if
the file is missing (`if [[ ! -f "$formula_src" ]]; then ... exit 1`). Change `:595`
to:
```bash
          formula_src="packaging/homebrew/chio.rb.tmpl"
```
(Leave `formula_out="release/chio.rb"` and the `sed` placeholder substitution
unchanged; only the source path moves.)

- [ ] **Step 2.4: Edit the documentation references**

- `docs/install/BINARY_DISTRIBUTION.md:27` - `\`Homebrew/chio.rb.tmpl\` and publishes it ...` -> `packaging/homebrew/chio.rb.tmpl`.
- `docs/install/BINARY_DISTRIBUTION.md:120` - table cell `\`Homebrew/chio.rb.tmpl\` rendered into ...` -> `packaging/homebrew/chio.rb.tmpl`.
- `docs/install/homebrew.md:13` - the markdown link `[\`Homebrew/chio.rb.tmpl\`](../../Homebrew/chio.rb.tmpl)`. This file is at `docs/install/`, so the relative path to the new location is `../../packaging/homebrew/chio.rb.tmpl`. Change to: `[\`packaging/homebrew/chio.rb.tmpl\`](../../packaging/homebrew/chio.rb.tmpl)`.
- `docs/operations/ROADMAP.md:140` - prose `\`Homebrew/chio.rb.tmpl\` release formula template (new)` -> `packaging/homebrew/chio.rb.tmpl`.

- [ ] **Step 2.5: Verify no stale reference and the new path resolves**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'Homebrew/chio.rb' . | grep -v '^\./docs/superpowers/'
test -f packaging/homebrew/chio.rb.tmpl && echo "template resolves: OK"
```
Expected: the grep prints nothing (no remaining `Homebrew/chio.rb` literal), then
`template resolves: OK`. Confirm the render step's source path is correct:
```bash
grep -n 'formula_src=' .github/workflows/release-binaries.yml
```
Expected: shows `formula_src="packaging/homebrew/chio.rb.tmpl"`.

- [ ] **Step 2.6: Commit and gate**

```bash
git add -A
git commit -m "refactor: move Homebrew formula template to packaging/homebrew"
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: gate passes (no Rust touches this; regression check).

---

## Task 3: Move papers/, assets/, and the root RELEASE_AUDIT addendum into docs/

This task bundles the three cluster-D doc moves into one commit (they share the
`docs/` destination and the same gate-script reference edits in
`check-stub-surfaces.py` and `check-review-slices.py`).

**Files moved:**
- `papers/` -> `docs/papers/`
- `assets/` -> `docs/assets/`
- root `RELEASE_AUDIT.md` -> `docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md`
  (renamed: `docs/release/RELEASE_AUDIT.md` ALREADY EXISTS and is a different file;
  the root file is the provider-native adapter addendum that itself points to the
  docs one)

**Reference edits (same commit):**
- `README.md:2` (`assets/hero.png`)
- root `RELEASE_AUDIT.md:19` self-test grep (the only reader; travels with the file)
- `scripts/check-stub-surfaces.py:485` (classification tuple)
- `scripts/check-review-slices.py:194` is editors (Task 5); the papers/assets/ops slice handling is verified below
- docs: `docs/README.md` papers entry if present

- [ ] **Step 3.1: Pre-move grep for papers/, assets/, and the root RELEASE_AUDIT**

```bash
echo "== papers/ =="
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e '\bpapers/' . | grep -vE '^\./papers/|stellar.org/papers|/assets/whitepaper'
echo "== assets/hero =="
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'assets/hero' -e 'assets/icons' . | grep -vE '^\./assets/'
echo "== root RELEASE_AUDIT (bare, not docs/release/ or platform/) =="
grep -rEn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  '(^|[^/])RELEASE_AUDIT\.md' . \
  | grep -vE 'docs/release/|platform/release-gates'
```
Expected:
- papers: only `scripts/check-stub-surfaces.py:485` (the `("audits/", "editors/",
  "formal/", "papers/")` tuple) is an operational path-prefix reference. The other
  hits are inside `papers/**` (self-referential) or are external URLs
  (`stellar.org/papers`, `kleros.io/assets/whitepaper`) - leave those alone.
- assets: only `README.md:2` (`<img src="assets/hero.png" ...>`). The `sbom.yml`
  `release-assets` hits and `kleros.io/assets` are unrelated.
- RELEASE_AUDIT: with the `docs/release/|platform/release-gates` filter, only the
  repo-root `RELEASE_AUDIT.md:19` (its own self-test command) survives. The raw
  `RELEASE_AUDIT\.md` pattern also matches ~10 sibling-doc relative links of the form
  `[RELEASE_AUDIT.md](RELEASE_AUDIT.md)` in
  `docs/release/CHIO_WEB3_PARTNER_PROOF.md:16`, `RELEASE_CANDIDATE.md:25,529`,
  `QUALIFICATION.md:15,295,381`, `PARTNER_PROOF.md:10`, `GA_CHECKLIST.md:12`, and
  `OPERATIONS_RUNBOOK.md:244` (the matched bare `RELEASE_AUDIT.md](RELEASE_AUDIT.md)`
  text is NOT prefixed with `docs/release/`, so a `docs/release/RELEASE_AUDIT`-only
  filter would let them through). These links point at the pre-existing, different
  `docs/release/RELEASE_AUDIT.md` and are EXPECTED; the `docs/release/` directory
  filter drops them and they must NOT change. `releases.toml:100`
  (`release_gate: RELEASE_AUDIT`) is a label string, not a path - leave it.

If the pre-move grep shows anything beyond this, STOP and add the edit before moving.

- [ ] **Step 3.2: Move papers/ and assets/**

```bash
git mv papers docs/papers
git mv assets docs/assets
```
The `docs/papers/.gitignore` (LaTeX intermediate patterns) and `docs/papers/.DS_Store`
travel with the move; `.DS_Store` is gitignored so `git mv` of the dir leaves it
untracked at the new path - no action. Confirm:
```bash
test -d docs/papers && test -d docs/assets && test ! -d papers && test ! -d assets \
  && echo "papers+assets moved: OK"
```
Expected: `papers+assets moved: OK`.

- [ ] **Step 3.3: Move and rename the root RELEASE_AUDIT addendum (it must NOT clobber the existing docs/release/RELEASE_AUDIT.md)**

```bash
test -f docs/release/RELEASE_AUDIT.md && echo "docs/release/RELEASE_AUDIT.md already exists (do not clobber)"
git mv RELEASE_AUDIT.md docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md
```
Expected: prints the "already exists" guard line, then the move succeeds to the
distinct name.

- [ ] **Step 3.4: Fix the README hero image path**

`README.md:2` - change `<img src="assets/hero.png" ...>` to:
```html
  <img src="docs/assets/hero.png" alt="Chio" width="900" />
```

- [ ] **Step 3.5: Fix the moved addendum's self-test command**

In `docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md`, the "Gate Commands" block
(was line 19) contains `grep -q 'iam_principals.toml' RELEASE_AUDIT.md`. This is a
copy-paste command that names the file by its old root path. Change it to the new
name so the documented command works from repo root:
```bash
grep -q 'iam_principals.toml' docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md
```
(Verified: no CI step or script runs this grep - the keystone-confirmed grep across
`.github/`, `scripts/`, `xtask/` for `iam_principals.toml` and
`error_taxonomy_doctest` returned nothing. It is a human-runnable example, so fixing
it prevents broken copy-paste, not a CI break.)

- [ ] **Step 3.6: Fix the stub-surface classification tuple**

`scripts/check-stub-surfaces.py:485` reads:
```python
    if path.startswith(".github/ISSUE_TEMPLATE/") or path.startswith(
        ("audits/", "editors/", "formal/", "papers/")
    ):
        return "docs"
```
`papers/` files now live under `docs/papers/`, and the function already classifies
any `docs/`-prefixed path as `"docs"` three branches below (line 492,
`path.startswith("docs/")`). So `papers/` is now redundant and dead. Remove just
`"papers/"` from the tuple
(leave `"audits/"`, `"editors/"`, `"formal/"` - `editors/` is handled in Task 5):
```python
    if path.startswith(".github/ISSUE_TEMPLATE/") or path.startswith(
        ("audits/", "editors/", "formal/")
    ):
        return "docs"
```
(`assets/` was never in this tuple; image files under `docs/assets/` now classify as
`"docs"` via the `docs/` branch - correct.)

- [ ] **Step 3.7: Fix the docs index papers entry if present**

```bash
grep -n 'papers' docs/README.md || echo "no papers entry in docs/README.md"
```
If `docs/README.md` lists a `papers/` link, update it to `docs/papers/` (relative:
the link inside `docs/README.md` would become `papers/...`). If the grep prints
"no papers entry", skip this step.

- [ ] **Step 3.8: Verify no stale references and new paths resolve**

```bash
echo "== no bare papers/ operational ref left =="
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e '"papers/"' scripts/ .github/
echo "== no assets/hero left outside docs =="
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'assets/hero' . | grep -vE '^\./docs/assets/'
echo "== resolves =="
test -f docs/assets/hero.png && test -d docs/papers \
  && test -f docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md \
  && test -f docs/release/RELEASE_AUDIT.md && echo "all resolve: OK"
```
Expected: the first two greps print nothing; the resolves check prints
`all resolve: OK` (the pre-existing `docs/release/RELEASE_AUDIT.md` is intact AND
the renamed addendum is present).

Run the two gate scripts that classify these paths, to prove they still pass:
```bash
python3 scripts/check-stub-surfaces.py && echo "stub-surfaces OK"
python3 scripts/check-review-slices.py || echo "review-slices: depends on diff base; OK if it only complains about base ref"
```
Expected: `stub-surfaces OK`. `check-review-slices.py` compares against a git base
ref; run on this branch it should pass or fail only on base-ref availability, not on
an unclassified-path error (papers->docs/papers and assets->docs/assets both classify
under the existing `docs/` review slice; see Task 5 for the editors slice).

- [ ] **Step 3.9: Commit and gate**

```bash
git add -A
git commit -m "refactor: move papers and assets into docs, relocate root release-audit addendum"
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: gate passes.

---

## Task 4: Move ops/knowledge-base into tools/knowledge-base

`ops/` holds only `knowledge-base/` (a Python cocoindex tool), so this empties and
removes the misleading `ops/` root dir.

**Files moved:** `ops/knowledge-base/` -> `tools/knowledge-base/`.
**Reference edits (same commit):**
- `Makefile:12` (`KB_DIR ?= ops/knowledge-base`)
- `.gitignore:41,57,58,59` (four `ops/knowledge-base/...` lines)
- `scripts/check-review-slices.py:202` (`"ops/**"` slice glob)
- internal: `tools/knowledge-base/chio_kb/query.py:336` self-referential message string

- [ ] **Step 4.1: Pre-move grep**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'ops/knowledge-base' . | grep -v '^\./ops/knowledge-base/'
echo "== bare ops/ slice/glob refs =="
grep -rn -e '"ops/' -e "'ops/" scripts/ .github/ Makefile
```
Expected: `Makefile:12`, `.gitignore:41,57,58,59`,
`scripts/check-review-slices.py:202`. (The many `target/.../ops/...` and
`web3-runtime/ops/` hits seen during research are runtime artifact paths unrelated
to `ops/knowledge-base/`; they live under `target/` or are web3-qualification output
dirs - do not touch.) The self-referential `chio_kb/query.py:336` string travels
with the move. Confirm no workflow references `ops/knowledge-base` (verified: none).

- [ ] **Step 4.2: Move the directory**

```bash
git mv ops/knowledge-base tools/knowledge-base
rmdir ops
test ! -d ops && echo "ops/ removed: OK"
```
Expected: `ops/ removed: OK` (knowledge-base was its only child). `git mv` of the
subdirectory leaves an empty `ops/` dir on disk (git does not track empty dirs, so
the commit is unaffected), so `rmdir ops` removes it before the `test ! -d ops`
check. All of `ops/`'s files are tracked (no untracked residue), so `rmdir` succeeds.

- [ ] **Step 4.3: Edit the Makefile KB_DIR**

`Makefile:12` reads `KB_DIR ?= ops/knowledge-base`. Change to:
```makefile
KB_DIR ?= tools/knowledge-base
```
(Every `kb-*` target uses `cd $(KB_DIR)`, so this one edit fixes all of them:
`kb-up`, `kb-down`, `kb-reset`, `kb-reseed`, `kb-update`, `kb-live`, `kb-status`,
`kb-smoke`, `kb-eval`, `kb-seed-memory`, `kb-dogfood`, `kb-lock-check`.)

- [ ] **Step 4.4: Edit the .gitignore paths**

In `.gitignore`, update the four `ops/knowledge-base/...` lines:
- `:41` `!ops/knowledge-base/.env.example` -> `!tools/knowledge-base/.env.example`
- `:57` `ops/knowledge-base/.pytest_cache/` -> `tools/knowledge-base/.pytest_cache/`
- `:58` `ops/knowledge-base/.venv/` -> `tools/knowledge-base/.venv/`
- `:59` `ops/knowledge-base/.cocoindex/` -> `tools/knowledge-base/.cocoindex/`

- [ ] **Step 4.5: Edit the review-slice glob**

`scripts/check-review-slices.py:202` - the `release-ops-evidence` slice lists
`"ops/**"`. Change to:
```python
            "tools/knowledge-base/**",
```
(Scoped to the moved subtree, not all of `tools/`, because `tools/` also holds
install scripts and version files that belong to the `ci-tooling-workspace` slice
review intent. A change under `tools/knowledge-base/**` must still land in a
reviewable slice or `check-review-slices.py` fails closed on that diff.)

- [ ] **Step 4.6: Fix the internal self-referential message (accuracy)**

`tools/knowledge-base/chio_kb/query.py:336` - the user-facing message
`"Update ops/knowledge-base/.env or export a valid shell key before querying."`
points at the old path. Change `ops/knowledge-base/.env` to
`tools/knowledge-base/.env`.

- [ ] **Step 4.7: Verify**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'ops/knowledge-base' . | grep -v '^\./tools/knowledge-base/'
test -d tools/knowledge-base && grep -q 'tools/knowledge-base' Makefile \
  && echo "kb moved + Makefile updated: OK"
```
Expected: the grep prints nothing (all `ops/knowledge-base` literals are gone except
self-references now under the new path), then `kb moved + Makefile updated: OK`.

- [ ] **Step 4.8: Commit and gate**

```bash
git add -A
git commit -m "refactor: move ops/knowledge-base to tools/knowledge-base"
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: gate passes (the KB tool is Python, not a Cargo member; this is a
regression check).

---

## Task 5: Move editors/ into integrations/editors/

Highest-risk move in this plan: `editors/zed-chio` is a Cargo workspace member, the
xtask snippets codegen writes into `editors/`, and the (already-moved) Dockerfiles
COPY `editors`. All edits land in the SAME commit as the move.

**Files moved:** `editors/` -> `integrations/editors/`.
**Reference edits (same commit):**
- `Cargo.toml:162` (`"editors/zed-chio"` member - BUILD-BREAKING if not updated)
- `xtask/src/snippets_subcommand.rs:20,21,22,62` (codegen output + schema + source constants/literals; the spec-drift gate `cargo xtask snippets regen --check` depends on these)
- `deploy/docker/Dockerfile.tee:28` and `deploy/docker/Dockerfile.sidecar:49` (`COPY editors ./editors` - BUILD-BREAKING for those images)
- `deploy/docker/Dockerfile.sidecar:34` (COPY-list comment)
- `scripts/check-review-slices.py:194` (delete the now-stale `"editors/**"` slice glob; `integrations/editors/**` already classifies via the earlier `adapters-edges` `"integrations/**"` glob)
- `scripts/check-stub-surfaces.py:485` (classification tuple)
- docs: `crates/chio-lsp/ARCHITECTURE.md:37,48`

- [ ] **Step 5.1: Pre-move grep**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'editors/' . | grep -vE '^\./editors/|/node_modules/|^\./sdks/'
```
Expected hits (the operational ones requiring edits):
- `Cargo.toml:162` `"editors/zed-chio",`
- `xtask/src/snippets_subcommand.rs:3,8,20,21,22,24,62,105`
- `deploy/docker/Dockerfile.tee:28`, `deploy/docker/Dockerfile.sidecar:34,49`
- `scripts/check-review-slices.py:194`, `scripts/check-stub-surfaces.py:485`
- `crates/chio-lsp/ARCHITECTURE.md:37,48`
Confirm there is no NEW `editors/` reference (e.g. a workflow `paths:` filter, which
research confirmed is absent). If one appeared, add its edit here.

- [ ] **Step 5.2: Move the directory**

```bash
mkdir -p integrations
git mv editors integrations/editors
test -d integrations/editors && test ! -d editors && echo "editors moved: OK"
```
Expected: `editors moved: OK`. (`integrations/` already exists with
`aws-bedrock`, `mcp-adapter`, and a `README.md`; the move adds `editors` beside them.)

- [ ] **Step 5.3: Edit the Cargo workspace member (BUILD-BREAKING)**

`Cargo.toml:162` reads `    "editors/zed-chio",`. Change to:
```toml
    "integrations/editors/zed-chio",
```
(The package name `zed-chio` is declared in
`integrations/editors/zed-chio/Cargo.toml:2` and does NOT change; only the member
path in the root manifest moves. `editors/vscode-chio` and `editors/snippets` are NOT
Cargo members - only `zed-chio` is - so this is the only member line.)

- [ ] **Step 5.4: Edit the xtask snippets constants (spec-drift gate depends on these)**

In `xtask/src/snippets_subcommand.rs`, update the three path constants and the inline
source-dir literal:
- `:20` `const VSCODE_OUTPUT: &str = "editors/vscode-chio/snippets/chio.code-snippets";` -> `"integrations/editors/vscode-chio/snippets/chio.code-snippets"`
- `:21` `const ZED_OUTPUT: &str = "editors/zed-chio/snippets/chio.json";` -> `"integrations/editors/zed-chio/snippets/chio.json"`
- `:22` `const SNIPPET_SCHEMA: &str = "editors/snippets/snippet.schema.json";` -> `"integrations/editors/snippets/snippet.schema.json"`
- `:62` `let source_dir = workspace_root.join("editors/snippets");` -> `workspace_root.join("integrations/editors/snippets")`

Also update the doc-comment mentions for accuracy (non-functional):
- `:3` `//! Reads the tool-neutral snippet sources under \`editors/snippets/\` and` -> `integrations/editors/snippets/`
- `:8` `//! The snippet schema (\`editors/snippets/snippet.schema.json\`) is` -> `integrations/editors/snippets/snippet.schema.json`
- `:105` comment `// authoritative shape contract advertised in \`editors/snippets/\`,` -> `integrations/editors/snippets/`

Note: `:24` `const HEADER` embeds the literal generated-file banner
`// generated by \`cargo xtask snippets regen\` - edit editors/snippets/*.snippet.yaml instead`.
This banner is written verbatim INTO the generated snippet files
(`integrations/editors/{vscode-chio,zed-chio}/snippets/...`) and the regen check
compares the on-disk file (including this header) against the freshly rendered
output. Update the banner text to `integrations/editors/snippets/*.snippet.yaml` AND
regenerate the files in Step 5.6 so on-disk headers match - otherwise
`snippets regen --check` reports drift.

- [ ] **Step 5.5: Edit the moved Dockerfiles' COPY lines (BUILD-BREAKING for sidecar/tee images)**

The Dockerfiles now live at `deploy/docker/` (Task 1). Their build context is repo
root, so the COPY source must reflect the new editors path:
- `deploy/docker/Dockerfile.tee:28` `COPY editors ./editors` -> `COPY integrations/editors ./integrations/editors`
- `deploy/docker/Dockerfile.sidecar:49` `COPY editors ./editors` -> `COPY integrations/editors ./integrations/editors`
- `deploy/docker/Dockerfile.sidecar:34` comment listing copied dirs (`#   - \`bench/\`, \`editors/\`, ...`) -> replace `editors/` with `integrations/editors/`.

(The COPY destination changes to `./integrations/editors` so the in-image workspace
layout matches `Cargo.toml`'s member path `integrations/editors/zed-chio`. If the
destination stayed `./editors`, `cargo build` inside the image would fail to find
the member.)

- [ ] **Step 5.6: Regenerate the snippet files at their new path**

The snippet outputs are generated artifacts; regenerate so the on-disk files (now
under `integrations/editors/...`) carry the updated header banner and match the
constants:
```bash
cargo xtask snippets regen
```
Expected: rewrites
`integrations/editors/vscode-chio/snippets/chio.code-snippets` and
`integrations/editors/zed-chio/snippets/chio.json` in place (the `git mv` already
moved them; this updates their header line). Then confirm the check passes:
```bash
cargo xtask snippets regen --check && echo "snippets in sync: OK"
```
Expected: `snippets in sync: OK` (no drift).

- [ ] **Step 5.7: Edit the review-slice and stub-surface gate scripts**

`scripts/check-review-slices.py:194` - the `products-editors-bench` slice lists
`"editors/**"`. DELETE that line (do not rewrite it to `integrations/editors/**`):
```python
            "crates/chio-wall-core/**",
            "bench/**",
        ),
    ),
```
(`classify()` returns the FIRST matching slice, and the earlier `adapters-edges`
slice already globs `"integrations/**"` at line 103, which comes before
`products-editors-bench` (line 183) in the `SLICES` tuple. After the move,
`integrations/editors/**` paths match `adapters-edges` first, so an
`"integrations/editors/**"` entry in `products-editors-bench` would be dead and never
reached. Deleting the now-stale `"editors/**"` line keeps the slice valid (it still
lists `crates/chio-cli/**` ... `bench/**`), and moved editor files still classify
(into `adapters-edges`), so the fail-closed coverage check is preserved.)

`scripts/check-stub-surfaces.py:485` tuple (after Task 3 removed `papers/`) reads
`("audits/", "editors/", "formal/")`. Replace `"editors/"` with
`"integrations/editors/"`:
```python
    if path.startswith(".github/ISSUE_TEMPLATE/") or path.startswith(
        ("audits/", "integrations/editors/", "formal/")
    ):
        return "docs"
```
(Without this, moved editor docs would fall through to `"production"` classification
and could trip the stub-surface gate.)

- [ ] **Step 5.8: Edit the chio-lsp architecture doc references**

`crates/chio-lsp/ARCHITECTURE.md:37` (`Preserve editor contract behavior from
\`editors/README.md\``) and `:48` (`First-party editor packages under \`editors/\``)
- change `editors/` to `integrations/editors/` in both.

- [ ] **Step 5.9: Verify no stale reference + workspace member resolves**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'editors/' . | grep -vE '^\./integrations/editors/|/node_modules/|^\./sdks/'
```
Expected: no output (every operational `editors/` literal now carries the
`integrations/` prefix; remaining self-references are inside `integrations/editors/`).

Confirm Cargo still sees the same member set (the build-breaking check):
```bash
cargo metadata --no-deps --format-version 1 | python3 -c \
  "import sys,json; d=json.load(sys.stdin); names=[p['name'] for p in d['packages']]; print('zed-chio present:', 'zed-chio' in names)"
```
Expected: `zed-chio present: True` (the member resolved at its new path).

- [ ] **Step 5.10: Commit and full gate (this is the load-bearing one)**

```bash
git add -A
git commit -m "refactor: move editors to integrations/editors with member, codegen, and image edits"
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: ALL pass. The build proves the `Cargo.toml` member path is correct; the
`zed-chio` integration test (`integrations/editors/zed-chio/tests/integration.rs`)
runs under `cargo test --workspace`. Then re-run the spec-drift snippet gate as CI
does:
```bash
cargo xtask snippets regen --check && echo "spec-drift snippets OK"
```
Expected: `spec-drift snippets OK`.

---

## Task 6: Fold infra/ into deploy/ and fuzz/oss-fuzz/

Empties and removes the `infra/` grab-bag: grafana dashboard and streaming composes
go under `deploy/`, the OSS-Fuzz scaffold goes beside `fuzz/`, and the syft SBOM
config moves into `deploy/sbom/` (the `deploy/` fold; the `assurance/` consolidation
is deferred).

**Files moved:**
- `infra/grafana/chio-perf.json` -> `deploy/dashboards/grafana/chio-perf.json`
- `infra/streaming-compose.yml` -> `deploy/compose/streaming-compose.yml`
- `infra/streaming-flink-compose.yml` -> `deploy/compose/streaming-flink-compose.yml`
- `infra/oss-fuzz/{project.yaml,Dockerfile,build.sh}` -> `fuzz/oss-fuzz/`
- `infra/sbom/syft.yaml` -> `deploy/sbom/syft.yaml`

**Reference edits (same commit):**
- `.github/workflows/release-binaries.yml:273,289` (`syft --config infra/sbom/syft.yaml`)
- `.github/workflows/sbom.yml:114,117,168` (`syft --config infra/sbom/syft.yaml`)
- self-referential compose comments (`streaming-compose.yml`, `streaming-flink-compose.yml`)
- docs/mirror references: `docs/install/PUBLISHING.md:261`, `docs/fuzzing/continuous.md` (multiple), `fuzz/target-map.toml:9`, `fuzz/README.md:11`, `.clusterfuzzlite/Dockerfile:5`, `.clusterfuzzlite/build.sh:13`

- [ ] **Step 6.1: Pre-move grep**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'infra/' . | grep -vE '^\./infra/|backbay/infra'
```
Expected hits to edit:
- CI-blocking SBOM config: `release-binaries.yml:273,289`, `sbom.yml:114,117,168`.
- docs/mirror: `docs/install/PUBLISHING.md:261` (`infra/sbom/syft.yaml`),
  `docs/fuzzing/continuous.md:165,169,194,209,212,216,220,235` (`infra/oss-fuzz/...`),
  `fuzz/target-map.toml:9`, `fuzz/README.md:11`, `.clusterfuzzlite/Dockerfile:5`,
  `.clusterfuzzlite/build.sh:13` (all `infra/oss-fuzz` mirror comments).
The `backbay/infra/compose.yaml` mention in `infra/streaming-compose.yml:5` is a
workspace-level reference (a different repo), not this repo's `infra/`; it lives
inside the moved file's comment and is addressed in Step 6.4. Confirm no other reader.

- [ ] **Step 6.2: Move the files into their destinations**

```bash
mkdir -p deploy/dashboards/grafana deploy/compose deploy/sbom fuzz/oss-fuzz
git mv infra/grafana/chio-perf.json deploy/dashboards/grafana/chio-perf.json
git mv infra/streaming-compose.yml deploy/compose/streaming-compose.yml
git mv infra/streaming-flink-compose.yml deploy/compose/streaming-flink-compose.yml
git mv infra/oss-fuzz/project.yaml fuzz/oss-fuzz/project.yaml
git mv infra/oss-fuzz/Dockerfile fuzz/oss-fuzz/Dockerfile
git mv infra/oss-fuzz/build.sh fuzz/oss-fuzz/build.sh
git mv infra/sbom/syft.yaml deploy/sbom/syft.yaml
rm -rf infra
test ! -d infra && echo "infra/ removed: OK"
```
Expected: `infra/ removed: OK`. The seven `git mv` lines relocate every tracked file
out of `infra/`, but the dir survives on disk because `infra/.DS_Store` is untracked
and gitignored (plus the now-empty `grafana/`, `oss-fuzz/`, `sbom/` subdirs git does
not track). `rm -rf infra` then deletes only that ignored `.DS_Store` and the empty
subdirs (no tracked file remains under `infra/` at this point, so nothing tracked is
lost and the commit is unaffected). Without the `rm -rf infra`, `test ! -d infra`
would fail. The grep in Step 6.6 confirms no tracked `infra/` reference remains.

- [ ] **Step 6.3: Edit the CI-blocking SBOM config references**

Update every `syft --config infra/sbom/syft.yaml` to
`syft --config deploy/sbom/syft.yaml`:
- `.github/workflows/release-binaries.yml:273` and `:289`
- `.github/workflows/sbom.yml:114`, `:117`, `:168`

- [ ] **Step 6.4: Edit the moved composes' self-referential comments**

In `deploy/compose/streaming-compose.yml`, the header comments (was `:9`, `:14`)
show usage `docker compose -f infra/streaming-compose.yml up -d` /
`... down -v`. Update both to `deploy/compose/streaming-compose.yml`. (The
`backbay/infra/compose.yaml` mention at was-`:5` is a different workspace path; leave
it.) In `deploy/compose/streaming-flink-compose.yml`, the header comments (was
`:6,10,14`) reference `infra/streaming-compose.yml` and
`infra/streaming-flink-compose.yml`; update both names to their `deploy/compose/`
paths.

- [ ] **Step 6.5: Edit the SBOM-config doc + OSS-Fuzz mirror references**

- `docs/install/PUBLISHING.md:261` - the table cell links `[\`infra/sbom/syft.yaml\`](../../infra/sbom/syft.yaml)`. The file is at `docs/install/`, so the new relative path is `../../deploy/sbom/syft.yaml`; change both the displayed text and the link to `deploy/sbom/syft.yaml`.
- `docs/fuzzing/continuous.md:165,169,194,209,212,216,220,235` - every `infra/oss-fuzz/...` prose path -> `fuzz/oss-fuzz/...`.
- `fuzz/target-map.toml:9` - comment naming `infra/oss-fuzz/build.sh` -> `fuzz/oss-fuzz/build.sh`.
- `fuzz/README.md:11` - prose `infra/oss-fuzz/build.sh` -> `fuzz/oss-fuzz/build.sh`.
- `.clusterfuzzlite/Dockerfile:5` - comment `# Mirrors the OSS-Fuzz scaffold under infra/oss-fuzz/` -> `fuzz/oss-fuzz/`.
- `.clusterfuzzlite/build.sh:13` - comment `# This script mirrors infra/oss-fuzz/build.sh. ...` -> `fuzz/oss-fuzz/build.sh`.

(These are the lockstep-mirror notes between `.clusterfuzzlite/`, `fuzz/`, and the
OSS-Fuzz copy; they document the three-files-in-lockstep contract and must name the
new path so the contract stays discoverable. The `syft.yaml:26`
`- "./supply-chain/sbom/**"` exclude is unchanged - `supply-chain/` stays at root.)

- [ ] **Step 6.6: Verify no stale infra/ reference + new paths resolve**

```bash
grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
  --exclude-dir=node_modules --exclude-dir=.codex --exclude-dir=docs/superpowers \
  -e 'infra/' . | grep -vE 'backbay/infra'
echo "== resolves =="
test -f deploy/sbom/syft.yaml && test -f fuzz/oss-fuzz/build.sh \
  && test -f deploy/dashboards/grafana/chio-perf.json \
  && test -f deploy/compose/streaming-compose.yml && echo "all resolve: OK"
echo "== syft config path in CI =="
grep -rn 'syft --config' .github/workflows/release-binaries.yml .github/workflows/sbom.yml
```
Expected: the first grep prints nothing (only `backbay/infra` workspace mentions, if
any, remain), `all resolve: OK`, and every `syft --config` line shows
`deploy/sbom/syft.yaml`.

- [ ] **Step 6.7: Commit and gate**

```bash
git add -A
git commit -m "refactor: fold infra into deploy and fuzz/oss-fuzz"
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: gate passes (infra files are config/data, not Cargo members; regression
check).

---

## Task 7: Phase-wide verification

After all six moves, run the go-dark guard and the full gate one final time, and
prove the root dir shrank.

- [ ] **Step 7.1: Run the crate-paths go-dark guard (if the keystone landed)**

```bash
if cargo xtask check-crate-paths 2>/dev/null; then
  echo "check-crate-paths: ran"
else
  echo "check-crate-paths not yet available (keystone Phase 1 not merged); rely on per-task greps"
fi
```
Expected: `check-crate-paths: OK (...)` if the keystone plan
(`2026-06-08-phase-1-crate-paths-guard.md`) has landed, else the not-available note.
This guard asserts the `crates/chio-*` literals still resolve; this plan does not
move any crate, but the guard is the standing fail-closed check that none of these
moves disturbed a crate-path config. If it reports `unresolved:` lines, triage each
(a real finding) before declaring the phase done.

Spelling note: the keystone plan ships this as the single-token hyphenated
subcommand `cargo xtask check-crate-paths` (matching the existing xtask dispatcher
style), which is what this step invokes. The design spec section 2.2 writes it
noun-verb as `cargo xtask check crate-paths`; that spelling becomes correct only
after the Phase 1b clap conversion lands and rewrites the dispatcher into a
noun-verb tree. Until then, use `check-crate-paths`.

- [ ] **Step 7.2: Confirm the moved root entries are gone and destinations exist**

```bash
for stale in Dockerfile Dockerfile.sidecar Dockerfile.tee Homebrew papers assets \
             RELEASE_AUDIT.md editors ops infra; do
  if [ -e "$stale" ]; then echo "STALE STILL AT ROOT: $stale"; fi
done
echo "== destinations =="
test -d deploy/docker && test -d packaging/homebrew && test -d docs/papers \
  && test -d docs/assets && test -f docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md \
  && test -d integrations/editors && test -d tools/knowledge-base \
  && test -d fuzz/oss-fuzz && test -d deploy/compose && test -d deploy/sbom \
  && echo "all destinations present: OK"
test -f .dockerignore && test -f deny.toml && test -d supply-chain \
  && test -f releases.toml && test -d .cargo && test -d .kani \
  && test -d .clusterfuzzlite && echo "keep-at-root items intact: OK"
```
Expected: no `STALE STILL AT ROOT` lines, `all destinations present: OK`, and
`keep-at-root items intact: OK` (the verified-pinned configs were not touched).

- [ ] **Step 7.3: Final full workspace gate**

```bash
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: all pass. This is the phase exit criterion. Per project memory, also run
the supply-chain gates locally if the toolchain is installed:
```bash
cargo deny check advisories licenses sources bans 2>/dev/null || echo "cargo-deny not installed; CI covers it"
cargo vet --locked 2>/dev/null || echo "cargo-vet not installed; CI covers it"
```
Expected: pass if installed (this plan did not touch `deny.toml` or `supply-chain/`,
so these are pure regression checks), else the not-installed note.

---

## Self-Review

### (1) Spec-item -> task mapping (spec Phase 5, file-moves subset)

| Spec Phase 5 item | Task | Covered |
| --- | --- | --- |
| Move Dockerfiles + 7 verified edits, same commit, `.dockerignore` stays | Task 1 | Yes - edits #1-#5 (sidecar-image.yml:106; chio-tee-image.yml:50,6,20; compose.yaml:8,27; tee docker-compose.yml:5; check-sidecar-docker-context.test.sh:5) + docs |
| Move `Homebrew` | Task 2 | Yes - incl. the CI fail-closed `formula_src` at release-binaries.yml:595 |
| Move `papers` -> docs/papers | Task 3 | Yes |
| Move `assets` -> docs/assets (README hero) | Task 3 | Yes - README.md:2 |
| Move `RELEASE_AUDIT.md` -> docs/release | Task 3 | Yes, with the verified correction: the destination filename ALREADY EXISTS as a different file, so the root addendum moves to `docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md` (clobber-avoidance; both files preserved) |
| Move `editors` -> integrations/editors | Task 5 | Yes - incl. Cargo.toml:162 member, snippets_subcommand.rs constants, moved-Dockerfile COPY lines |
| Move `ops/knowledge-base` -> tools/knowledge-base | Task 4 | Yes - Makefile:12 KB_DIR + 4 .gitignore lines + review-slice |
| Fold `infra/` into deploy/ + fuzz/oss-fuzz/ | Task 6 | Yes - sbom config CI edits + grafana + compose + oss-fuzz |
| KEEP-AT-ROOT list left untouched | KEEP note + Task 7.2 | Yes - supply-chain, releases.toml, deny.toml, .cargo, .kani, .clusterfuzzlite, .dockerignore, osv-scanner.toml, .tooling |
| Run `check-crate-paths` after path-literal moves | Task 7.1 | Yes (conditional on keystone) |

Gaps (intentional, stated in Scope): the `assurance/` consolidation (audits/ +
compliance/ + docs/compliance/ + infra/sbom merge) is the medium-risk tail of spec
Phase 5 and is NOT in this plan - it needs the generalized guard and its own
verification. `infra/sbom/syft.yaml` is parked in `deploy/sbom/` (inside the `deploy/`
fold the brief mandates) rather than a not-yet-existing `assurance/` tree, so the
`infra/` dir is fully emptied without front-running the assurance work. The
`coverage/`, `.codex/`, orphan-script deletions, and README rewrite are Phase 0 /
Phase 0b (keystone plan Task A + a separate plan), not duplicated here. `playwright.config.ts`
shim drop is a Phase 0/JS cleanup, not part of these directory moves.

### (2) Placeholder red-flag scan

No TBD/TODO/"implement later"/"similar to Task N". Every edit step shows the exact
old text and the exact replacement with file:line. Every command shows expected
output. The only conditional is Task 7.1 (guard availability), which is explicit and
has a defined fallback, not a placeholder. The Step 1.8 docker dry check is optional
and guarded by `command -v docker`; the real verification is the resolves+grep in
Step 1.7.

### (3) Type/method/name consistency

- Destination paths are consistent across tasks and Task 7.2: `deploy/docker/`,
  `packaging/homebrew/`, `docs/papers/`, `docs/assets/`,
  `docs/release/RELEASE_AUDIT_PROVIDER_ADDENDUM.md`, `integrations/editors/`,
  `tools/knowledge-base/`, `fuzz/oss-fuzz/`, `deploy/compose/`, `deploy/sbom/`,
  `deploy/dashboards/grafana/`.
- The editors move (Task 5) edits the Dockerfiles at their post-Task-1 path
  (`deploy/docker/Dockerfile.{tee,sidecar}`), and the COPY destination becomes
  `./integrations/editors` to match the `Cargo.toml` member path
  `integrations/editors/zed-chio` (Step 5.3 <-> 5.5 consistent).
- The xtask snippet constants (`VSCODE_OUTPUT`, `ZED_OUTPUT`, `SNIPPET_SCHEMA`) and
  the inline `editors/snippets` literal at snippets_subcommand.rs:62 are all updated
  to `integrations/editors/...` (Step 5.4), and the generated-file HEADER banner is
  updated + regenerated (Step 5.6) so `snippets regen --check` (the spec-drift gate
  at spec-drift.yml:68) stays in sync - verified the gate command in research.
- The `scripts/check-stub-surfaces.py:485` tuple is edited twice across the plan but
  consistently: Task 3 removes `"papers/"` (now covered by the `docs/` branch),
  Task 5 changes `"editors/"` to `"integrations/editors/"`; the final tuple is
  `("audits/", "integrations/editors/", "formal/")`. No conflict (different commits,
  cumulative).
- `scripts/check-review-slices.py` edits are scoped per slice: Task 4 changes
  `"ops/**"` -> `"tools/knowledge-base/**"`; Task 5 DELETES the stale `"editors/**"`
  line (it does not rewrite it, because `classify()` returns the first matching slice
  and the earlier `adapters-edges` slice already globs `"integrations/**"`, so moved
  `integrations/editors/**` files classify there first). Both keep the moved subtree
  mapped to a review slice so the fail-closed coverage check (classify returns None
  -> exit 1) does not trip.
- The KEEP-AT-ROOT note and Task 7.2's keep-intact assertion list the same set
  (supply-chain, releases.toml, deny.toml, .cargo, .kani, .clusterfuzzlite,
  .dockerignore), consistent with the migration-validation appendix verdicts.
- All commit messages use conventional-commit `refactor:` and contain no em dashes;
  all prose uses hyphens/parentheses.

All three checks pass; issues found during drafting (RELEASE_AUDIT clobber,
editors-is-a-Cargo-member, editors-COPYed-into-Dockerfiles, papers-redundant-in-stub-tuple,
fail-closed review-slice coverage) were resolved inline above.
