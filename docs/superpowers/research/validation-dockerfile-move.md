# Validation Appendix: Move root Dockerfiles into deploy/docker/

Area: Dockerfile relocation (`Dockerfile`, `Dockerfile.sidecar`, `Dockerfile.tee` -> `deploy/docker/`).

Verdict: safe-with-edits.

Read-only adversarial validation. No files were modified. Evidence is file:line.

## 1. Scope confirmation

Three root files in scope (all tracked, build context = repo root):

- `/Users/connor/Medica/backbay/standalone/arc/Dockerfile` (3.6K, main multi-target image)
- `/Users/connor/Medica/backbay/standalone/arc/Dockerfile.sidecar` (5.7K)
- `/Users/connor/Medica/backbay/standalone/arc/Dockerfile.tee` (2.6K)
- `.dockerignore` at root (129B).

OUT OF SCOPE separate Dockerfiles that must NOT be touched (different files, different paths):

- `deploy/sidecar/Dockerfile` (already lives in deploy/, has its own `docker build -f deploy/sidecar/Dockerfile`).
- `sdks/k8s/controller/Dockerfile` (controller image, `docker build -t $(IMG) .` in its own Makefile).
- `.clusterfuzzlite/Dockerfile`, `infra/oss-fuzz/Dockerfile` (fuzzing tool-convention files).
- `ops/knowledge-base/Dockerfile.kb-mcp` (referenced by `ops/knowledge-base/docker-compose.yml:73`).
- `docs/.../Dockerfile.distroless` (doc-only mention).
- `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md:295,442` are an illustrative inline code block / tree diagram, NOT a path reference to the root file.
- Worktree copies under `.worktrees/**` and `.claude/worktrees/**` are independent checkouts, not part of this repo's migration.

## 2. Build context: must stay repo-root (CRITICAL)

All three Dockerfiles COPY paths relative to the repo root, so the build context MUST remain repo-root after the move. Moving the Dockerfile does NOT move the context (context is set by the build invocation, not the Dockerfile location). Evidence:

- `Dockerfile:14` `COPY Cargo.toml Cargo.lock ./`; `:15` `COPY crates ./crates`; `:16` `COPY examples ./examples`; `:17` `COPY formal/diff-tests ./formal/diff-tests`; `:18` `COPY tests/e2e ./tests/e2e`; `:70-71` `COPY ... examples/docker/...`.
- `Dockerfile.sidecar:45-79` `COPY Cargo.toml Cargo.lock`, `crates`, `contracts`, `bench`, `editors`, `wit`, `examples`, `formal`, `tests`, `sdks`, `xtask`, `integrations` (all root-relative).
- `Dockerfile.tee:24-35` same root-relative set (`Cargo.toml`, `crates`, `bench`, `contracts`, `editors`, `wit`, `examples`, `formal`, `integrations`, `tests`, `sdks`, `xtask`).

Implication: `.dockerignore` MUST STAY AT ROOT. Docker/buildx loads `.dockerignore` from the build-context root, not from beside the Dockerfile. Moving it would silently stop excluding `target/`, `node_modules/`, `.git`, etc., bloating the context and likely changing build behavior. Keep `/Users/connor/Medica/backbay/standalone/arc/.dockerignore` exactly where it is.

## 3. CI-blocking references (MUST edit, in lockstep with the move)

These run in live GitHub Actions and will fail (file-not-found) the moment the files move:

1. `.github/workflows/sidecar-image.yml:106` `file: Dockerfile.sidecar` (build-push-action; `context: .` at `:105` stays `.`). Change to `file: deploy/docker/Dockerfile.sidecar`. Do NOT change `context: .`.
   - Also `:4-7` triggers on `push` tags only (no `paths:` filter for this file), so no path-trigger edit needed here.

2. `.github/workflows/chio-tee-image.yml:50` `run: docker build -f Dockerfile.tee -t chio-tee:ci .` Change `-f Dockerfile.tee` to `-f deploy/docker/Dockerfile.tee`. The trailing `.` (context) stays `.`.
   - `.github/workflows/chio-tee-image.yml:6` and `:20` `paths:` triggers list `Dockerfile.tee` (pull_request and push). Update both to `deploy/docker/Dockerfile.tee` so the workflow still triggers when the file changes (otherwise the image silently stops being rebuilt on edits = stale-image fail-open).

The main root `Dockerfile` is NOT built by any workflow via `docker build`/`build-push` (grep of all `.github/workflows/*` found zero). It is only consumed by compose (next section).

## 4. Compose references (MUST edit; context resolution detail)

Compose `dockerfile:` is resolved relative to the build `context`, and all three composes set context to repo root via `../..` (the compose files live two levels deep). So the `dockerfile:` value is repo-root-relative and must gain the `deploy/docker/` prefix.

3. `examples/docker/compose.yaml:8` `dockerfile: Dockerfile` (context `../..` at `:7`) -> `dockerfile: deploy/docker/Dockerfile`.
4. `examples/docker/compose.yaml:27` `dockerfile: Dockerfile` (context `../..` at `:26`) -> `dockerfile: deploy/docker/Dockerfile`.
5. `examples/tee-sidecar/docker-compose.yml:5` `dockerfile: Dockerfile.tee` (context `../..` at `:4`) -> `dockerfile: deploy/docker/Dockerfile.tee`.

`examples/otel-genai/docker-compose.yml` uses only upstream images (no `build:`/Dockerfile) - no edit. `ops/knowledge-base/docker-compose.yml` references `Dockerfile.kb-mcp` (out of scope).

## 5. Script references (NOT CI-wired today, but hard-coded paths break if invoked)

Neither script is invoked by `ci.yml`, `scripts/ci-workspace.sh`, or any workflow (verified by exact-name grep). They are manually-run / orphaned, so they will not block CI, but they encode hard-coded paths that fail-open or fail-loud if anyone runs them after the move. Fix them to avoid silent drift:

6. `scripts/tests/check-sidecar-docker-context.test.sh:5` `dockerfile="${repo_root}/Dockerfile.sidecar"` -> `${repo_root}/deploy/docker/Dockerfile.sidecar`. (Line 11 does an exact `grep -Fxq "COPY ${source} ${destination}"`; that content does not change, only the file path.) Line 12 is just an error message string.

7. `scripts/check-docker-deployable-experience.sh` drives `examples/docker` via `docker compose up -d --build` (`:5` `example_dir=.../examples/docker`, `:22`). It relies on the compose file, so once edit #3/#4 land this script needs no further change. Listed for completeness; no direct Dockerfile path inside it.

## 6. Documentation references (MUST edit for accuracy; non-blocking, no fail-open)

These are prose/command examples that become wrong after the move. They do not block CI but produce broken copy-paste commands:

8. `deploy/SIDECAR_BUILD_GUIDE.md:17` `docker build -f Dockerfile.sidecar -t chio-sidecar:local .` -> `-f deploy/docker/Dockerfile.sidecar` (keep trailing `.`). Lines 5 and 28 are prose mentions of `Dockerfile.sidecar` - update the names for accuracy.
9. `docs/install/BINARY_DISTRIBUTION.md:45` prose "built from `Dockerfile.sidecar`" -> update path/name.
10. `docs/operations/ROADMAP.md:141` prose `Dockerfile.sidecar` -> update name.
11. `examples/tee-sidecar/README.md:5` and `:42` prose `Dockerfile.tee` -> update name/path.
12. `examples/tee-sidecar/chio-tee.toml:5` comment "Runtime paths match Dockerfile.tee and docker-compose.yml" -> update name.
13. `Dockerfile:3-4` and `Dockerfile.tee:2` internal comments cross-reference the sibling Dockerfiles by bare name. After the move they are still siblings in `deploy/docker/`, so the bare names remain correct; no edit strictly required, but optionally clarify.
14. `deploy/README.md:19,105` refer to `sidecar/Dockerfile` (the out-of-scope `deploy/sidecar/Dockerfile`), NOT the moved files - leave as-is. Consider adding rows for the three newly relocated files.

## 7. buildx / bake / compose summary

- No `*.bake.hcl` or `docker-bake.*` files exist anywhere in the repo (find returned none).
- compose files referencing in-scope Dockerfiles: items #3, #4, #5 above. All set `context: ../..` (repo root), so they keep working as long as the `dockerfile:` key is reprefixed.
- buildx is used in `sidecar-image.yml` via `docker/build-push-action` (item #1) - the `file:` field is the only path to change; `context: .` stays.

## 8. Build-context invocation inventory (quoted)

- `sidecar-image.yml:105-106` context `.` + `file: Dockerfile.sidecar` => context repo-root, file at root. After move: file path changes, context unchanged.
- `chio-tee-image.yml:50` `docker build -f Dockerfile.tee -t chio-tee:ci .` => `-f` is file, trailing `.` is context (repo-root). After move: `-f` changes, `.` unchanged.
- `examples/docker/compose.yaml:6-9` and `:25-28` `build: { context: ../.., dockerfile: Dockerfile, target: ... }` => context repo-root.
- `examples/tee-sidecar/docker-compose.yml:3-6` `build: { context: ../.., dockerfile: Dockerfile.tee }` => context repo-root.

No invocation uses `docker build <dir>` form (context = the Dockerfile's own dir); every in-scope build sets context to repo root explicitly. So the move does not silently change any build context provided edits #1-#5 land.

## 9. Net result

Safe to move all three files into `deploy/docker/` IF and ONLY IF:

- `.dockerignore` stays at repo root (build context stays repo root).
- Edits #1-#5 (CI workflows + compose) land in the SAME commit as the move; otherwise `sidecar-image.yml`, `chio-tee-image.yml`, and the two example composes break immediately.
- Edits #6-#13 (scripts + docs) land to avoid drift / broken commands.
- The `chio-tee-image.yml` `paths:` triggers (#2, lines 6 and 20) are updated, else edits to the moved `Dockerfile.tee` no longer trigger a rebuild (silent stale-image fail-open).
