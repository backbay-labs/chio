# Migration validation: supply-chain/, osv-scanner.toml, releases.toml, deny.toml, .tooling/, tool-mandated root dirs

Read-only adversarial validation of a planned relocation/merge step in the Chio
repo at `/Users/connor/Medica/backbay/standalone/arc`. Scope: confirm what would
break, and produce an exact fail-closed edit checklist. No files were modified.

Evidence convention below: `path:line`. All paths are repo-relative to the arc
workspace root unless stated otherwise.

## Summary verdict per item

| Item | Planned step | Verdict | Why |
| --- | --- | --- | --- |
| `supply-chain/` | relocate | KEEP AT ROOT (movable only with a Cargo.toml store.path edit + several script edits) | `cargo vet --locked` runs from repo root with no path override; many scripts/workflows hardcode `supply-chain/...` |
| `osv-scanner.toml` | move into `supply-chain/` | SAFE WITH EDITS | invoked with explicit `--config "${GITHUB_WORKSPACE}/osv-scanner.toml"`; one workflow line + one slice list to update |
| `releases.toml` | move to `docs/release/` | BLOCKED / higher-risk | path hardcoded cwd-relative in 3 workflows + 2 scripts; CODEOWNERS pin; a missing-file fail-closed check in release-binaries.yml |
| `deny.toml` | stay at root | CONFIRM KEEP AT ROOT | `cargo deny check ...` run with no `--config`, reads `deny.toml` from cwd |
| `.tooling/*.version` | merge into `tools/versions.toml` | SAFE WITH EDITS (broad blast radius) | 7 workflows + 4 scripts + 2 string-literal test guards read `cat .tooling/<x>.version`; `tools/versions.toml` has no current reader |
| `.cargo/`, `.kani/`, `.clusterfuzzlite/` | do not move | CONFIRM KEEP AT ROOT | tool-mandated default paths; readers assume root |

---

## 1. supply-chain/ (cargo-vet) -> KEEP AT ROOT

How cargo-vet is invoked (no manifest/path/config override, runs from repo root
after `actions/checkout`):

- `.github/workflows/cargo-vet.yml:126-130` -- step `cargo vet --locked` runs
  bare `cargo vet --locked`. No `--manifest-path`, no `--store-path`.
- `.github/workflows/ci.yml:191-192` -- duplicate job: `run: cargo vet --locked`.

cargo-vet default: the audit store lives in `supply-chain/` resolved relative to
the workspace root (the directory containing the root `Cargo.toml`). With no
override, moving `supply-chain/` makes both jobs fail at load (no store found).

Configurable escape hatch exists but is NOT currently set:

- `Cargo.toml:196` declares `[workspace.metadata.cargo-vet]` and the table is
  EMPTY (verified: lines 196-197, nothing under it before
  `[workspace.metadata.cargo-auditable]` at :198). cargo-vet reads
  `store.path` from this table; absent, it defaults to `supply-chain/`.

Hardcoded `supply-chain/...` readers that ALSO break on a move (independent of
cargo-vet itself):

- `.github/workflows/cargo-vet.yml:12,19` -- `paths:` trigger filters on
  `supply-chain/**` (push and pull_request). A move silently stops triggering
  the gate on relevant changes (fail-OPEN, the worst outcome).
- `.github/workflows/cargo-vet.yml:79` -- `git show "$BASE_SHA:supply-chain/config.toml"`.
- `.github/workflows/cargo-vet.yml:82` -- `--head supply-chain/config.toml` passed
  to `scripts/check-cargo-vet-exemptions.py`.
- `.github/workflows/sbom.yml:78` -- `out_dir="supply-chain/sbom/${tag}"` (SBOM
  output dir).
- `.github/workflows/release-binaries.yml:803,810,828,829,842,843,844` --
  writes/reads `supply-chain/checksums/v<tag>.txt[.sig|.pem]`.
- `infra/sbom/syft.yaml:26` -- `- "./supply-chain/sbom/**"` exclude glob.
- `docs/release-evidence.md:11-13` -- documents `supply-chain/checksums/...`.
- `scripts/check-stub-surfaces.py:228,422` -- allowlist + match keyed on
  `supply-chain/config.toml` (the bollard-stubs exemption). A move breaks the
  stub-surface gate.
- CODEOWNERS: no explicit `supply-chain/` line found (verified via grep on
  `.github/CODEOWNERS`); ownership likely falls through to a default rule.

Verdict: KEEP AT ROOT. Moving is technically possible only by (a) adding
`store.path = "<new>"` under `[workspace.metadata.cargo-vet]` in `Cargo.toml`,
AND (b) updating every hardcoded reader above, AND (c) updating the two `paths:`
triggers so the gate still fires. The checksum/SBOM sub-paths
(`supply-chain/checksums/`, `supply-chain/sbom/`) are a separate write contract
shared by release-binaries.yml and sbom.yml and would have to move in lockstep.
Recommendation: do not move; the surface area is large and the failure mode for
the trigger paths is fail-open.

## 2. osv-scanner.toml -> SAFE WITH EDITS (can move into supply-chain/)

Reader uses an explicit absolute `--config`, NOT cwd discovery:

- `.github/workflows/cve-monitor.yml:96-97` --
  `osv-scanner --recursive --format json --output osv-scanner.json --config "${GITHUB_WORKSPACE}/osv-scanner.toml" ...`.

Because the path is explicit, osv-scanner does not auto-discover the file; moving
it only requires updating this one `--config` argument.

Other readers:

- `.github/workflows/cve-monitor.yml` `paths:` (lines 6-18) does NOT list
  `osv-scanner.toml` itself; it lists `deny.toml`, lockfiles, and the workflow.
  So a move does not break the trigger, but note the config is also not a trigger
  today (pre-existing).
- `scripts/check-review-slices.py:217` -- `osv-scanner.toml` literal in the
  `ci-tooling-workspace` review-slice glob list. Update to the new path.

Verdict: SAFE WITH EDITS. Two edits: the `--config` value at cve-monitor.yml:97
and the slice literal at check-review-slices.py:217.

## 3. releases.toml -> BLOCKED / higher-risk than expected

This is a live mutation-gate state file, not a doc. Parsed by bespoke bash/awk
extractors, several of which resolve the path cwd-relative (= repo root in CI):

- `scripts/mutants-gate.sh:72-74` -- resolves SCRIPT-relative:
  `script_dir=$(dirname $0)`, `repo_root=${script_dir}/..`,
  `releases_toml="${repo_root}/releases.toml"`. Assumes `releases.toml` is one
  level up from `scripts/` (i.e. repo root). A move to `docs/release/` breaks
  this; the script then logs "missing -> advisory" (fail-OPEN for the gate).
- `scripts/mutants-comment.sh:60,85` -- `read_release_scalar` defaults to
  `releases.toml` (cwd-relative); `resolve_gate_mode` (:85) hardcodes
  `local releases_toml="releases.toml"`.
- `.github/workflows/mutants.yml:209` -- awk reads bare `releases.toml` for
  `pr_survivor_issue_budget` (cwd-relative).
- `.github/workflows/release-binaries.yml:920-921` -- fail-closed guard:
  `if [ ! -f releases.toml ]; then echo "::error::releases.toml is missing on main"; exit 1`.
  A move makes the release-binaries mutants-gate-flip job FAIL CLOSED (hard exit
  1) on main.
- `.github/workflows/release-binaries.yml:945,995,997,1006` -- reads
  `releases.toml`, then Python `pathlib.Path("releases.toml")` rewrites
  `cycle_end_tag`, then `grep -n cycle_end_tag releases.toml`.

Governance / docs coupling:

- `.github/CODEOWNERS:66` -- `releases.toml  @backbay-labs/chio-maintainers`.
  Moving the file orphans this pin unless the new path gets an equivalent rule.
- `docs/release/RELEASE_AUDIT.md:25,26,32` -- treats root `releases.toml` as the
  canonical publication-status source. (Note: the proposed destination
  `docs/release/` already exists and already contains RELEASE_AUDIT.md.)
- `docs/fuzzing/mutants.md:156,172,201,224,226,260,294,374` -- documents
  "releases.toml at the repo root" as the permanent path; CODEOWNERS gate
  described at :226,:260.
- Many `audits/...` evidence docs reference `releases.toml [trust_boundary_crates]`
  / `[per_crate_kill_rate_percent]` (e.g. `audits/mutation/2026-05-08-per-crate-baseline.md:6,10,15`).
- `scripts/check-review-slices.py:202` -- `releases.toml` literal in the
  release-evidence review slice.

Verdict: BLOCKED-NEEDS-OWNER-DECISION (or higher-risk-than-expected). The "Read
by scripts/mutants-gate.sh" comment in the file header (releases.toml:3) and the
documented "permanent path... repo root" contract in mutants.md make this a
governance-pinned operational file. If a move is mandated, ALL of the readers
above must change atomically, the CODEOWNERS pin must be re-added for the new
path, and the mutants.yml/release-binaries.yml fail-open/fail-closed behaviors
re-verified. The cwd-relative readers (mutants-comment.sh, mutants.yml:209,
release-binaries.yml) would need an explicit path prefix since CI cwd is repo
root. Recommendation: do NOT move; if relocation is required for tidiness, prefer
a thin root-level pointer kept in place, owner decision required.

## 4. deny.toml -> CONFIRM KEEP AT ROOT

cargo-deny reads `deny.toml` from the current working directory by default; no
`--config` is passed:

- `.github/workflows/ci.yml:207-219` -- five steps `cargo deny check
  {advisories,licenses,sources,bans}` plus duplicate-baseline, all bare (no
  `--config`, no `--manifest-path`). cwd is repo root post-checkout.
- No `cargo deny ... --config` invocation exists anywhere
  (grep across `.github/workflows/`, `scripts/`, `xtask/` returned only the
  ci.yml steps and a comment; verified).
- `.github/workflows/cve-monitor.yml:12` -- `deny.toml` is a `paths:` trigger for
  the CVE monitor (so it must keep the same path to keep triggering).
- `.github/CODEOWNERS:57` -- `deny.toml  @backbay-labs/chio-maintainers`.
- `scripts/check-cargo-deny-duplicate-baseline.py:13` -- reads
  `scripts/cargo-deny-duplicate-baseline.txt` (the baseline data file, not
  deny.toml itself); unaffected by deny.toml location but part of the same gate.

Verdict: KEEP AT ROOT (confirmed). Moving deny.toml would require adding
`--config <path>` to all five cargo-deny steps and updating the cve-monitor
trigger and CODEOWNERS. No reason to move; default cwd discovery is the contract.

## 5. .tooling/*.version -> SAFE WITH EDITS, broad blast radius

Current readers all use the shell idiom `$(cat .tooling/<name>.version)` (a
single-line plain-text version string), NOT a TOML parse. `tools/versions.toml`
currently has ZERO readers in CI/scripts (the only `versions.toml` hits are the
unrelated JVM SDK `gradle/chio.versions.toml`). Therefore "merging into
tools/versions.toml" is not a path rename: it changes the FILE FORMAT from
one-line plain text to a TOML table, so every consumer must switch from `cat` to
a TOML extraction, AND the producers (the three `.version` files) get deleted.

cargo-ndk.version readers:

- `.github/workflows/nightly.yml:286` -- `cargo install cargo-ndk --version "$(cat .tooling/cargo-ndk.version)" --locked`
- `.github/workflows/release-qualification.yml:152` -- same idiom.

wasm-pack.version readers:

- `.github/workflows/web-sdk.yml:43,137`
- `.github/workflows/demo-pages.yml:58`
- `.github/workflows/release-npm.yml:252`
- `.github/workflows/browser-kernel-twiggy.yml:34`
- `.github/workflows/nightly.yml:285`
- `.github/workflows/release-qualification.yml:150`
- `sdks/typescript/scripts/build-wasm.sh:25` -- `WASM_PACK_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-pack.version")"`
- `scripts/check-sdk-release.sh:667` -- `required_wasm_pack_version="$(cat "${repo_copy_dir}/.tooling/wasm-pack.version")"`

wasm-bindgen.version readers:

- `.github/workflows/web-sdk.yml:45`
- `.github/workflows/demo-pages.yml:61`
- `.github/workflows/release-npm.yml:256`
- `.github/workflows/browser-kernel-twiggy.yml:37`
- `.github/workflows/release-qualification.yml:151`
- `sdks/typescript/scripts/build-wasm.sh:26` -- `WASM_BINDGEN_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-bindgen.version")"`
- `scripts/check-sdk-release.sh:677` -- `required_wasm_bindgen_version="$(cat "${repo_copy_dir}/.tooling/wasm-bindgen.version")"`

String-literal test guards (these grep for the EXACT command string and FAIL if
the workflow text changes; they break even if the new mechanism is correct):

- `scripts/tests/release-qualification-formal-tools.test.sh:27` -- asserts
  literal `cargo install wasm-bindgen-cli --version "$(cat .tooling/wasm-bindgen.version)" --locked`.
- `scripts/tests/release-qualification-formal-tools.test.sh:51,52` -- asserts the
  wasm-pack and wasm-bindgen literals via `first_line(...)`.
- `scripts/tests/release-npm-package-matrix.test.sh:57` -- `grep -F 'cargo install wasm-pack --version "$(cat .tooling/wasm-pack.version)" --locked'`.

Packaging coupling (the directory name is baked into a tar manifest):

- `scripts/check-sdk-release.sh:466` -- `tar ... -cf - .cargo .tooling Cargo.lock ...`
  copies the literal `.tooling` directory into the SDK release sandbox; the
  version reads at :667,:677 then read from that copied dir. Deleting `.tooling`
  without updating this tar list and the two reads breaks the SDK release check.
- `scripts/check-review-slices.py:211` -- `.tooling/**` in the
  `ci-tooling-workspace` review slice glob.
- `sdks/typescript/scripts/build-wasm.sh:4,7` -- header comments reference
  `.tooling/{wasm-pack,wasm-bindgen}.version` (cosmetic, update for accuracy).

Verdict: SAFE WITH EDITS, but the blast radius is 7 workflows + 2 SDK/release
scripts + 3 test guards + 1 tar manifest + 1 review-slice list. The cleaner
fail-closed approach is to keep the one-line-file contract (move the three files
under `tools/versions/` and update the `cat` paths) rather than reformatting into
`tools/versions.toml`, because a TOML reformat forces every `cat` to become a
parser and breaks the three exact-string test guards. If a TOML merge is required,
all 3 test guards must be rewritten to assert the new command form.

## 6. .cargo/config.toml, .kani/, .clusterfuzzlite/ -> CONFIRM KEEP AT ROOT

- `.cargo/config.toml` -- Cargo-mandated location. Cargo discovers
  `.cargo/config.toml` by walking up from cwd to the root; the workspace-root
  `.cargo/` is the canonical spot. Content (verified) is the `xtask` alias:
  `[alias] xtask = "run --quiet --package xtask --"`. Moving it silently disables
  `cargo xtask ...` everywhere (fail-open: the alias just stops existing). Do not
  move.
- `.kani/harnesses.toml` -- read cwd/root-relative by default:
  `scripts/run-kani-manifest.sh:96` -- `MANIFEST="${KANI_MANIFEST:-.kani/harnesses.toml}"`
  and :36 documents "relative to repo root". `.github/workflows/nightly.yml:139`
  documents `[[harness]]` entries in `.kani/harnesses.toml`. The override env
  `KANI_MANIFEST` exists, but the default and the nightly lane assume
  `.kani/harnesses.toml` at root. Do not move (would require setting
  `KANI_MANIFEST` in every invocation).
- `.clusterfuzzlite/` -- ClusterFuzzLite GitHub Actions (`build_fuzzers`) default
  to `.clusterfuzzlite/build.sh` / `Dockerfile` / `project.yaml` at repo root.
  `.github/workflows/cflite_pr.yml:37` triggers on `.clusterfuzzlite/**`;
  `cflite_pr.yml:146` greps `^(\.cargo/|\.clusterfuzzlite/|...)`. The tool name
  IS the directory name. Do not move.

## Aggregate edit checklist (only if a move is forced)

osv-scanner.toml -> supply-chain/ (lowest risk, recommended-allowable):
1. `.github/workflows/cve-monitor.yml:97` -- `--config "${GITHUB_WORKSPACE}/supply-chain/osv-scanner.toml"`.
2. `scripts/check-review-slices.py:217` -- change literal to `supply-chain/osv-scanner.toml`.

supply-chain/ relocation (NOT recommended): add `store.path` under
`Cargo.toml:196 [workspace.metadata.cargo-vet]`; update cargo-vet.yml:12,19
(triggers), :79,:82; sbom.yml:78; release-binaries.yml:803,810,828,829,842-844;
infra/sbom/syft.yaml:26; check-stub-surfaces.py:228,422; docs/release-evidence.md:11-13.

releases.toml relocation (BLOCKED, owner decision): mutants-gate.sh:74;
mutants-comment.sh:60,85; mutants.yml:209; release-binaries.yml:920,945,995,1006;
CODEOWNERS:66; check-review-slices.py:202; plus docs in docs/fuzzing/mutants.md
and docs/release/RELEASE_AUDIT.md.

.tooling merge: update the 14 workflow lines + build-wasm.sh:25-26 +
check-sdk-release.sh:466,667,677 + the 3 test guards
(release-qualification-formal-tools.test.sh:27,51,52;
release-npm-package-matrix.test.sh:57) + check-review-slices.py:211.

deny.toml / .cargo / .kani / .clusterfuzzlite: no edits; keep at root.
