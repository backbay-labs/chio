# Research M05: P0 Wave-Opener Ready Pack

Date: 2026-04-30
Branch: `research/w2/m05-p0-notes`
Scope: implementation notes for `M05.P0.T1`

## Sources Read

- `.planning/trajectory-2/05-adversarial-escape-threat-model.md`
- `.planning/trajectory-2/tickets/M05/P0.yml`
- `.planning/trajectory-2/decisions.yml` decisions D13 and D14
- `.planning/trajectory-2/freezes.yml`
- `.planning/trajectory-2/WAVE-OPENER-STRATEGY.md`
- `.planning/trajectory-2/ci-stubs/adversarial-suite.yml`
- `.planning/trajectory-2/ci-stubs/wasm-guard-escape.yml`
- `.planning/trajectory-2/ci-stubs/m04-freeze-guard.yml` as the reusable freeze-guard shape
- Live manifests for `crates/chio-attest-verify` and `crates/chio-wasm-guards`

## P0 Objective

`M05.P0.T1` is deliberately small: absorb dependency and lockfile churn before the
load-bearing M05 phases open. The ticket asks for:

- `toml` as a direct dependency of `chio-attest-verify`.
- `arbitrary` as the direct dependency used by `chio-wasm-guards` escape tests and
  fuzz plumbing.
- `Cargo.lock` refreshed once so P1, P3, P4, and P5 do not each contend on the
  shared lockfile.

This is a wave-opener prep PR. It should not create the adversarial suite, add
escape fixtures, alter threat-model JSON, or implement the expected-identity
policy loader.

## Live Dependency State

Current branch state matters:

- `crates/chio-attest-verify/Cargo.toml` does not list `toml`.
- `Cargo.lock` already contains `toml` versions `0.5.11`, `0.8.23`, and
  `0.9.12+spec-1.1.0` through other crates. P0 should prefer the existing
  `toml = "0.8"` line shape used by `chio-conformance` and `chio-tee`.
- `crates/chio-wasm-guards/Cargo.toml` already has:
  `arbitrary = { version = "1", features = ["derive"], optional = true }`
  and the crate's `fuzz` feature already enables `dep:arbitrary`.
- `Cargo.lock` already includes `arbitrary 1.4.2`, and the
  `chio-wasm-guards` package entry already lists `arbitrary`.

Implementation consequence: the P0 implementer should not add a duplicate
`arbitrary` entry. Treat the existing optional direct dependency as satisfying
the "direct dep" requirement unless Cargo metadata on the implementation branch
proves otherwise. The likely real diff is `toml = "0.8"` in
`crates/chio-attest-verify/Cargo.toml`, plus any lockfile metadata change Cargo
emits after a targeted build/update.

## Files To Touch

Expected implementation PR write set:

- `crates/chio-attest-verify/Cargo.toml`
  - Add `toml = "0.8"` near the other non-workspace parser/format deps.
  - Do not introduce a workspace-level pin unless the implementer chooses to
    normalize existing `toml = "0.8"` users in a separate cleanup PR. P0 should
    stay narrow.
- `crates/chio-wasm-guards/Cargo.toml`
  - Usually no change needed because `arbitrary` is already direct and optional.
  - If the ticket runner insists on a test-only direct dev dependency, prefer
    documenting why the existing optional dependency is used by the `fuzz`
    feature before adding a second manifest entry.
- `Cargo.lock`
  - Refresh only through Cargo. Do not hand-edit.
- Optional trajectory metadata only if the orchestrator requires it:
  - `.planning/trajectory-2/tickets/M05/P0.yml`
  - generated trajectory manifest output from
    `cargo xtask trajectory regen-manifest`

Protected trust-boundary implementation paths to avoid in P0:

- `crates/chio-adversarial-suite/**`
- `fuzz/fuzz_targets/wasm_guard_escape.rs`
- `crates/chio-wasm-guards/tests/escape/**`
- `crates/chio-attest-verify/src/policy.rs`
- `spec/security/chio-threat-model.v1.json`
- `crates/chio-conformance/tests/threats/**`

## Expected Gates

Run the ticket gate exactly:

```bash
cargo build -p chio-attest-verify --quiet
cargo build -p chio-wasm-guards --quiet
cargo tree -p chio-attest-verify --depth 1 | grep -F 'toml '
```

Also run the repository hygiene gates that are cheap for a manifest-only PR:

```bash
cargo fmt --all -- --check
cargo xtask trajectory regen-manifest
git diff --check
```

If the manifest regen changes files, include them in the same PR and mention
they are generated trajectory metadata. If it does not change anything, say so
in the PR body.

## Freeze-Guard Considerations

M05 is a trust-boundary milestone, but P0 does not touch the active
`m05-adversarial-corpus-pivot` path globs. The P0 write set should be limited to
Cargo manifests, `Cargo.lock`, and generated trajectory metadata.

Even without a frozen-path hit, the M05 process still expects the M05 freeze
label / PR-title convention because the P0 ticket says every M05 PR carries the
M05 freeze label. Use an `[M05]` PR title prefix if the trajectory branch rules
are already active.

Do not touch `freezes.yml`, `decisions.yml`, `OWNERS.toml`, or CODEOWNERS from
this P0 implementation PR. Those are wave orchestration surfaces, not the P0
dependency bump.

## Corpus And Test Contract For Later Phases

D13 fixes the adversarial vector contract:

- JSON files live at
  `crates/chio-adversarial-suite/cases/<class>/<sha>.json`.
- Each vector carries at least `{ class, expected_verdict, expected_reason }`.
- The milestone narrative extends the envelope with `threat_id` for coverage
  linkage.

D14 fixes the auto-promotion contract:

- `scripts/promote_fuzz_seed.sh --mode adversarial` writes
  `pending: true`.
- Pending vectors do not count as threat-model coverage until human triage
  strips the flag.
- Orphan `pending: true` vectors block trajectory close.

P0 should not create corpus files. It only makes the future TOML policy loader
and WASM escape/fuzz harness dependency graph predictable.

## WASM Guard Surface Notes

Current `chio-wasm-guards` public surface already has the pieces M05.P3 will
consume:

- Runtime and host modules under `crates/chio-wasm-guards/src/{runtime,host,component,wiring,error}.rs`.
- Existing test suite under `crates/chio-wasm-guards/tests/`.
- `fuzz` feature enabling `dep:arbitrary` and `wasmtime-runtime`.

The P3 escape harness should import through public crate APIs and should fail to
compile if host-call signatures drift. P0 should not add escape tests or change
runtime behavior.

## First PR Shape

Suggested branch:

```text
wave/W2/m05/p0.t1-cargo-lock-bump-toml-arbitrary
```

Suggested commit subject:

```text
chore(m05): pin p0 dependency surface
```

Suggested PR title:

```text
[M05] chore(m05): pin P0 dependency surface
```

Suggested PR body bullets:

- Adds `toml = "0.8"` as a direct `chio-attest-verify` dependency for the
  upcoming per-tenant expected-identity policy loader.
- Confirms `chio-wasm-guards` already carries the direct optional `arbitrary`
  dependency behind the `fuzz` feature, so no duplicate manifest entry was
  added unless the implementation branch proves otherwise.
- Refreshes `Cargo.lock` and trajectory manifest output if Cargo or xtask emit
  changes.
- Does not touch M05 frozen implementation paths.
- Gate output:
  - `cargo build -p chio-attest-verify --quiet`
  - `cargo build -p chio-wasm-guards --quiet`
  - `cargo tree -p chio-attest-verify --depth 1 | grep -F 'toml '`
  - `cargo fmt --all -- --check`

## Stop Conditions

Stop and report rather than expanding scope if:

- The implementation branch wants changes under any protected M05 freeze path.
- Adding `toml = "0.8"` pulls in a new major `toml` stack instead of reusing the
  existing locked `0.8.x` package.
- Cargo tries to rewrite unrelated workspace dependency versions.
- `cargo xtask trajectory regen-manifest` wants to modify decisions, freezes, or
  owner files.
