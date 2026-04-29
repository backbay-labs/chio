# trajectory-2 CI workflow stubs

Nine new CI gates land across trajectory-2. Each lives here as a stub
until its wave-opener ticket activates it. The stubs are kept out of
`.github/workflows/` on purpose: enabling them before the supporting
crates, scripts, and corpora exist would fail every PR closed and stall
trajectory-2 from the first wave.

## Why stubs live here, not in `.github/workflows/`

- They reference crates and scripts that do not yet exist (e.g.
  `chio-adversarial-suite`, `scripts/check-threat-model-coverage.sh`).
- A `.github/workflows/*.yml` is registered the moment it merges to
  `main`; activating early would gate every PR on red CI.
- Authoring them now lets the wave-opener tickets land mechanically:
  they copy the stub, drop the `[trajectory-2 stub]` tag, and wire the
  gate to required.

## Activation order

| Wave | Stub | Activated by ticket | Disposition |
|------|------|---------------------|-------------|
| W1 | `mutation-coverage.yml` | `M02.P3.T1` | required on six trust-boundary crates after two consecutive nightly >= 80% kills |
| W1 | `verdict-matrix.yml` | `M02.P5.T1` | required on any SDK PR |
| W1 | `dhat-allocations.yml` | `M06.P5.T1` | required on every PR |
| W1 | `cold-start-budget.yml` | `M06.P5.T2` | required on browser-kernel touches |
| W2 | `adversarial-suite.yml` | `M05.P1.T1` | required on kernel-core / attest-verify PRs |
| W2 | `wasm-guard-escape.yml` | `M05.P3.T1` | nightly only; advisory dashboards + P0 incident on escape-class crash |
| W2 | `threat-model-coverage.yml` | `M05.P5.T1` | required on every PR; fail-closed at < 100% |
| W2 | `lean-build.yml` | `M04.P4.T1` | required on capability-algebra PRs |
| W2 | `apalache-delegation.yml` | `M04.P4.T2` | required on capability or delegation PRs |
| W2 | `m04-freeze-guard.yml` | `M04.P1.T1` | required on every PR; unions both M04 freeze rows during the M04.P3 overlap window |

W1 = Wave 1 (M01 || M02 || M06). W2 = Wave 2 (M03 || M04 || M05).

## Copy procedure

Each stub copies in with one bash line. Run from the repo root:

```bash
cp .planning/trajectory-2/ci-stubs/mutation-coverage.yml     .github/workflows/mutation-coverage.yml
cp .planning/trajectory-2/ci-stubs/verdict-matrix.yml        .github/workflows/verdict-matrix.yml
cp .planning/trajectory-2/ci-stubs/dhat-allocations.yml      .github/workflows/dhat-allocations.yml
cp .planning/trajectory-2/ci-stubs/cold-start-budget.yml     .github/workflows/cold-start-budget.yml
cp .planning/trajectory-2/ci-stubs/adversarial-suite.yml     .github/workflows/adversarial-suite.yml
cp .planning/trajectory-2/ci-stubs/wasm-guard-escape.yml     .github/workflows/wasm-guard-escape.yml
cp .planning/trajectory-2/ci-stubs/threat-model-coverage.yml .github/workflows/threat-model-coverage.yml
cp .planning/trajectory-2/ci-stubs/lean-build.yml            .github/workflows/lean-build.yml
cp .planning/trajectory-2/ci-stubs/apalache-delegation.yml   .github/workflows/apalache-delegation.yml
cp .planning/trajectory-2/ci-stubs/m04-freeze-guard.yml      .github/workflows/m04-freeze-guard.yml
```

`m04-freeze-guard.yml` is a generic per-milestone freeze-guard; copy
the same file to `m03-freeze-guard.yml` and `m10-freeze-guard.yml`,
adjusting the workflow `name:`, the env `CHIO_FREEZE_MILESTONE`, and
the `[Mnn]` / `[Mnn-bypass]` PR-title regex per the comment block at
the bottom of the stub. M05 reuses the existing trajectory-1
`m05-freeze-guard.yml` with widened path globs (see
`WAVE-OPENER-STRATEGY.md` section 2.2).

After copy, edit the destination so:

1. The `name:` header drops the `[trajectory-2 stub]` suffix. The
   GitHub branch ruleset matches by `name:`, so the unsuffixed string
   must match the required-check name registered in the ruleset.
2. Any pre-req paths that were stubbed (e.g. nonexistent
   `scripts/check-*.sh`) are confirmed present in the same PR.
3. If activating as required, register the unsuffixed `name:` in the
   branch ruleset alongside the trajectory-1 required checks listed in
   `.github/workflows/ci.yml`.

## Required vs advisory

Trajectory-2 follows trajectory-1's posture rules:

- **Required**: gate is in the branch ruleset; PR cannot merge red.
  Eight of the nine stubs land required (all but `wasm-guard-escape`).
- **Advisory**: `continue-on-error: true` on the job; lane reports to
  dashboards but never blocks. `wasm-guard-escape.yml` is advisory by
  default; an escape-class panic still files a P0 incident through
  `scripts/file-wasm-guard-incident.sh`.
- **Posture flip**: `mutation-coverage.yml` activates required only
  after two consecutive nightly green runs at >= 80% kill rate per
  M02.P3.T1's gate condition. Until then it lands as advisory and the
  cutover ticket flips the ruleset.

## House rules

No em-dashes, fail-closed, conventional commits. See `STYLE.md` and
`/CLAUDE.md` for the full set.
