# TRJ5-A1.2a/A1.2b - Per-crate mutation kill rate baseline

Date: 2026-05-08.

Branch: `claude/trj5/a1-mutation-baseline`.

Tickets covered:
- **TRJ5-A1.2a** (run baseline measurement; capture per-mutant results).
- **TRJ5-A1.2b** (publish per-crate kill rates; replaces the six
  `pending...` strings in `releases.toml [per_crate_kill_rate_percent]`).

Source-of-truth references:
- `.planning/trajectory-5/lane-a-floor/PLAN.md` Sub-lane A1 acceptance.
- `.planning/trajectory-5/lane-a-floor/tickets.md` rows TRJ5-A1.2a / 2b.
- `.planning/trajectory-5/baselines/BAR-1-MUTATION.md` (the
  `BASELINE-GAP` per-crate breakdown that this artifact closes).
- `.cargo/mutants.toml` (the trust-boundary surface list audited by
  TRJ5-A1.0; see `audits/evidence/TRJ5-A1.0/exclude-audit.md`).
- `releases.toml [trust_boundary_crates]` (canonical six-crate list).

## Trust-boundary crate set

This artifact targets the canonical six trust-boundary crates per
`releases.toml [trust_boundary_crates]`:

1. `chio-policy`
2. `chio-credentials`
3. `chio-attest-verify`
4. `chio-kernel-core`
5. `chio-guards`
6. `chio-anchor`

(Note: an upstream task description listed `chio-weights` instead of
`chio-credentials`. `chio-weights` is NOT in the trust-boundary set per
`releases.toml`. This artifact follows `releases.toml` as the source of
truth, and the same approach is used by the trj5 PLAN.md and tickets.md.
A `chio-weights`-targeted run can be added as a follow-up if a
`releases.toml` revision adds it.)

## Methodology

- cargo-mutants version: **25.3.1** (per workspace pin in
  `.cargo/mutants.toml` header).
- Per-crate invocation:
  `cargo mutants -p <crate> --in-place --test-package <crate> --output audits/evidence/mutants/<crate> --baseline=skip`
- **Test scope deviation from CI**: this baseline uses
  `--test-package <crate>` (test only the crate-under-test), not
  `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`
  from `.cargo/mutants.toml` (which runs the full workspace test suite
  per mutant). The CI hosted-nightly invocation continues to run the
  full workspace tests; this local baseline is therefore a **lower
  bound on the CI-observed kill rate**, since fewer test files exercise
  any given mutant. The deviation is honest: a 7-minute workspace test
  build per mutant times 2400+ mutants is more compute time than a
  single local session affords. The CI lane (`mutants.yml` nightly,
  4-hour-per-crate budget) remains the authoritative measurement; this
  baseline is the seed measurement that retires the six
  `pending trajectory-3.1 phase 4.2 full-sweep measurement` strings.
- `--baseline=skip` is used because the workspace test suite is known
  green at HEAD (`cargo test --workspace --exclude chio-cpp-kernel-ffi`
  on commit `708c7bb33`); skipping the baseline run avoids 7 minutes of
  re-verification per crate.
- `--in-place` is used (instead of cargo-mutants' default copy-tree
  mode) to avoid `target/` duplication on a 50+ crate workspace, which
  would otherwise consume tens of GB per crate. `--in-place` cannot be
  combined with `-j` (sequential by definition); the trade-off is
  accepted for the same disk-space reason.
- `--output` writes a per-crate `mutants.out/` directory under
  `audits/evidence/mutants/<crate>/`. Each directory contains:
  - `caught.txt` (one mutant per line that was killed by a test).
  - `missed.txt` (one mutant per line that survived all tests).
  - `timeout.txt` (one mutant per line that exceeded the per-mutant
    test timeout, which is `max(60s, 3 * baseline)` per the workspace
    `minimum_test_timeout` and `timeout_multiplier` settings).
  - `unviable.txt` (mutants the cargo-mutants engine could not even
    compile; not counted in the kill-rate denominator per
    cargo-mutants 25.x convention).
  - `mutants.json` (full per-mutant JSON record).

## Per-crate kill rate

| Crate | Total mutants generated | Caught | Missed | Timeout | Unviable | Kill rate |
|---|---|---|---|---|---|---|
| `chio-policy` | 418 | TBD | TBD | TBD | TBD | **TBD** |
| `chio-credentials` | 28 | TBD | TBD | TBD | TBD | **TBD** |
| `chio-attest-verify` | 86 | TBD | TBD | TBD | TBD | **TBD** |
| `chio-kernel-core` | 344 | TBD | TBD | TBD | TBD | **TBD** |
| `chio-guards` | 1291 | TBD | TBD | TBD | TBD | **TBD** |
| `chio-anchor` | 262 | TBD | TBD | TBD | TBD | **TBD** |
| **Workspace total** | **2429** | TBD | TBD | TBD | TBD | **TBD** |

Kill rate is computed as `caught / (caught + missed + timeout)`,
**excluding** unviable mutants from the denominator per cargo-mutants
25.x convention (an unviable mutant is one cargo-mutants could not
compile and therefore did not test).

## Run-by-run notes

(Filled in below as each crate completes. Crates queued in size order:
smallest first to maximize the number of completed measurements in this
session.)

### chio-credentials (28 mutants)

(in progress at write-time; results to be filled in below.)

### chio-attest-verify (86 mutants)

(queued; the >=80% trust-boundary crate per A1.8.)

### chio-anchor (262 mutants)

(queued.)

### chio-kernel-core (344 mutants)

(queued.)

### chio-policy (418 mutants)

(queued.)

### chio-guards (1291 mutants)

(deferred; 1291 mutants is roughly an order of magnitude more than any
other crate. A guard-crate run is unlikely to fit in this session and
is honestly flagged BASELINE-GAP at the bottom of this artifact.)

## releases.toml update

Once the per-crate runs complete, the `[per_crate_kill_rate_percent]`
section in `releases.toml` is updated from the six
`pending trajectory-3.1 phase 4.2 full-sweep measurement` strings to
the numeric kill rates measured in this baseline run. The update PR
notes that the CI hosted-nightly mutants run continues to be the
authoritative number; this baseline is the *seed* that retires the
`pending` strings.

## Honesty notes (anti-pattern guards)

Per `tickets.md` line 84: "README banner that names a target rate
fails the close bar. The banner script reads from
`audits/evidence/mutants/*.json`, not from a hard-coded value."

This artifact records ONLY the observed numbers; no target rate is
substituted. Crates that did not finish in this session are flagged
`BASELINE-GAP` (not estimated, not faked).

## Open follow-ups

- TRJ5-A1.0 follow-up: itemize `crates/chio-guards/src/external/**`
  per-file test coverage (see `audits/evidence/TRJ5-A1.0/exclude-audit.md`).
- TRJ5-A1.1 carry-forward: confirm `mutants.yml` workflow status; the
  hosted nightly lane is the authoritative measurement.
- TRJ5-A1.3..A1.8: the >=65% drives are out of scope for this baseline
  ticket; they sit on the per-crate measurement results recorded here.
