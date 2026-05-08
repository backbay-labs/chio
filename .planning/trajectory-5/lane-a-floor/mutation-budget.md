# Trajectory 5 - Lane A: Mutation Budget

This document is the per-crate mutation-kill budget for sub-lane A1.

## Source of truth

- The trust-boundary crate set is defined in `releases.toml` under
  `[trust_boundary_crates]`.
- The current README banner reads `Mutation kill: 31% - six-crate
  trust-boundary mutation baseline, mixed sweep/shard n=375 viable mutants
  - 2026-04-29` (see `README.md` line 17).
- The trj4 floor is per `audits/T0.B-substrate-hardening.md` line 16:
  ">= 65% per crate, >= 80% on `chio-attest-verify`, with explicit
  `# unreachable: <justification>` annotations on residual survivors".

## Per-crate budgets

| Crate | Current kill | Target kill | Owner-class | Notes |
|---|---|---|---|---|
| `chio-policy` | unmeasured (`releases.toml` reports `pending trajectory-3.1 phase 4.2 full-sweep measurement`) | >= 65% | substrate eng | Trust-boundary mutants are dense: parser, schema enforcer, decision evaluator. |
| `chio-credentials` | unmeasured | >= 65% | substrate eng | Mutants dense around credential issuance paths and revocation flags. |
| `chio-attest-verify` | unmeasured | >= 80% | substrate eng | Highest-effort crate; `# unreachable:` annotations required on residuals (T0.B audit line 16). |
| `chio-kernel-core` | unmeasured | >= 65% | substrate eng | Already has Kani coverage on hot paths (`kani_public_harnesses.rs`); mutants are tractable. |
| `chio-guards` | unmeasured | >= 65% | substrate eng | Per-guard mutants; pass-through paths exist (see "Pass-through caveat" below). |
| `chio-anchor` | unmeasured | >= 65% | substrate eng | Witness state machine has nontrivial branching; mutants meaningful. |

The aggregate 31% banner is the only published number today. Per the
Quality Skeptic
(`.planning/trajectory-5/debate/04-quality-verification-skeptic.md` line
13): "no published per-crate numbers, just a 31% aggregate". mutation evidence item
publishes the first per-crate split.

## Mutation-runner command pattern

The repo uses cargo-mutants under `mutants.yml`. The canonical per-crate
run pattern (modeled on `audits/T0.B-substrate-hardening.md` evidence
shape):

```sh
cargo mutants \
  -p <crate> \
  --in-place \
  --output audits/evidence/mutants/<crate>/$(date -u +%Y%m%d).json \
  --json
```

The `--in-place` flag ensures `cargo-mutants` mutates the production
sources in `crates/<crate>/src/` rather than test or fuzz harness
files; this aligns with the trust-boundary-line-targeting requirement
in R2 MAJOR 7.4.

For `chio-attest-verify` the >= 80% target may require sharding because
of mutant volume; `mutants.yml` already supports the
`--shard <i>/<n>` parameter pattern (existing infrastructure per
TRJ4-010 close).

For each crate, a "good" run produces:

- `audits/evidence/mutants/<crate>/<date>.json` containing per-mutant
  results.
- A summary section under `[per_crate_kill_rate_percent]` in
  `releases.toml`.

## Exclusion-list audit (mutation exclusion audit; R2 OBSERVATION 1.2 / MAJOR 7.4)

The `.cargo/mutants.toml` `exclude_globs` list (lines 164-203) excludes
tests, benches, build scripts, fuzz harnesses, and Kani harness files,
plus a handful of non-trivial production files
(`chio-kernel-core/src/clock.rs`, `chio-policy/src/models.rs`,
`chio-guards/src/external/**`). Each carries a single-line rationale.

This is defensible for the listed exclusions, but if the "31%
aggregate" was computed against an exclusion list that hides
mutation-killable lines, the kill-rate bump from 31% to 65% may be
artificially compressed. R2 Section 1.2 / 7.4 asks for a re-audit of
the exclusion list under the release work frame.

mutation exclusion audit is the audit ticket. Output:
`audits/evidence/mutation exclusion audit/exclude-audit.md` with each exclusion line
marked one of:

- `OK -- test/build/fuzz scaffolding`.
- `OK -- covered by Kani harness <path>`.
- `OK -- covered by production-call-path conformance test <path>`.
- `FOR-REMOVAL -- production code with no compensating coverage`.

`FOR-REMOVAL` lines are removed from `.cargo/mutants.toml` and the
per-crate kill rate is re-baselined. Without this audit, the >=65%
target is held against a pre-existing exclusion list whose
justification has not been re-checked.

## Pass-through caveat

Not every line in every crate is meaningful trust-boundary surface. For
example, `chio-guards` contains adapter-glue between specific guard
implementations and the generic guard pipeline; some pass-through code
genuinely cannot be killed by any test. The existing
`# unreachable: <justification>` convention (T0.B audit line 16) is the
remediation path: each residual survivor gets an inline annotation that
the mutation runner consumes as an exclusion.

| Crate | Pass-through density | Annotation expectation |
|---|---|---|
| `chio-policy` | low | < 5% of residuals annotated |
| `chio-credentials` | low | < 5% of residuals annotated |
| `chio-attest-verify` | medium | up to 20% of residuals annotated to reach >= 80% |
| `chio-kernel-core` | low | < 5% of residuals annotated |
| `chio-guards` | high | up to 30% of residuals annotated |
| `chio-anchor` | medium | up to 15% of residuals annotated |

These are estimates from spot-reading the source; the actual annotation
density is empirical and is captured by mutation evidence item close bars.

## Banner regeneration

`.github/workflows/mutants-banner.yml` regenerates the README banner.
mutation evidence item changes the banner script to read the **lowest observed**
per-crate kill rate, not a target. Target banner shape after Lane A
closes:

```html
<!-- chio-mutants-banner:start -->
<strong>Mutation kill: 65% (lowest of six trust-boundary crates;
chio-attest-verify 82%)</strong> - measured <YYYY-MM-DD>
<!-- chio-mutants-banner:end -->
```

The exact line is generated; the format above is the target shape.

## Two-night history requirement

Per T0.B audit acceptance line 16 ("Two consecutive green hosted
nightlies, both `status_at_capture: success`"), the close bar requires
two consecutive nightly runs without flake. mutation evidence item captures both run
URLs to `audits/evidence/mutants/two-night-history.md`.

## Anti-patterns rejected by this budget

- **Aggregate-only banner.** "31% aggregate" hides the per-crate weakest
  link. The new banner cites the lowest per-crate value.
- **Unmeasured target.** "We aim for 65%" without a captured run is not
  acceptable. Every value in `releases.toml` is backed by a JSON
  evidence file.
- **`unreachable!()` instead of `# unreachable:`** annotations. The
  former is a runtime panic; the latter is a mutation-runner exclusion.
  The two are not interchangeable.
