# Fuzz Crash Triage Runbook

When a fuzz crash lands in CI (ClusterFuzzLite, the in-tree `fuzz.yml`
matrix, or OSS-Fuzz post-acceptance), the crash-to-issue automation in
`.github/workflows/fuzz_crash_triage.yml` (M02.P4.T1) downloads the
crash artifact, minimizes it with `cargo fuzz tmin`, dedupes against
open `fuzz-crash`-labelled issues by SHA-256 prefix token, and either
comments on the existing issue or files a new one against the
`.github/ISSUE_TEMPLATE/fuzz_crash.yml` issue form. The minimized input
ships in the issue body as a base64 blob plus a reproduce-locally
snippet. This runbook tells the human triager how to assess severity,
dedupe against open issues, promote a useful crash to a permanent
regression test, and meet the time-to-fix SLOs Chio commits to OSS-Fuzz
upstream.

The runbook is normative for fuzz triagers. Every decision documented
here is the one Chio expects to defend in a release-audit review.

## Severity bands

The issue template surfaces a severity dropdown (`Critical`, `High`,
`Medium`, `Low`). The triager picks one within the 24h
acknowledgement window (see "Time-to-fix SLOs" below). The bands are
defined by trust-boundary impact, not by call-stack aesthetics: the
question is "what does an attacker who can reach this fuzz target
actually get". A crash is critical when the answer is "anything that
crosses the trust boundary"; the other bands narrow down from there.

### Critical

The crash demonstrates one of:

- Remote-exploitable memory corruption or sandbox escape from a
  network-reachable surface.
- Authentication or capability bypass (e.g., a malformed JWT VC,
  capability token, or DPoP proof verifies as valid when it should
  reject; a scope subset check returns `true` for a non-subset).
- Key compromise or signing-oracle behavior (a verifier accepts a
  forged signature; a signer emits material under attacker
  influence).
- Deterministic-replay break (a verifier accepts a receipt whose
  canonical bytes do not round-trip, opening a forge surface against
  the receipt log).
- Supply-chain attestation forge (an `attest_verify` input that
  passes verification with the wrong subject or wrong predicate).

Critical crashes route to the on-call human (currently
`@bb-connor`) and block the next release cut until fixed or
explicitly deferred with a CVE-style writeup.

### High

The crash demonstrates one of:

- Denial of service via OOM, panic, or unbounded loop on a
  network-reachable parser (the affected target then refuses to
  serve any further traffic until restarted).
- Data-integrity violation that does not cross the trust boundary
  (e.g., a parser silently truncates a field that downstream code
  reads back; the receipt log persists a record whose canonical
  bytes do not match the signed envelope).
- Tenant scope leak (a multi-tenant code path returns rows or
  capabilities owned by a different tenant; a verdict bound to one
  scope is accepted for another).

High crashes route to the owning sub-system maintainer per
`CODEOWNERS` (M02.P4.T4) and must hit the 30d fix-or-defer SLO
(matches the OSS-Fuzz upstream commitment in
`.planning/trajectory/02-fuzzing-post-pr13.md` item 10).

### Medium

The crash demonstrates one of:

- Single-target panic that does not escape the trust boundary
  (e.g., a `chio-yaml-parse` panic on malformed input where the
  caller already wraps the parse in `catch_unwind` and emits a
  "deny, malformed config" verdict).
- Recoverable parse error that should be silently consumed but
  currently propagates as a thread panic visible in operator logs
  (noisy, not exploitable).
- Test-only or example-only code path (the crash reproduces only
  under a `#[cfg(test)]` or `examples/` build configuration).

Medium crashes are queued for the owning sub-system maintainer and
hit the 30d fix-or-defer SLO.

### Low

The crash demonstrates one of:

- Performance regression detected by the libFuzzer slow-input
  warning (no functional break; the input is just slower to process
  than a tunable threshold).
- Cosmetic issues (an error message format that confuses the
  operator without affecting the verdict).
- Fuzz harness instability that does not reflect a defect in the
  target under test (e.g., a corpus seed that races with the
  ClusterFuzzLite test-runner setup).

Low crashes are deferred to the next quarterly fuzz-cleanup pass.
The issue stays open with a `triage:low` label so the cleanup pass
has a worklist.

## Dedupe rules

The crash-to-issue Action does the first dedupe pass automatically:
it computes the sha256 of the minimized libFuzzer input and matches
the leading hex substring against the titles of open `fuzz-crash`
issues. When it finds a match it appends a comment with the new
workflow run-link and does not open a duplicate.

The triager does the second dedupe pass manually before doing
anything else with a fresh issue. The manual heuristic:

- Same crash type (`PanicMessage`, `OOM`, `abort`, `LeakSanitizer`,
  `AddressSanitizer`) AND
- Same fuzz target (`receipt_decode`, `jwt_vc_verify`, etc.) AND
- Same call-site source location (the topmost in-tree frame in the
  ASan or panic backtrace, normalized to file:line ignoring inlining
  hints).

When all three match an existing issue, the triager:

1. Comments on the existing issue with the new run-link, the
   workflow-artifact URL, and the new minimized input attached.
2. Closes the duplicate as `not-planned` with a `duplicate of #NNN`
   reference.
3. Does not open a new issue.

When only two of the three match, the triager opens the new issue
and links the related one in the body ("possibly related to #NNN,
same crash type and target but different call site"). Reviewers can
then merge them later if root-cause analysis shows they share a
fix.

The dedupe pass keeps the `fuzz-crash` queue scoped to one issue
per distinct defect; without it, a single regression in a
high-traffic parser fans out to dozens of duplicate issues over a
single nightly soak.

## Time-to-fix SLOs

Chio commits to the following triage SLOs and documents them for
OSS-Fuzz upstream as part of the application package
(see `.planning/trajectory/02-fuzzing-post-pr13.md` "OSS-Fuzz
application steps" item 10):

| Severity | Acknowledgement | Fix-or-defer        |
|----------|-----------------|---------------------|
| Critical | 24h             | 7d                  |
| High     | 24h             | 30d                 |
| Medium   | 24h             | 30d                 |
| Low      | 24h             | next quarterly pass |

"Acknowledgement" means a human triager has applied a severity
label, completed the dedupe pass, and either started a fix or
opened a deferral comment on the issue. The 24h clock starts when
the crash-to-issue Action opens the issue (not when the underlying
fuzz run started).

"Fix-or-defer" means one of:

- A PR that lands the fix and a paired regression test (see
  "Promotion to regression test" below) is merged into
  `project/roadmap-04-25-2026` (or `main` post-roadmap-cut).
- A deferral comment on the issue documents why the fix is being
  pushed past the SLO window, names the responsible maintainer,
  and sets a new target date. Deferrals are visible to OSS-Fuzz
  upstream and counted against the program's overall SLO health.

Critical and High issues that miss their fix-or-defer SLO escalate
to the on-call (currently `@bb-connor`) and surface in the next
weekly fuzz-program review. Medium and Low misses surface in the
quarterly cleanup pass.

The 24h acknowledgement applies to all severities so the dedupe
queue stays clean even for Low issues; without an acknowledgement
SLO the Low backlog tends to grow until it masks new Critical
crashes that share a call-site with an existing Low ticket.

## Promotion to regression test

When a Critical, High, or Medium crash has a useful minimized input,
the triager promotes it to a permanent regression test using
`scripts/promote_fuzz_seed.sh` (M02.P4.T2). The promoted test
becomes a permanent fixture under
`crates/<owning-crate>/tests/regression_<sha>.rs` (libfuzzer mode)
or `crates/<owning-crate>/tests/property_<sha>.rs` (proptest mode,
sibling to the M03 invariant program).

Quick example invocation:

```bash
# Promote a libFuzzer crash to a regression test in chio-credentials.
scripts/promote_fuzz_seed.sh \
  --mode libfuzzer \
  --target jwt_vc_verify \
  --crate chio-credentials \
  --input /tmp/fuzz-crash/crash-3f8a1c.bin \
  --issue 142
```

The script copies the minimized input into the crate's test-fixture
directory, generates a `regression_<sha>.rs` test that asserts the
fixture decodes (or rejects) as expected, and stages the new files
for commit. The triager reviews the generated test, adjusts the
assertion if the script's default does not capture the right
invariant, and opens the fix PR with the regression test paired
in the same commit.

Pair the fix and the regression test in one PR. A fix without a
regression test means the next nightly soak can reintroduce the
exact same defect with no signal.

## Regression-test deletion

Regression tests under `tests/regression_*.rs` and
`crates/*/tests/regression_*.rs` are append-only by policy. Deleting
one removes a known-defect oracle and re-opens the surface that
defect protected.

Two guards enforce the policy:

- `scripts/check-regression-tests.sh` (M02.P4.T3) runs from the
  `check-regression-tests` job in `.github/workflows/ci.yml` and fails
  the build when a committed `regression_<sha>.rs` file is removed
  without a paired issue link that names the deleted file.
- `CODEOWNERS` (M02.P4.T4) requires `@bb-connor` review on any
  diff that touches `tests/regression_*.rs` or
  `crates/*/tests/regression_*.rs`.

When a regression test genuinely needs to come out (the underlying
defect was fixed by a refactor that made the original assertion
non-meaningful, or the target was deleted), the deleting PR must:

1. Link the original `fuzz-crash` issue in the PR body.
2. Explain why the test is no longer protective (one paragraph in
   the PR body).
3. Get explicit `@bb-connor` approval on the deletion line.

The CI guard refuses the merge until those conditions are met.

## Cross-references

- Crash-to-issue Action:
  [`.github/workflows/fuzz_crash_triage.yml`](../../.github/workflows/fuzz_crash_triage.yml)
  (M02.P4.T1)
- Crash-issue template:
  [`.github/ISSUE_TEMPLATE/fuzz_crash.yml`](../../.github/ISSUE_TEMPLATE/fuzz_crash.yml)
  (M02.P4.T1)
- Seed-promotion script:
  [`scripts/promote_fuzz_seed.sh`](../../scripts/promote_fuzz_seed.sh)
  (M02.P4.T2)
- Regression-deletion guard:
  [`scripts/check-regression-tests.sh`](../../scripts/check-regression-tests.sh)
  (M02.P4.T3)
- Code ownership for regression tests:
  [`CODEOWNERS`](../../CODEOWNERS) (M02.P4.T4)
- Continuous-fuzzing program runbook:
  [`docs/fuzzing/continuous.md`](continuous.md) (M02.P1.T7 and
  later extensions)
- Mutation-testing runbook:
  [`docs/fuzzing/mutants.md`](mutants.md) (M02.P2.T1)
- Source-of-truth milestone doc:
  [`.planning/trajectory/02-fuzzing-post-pr13.md`](../../.planning/trajectory/02-fuzzing-post-pr13.md)
  (Phase 4 P4.T5; OSS-Fuzz application steps item 10 for the
  Triage SLO commitment)
