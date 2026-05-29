# GitHub Actions Billing Runbook

**Owner:** Chio maintainers
**Last updated:** 2026-05-02

## Purpose

This runbook prevents a repeat of the 2026-04-26T23:00Z GitHub
Actions billing or spending-limit trip that forced an earlier
admin-merge bypass window.

## Cap value

Cap value: set the GitHub Actions paid spending limit to at least
$2,500 per month for the account that owns `backbay-labs/chio`.

Rationale:

- Expected full CI sweep: $3-$5 per PR.
- Busy development cadence: roughly 10 PRs per day.
- Expected daily burn: $30-$50.
- 50% headroom floor: $75 per day.
- Monthly cap floor at 31 days: $2,325.
- Rounded operational cap: $2,500 per month.

Set an 80% alert at $2,000 monthly spend. Treat the alert as a same-day
capacity review, not as a stop-work signal.

## Restoration steps

If hosted Actions stops at runner-start with a billing or spending
limit annotation:

1. Open the billing settings for the owner account:
   `https://github.com/settings/billing`.
2. Confirm whether the failure is a payment-method problem or a
   spending limit.
3. Fix the payment method or raise the spending cap.
4. Re-run one lightweight workflow on `main`:

```bash
gh workflow run audit-log-schema-lint.yml --ref main
```

5. Re-run the main CI workflow when the lightweight workflow starts:

```bash
gh workflow run ci.yml --ref main
```

6. Record the run URLs in the incident log under `compliance/hitrust/`
   (see `compliance/hitrust/control-mapping.csv` for the relevant control entries).

## Verification

Minimum restoration signal:

- A workflow run is created by GitHub Actions.
- The run reaches queued, pending, or in-progress after creation.
- At least one required-check context reports a job URL instead of a
  billing annotation.

Full release signal:

- Required checks are green on the final stabilization branch.
- Every PR in the recorded CI-debt backlog has been replayed or covered
  by a later green main run.

## Escalation

Do not silently admin-merge because of a billing or spending-limit
failure. If the spending limit trips again:

- Raise the cap or reduce workflow fan-out.
- Document the action in this runbook.
- Record the incident in the audit doc.
- Treat a repeated trip during final stabilization as a release-gate
  blocker until a clean hosted CI run exists.

## Cost controls

- Keep PR-tier CI Linux-only unless a ticket explicitly touches
  platform-specific macOS behavior.
- Keep macOS coverage in release workflows, not every PR.
- Quarantine known flaky tests by ticket and audit-doc entry rather
  than repeatedly rerunning whole matrices.
- Prefer `gh workflow run <workflow> --ref <branch>` for targeted
  probes.
