# M03 Audit: Hosted CI Truth + Reproducible Builds

**Trajectory:** trajectory-3
**Milestone:** M03
**Wave:** W1
**Status:** TEMPLATE
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M03 ends the admin-merge bypass and ships hosted CI + reproducible-build
artifacts. Release gate: RELEASE_AUDIT.

The milestone has two bound halves:

1. Restore hosted CI (billing, workflows, spending cap) so every PR
   from #426 onward executes the full required-check matrix on
   GitHub-hosted runners.
2. Stand up a `reproducible-build.yml` workflow that produces a
   bit-identical Linux x86_64 release binary across two independent
   runners and a third hash-compare gate, with one named external
   third-party rebuilder co-signing the published checksum.

Both halves close together; partial closure leaves the trajectory in
the same admin-merge posture it inherited.

## 2. Hard counts at P0 (baseline pulled from research/m03/RESEARCH.md)

Snapshot taken 2026-05-02 from `gh` CLI against `bb-connor/arc`. The
M03 P0 ticket re-pins these with reproduce-with-this-command numbers
at audit-doc open.

- **Days since admin-merge bypass began:** 4 (failure first observed
  2026-04-26T23:00Z; bypass opened immediately after).
- **CI workflow files YAML-disabled:** 0 (workflows are present and
  syntactically intact; they are *account-blocked* by the billing
  failure annotation, not disabled in source).
- **CI workflow files account-blocked:** 41 (all hosted-Actions
  workflows aborted at boot; jobs never reached `Checkout`).
- **PRs admin-merged in the bypass window:** 118 PRs across #306-#425.
  All 118 carry an admin-merge override on at least one
  required-check.
- **Total workflow runs since trip:** 6,865 (per GitHub API count).
  Last 500 runs: 489 FAILURE, 10 cancelled, 1 SUCCESS (a single
  `m05-freeze-guard` job that predated the cap).
- **Last green ubuntu-latest run on `main`:** between
  2026-04-26T19:48Z and 2026-04-26T23:00Z; precise transition at the
  run page-60 boundary of `actions/runs?per_page=100`.
- **Failing-test count at last green hosted-CI run:** [TODO M03 P0:
  re-derive after billing restored; the count cannot be inferred from
  account-blocked jobs because no test stage ran].
- **Cost-per-PR baseline (research-time estimate):** Build/lint/test
  ~$0.24, Coverage up to $1.44, MSRV ~$0.12, cargo-vet+cargo-deny
  ~$0.16, formal-tla+kani-public-pr up to $0.72; total per-PR worst
  case ~$2.68 plus mutation lane on nightly only.

## 3. Reproducible-build evidence

[TODO M03 milestone agent fill at P4 close:]

- Independent third-party rebuilder identity (per D13):
- Rebuilder's matched hash:
- Date received:
- Audit-trail linkage:
- Builder A run URL:
- Builder B run URL:
- `reproducibility-gate` run URL:
- `supply-chain/checksums/v3.18.txt` cosign signature + Rekor UUID:

## 3a. Hosted CI liveness evidence (P1)

P1 records that hosted GitHub Actions is alive and starting real
workflow runs after trajectory-3 PRs. The 2026-05-02 steering update
defers full green completion to final stabilization; this section is
therefore a liveness matrix, not a green-release attestation.

Required-check contexts and current run URLs:

| Required check context | Workflow/run evidence | Status at record time |
|------------------------|-----------------------|-----------------------|
| Build, lint, test | https://github.com/bb-connor/arc/actions/runs/25242850087 | queued on `main` push `2d63ff7e36ef86d929e7bc9a14119adee68017d0` |
| MSRV build and test | https://github.com/bb-connor/arc/actions/runs/25242850087 | queued inside `ci.yml` on `main` push |
| cargo-vet (supply-chain audit) | https://github.com/bb-connor/arc/actions/runs/25242850087 | queued inside `ci.yml` on `main` push |
| cargo-deny (supply-chain bans/advisories/licenses) | https://github.com/bb-connor/arc/actions/runs/25242850087 | queued inside `ci.yml` on `main` push |
| freeze-guard | https://github.com/bb-connor/arc/actions/runs/25242846785 | completed success on PR #444 head `507b11cd0fb2e2260b0639025da25c0714d34060` |
| bench-regression | https://github.com/bb-connor/arc/actions/runs/25242843165 | queued on PR #444 head `507b11cd0fb2e2260b0639025da25c0714d34060` |

Observed policy state:

- Hosted CI is no longer billing-exhausted at runner-start: real runs
  are created for PR and `main` push events.
- Old pre-trajectory-3 failures remain M03.P2 bisect targets.
- Admin-merged PRs under the 2026-05-02 steering policy are tracked in
  `.planning/trajectory-3/work/CI-DEBT.md`.
- Full green required-check closure is deferred to the end-of-trajectory
  stabilization pass.

## 4. Closure attestations

[TODO M03 milestone agent fill at P5 close:]

- Hosted CI green for v3.18 release commit (run URL):
- Reproducible-build hash published at:
  supply-chain/checksums/v3.18.txt
- SLSA-style provenance file:
  .github/workflows/release-provenance.yml output
- Spending cap pinned (cap value, alert threshold, runbook path):
- 118-PR bisect status (regressions surfaced, owning milestones):

## 5. Cross-references

M03 is on the critical path of every other trajectory-3 milestone
because the hosted-CI lane it restores is the substrate every gate
runs on. Cross-milestone consumers:

- **M02 (AI-lab evaluation beachhead):** the verdict-matrix non-Rust
  driver workflow runs on the restored CI lane; M02 P5 conformance
  memo cites a green run URL on the restored substrate.
- **M04 (mutation + verdict-matrix promotion):** the nightly mutation
  lane and the gate-flip evidence depend on hosted CI executing
  through completion. M04 P3 mutation-gate flip is contingent on
  M03 P1 close.
- **M05 (threat-coverage closure):** post-flip workflow runs of
  `.github/workflows/threat-model-coverage.yml` are referenced from
  the M05 P5 audit hook; M03 ensures those runs are available.
- **M06 (formal + supply-chain):** the supply-chain audit doc
  cross-references the reproducible-build hash at
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`.
- **M08 (independent crypto/protocol review):** the reviewer cites
  the reproducible-build hash and the third-party rebuilder match in
  `.planning/trajectory-3/audits/M08-vendor-evidence.md`.
- **M09 (HITRUST i1 assessment):** the assessor consumes the
  hosted-CI green status, the spending-cap runbook, and the
  reproducible-build evidence as control-mapping inputs.
- **M10 (AWS Bedrock + MCP conformance):** the AWS security review at
  M10 P3 expects a clean CI lane; admin-merge bypass would surface
  as a reviewer round-trip.

## 6. Halt-trigger inventory

Trajectory-3 canonical halts that apply to this milestone:

- **Halt 1 (hosted-CI billing not restored by week 2):** trips if
  M03 P1 does not close within two weeks of milestone open. The
  bypass cannot persist past Wave 1 close; every downstream
  trajectory-3 milestone freezes if M03 P1 misses.
- **Halt 5 (reproducibility match fails):** trips if the third-party
  rebuilder hash does not match the published checksum at v3.18.
  Halt unwinds to P3 (`SOURCE_DATE_EPOCH` plumbing) before retrying.
- **Halt 8 (admin-merge regressed):** trips if any post-restoration
  PR re-admin-merges. M03 ensures the spending cap does not surprise
  the team into another bypass.
- **Halt 11 (CVE/regression in the 118-PR bisect):** trips if a
  surfaced regression is critical and lacks an owning milestone.
  Routed to milestone owner; M03 does not fix every regression
  surfaced.

## 7. Reproducibility scope carve-outs

Per D13 and the milestone-narrative scope statement, the following
are explicitly out of scope for M03 v3.18:

- macOS and Windows reproducible builds (codesign and PE COFF
  timestamp non-determinism); deferred to trajectory-4.
- Self-hosted runners and third-party hosted runners (BuildJet,
  Namespace.so, Depot, RunsOn); deferred to trajectory-4 follow-up
  if cost becomes the bottleneck.
- Org migration of the hosted-CI billing account; personal-account
  ownership stays for v3.18.
- Build-from-source verification by every consumer; M03 ships the
  pipeline plus exactly one third-party rebuild.

## 8. Cross-references (legacy table)

- M06 supply-chain audit doc:
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
- The M08 reviewer cites the reproducible-build hash:
  `.planning/trajectory-3/audits/M08-vendor-evidence.md`
- The M09 assessor cites hosted-CI restoration evidence:
  `.planning/trajectory-3/audits/M09-vendor-evidence.md`
- The trajectory-3 freeze register: `.planning/trajectory-3/freezes.yml`
- The decisions register (D13 names the rebuilder):
  `.planning/trajectory-3/decisions.yml`
