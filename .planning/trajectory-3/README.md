# trajectory-3

Post-trajectory-2 planning artifacts. trajectory-2 closed M01-M10 across 113
PRs; trajectory-3 is the customer-anchored legibility cycle. The frame is
50/30/20 customer-anchored / deepen-the-substrate / external-attestation:
half the calendar is real-customer pilot work + AI-lab evaluation
beachhead, three tenths is paying down the load-bearing debt
trajectory-2 papered over (mutation thresholds, threat-coverage, formal
invariants), and the remaining fifth is the long-clock vendor calendars
(crypto/protocol review, HITRUST i1) that turn the customer-anchored
work into externally legible evidence.

## Genesis

trajectory-3 was produced by a two-round verdict debate (2026-04-29 ->
2026-04-30). Round 1 enumerated five candidate frames (halt-to-stabilize,
customer-led, deepen-the-substrate, audit-led, expand-distribution).
Round 2 stress-tested each against the post-trajectory-2 state of the
repo (admin-merge bypass on hosted CI, mutation lane shipped advisory
not gating, three carry-forward threat-coverage gaps, no design-partner
named on `main`, vendor calendar lead times of 12-44 weeks).

The synthesizer rejected all five pure frames. A pure customer-led
trajectory would defer the load-bearing CI / mutation / threat work and
ship a pilot on an unsupported substrate. A pure halt-to-stabilize would
leave Chio without a single external user reference. A pure audit-led
trajectory would burn 10-12 months on vendor calendars while the
codebase stayed unanchored. The verdict that closed the debate is the
50/30/20 blend: customer (M01 Opus pilot, M02 AI-lab beachhead, M07
mobile MVP, M10 Bedrock listing) is the load-bearing axis; deepen
(M03 hosted CI, M04 mutation gate, M05 threat closure, M06 formal +
supply-chain) is the debt cycle that makes the pilot referenceable; and
external attestation (M08 NCC Group or Trail of Bits, M09 HITRUST i1) runs as
two parallel long-clock vendor calendars starting week 1, surfacing
their evidence at trajectory close.

trajectory-3 scope: roughly 44-48 calendar weeks at 5 FTE engineering +
1 program lead + 0.5 security reviewer, vendor budget posture
~$350-450k. Halt triggers (section "Cross-doc invariants" + per-AUTONOMOUS-PROMPT)
include the eleven canonical orchestrator triggers plus four
trajectory-3-specific ones: design-partner withdrawal, vendor calendar
slip beyond 25%, HITRUST assessor rejection, M08 reviewer critical CVE.

## The Ten Milestones

| # | Title | One-liner | Lens | TB |
|---|-------|-----------|------|----|
| 01 | [Opus Cluster Design-Partner Production Pilot](01-opus-design-partner-pilot.md) | Ship v3.18 to a real production tenant (Opus cluster, Backbay healthcare) and observe under real workload for 30 days. | adoption / operational | yes |
| 02 | [AI-Lab Evaluation Infrastructure Beachhead](02-ai-lab-evaluation-beachhead.md) | Make Chio the verdict-evidence substrate for an AI lab (Anthropic / METR / Apollo) tool-use evaluation pipeline. | adoption / protocol | yes |
| 03 | [Hosted CI Truth + Reproducible Builds](03-hosted-ci-truth-and-reproducible-builds.md) | End the admin-merge bypass; restore hosted CI; publish reproducible-build hashes. | quality / release | yes |
| 04 | [Mutation Gate + Verdict Matrix Promotion](04-mutation-and-verdict-matrix-promotion.md) | Promote the mutation lane and verdict matrix from advisory to gating at honest thresholds. | quality | yes |
| 05 | [Threat-Coverage Closure](05-threat-coverage-closure.md) | Close `weights_hash_spoof`, `dispatch_allow`, M06 placeholder; zero `partial` rows. | security | yes |
| 06 | [Focused Formal Invariants + Supply-Chain Hygiene v2](06-focused-formal-and-supply-chain.md) | 3-4 highest-leverage TLA+/Apalache invariants; cargo-vet; SBOM publication; CVE alerting. | formal / supply-chain | yes |
| 07 | [chio-kernel-mobile MVP + Device Attestation](07-chio-kernel-mobile-mvp.md) | Real iOS + Android kernel binding with Apple App Attest + Android Play Integrity. | platform-expansion | yes |
| 08 | [Independent Crypto + Protocol Review](08-independent-crypto-protocol-review.md) | NCC Group or Trail of Bits review of cemented v3.0 surface (long-clock vendor lane). | external-attestation | yes |
| 09 | [HITRUST i1 Assessment](09-hitrust-i1-assessment.md) | HITRUST i1 readiness + assessment scoped to the Opus design-partner deployment. | external-attestation | yes |
| 10 | [AWS Bedrock + MCP Conformance Listing](10-aws-bedrock-mcp-conformance.md) | One cloud marketplace listing with MCP-conformant Chio integration. | distribution | yes |

All ten milestones are trust-boundary; trajectory-3 has no non-trust-boundary
work because every milestone touches the load-bearing customer / external
surface.

## Wave plan

```
W1 = M01 + M02 + M03 + M04 + M05    (debt + pilot + CI; weeks 1-15)
W2 = M06 + M07                       (formal + mobile; weeks 12-26)
W3 = M10                             (distribution; weeks 22-30)

vendor calendars (parallel, start week 1):
  M08 NCC Group or Trail of Bits review (RFP weeks 1-5; vendor weeks 6-14;
                             active weeks 15-30; remediation 30-44)
  M09 HITRUST i1            (gap weeks 8-14; remediation 14-24;
                             assessor weeks 24-36)
```

Wave plan detail lives in `EXECUTION-BOARD.md`. M08 + M09 do not gate
W1/W2/W3 transitions; their evidence lands at trajectory close.

## Cross-doc invariants

| Artifact | Owner | Consumers | Notes |
|----------|-------|-----------|-------|
| Opus tenant runbook + log-export schema | M01 | M09 (HITRUST scope), M07 (mobile patient-app extension) | Real PagerDuty hookup; 30-day incident report. |
| AI-lab eval-receipt format | M02 | M04 (verdict-driver parity), partner-signed conformance assertion | Python + Go drivers `unsupported -> passing`. |
| Hosted CI workflows + reproducible-build pipeline | M03 | every other milestone (CI is load-bearing again) | SLSA-style provenance, public checksum index, third-party reproduction. |
| Mutation lane + verdict matrix | M04 | M08 (the M08 reviewer cites the gate) | Honest threshold (target 80%, accept 65%); CI gates flip from advisory to required. |
| Threat-coverage table | M05 | M08 reviewer cross-checks closure | Zero `partial` or `placeholder` rows. |
| Apalache focused-invariants + SBOM/cargo-vet | M06 | M09 assessor consumes SBOM | 3-4 highest-leverage invariants; full FSM deferred to trajectory-4 (D04). |
| chio-kernel-mobile bindings + attestation | M07 | M01 mobile patient-app | iOS framework + Android AAR; App Attest + Play Integrity. |
| NCC Group or Trail of Bits report | M08 | release narrative; M03 / M04 / M05 cited | Public report with remediation log. |
| HITRUST i1 certificate | M09 | Opus cluster procurement; release narrative | Scoped to v3.18 + Opus deployment. |
| AWS Bedrock listing + MCP conformance entry | M10 | distribution narrative | AWS approval is the third-party evidence. |

## House rules

Inherited from `/CLAUDE.md`:

- No em dashes (U+2014). Use hyphens or parentheses.
- Fail-closed: errors deny by default. Invalid policies reject at load.
- Conventional commits.
- Clippy `unwrap_used = "deny"` and `expect_used = "deny"` workspace-wide.

trajectory-3 specific:

- Trajectory-3 ticket IDs reference each other only via `depends_on`.
  Cross-trajectory references go in `soft_deps` as string sentences.
- Each milestone has exactly one narrative file at the trajectory-3 root.
- Per-phase ticket files live under `tickets/M{NN}/P{n}.yml`.
- `tickets/manifest.yml` is generated; do not hand-edit.
- Authoring contract: `STYLE.md`.

## Locked decisions (resolved 2026-04-30)

The verdict debate produced fifteen decisions D01..D15 (full text in
`decisions.yml`). Quick reference:

- D01 blend frame chosen over halt / customer-only / expand / audit-led
- D02 HITRUST i1 replaces ISO 42001 (calendar + partner ask)
- D03 M10 descoped to AWS Bedrock + MCP only (not three clouds)
- D04 M06 split: focused invariants only; full Apalache FSM -> trajectory-4
- D05 M06 split: API-tier + supply-chain only; full crate consolidation
  88->70 -> trajectory-4
- D06 FTE assumption: 5 eng + 1 program lead + 0.5 security reviewer
- D07 vendor budget posture: ~$350-450k
- D08 week-12 contingency: ship gate at honest threshold, do NOT slip M08
- D09..D15 see `decisions.yml`

## File map

```
.planning/trajectory-3/
  README.md                 (this file)
  STYLE.md                  (authoring contract)
  EXECUTION-STATE.json      (seed state, milestone status table)
  EXECUTION-BOARD.md        (waves, freezes, ownership detail)
  AUTONOMOUS-PROMPT.md      (orchestrator brief)
  COLD-READER-NOTES.md      (cold-reader onboarding)
  CHANGELOG.md              (authoring history)
  OWNERS.toml               (path -> reviewer mapping)
  freezes.yml               (collision detector seed)
  decisions.yml             (locked design decisions)
  01-opus-design-partner-pilot.md
  02-ai-lab-evaluation-beachhead.md
  03-hosted-ci-truth-and-reproducible-builds.md
  04-mutation-and-verdict-matrix-promotion.md
  05-threat-coverage-closure.md
  06-focused-formal-and-supply-chain.md
  07-chio-kernel-mobile-mvp.md
  08-independent-crypto-protocol-review.md
  09-hitrust-i1-assessment.md
  10-aws-bedrock-mcp-conformance.md
  audits/                   (per-milestone audit doc skeletons)
  research/m01/ .. research/m10/
  tickets/
    schema.json
    manifest.yml            (regenerated; concatenation of per-phase files)
    M01/README.md, P0..P5.yml
    ...
    M10/README.md, P0..P5.yml
```
