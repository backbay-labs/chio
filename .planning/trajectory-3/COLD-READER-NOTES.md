# Cold-reader notes (trajectory-3)

What an outside reviewer or new agent must know to onboard onto
trajectory-3.

## What trajectory-3 is

trajectory-3 is the third planning cycle for the Chio (formerly ARC)
project. It follows trajectory-2, which closed M01-M10 across 113 PRs
of pure engineering output (error taxonomy, mutation, PQ + TEE,
delegation + revocation oracle, adversarial + threat-model, perf,
adoption beachhead, chio-arena, economic + lineage, hardware custody +
model cards).

trajectory-3 is the customer-anchored legibility cycle. It exists
because trajectory-2 closed without a single named external customer
on `main`, with hosted CI in admin-merge-bypass mode, and with three
threat-coverage rows still flagged `partial`.

## The verdict, one paragraph

The verdict-debate output is a 50/30/20 blend: half the calendar is
real-customer pilot work (M01 healthcare design-partner pilot, M02
AI-lab evaluation beachhead, M07 mobile MVP, M10 AWS Bedrock
listing); 30%
is paying down the trajectory-2 debt that makes the customer work
referenceable (M03 hosted CI + reproducible builds, M04 mutation +
verdict matrix, M05 threat-coverage closure, M06 focused formal +
supply-chain v2); 20% is external-attestation evidence (M08 NCC Group
or Trail of Bits crypto + protocol review, M09 HITRUST i1) running as
two parallel long-clock vendor calendars starting week 1.

## Roster

Ten milestones, all trust-boundary, ~44-48 calendar weeks at
5 FTE engineering + 1 program lead + 0.5 security reviewer.

| # | Slug | Title | Effort weeks |
|---|------|-------|--------------|
| 01 | healthcare-design-partner-pilot | Healthcare Design-Partner Production Pilot | 4/6/9 |
| 02 | ai-lab-evaluation-beachhead | AI-Lab Evaluation Infrastructure Beachhead | 6/9/13 |
| 03 | hosted-ci-truth-and-reproducible-builds | Hosted CI Truth + Reproducible Builds | 4/6/9 |
| 04 | mutation-and-verdict-matrix-promotion | Mutation Gate + Verdict Matrix Promotion | 6/9/13 |
| 05 | threat-coverage-closure | Threat-Coverage Closure | 3/5/7 |
| 06 | focused-formal-and-supply-chain | Focused Formal + Supply-Chain Hygiene v2 | 7/10/14 |
| 07 | chio-kernel-mobile-mvp | chio-kernel-mobile MVP + Device Attestation | 8/11/15 |
| 08 | independent-crypto-protocol-review | Independent Crypto + Protocol Review | 4/6/9 (Chio-side); 26-44 calendar |
| 09 | hitrust-i1-assessment | HITRUST i1 Assessment | 5/8/12 (Chio-side); 12-36 calendar |
| 10 | aws-bedrock-mcp-conformance | AWS Bedrock + MCP Conformance Listing | 6/9/13 |

## Wave plan

- **W1** (weeks 1-15): M01 + M02 + M03 + M04 + M05 (debt + pilot + CI).
- **W2** (weeks 12-26): M06 + M07 (formal + mobile).
- **W3** (weeks 22-30): M10 (distribution).
- **Vendor calendars** (parallel, weeks 1-44): M08 + M09 start week 1.

## Halt triggers

The eleven canonical orchestrator halt triggers carry over from
trajectory-1 and trajectory-2. trajectory-3 adds four:

12. Design-partner withdrawal (M01 healthcare design partner or M02 AI lab).
13. Vendor calendar slip > 25% (M08 or M09).
14. HITRUST assessor rejection (M09).
15. M08 reviewer critical CVE (CVSS >= 9.0).

## What is load-bearing in trajectory-3 that was not in trajectory-2

- **External customer**: trajectory-3 is the first cycle with a named,
  contracted design partner. The M01 healthcare design partner is
  selected at M01.P0/P1 from a candidate pool (regional payer,
  digital-health startup with BAA-ready posture, AI-driven
  underwriting platform, telehealth network); trajectory-3 docs do
  not bind the partner identity (D09). The M02 AI-lab evaluation
  partner is external (Anthropic evaluations team OR METR OR Apollo
  Research, pick one in week 1 per D10).
- **Vendor calendars**: M08 and M09 are calendar-driven, not
  implementation-driven. Their tickets often look like 0.25-day
  "vendor wait" / "evidence received" markers. This is intentional;
  do not collapse them into engineering tickets.
- **Honest thresholds**: D08 says "ship gate at honest threshold (e.g.
  65% mutation kill), document gap, do NOT slip M08". This is the
  contingency rule for week-12; do not gold-plate beyond it.
- **One cloud, not three**: D03 binds M10 to AWS Bedrock only. Do not
  silently widen to GCP / Azure.

## What an executor needs to read first

1. `.planning/trajectory-3/README.md` (this directory's index)
2. `.planning/trajectory-3/EXECUTION-BOARD.md` (operations doc)
3. The narrative file for the milestone you are touching
   (`{NN}-{slug}.md`)
4. `.planning/trajectory-3/decisions.yml` (cite by id)
5. The audit doc for the milestone
   (`.planning/trajectory-3/audits/M{NN}-{slug}.md`)
6. The phase YAML for your phase (`tickets/M{NN}/P{n}.yml`)

## What a reviewer needs to check

- Trust-boundary: every milestone in trajectory-3 is trust-boundary,
  which means security x2 review on every PR.
- Cross-doc invariants: every artifact in the README's invariants
  table has one owner; tickets touching the artifact outside its
  owning milestone are halt-and-ping.
- Vendor evidence freshness: M08 / M09 audit docs must record vendor
  dates within 7 days of receipt.
- Customer naming hygiene: trajectory-3 docs do NOT name the M01
  healthcare design partner. Use "the design partner",
  "design-partner deployment", or "the M01 design partner" in
  narratives, audits, and tickets. The selected partner is named in
  the audit doc evidence log only.

## Where the verdict lives

The verdict that produced trajectory-3 lives in the conversation
history of the synthesizer that ran 2026-04-30. Key points:

- All five pure frames (halt / customer-only / deepen / audit-led /
  expand) were rejected as monocultural.
- The blend frame was selected because it lets external attestation
  (M08, M09) sit on a stable substrate (M03 + M04 + M05) while a real
  customer (M01, M02) consumes it.
- ISO 42001 was rejected for trajectory-3 in favor of HITRUST i1
  (D02): the calendar is shorter and the design partner asked for
  HITRUST first.
- Three clouds was rejected (D03): one credible AWS listing beats
  three half-listings.

## Where things will go wrong

The cold-reader's three predicted failure modes:

1. **Mutation kill-rate sandbagging**: M04 hits the 80% target on
   chio-attest-verify but lags below 65% on chio-revocation-oracle.
   The honest-threshold rule (D08) applies; do not lift the gate.
2. **Vendor lead-time miscalibration**: NCC Group or Trail of Bits booking
   may slip past week 14. The decision register's vendor calendar
   bands accommodate this; the halt trigger is > 25% slip.
3. **Bedrock listing reviewer feedback round-trips**: AWS marketplace
   reviewers commonly request 2-3 round-trips. Schedule M10 P3
   tickets with a 4-week buffer; do not crash into Wave 3 close.

---

End of cold-reader notes.
