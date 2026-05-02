# M08: Independent Crypto + Protocol Review (NCC Group or Trail of Bits)

**Wave:** Wv (vendor calendar; parallel to all code waves)
**Trust-boundary:** yes
**Tickets:** ~9 (P0) + ~7 (P1) + 30-90 (P2) + 30-90 (P3) + 5-30 (P4) + 5 (P5)
**Effort weeks:** 4/6/9 (Chio-side, low/real/high); 26-44 calendar weeks
**Branch prefix:** `wave/Wv/m08/p{n}.t{k}-<slug>`

## In one paragraph

M08 contracts a third-party crypto and protocol review of Chio's
cemented v3.0 surface from NCC Group or Trail of Bits. Release gate is
RELEASE_AUDIT: published reviewer report with remediation log.
Implementation Chio-side is calendar-driven: RFP authoring (P0), vendor
booking + scoping (P1), reviewer-question response during active review
(P2-P3), remediation PR fan-out (P4), and final report publication (P5).
Most tickets carry `agent_role: vendor-coord` per the trajectory-3
schema; remediation tickets in P4 carry `agent_role: gsd-executor` (or
the appropriate Rust crate role) with trust-boundary review.

## Phases at a glance

| Phase | Calendar weeks | One-liner | Chio-side person-days |
|-------|---------------|-----------|----------------------|
| P0 | 1-5 | RFP draft + vendor shortlist (NCC + ToB) + handoff package + SOW signed | ~5 |
| P1 | 6-14 | Vendor booking + onboarding session + scoping + SOW addenda | ~3 |
| P2 | 15-22 | Active review (first half); reviewer-question response loop | ~25-50 |
| P3 | 23-30 | Active review (second half); preliminary findings; halt-15 template | ~25-55 |
| P4 | 30-40 | Remediation PR fan-out; vendor sign-off receipt collection | ~10-60 |
| P5 | 40-44 | Final report received; remediation log committed; published | ~3 |

Total Chio-side: 70-175 person-days spread across 44 calendar weeks.
Variance is dominated by P4 (number of findings above Medium severity).

## Locked decisions

- D07 vendor budget posture ~$150-250k for this milestone.
- D12 vendor shortlist NCC Group or Trail of Bits; final pick by week 5.
- Substitute ladder per D12 amendment: Galois -> Kudelski -> Cure53 ->
  Cryptography Engineering LLC; rows live in audit doc Section 2.
- Coordinated-disclosure window: 90 days default per industry standard.
- Right-of-reply on draft report: 10 business days.
- Post-remediation re-test on Critical / High: 1 week (paid via SOW).

## Active freezes

- No code-side freeze. The protocol surface (`spec/PROTOCOL.md` v3.0)
  is cemented from trajectory-2 close; M08 reviews it unchanged.
- Audit-doc lane freeze: `.planning/trajectory-3/audits/M08-vendor-
  evidence.md` is owned by M08 from P0 onward. Other milestones
  cross-reference read-only.
- M08 may receive remediation PRs that touch
  `crates/chio-attest-verify/`, `crates/chio-revocation-oracle/`,
  `crates/chio-kernel-core/`, `spec/PROTOCOL.md` (post-active-review
  only). Remediation PRs serialize against any active trajectory-3
  freeze on those paths.

## Agent roles

- **vendor-coord** (most tickets): RFP send, contract sign, scoping
  calls, status updates, finding triage routing, vendor sign-off
  receipt collection. Reads + writes only the audit doc and the RFP
  doc; does not touch source code. Drafts vendor-facing prose;
  @bb-connor signs all outbound vendor communications. Logs every
  outbound + inbound vendor event in Section 3 of the audit doc.
  Status verbs: `awaiting`, `received`, `redlined`, `signed`,
  `answered`, `deferred`.
- **planning agent** (RFP authoring, SOW redline, factual-correction
  memo, remediation log compile, close memo): @bb-connor co-signs.
- **gsd-executor** + crate-specific agent (P4 remediation tickets):
  trust-boundary security x2 review applies on every PR.

## Cross-milestone interactions

- Cites M04 mutation gate evidence; handoff addendum at P1.T5.
- Cross-checks M05 threat-coverage closure; handoff addendum at P1.T6.
- Receives M06 formal coverage output; handoff via the rolling
  addendum once M06 invariants close.
- Independent of M01 / M02 customer work but cross-checked by them
  (customer milestones reference the published report once available).
- M03 release artifact channel publishes the final report PDF and
  updates `releases.toml`; M08.P5.T3 coordinates the publication.

## When this milestone is done

- Vendor report published with remediation log on the M03 release
  artifact channel.
- All Critical findings (CVSS >= 9.0) remediated; non-critical
  remediation roadmap committed in audit doc Section 4.
- M04 mutation gate, M05 threat closure, M06 Apalache invariants
  cross-cited in the published report; closure attestations populated
  in audit doc Section 5.
- Chio response memo (M08.P5.T5) published alongside the vendor
  report.
- Calendar adherence recorded; halt-trigger history (none / list)
  recorded; D07 budget variance recorded.

## Halt-trigger references

- **Halt 12** (design-partner withdrawal): not directly applicable;
  M08 has no design partner. Customer-side pressure to reshape the
  protocol during P2-P3 surfaces here.
- **Halt 13** (vendor calendar slip > 25% or both vendors decline):
  Risks 1, 3 in milestone narrative. Most likely on weeks 6-14
  (8-week vendor booking lead).
- **Halt 15** (Critical CVE filed mid-review): Risk 2 in milestone
  narrative. Pre-staged hot-fix template at M08.P3.T-halt15-template.
