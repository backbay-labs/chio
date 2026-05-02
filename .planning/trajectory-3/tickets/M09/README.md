# M09: HITRUST i1 Assessment

**Wave:** Wv (vendor calendar)  |  **Trust-boundary:** yes  |  **Tickets:** ~46  |  **Effort weeks:** 5/8/12 (Chio-side); 12-36 calendar

## In one paragraph

M09 procures a HITRUST i1 readiness + assessment scoped to the Opus
design-partner deployment (D02 picks HITRUST i1 over ISO 42001).
Release gate is QUALIFICATION: HITRUST i1 certificate issued, scoped
to v3.18 + Opus deployment per D09. Implementation is dominated by
vendor-coord work (RFP, scoping, walkthroughs, follow-up evidence
requests) plus a smaller engineering surface (control-mapping CSV,
narrative authoring, evidence-pack automation script consuming M01 /
M03 / M05 / M06 outputs).

## Phases at a glance

| Phase | Calendar weeks | One-liner | Tickets |
|-------|---------------|-----------|---------|
| P0 | 1-7 | Audit doc seed + HITRUST scope + assessor shortlist | 8 |
| P1 | 8-14 | Gap assessment with HITRUST-authorized assessor | 9 |
| P2 | 14-19 | Remediation work (control mapping, narratives, IR runbook, evidence-pack seed) | 9 |
| P3 | 19-24 | Evidence package finalized for assessor portal | 6 |
| P4 | 24-32 | Assessor engagement + on-site / remote evaluation | 10 |
| P5 | 32-36 | Certificate issuance + audit doc closure | 6 |

## Locked decisions

- D02 HITRUST i1 over ISO 42001
- D07 vendor budget posture ~$80-150k for this milestone
- D09 scope is the Opus design-partner deployment

## Active freezes

- `m01-m09-audit-handoff` (M01.P3 through M01.P5; covers
  `spec/audit-log/export-schema.v1.json` and
  `.planning/trajectory-3/audits/M01-opus-pilot.md`). M09.P3.T2
  cannot leave pending until the freeze closes (M01.P5.T5 merge).
- M09 freezes the assessor evidence document under
  `.planning/trajectory-3/audits/M09-vendor-evidence.md` from P0.T2
  onward.
- M06 SBOM (`supply-chain/**`) is consumed but not owned by M09;
  M06.P3 close is gating for M09.P3.

## Cross-milestone hard deps

- M01 audit-log export schema v1 (frozen via `m01-m09-audit-handoff`)
- M01 operator runbook + 30-day BOP audit-log samples (M01.P5.T5
  close)
- M03 SLSA-style provenance + reproducible-build hash
- M05 threat-coverage closure (zero `partial` / `placeholder` rows)
- M06 SBOM + cargo-vet ledger + CVE-monitoring workflow output
- M06 formal-method outputs (Apalache invariants) plain-English
  bridge authored in P2.T7

## When this milestone is done

- HITRUST i1 certificate received from the authorized assessor.
- Certificate scoped to v3.18 + Opus deployment per D09.
- `compliance/hitrust/control-mapping.csv` complete (every i1 control
  marked `evidenced` or `accepted-risk`).
- `compliance/hitrust/build-evidence-pack.sh` idempotent and exercised
  by P3.T3 + P4 follow-up tickets.
- Audit doc records: assessor identity, certificate id, scope,
  issuance + expiration dates, finding log, remediation
  cross-references, vendor-quote variance from D07 band.
- Public certificate landing page at
  `docs/external-attestation/hitrust-i1/index.md`.
- Renewal-cadence trigger filed (1-year validity; trajectory-4
  candidate).
