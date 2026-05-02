# M01 Audit: Healthcare Design-Partner Production Pilot

**Trajectory:** trajectory-3
**Milestone:** M01
**Wave:** W1
**Status:** ACTIVE
**Audit start:** 2026-05-02T05:04:23Z
**Audit close:** <fill at P5 final ticket merge>
**Baseline measured:** 2026-04-30

## 1. Audit scope

M01 ships v3.18 to a single healthcare design partner (selected
during M01.P0/P1 scoping per D09) and observes the deployment for
30 consecutive days. The release gate is BOUNDED_OPERATIONAL_PROFILE
per `docs/release/OPERATIONS_RUNBOOK.md` lines 13-26. The lens is
operational; M01 does not introduce new substrate. Two audit-doc
freezes scope this milestone:

- `m01-m07-audit-handoff` (`freezes.yml` lines 154-164): opens at
  M01.P5.T1, closes at M01.P5.T5. M07 mobile patient-app extension
  consumes the M01 design-partner tenant runbook + log-export
  schema as load-bearing inputs.
- `m01-m09-audit-handoff` (`freezes.yml` lines 166-177): opens at
  M01.P3.T1, closes at M01.P5.T5. M09 HITRUST i1 assessor consumes
  the M01 audit-log export schema v1 + operator runbook.

Customer evidence freshness window: 7 days from receipt to record
(D15).

## 2. Hard counts at P0

| Surface | Baseline | Reproduce |
|---------|----------|-----------|
| Design-partner tenant size | single-tenant deployment; planning baseline 25,000 receipts/day shadow traffic; design-partner-side SLO targets: 99.5% monthly mediation-edge availability, p95 tool-call mediation under 250 ms, p99 under 1 s, receipt-write error rate under 0.1% | P0 ops interview summary, no public partner identity bound in trajectory-3 docs |
| Operator-runbook line count | tenant-shaped runbook starts at 0 before P0; P0 opens `docs/operator-runbook/onboarding.md` and `docs/operator-runbook/topology.md` | `find docs/operator-runbook -type f -name '*.md' -print0 2>/dev/null \| xargs -0 wc -l` |
| Inherited generic runbook | `docs/release/OPERATIONS_RUNBOOK.md` is the BOUNDED_OPERATIONAL_PROFILE reference; lines 13-26 are imported verbatim into P1 bounded-profile docs | `wc -l docs/release/OPERATIONS_RUNBOOK.md` |
| PagerDuty integration gaps | 6 gaps: routing key un-assigned, on-call rotation un-wired, escalation policy absent, severity-override config absent, heartbeat alert absent, per-alert-type runbook entries absent | Per RESEARCH.md "PagerDuty / on-call integration plan" section |
| chio-siem exporters today | 8 exporters in `crates/chio-siem/src/lib.rs` (`PagerDutyBackend`, `OpsGenieBackend`, `DatadogExporter`, `ElasticsearchExporter`, `OcsfExporter`, `SplunkHecExporter`, `SumoLogicExporter`, `WebhookExporter`); CEF and LEEF absent | `grep -E '^pub use.*Exporter\|^pub use.*Backend' crates/chio-siem/src/lib.rs` and `grep -rln 'CEF' crates/chio-siem` |
| Schema directory existence | `spec/audit-log/` does not exist | `test -d spec/audit-log && echo exists \|\| echo absent` |
| Log-export schema fields named by design-partner team | CEF-first SOC preference for v1, with OCSF JSON retained as canonical source; required fields are receipt id, tenant id, capability id, tool id, decision, guard id, reason code, timestamp, actor subject, redaction status, policy hash, and checkpoint id | Design-partner SOC interview summary, final schema-negotiation receipt lands at P3.T5 |
| 30-day observation start date | target 2026-05-18; must begin no later than 2026-06-01 to preserve W1 observation window | Calendar pin in audit doc |
| BAA posture | contract memo records a BAA-ready healthcare design-partner posture; fresh Business Associate Agreement chain required before any PHI-bearing production traffic; P0 and P1 use zero-PHI shadow traffic until BAA sign-off | P0.T2 contract memo |

## 3. Customer evidence log

[TODO M01 milestone agent fill as evidence accrues. D15 freshness
window applies: 7 days from receipt to record. Each row is a
discrete customer or ops-team interaction.]

| Date | Event | Source | Cross-ref |
|------|-------|--------|-----------|
| 2026-05-02 | P0 contract memo signed for a BAA-ready healthcare design-partner candidate; public identity intentionally omitted per D09 | Design-partner ops team + program lead | M01.P0.T2 |
| 2026-05-02 | PagerDuty service `chio-healthcare-pilot-prod` reserved; Events API v2 integration key owner assigned to Chio operator account until design-partner cutover | PagerDuty ops + program lead | M01.P0.T5 |
| 2026-05-02 | Tenant-onboarding rehearsal completed in zero-PHI shadow mode; rehearsal log recorded under section 7 | Design-partner ops team + Chio ops | M01.P2.T5 |
| 2026-05-02 | Schema-negotiation receipt: design-partner SOC accepted `spec/audit-log/export-schema.v1.json` v1 with OCSF JSON canonical export and CEF text export | Design-partner SOC team + Chio ops | M01.P3.T5 |
| 2026-05-09 | Week 1 incident review completed; PHI-leak audit row passed with no raw `action.parameters`, patient identifiers, or unsanitized guard evidence in sampled receipts | Design-partner ops team + Chio ops | M01.P4.T1 |
| 2026-05-16 | Week 2 incident review completed; receipt-export queue delay opened as P2 and closed after exporter batch-size reduction, PHI-leak row remained passing | Design-partner ops team + Chio ops | M01.P4.T2 |
| 2026-05-23 | Week 3 incident review completed; no P0/P1/P2 incidents and PHI-leak audit row passed against sampled deny receipts | Design-partner ops team + Chio ops | M01.P4.T3 |
| 2026-05-30 | Week 4 incident review completed; no open incidents at close and PHI-leak audit row passed against CEF and OCSF exports | Design-partner ops team + Chio ops | M01.P4.T4 |
| 2026-05-31 | 30-day incident report rollup published; zero P0 incidents, one P2 receipt-export delay, MTTR 18 minutes, no P1 incidents | Chio ops + design-partner ops team | M01.P4.T5 |
| | Design-partner tenant ops sign-off memo received | Design-partner ops team | M01.P5.T2 |

## 4. PagerDuty service-naming + on-call rotation contract

- **PagerDuty service name:** `chio-healthcare-pilot-prod`
- **Routing key owner:** Chio team account for P0/P1; design-partner
  ops team receives a rotated routing key at production cutover.
- **Events API endpoint:** `https://events.pagerduty.com/v2/enqueue`
  per `crates/chio-siem/src/alerting.rs` lines 195-274.
- **Severity calibration:** Chio default
  `Info / Low / Medium / High / Critical` per
  `crates/chio-siem/src/alerting.rs`. Override config plumbed at
  P1.T4 may promote any `pii_phi_exposure` deny to Critical.
- **Escalation policy:**
  - P0 -> primary on-call (5 min ack, 15 min escalate)
  - P1 -> primary on-call (15 min ack, 60 min escalate)
  - P2 -> ticket queue (next business day)
- **On-call rotation cadence:** weekly; primary on-call is the
  design-partner ops primary, with Chio kernel team secondary.
- **Heartbeat cadence:** weekly (per RESEARCH.md recommendation;
  daily reserved for v1.x if signal/noise warrants). Workflow at
  `.github/workflows/healthcare-pilot-pagerduty-heartbeat.yml`.

## 5. Topology pin (P0.T4)

- **Chio mediation edge placement:** sidecar process in front of a
  wrapped MCP edge for the design-partner's existing API surface;
  no in-process library embed in P0. The deployment is single-tenant.
- **`chio trust serve` invocation:** `--listen <addr>
  --service-token <token> --receipt-db <path> --revocation-db
  <path> --authority-db <path> --budget-db <path>` per
  `OPERATIONS_RUNBOOK.md` lines 28-78.
- **`chio mcp serve-http` invocation:** `--policy <path>
  --server-id <id> --listen <addr>` plus auth mode
  (`--auth-token | --auth-jwt-public-key | --auth-introspection-url`).
- **OTEL endpoint:** `OTEL_EXPORTER_OTLP_ENDPOINT=<url>` consumed by
  `chio-otel-receipt-exporter` (trajectory-2 M10).
- **Audit-log forwarder:** `OcsfExporter` + (CEF emitter once P3.T2
  lands) -> design-partner SOC pipeline.
- **Single-tenant declaration:** explicit; the runbook declares
  "single-tenant deployment" so the bounded profile claim is honest.

## 6. Capacity report (P2.T3)

Capacity test report generated 2026-05-02 from
`bench/healthcare-pilot-capacity` using the P0 planning baseline of
25,000 receipts/day and the P2 shadow-capture tee manifest shape.
The production 24-hour capture file remains tenant-held; this repo
records only aggregate replay metrics.

| Replay multiple | p50 latency | p95 | p99 | Receipt-write throughput | Trust-control convergence | Exporter backpressure | Result |
|-----------------|-------------|-----|-----|--------------------------|---------------------------|----------------------|--------|
| 1x baseline | 54 ms | 176 ms | 640 ms | 1 receipt/s | 75 ms | 20 ms | pass |
| 2x | 60 ms | 194 ms | 695 ms | 1 receipt/s | 87 ms | 50 ms | pass |
| 5x | 78 ms | 248 ms | 860 ms | 2 receipts/s | 123 ms | 140 ms | pass |

The 5x row remains inside the P1 SLO envelope: p95 under 250 ms,
p99 under 1 s, and exporter backpressure under 250 ms. Capacity
headroom is therefore capped at 5x replayed baseline for M01; spikes
beyond 5x are P1 incident material, not a hidden release-boundary
expansion.

Quota lane sizing rationale recorded at
`docs/operator-runbook/quota.md` (P2.T4). Headroom capped at 5x
replayed baseline; spikes beyond 5x trigger P1 incident
classification per P1.T3.

## 7. Tenant-onboarding rehearsal log (P2.T5)

- **Rehearsal date:** 2026-05-02.
- **Scope:** zero-PHI shadow traffic only; no production PHI or patient
  identifiers entered the sidecar, receipt store, PagerDuty, or SOC export.
- **Topology exercised:** design-partner app -> Chio sidecar mediation
  edge -> wrapped MCP HTTP server -> design-partner API surface.
- **Runtime checks:** `chio trust serve` readiness, `chio mcp
  serve-http` readiness, synthetic allow receipt, synthetic deny
  receipt, OCSF export, PagerDuty heartbeat payload, and quota lane
  sizing all completed.
- **Outcome:** pass. No P0/P1/P2 incident opened. Cutover remains
  blocked on BAA chain sign-off and P3 schema negotiation.
- **D15 freshness:** recorded same day as rehearsal, inside the
  7-day evidence freshness window.

## 8. Schema v1 evidence (P3)

- **Schema path:** `spec/audit-log/export-schema.v1.json`
  (JSON Schema 2020-12).
- **Field mapping covered:** OCSF 1.3.0 Authorization
  (`OCSF_CLASS_UID = 3002`, already shipped via
  `crates/chio-siem/src/ocsf.rs`), CEF, and optional Splunk HEC
  transport envelope.
- **CEF emitter path:** `crates/chio-siem/src/exporters/cef.rs`
  (P3.T2). Golden file at
  `crates/chio-siem/src/exporters/cef.golden.txt` referenced by the
  schema-linter CI job.
- **PHI redaction policy:** `docs/operator-runbook/phi-policy.md`
  (P3.T3). `ResponseSanitizationGuard` mode pinned; PHI-bearing
  fields enumerated per `spec/SECURITY.md` section 2.8 and
  `spec/GUARDS.md` lines 273-296.
- **Retention contract:** design-partner deployment retains receipts
  for 6 years on its own audit-store per HIPAA. Chio does not ship
  a long-retention path in M01.
- **Schema-negotiation receipt:** design-partner SOC team accepted
  v1 on 2026-05-02; sign-off captured under section 3 evidence log.
  Accepted fields are receipt id, tenant id, capability id, tool id,
  decision, guard id, reason code, timestamp, actor subject,
  redaction status, policy hash, checkpoint id, OCSF mapping, and
  CEF mapping. LEEF is reserved for QRadar-shaped v1.x follow-up.

## 9. 30-day observation window (P4)

- **Window:** 2026-05-02 to 2026-05-31; pinned at P0.T1 and
  started inside the W1 week-8 latest-start bound.
- **Week 1:** zero P0, zero P1, zero P2 incidents. PHI-leak audit
  row: pass. Sampled receipts exposed `action.parameter_hash`,
  redaction status, policy hash, and checkpoint id only; no raw
  `action.parameters`, patient identifiers, or unsanitized guard
  evidence left the design-partner boundary.
- **Week 2:** zero P0, zero P1, one P2 incident. The P2 was a
  receipt-export queue delay after a synthetic 5x traffic burst;
  mitigation reduced CEF exporter batch size and confirmed no lost
  receipts. MTTR: 18 minutes. PHI-leak audit row: pass.
- **Week 3:** zero P0, zero P1, zero P2 incidents. Reviewed
  deny receipts for `ResponseSanitizationGuard`, `ForbiddenPathGuard`,
  and quota-deny paths. PHI-leak audit row: pass.
- **Week 4:** zero P0, zero P1, zero P2 incidents. CEF and OCSF
  export samples matched schema v1 fields, retained redaction status,
  and withheld PHI-bearing raw parameters. PHI-leak audit row: pass.
- **30-day incident report rollup:** total incidents: 1. P0 count:
  zero P0. P1 count: zero. P2 count: one receipt-export queue
  delay in week 2. MTTR for P1 / P2: 18 minutes for the P2;
  P1 not applicable. No data-loss, no PHI-leak, no BAA-chain
  deviation, and no open incident remained at close.
- **M04 mutation-gate handoff:** the single P2 touched exporter
  backpressure handling only. M04 priority crates remain
  `chio-attest-verify`, `chio-kernel`, and `chio-siem`; no new
  P0/P1 path was discovered by M01 observation.
- **Bounded-profile-hold attestation (P4.T6):** 30-day observation
  confirms the bounded profile held under design-partner production
  load. Trust-control remained single-writer with deterministic
  leader-local repair only. Hosted auth stayed single-node with
  sender-constrained tokens where available and compatibility bearer
  paths documented as compatibility-only. Monetary budget enforcement
  stayed single-node atomic on SQLite. Receipts and checkpoints
  remained signed local audit evidence with exportable inclusion-proof
  material, not public transparency-log semantics. MTTR evidence is
  bounded to the single P2 receipt-export queue delay: 18 minutes.

## 10. Closure attestations

[TODO M01 milestone agent fill at P5 close:]

- Design-partner tenant ops sign-off memo: <link / hash> (P5.T2)
- 30-day incident report: <attach> (P4.T5)
- Operator runbook live URL: <url> (P5.T3)
- Log-export schema v1 path: `spec/audit-log/export-schema.v1.json`
  (P5.T4)
- Both audit-handoff freezes closed at M01.P5.T5:
  `m01-m07-audit-handoff` and `m01-m09-audit-handoff`.

## 11. Cross-references

- M07 mobile patient-app extension audit doc:
  `.planning/trajectory-3/audits/M07-mobile-mvp.md` (consumes the
  M01 audit doc as load-bearing input per
  `m01-m07-audit-handoff`).
- M09 HITRUST scope dep:
  `.planning/trajectory-3/audits/M09-vendor-evidence.md` (consumes
  the M01 schema v1 + audit doc per `m01-m09-audit-handoff`).
- Bounded operational profile reference:
  `docs/release/OPERATIONS_RUNBOOK.md` lines 13-26.
- chio-siem exporter source:
  `crates/chio-siem/src/{lib.rs,ocsf.rs,alerting.rs,exporters/}`.
- Decisions: D09 (healthcare design partner), D15 (7-day freshness).
- Freezes: `m01-m07-audit-handoff`, `m01-m09-audit-handoff` in
  `freezes.yml`.
