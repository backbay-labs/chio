# M01 Audit: Healthcare Design-Partner Production Pilot

**Trajectory:** trajectory-3
**Milestone:** M01
**Wave:** W1
**Status:** TEMPLATE (orchestrator + M01 author fill as phases close)
**Audit start:** <fill at P0 wave-opener merge>
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

[TODO M01 milestone agent fill at P0.T1:]

| Surface | Baseline | Reproduce |
|---------|----------|-----------|
| Design-partner tenant size | <single tenant>, <estimated daily receipt volume>, <design-partner-side SLO targets> | Design-partner ops interview at P0.T1; record summary |
| Operator-runbook line count | tenant-shaped runbook does not exist; `docs/operator-runbook/` line count = 0 | `find docs/operator-runbook -type f -name '*.md' \| xargs wc -l 2>/dev/null \|\| echo 0` |
| Inherited generic runbook | `docs/release/OPERATIONS_RUNBOOK.md` line count | `wc -l docs/release/OPERATIONS_RUNBOOK.md` |
| PagerDuty integration gaps | 6 gaps: routing key un-assigned, on-call rotation un-wired, escalation policy absent, severity-override config absent, heartbeat alert absent, per-alert-type runbook entries absent | Per RESEARCH.md "PagerDuty / on-call integration plan" section |
| chio-siem exporters today | 8 exporters in `crates/chio-siem/src/lib.rs` (`PagerDutyBackend`, `OpsGenieBackend`, `DatadogExporter`, `ElasticsearchExporter`, `OcsfExporter`, `SplunkHecExporter`, `SumoLogicExporter`, `WebhookExporter`); CEF and LEEF absent | `grep -E '^pub use.*Exporter\|^pub use.*Backend' crates/chio-siem/src/lib.rs` and `grep -rln 'CEF' crates/chio-siem` |
| Schema directory existence | `spec/audit-log/` does not exist | `test -d spec/audit-log && echo exists \|\| echo absent` |
| Log-export schema fields named by design-partner team | <ArcSight/CEF or QRadar/LEEF or Splunk-HEC or Elastic or generic syslog>; <fields named> | Design-partner SOC interview at P0.T1; record on the schema-negotiation receipt at P3.T5 |
| 30-day observation start date | <pinned at P0.T1>; no later than week 8 of W1 | Calendar pin in audit doc |
| BAA posture | <pre-existing BAA covering design partner + Chio> OR <fresh BAA cut for M01>; sign-off date | P0.T2 contract memo |

## 3. Customer evidence log

[TODO M01 milestone agent fill as evidence accrues. D15 freshness
window applies: 7 days from receipt to record. Each row is a
discrete customer or ops-team interaction.]

| Date | Event | Source | Cross-ref |
|------|-------|--------|-----------|
| | P0 contract memo signed | Design-partner ops team + program lead | M01.P0.T2 |
| | PagerDuty service `chio-healthcare-pilot-prod` provisioned | PagerDuty ops + program lead | M01.P0.T5 |
| | Tenant-onboarding rehearsal completed | Design-partner ops team | M01.P2.T5 |
| | Schema v1 negotiation receipt | Design-partner SOC team | M01.P3.T5 |
| | Week 1 incident review | Design-partner ops team | M01.P4.T1 |
| | Week 2 incident review | Design-partner ops team | M01.P4.T2 |
| | Week 3 incident review | Design-partner ops team | M01.P4.T3 |
| | Week 4 incident review | Design-partner ops team | M01.P4.T4 |
| | 30-day report published | Chio team | M01.P4.T5 |
| | Design-partner tenant ops sign-off memo received | Design-partner ops team | M01.P5.T2 |

## 4. PagerDuty service-naming + on-call rotation contract

[TODO M01 milestone agent fill at P0.T5:]

- **PagerDuty service name:** `chio-healthcare-pilot-prod`
- **Routing key owner:** <Chio team account | design-partner ops team account>
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
- **On-call rotation cadence:** <weekly | bi-weekly>; rotation
  members from design-partner ops + Chio kernel team.
- **Heartbeat cadence:** weekly (per RESEARCH.md recommendation;
  daily reserved for v1.x if signal/noise warrants). Workflow at
  `.github/workflows/healthcare-pilot-pagerduty-heartbeat.yml`.

## 5. Topology pin (P0.T4)

[TODO M01 milestone agent fill at P0.T4:]

- **Chio mediation edge placement:** <sidecar process | in-process
  library | wrapped MCP edge> relative to the design-partner's
  existing API surface (path + default port pinned at P0.T4 once
  the partner is selected).
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

[TODO M01 milestone agent fill at P2.T3 close:]

| Replay multiple | p50 latency | p95 | p99 | Receipt-write throughput | Trust-control convergence | Exporter backpressure |
|-----------------|-------------|-----|-----|--------------------------|---------------------------|----------------------|
| 1x baseline | | | | | | |
| 2x | | | | | | |
| 5x | | | | | | |

Quota lane sizing rationale recorded at
`docs/operator-runbook/quota.md` (P2.T4). Headroom capped at 5x
replayed baseline; spikes beyond 5x trigger P1 incident
classification per P1.T3.

## 7. Schema v1 evidence (P3)

[TODO M01 milestone agent fill at P3.T5:]

- **Schema path:** `spec/audit-log/export-schema.v1.json`
  (JSON Schema 2020-12).
- **Field mapping covered:** OCSF 1.3.0 Authorization
  (`OCSF_CLASS_UID = 3002`, already shipped via
  `crates/chio-siem/src/ocsf.rs`), <CEF or LEEF>, Splunk HEC.
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
  v1 on <date>; sign-off captured under section 3 evidence log.

## 8. 30-day observation window (P4)

[TODO M01 milestone agent fill at P4.T1..T6:]

- **Window:** <start date> to <end date>; pinned at P0.T1.
- **Week 1:** <incidents>; PHI-leak audit row: <pass/fail>.
- **Week 2:** <incidents>; PHI-leak audit row: <pass/fail>.
- **Week 3:** <incidents>; PHI-leak audit row: <pass/fail>.
- **Week 4:** <incidents>; PHI-leak audit row: <pass/fail>.
- **30-day rollup:** <total incidents>; P0 count <0 expected>;
  P1 / P2 with MTTR.
- **Bounded-profile-hold attestation (P4.T6):** "30-day observation
  confirms trust-control single-writer, single-node hosted auth,
  single-node atomic monetary budgets, and signed local audit
  evidence held under design-partner production load."

## 9. Closure attestations

[TODO M01 milestone agent fill at P5 close:]

- Design-partner tenant ops sign-off memo: <link / hash> (P5.T2)
- 30-day incident report: <attach> (P4.T5)
- Operator runbook live URL: <url> (P5.T3)
- Log-export schema v1 path: `spec/audit-log/export-schema.v1.json`
  (P5.T4)
- Both audit-handoff freezes closed at M01.P5.T5:
  `m01-m07-audit-handoff` and `m01-m09-audit-handoff`.

## 10. Cross-references

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
