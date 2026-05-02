# M01: Healthcare Design-Partner Production Pilot

**Wave:** W1  |  **Trust-boundary:** yes  |  **Tickets:** 32  |  **Effort weeks:** 4/6/9 (low/real/high)

## In one paragraph

M01 ships v3.18 to a single healthcare design partner (selected at
M01.P0/P1 from a candidate pool per D09) and observes the deployment
for 30 consecutive days. The release gate is
BOUNDED_OPERATIONAL_PROFILE: the design-partner tenant ops review
attests the bounded profile holds under real workload. Implementation
lands a tenant-shaped operator runbook under `docs/operator-runbook/`,
plumbs a real PagerDuty hookup against the design-partner on-call
(the `crates/chio-siem/src/alerting.rs` `PagerDutyBackend` is
read-only consumed; M01 names the routing key and rotation), ships
an audit-log export schema v1 at
`spec/audit-log/export-schema.v1.json` plus a new CEF emitter at
`crates/chio-siem/src/exporters/cef.rs`, and sustains a
capacity-tested quota lane sized to design-partner production load
via a new `bench/healthcare-pilot-capacity/` crate. Two audit-doc
freezes (`m01-m07-audit-handoff`, `m01-m09-audit-handoff`) point at
this milestone.

## Phases at a glance

| Phase | One-liner | Tickets | Effort days |
|-------|-----------|---------|-------------|
| P0 | Audit doc + design-partner contract + tenant onboarding plan | 5 | 4.5 |
| P1 | Operator runbook hardening + PagerDuty integration | 6 | 7.5 |
| P2 | Quota under real load: capacity test + tenant onboarding rehearsal | 5 | 6.5 |
| P3 | Audit-log export schema v1 negotiated with design-partner team | 5 | 5.5 |
| P4 | 30-day production observation + week-by-week incident review | 6 | 3.5 |
| P5 | Design-partner tenant ops review attests bounded operational profile | 5 | 3.0 |
| **Total** | | **32** | **30.5** |

## Ticket inventory

### P0 (5 tickets, 4.5 days)

- M01.P0.T1 (1.0d) - Open audit doc and fill four hard-count rows
- M01.P0.T2 (0.5d) - Healthcare design-partner contract memo + BAA posture
- M01.P0.T3 (1.5d) - Tenant onboarding plan
- M01.P0.T4 (1.0d) - Production deployment topology diagram
- M01.P0.T5 (0.5d) - PagerDuty service-naming + rotation contract memo

### P1 (6 tickets, 7.5 days)

- M01.P1.T1 (1.5d) - Runbook index + bounded-profile import
- M01.P1.T2 (1.0d) - SLO definition
- M01.P1.T3 (1.5d) - Incident classification + MTTR table
- M01.P1.T4 (1.5d) - PagerDuty integration doc + severity-override config
- M01.P1.T5 (1.0d) - On-call rotation + escalation policy
- M01.P1.T6 (1.0d) - Weekly heartbeat-alert workflow

### P2 (5 tickets, 6.5 days)

- M01.P2.T1 (2.0d) - Sustained-load runner crate scaffold
- M01.P2.T2 (1.0d) - Shadow-traffic capture script
- M01.P2.T3 (1.5d) - Capacity test report
- M01.P2.T4 (1.0d) - Quota lane sizing doc
- M01.P2.T5 (1.0d) - Tenant-onboarding rehearsal log

### P3 (5 tickets, 5.5 days)

- M01.P3.T1 (1.5d) - Open `spec/audit-log/export-schema.v1.json` (triggers `m01-m09-audit-handoff` freeze)
- M01.P3.T2 (1.5d) - CEF emitter at `crates/chio-siem/src/exporters/cef.rs`
- M01.P3.T3 (1.0d) - PHI-redaction policy doc
- M01.P3.T4 (1.0d) - Schema-linter CI job + golden file
- M01.P3.T5 (0.5d) - Schema-negotiation receipt

### P4 (6 tickets, 3.5 days)

- M01.P4.T1 (0.5d) - Week 1 incident-review entry
- M01.P4.T2 (0.5d) - Week 2 incident-review entry
- M01.P4.T3 (0.5d) - Week 3 incident-review entry
- M01.P4.T4 (0.5d) - Week 4 incident-review entry
- M01.P4.T5 (1.0d) - 30-day incident report compiled and committed
- M01.P4.T6 (0.5d) - MTTR + bounded-profile-hold attestation

### P5 (5 tickets, 3.0 days)

- M01.P5.T1 (0.5d) - Open `m01-m07-audit-handoff` freeze; audit doc evidence log entry
- M01.P5.T2 (1.0d) - Design-partner ops sign-off memo recorded under closure attestations
- M01.P5.T3 (0.5d) - Operator runbook live URL recorded
- M01.P5.T4 (0.5d) - Schema v1 path recorded under closure
- M01.P5.T5 (0.5d) - Closure: success-criteria rows green; both freezes closed

## Locked decisions

- D09 - Healthcare design-partner naming policy (partner identity selected at M01.P1 scoping)
- D15 - Customer evidence freshness 7-day window

## Active freezes

- `m01-m07-audit-handoff` - opens at M01.P5.T1, closes at M01.P5.T5; M07 consumes M01 audit doc
- `m01-m09-audit-handoff` - opens at M01.P3.T1, closes at M01.P5.T5; M09 consumes M01 audit-log schema v1 + audit doc

## When this milestone is done

- Design-partner ops sign-off memo received within 7 days of P5 close.
- 30-day incident report committed under
  `.planning/trajectory-3/audits/M01-healthcare-pilot.md`.
- Operator runbook + log-export schema v1 + PagerDuty hookup all live.
- Both audit-handoff freezes closed at M01.P5.T5.
