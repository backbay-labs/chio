# Healthcare Pilot SLO

This page defines the Chio mediation-edge service objectives for the M01
healthcare design-partner pilot. The design-partner API keeps its own upstream
SLOs; this page covers only Chio-owned mediation, receipt, export, and alerting
surfaces.

## Measurement Window

SLOs are measured over rolling 7-day and 30-day windows. P4 uses the 30-day
window for the final pilot observation report.

## Availability

| Surface | Objective | Error budget event |
|---------|-----------|--------------------|
| Chio sidecar mediation edge | 99.5% monthly availability | Sidecar cannot accept authenticated requests. |
| Trust-control service | 99.5% monthly availability | Trust-control readiness check fails. |
| Receipt persistence | 99.9% successful writes for evaluated requests | Receipt write failure after policy or guard evaluation. |
| PagerDuty alert dispatch | 99.0% successful dispatch for P0/P1 alerts | PagerDuty Events API dispatch fails or times out. |
| SOC export | 99.0% successful export for audit rows | Export queue drops or fails a row after retry budget. |

Availability excludes design-partner upstream API downtime. If the wrapped MCP
server is down, Chio returns a tool failure without bypassing mediation.

## Latency

Mediation latency is measured from sidecar request receipt to policy decision
completion, excluding upstream tool execution.

| Metric | Target | Notes |
|--------|--------|-------|
| p50 | under 75 ms | Normal steady-state decision path. |
| p95 | under 250 ms | Matches P0 design-partner planning baseline. |
| p99 | under 1 s | Includes transient receipt-store and exporter pressure. |
| Receipt write p95 | under 100 ms | Measured at local SQLite store boundary. |
| PagerDuty P0 dispatch p95 | under 5 s | Dispatch latency only, not human ack. |

If p95 exceeds target for two consecutive 30-minute windows, classify as P2.
If p99 exceeds target and receipt-write failures exceed 0.1%, classify as P1.

## Error Budget

The monthly sidecar availability error budget is 0.5%. The pilot stops feature
changes for the tenant when the 7-day burn rate exceeds 2x monthly budget.

Error budget burn sources:

- Sidecar readiness failure.
- Trust-control readiness failure.
- Authentication subsystem outage.
- Receipt persistence denial spike.
- Exporter backpressure that blocks receipt persistence.

Not counted against Chio error budget:

- Design-partner upstream API outage.
- PagerDuty public service outage.
- SOC collector outage.
- Planned design-partner maintenance window.

## Metrics and Alerts

The authoritative metric taxonomy lives in `crates/chio-metrics-spec`.
Operators should load the Prometheus rule pack under `deploy/prometheus/`:

- `chio-recording-rules.yml` defines p95 latency and error-ratio series for
  mediation, receipt writes, alert dispatch, SOC export, guard evaluation,
  federation hops, and anchor rounds.
- `chio-alert-rules.yml` defines dual-window burn alerts using 14.4x over 1
  hour and 6x over 6 hours, plus missing-data alerts for every counter used by
  those burn-rate rules. Receipt-write failures use the 99.9% objective;
  sidecar availability uses 99.5%; alert dispatch and SOC export use 99.0%.
- `ChioFailOpenSuspected` pages immediately because fail-open behavior violates
  the kernel safety contract.
- Alert labels `notification_route`, `opsgenie`, and `severity` are consumed by
  the existing `chio-siem` alerting path for PagerDuty and OpsGenie routing.

## Receipt and Export Objectives

Every evaluated request must end with one of these outcomes:

- Allow with a signed receipt.
- Deny with a signed receipt.
- Deny because receipt persistence failed.

Receipt persistence failure is fail-closed. It is not converted into allow.

OCSF export is the canonical audit export in P1. CEF preview lands in P3. SOC
export lag must stay under 5 minutes for P0/P1 incidents and under 30 minutes
for P2 incidents.

## Reporting

P4 records:

- p50, p95, and p99 mediation latency.
- Receipt-write success rate.
- Availability percentage.
- Error budget burn.
- MTTR for any P1 or P2 incident.
- Zero P0 incident attestation or P0 exception log.
