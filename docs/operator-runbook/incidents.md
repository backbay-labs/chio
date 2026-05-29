# Incident Classification and MTTR

This page classifies healthcare pilot incidents. It maps Chio-owned
mediation, trust-control, receipt, SOC export, and PagerDuty failures into
P0/P1/P2 response levels.

## Severity Table

| Class | Page target | MTTR target | Examples |
|-------|-------------|-------------|----------|
| P0 | Primary on-call within 5 minutes | Restore or fail-closed mitigation within 1 hour | PHI in PagerDuty summary, `pii_phi_exposure` deny with leaked payload, fail-open access, receipt persistence bypass, trust-control split-brain, capability revocation bypass. |
| P1 | Primary on-call within 15 minutes | Restore or fail-closed mitigation within 4 hours | Sidecar unavailable, receipt-write error rate over 0.1%, p99 mediation over 1 s with customer impact, SOC export queue loss, PagerDuty dispatch failure for high-severity denies. |
| P2 | Ticket queue next business day | Resolve within 2 business days | p95 latency above 250 ms for two 30-minute windows, heartbeat miss, documentation drift, synthetic SOC export failure in shadow mode. |

Any P0 that indicates fail-open access, scoped revocation bypass, capability
lineage break, or PHI exposure in a trust-boundary path is a halt candidate
under the current halt rules.

## P0 Criteria

Open P0 immediately for:

- `pii_phi_exposure` where PHI appears in a receipt, alert summary, SOC row, or
  unredacted guard evidence.
- Trust-control split-brain or conflicting single-writer state.
- Receipt persistence failure that allows the tool call.
- Revoked capability accepted by the sidecar.
- Policy load failure that allows traffic.
- Guard evaluation panic that allows traffic.
- Direct access to the wrapped MCP server bypassing the sidecar.
- PagerDuty alert content carrying patient identifiers.

P0 response must include containment, receipt evidence capture, and a decision
on whether a canonical halt trigger fired.

## P1 Criteria

Open P1 for:

- Sidecar readiness failure in production mode.
- Trust-control readiness failure in production mode.
- Receipt-write error rate above 0.1%.
- p99 mediation latency above 1 s with real tenant traffic.
- P0/P1 alert dispatch failures lasting more than 10 minutes.
- SOC export queue loss or unrecoverable audit row failure.
- Budget-store corruption or unrecoverable SQLite lock contention.

P1 response focuses on fail-closed restoration and operator communication.

## P2 Criteria

Open P2 for:

- p95 mediation latency above 250 ms for two consecutive windows.
- Weekly heartbeat missed once.
- SOC synthetic export failure in shadow mode.
- PagerDuty routing-key rotation overdue by less than 24 hours.
- Runbook entry drift from deployed config.
- Non-production `chio doctor` warning.

P2 work may stay in the ticket queue if no trust-boundary claim is at risk.

## MTTR Bookkeeping

Every P0/P1/P2 record includes:

1. Detection time.
2. Page or ticket time.
3. Human acknowledgement time.
4. Fail-closed containment time.
5. Customer-visible restore time.
6. Root-cause summary.
7. Receipt ids or synthetic evidence ids.
8. Follow-up owner.

The P4 30-day report records mean time to recovery for every P1 and P2. P0
must be zero for a green pilot closeout.

## PHI Guardrail

Never paste patient name, MRN, SSN, diagnosis code, address, date of birth, or
free-text clinical content into PagerDuty, GitHub, or the runbook. Use receipt
ids, checkpoint ids, policy hashes, and redaction status instead.
