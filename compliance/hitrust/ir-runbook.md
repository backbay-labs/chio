# Chio HITRUST Incident Response Runbook

> **Status: internal readiness.** This runbook is documented; it has not
> yet been exercised, so first-cycle execution evidence is an open gap.

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**Owner:** Chio incident commander
**HIPAA reference:** 45 CFR 164.400-414

## Severity classes

| Severity | Trigger | Initial action | Notification posture |
|----------|---------|----------------|----------------------|
| Sev-1 | PHI exposure, key compromise, fail-open at a trust boundary, scoped revocation bypass | revoke affected capabilities, freeze evidence, page incident commander | legal review for HIPAA 45 CFR 164.404 clock |
| Sev-2 | audit-log export failure, evidence-bundle integrity failure, verifier drift | deny affected workflow, preserve receipts, open remediation ticket | customer notice if service or evidence integrity is affected |
| Sev-3 | documentation discrepancy, accepted-risk evidence gap, non-production issue | record in risk register and schedule correction | no external notice unless assessor requests |

## Response workflow

1. Triage the event and classify severity.
2. Freeze relevant receipt logs, audit-log exports, and deployment
   evidence.
3. Revoke affected capability grants or key material.
4. Preserve signed decision receipts and kernel logs.
5. Confirm whether PHI, ePHI, or other regulated data was involved.
6. Engage legal for HIPAA breach assessment under 45 CFR 164.400-414.
7. Notify the design-partner tenant according to the BAA channel.
8. Record root cause, remediation, and evidence hashes in the audit doc.

## HIPAA notification clock

If the event is a breach of unsecured protected health information, the
legal owner evaluates notification duties under 45 CFR 164.404, 164.406,
164.408, and 164.410. The runbook treats 60 calendar days as the outer
notification clock and starts the clock at discovery, not at root-cause
closure.

## Trust-boundary fail-closed actions

- Capability validation failure: deny access and preserve verifier
  evidence.
- Guard runtime failure: deny tool execution and record the guard error.
- Receipt signing failure: deny completion and hold the tool response.
- Audit-log export failure: continue local receipt retention and block
  external evidence promotion until export integrity is restored.
- Key custody incident: rotate keys, revoke old key ids, and attach the
  cutover receipt.

## Evidence record

Each incident record includes incident id, severity, affected tenant,
affected control rows, receipt hashes, containment time, notification
decision, remediation commit or runbook update, and closure approver.
