# On-Call Rotation and Escalation

This page records the weekly support rotation for the healthcare design-partner
pilot.

## Roles

| Role | Owner | Responsibility |
|------|-------|----------------|
| Primary on-call | Design-partner ops at cutover, Chio ops during P0/P1 | First responder for P0/P1 pages. |
| Secondary on-call | Chio kernel team | Chio sidecar, trust-control, receipt, and policy support. |
| SOC contact | Design-partner SOC | Audit export, OCSF row acceptance, and schema feedback. |
| Program lead | Chio program lead | Contract memo, BAA chain status, and escalation communications. |

## Weekly Cadence

Rotation changes weekly on Monday at 09:00 America/New_York unless the
design-partner ops calendar names a different handoff time. Do not use a
bi-weekly rotation during the 30-day observation window unless both ops teams
approve it in writing.

Each handoff includes:

1. PagerDuty primary on-call owner.
2. PagerDuty secondary on-call owner.
3. Chio sidecar deploy version.
4. Trust-control state store path.
5. SOC collector endpoint status.
6. Open P1/P2 incident summary.
7. Receipt checkpoint export status.
8. Next heartbeat due date.

## Escalation Policy

| Incident class | First page | Escalate after | Target |
|----------------|------------|----------------|--------|
| P0 | Primary on-call immediately | 15 minutes without ack | Secondary on-call and program lead |
| P1 | Primary on-call immediately | 60 minutes without ack | Secondary on-call |
| P2 | Ticket queue | Next business day | Primary on-call |

P0 acknowledgement target is 5 minutes. P1 acknowledgement target is 15
minutes. P2 is handled in the ticket queue.

## Backup Channel

The backup channel is stored outside this repo with the design-partner ops
contact list. This repository records process, not private phone numbers,
emails, or routing keys.

Use the backup channel when:

- PagerDuty Events API is unavailable.
- The PagerDuty service route is misconfigured.
- A P0 is open and primary on-call does not acknowledge in 15 minutes.
- Legal or BAA status changes require program-lead escalation.

## Shift Duties

Primary on-call duties:

- Acknowledge P0/P1 pages.
- Confirm fail-closed behavior before mitigation.
- Capture receipt ids and checkpoint ids.
- Keep PHI out of PagerDuty and GitHub.
- Update the incident record.

Secondary on-call duties:

- Debug Chio sidecar and trust-control behavior.
- Confirm policy and guard loading status.
- Review receipt persistence and export queues.
- Prepare follow-up patches if needed.

SOC contact duties:

- Confirm audit export receipt.
- Report schema mismatch.
- Confirm redaction status for synthetic rows.

## Handoff Exit

A shift cannot close handoff until:

- Open P0/P1 incidents have an owner.
- PagerDuty heartbeat status is known.
- SOC export status is known.
- Receipt checkpoint export status is known.
- The next primary on-call and secondary on-call are recorded.
