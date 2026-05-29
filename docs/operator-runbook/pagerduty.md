# PagerDuty Integration

This page records the PagerDuty operating contract for the healthcare
design-partner pilot.

## Service

- Service name: `chio-healthcare-pilot-prod`
- Endpoint: `https://events.pagerduty.com/v2/enqueue`
- Routing key owner during P0/P1: Chio operator account
- Routing key owner at production cutover: rotated to design-partner ops
- Minimum alert threshold: High
- Heartbeat cadence: weekly

The deployment configuration file is
`deploy/healthcare-design-partner/chio-siem-overrides.yaml`.

## Source Contract

`crates/chio-siem/src/alerting.rs` provides `PagerDutyBackend`, posts Events
API v2 payloads, and maps Chio severity into PagerDuty severity strings. The
pilot does not edit that source in P1.

The alert payload includes:

- short summary
- dedup key
- severity
- guard name
- tool name
- tool server
- serialized receipt in `custom_details`

The summary must remain PHI-free. It may name guard, reason, tool server, tool
name, receipt id, and policy hash. It must not carry patient identifiers or
clinical free text.

## Severity Overrides

The default source mapping treats secret, credential, token leak, egress,
firewall, exfil, and known-bad denies as Critical. The healthcare pilot adds a
deployment override:

- `pii_phi_exposure` -> Critical
- `patient_identifier_exposure` -> Critical
- `receipt_redaction_failure` -> Critical
- `pagerduty_payload_phi` -> Critical

These overrides are deployment configuration, not a chio-siem source change.

## Alert Types

| Alert | PagerDuty severity | Runbook |
|-------|--------------------|---------|
| `critical-deny` | critical | `incidents.md#p0-criteria` |
| `high-deny` | error | `incidents.md#p1-criteria` |
| `exporter-dlq-overflow` | error | `incidents.md#p1-criteria` |
| `trust-control-split-brain` | critical | `incidents.md#p0-criteria` |
| `pii_phi_exposure` | critical | `incidents.md#phi-guardrail` |
| `heartbeat` | info | this page |

## Test Alert

Use the weekly heartbeat workflow to verify:

1. Secret exists.
2. PagerDuty accepts Events API v2 payload.
3. Summary contains no PHI.
4. Dedup key is stable.
5. Chio service name routes to the correct escalation policy.

The heartbeat body uses synthetic values only. It does not serialize a real
receipt or patient data.

## Failure Handling

PagerDuty dispatch failure is an incident telemetry failure. It does not allow
tool traffic. Access decisions still follow authentication, policy, guard
evaluation, and receipt persistence.

If PagerDuty is down, keep mediation running fail-closed and route incident
coordination through the design-partner backup channel recorded outside this
repo.
