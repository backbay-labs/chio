# Healthcare Pilot PHI Policy

This page pins the M01 healthcare design-partner PHI and PII redaction policy.
It applies to request arguments, tool responses, signed receipts, PagerDuty
alerts, and audit-log exports.

## Guard Configuration

The pilot enables `ResponseSanitizationGuard` in both pre-invocation and
post-invocation paths.

Required deployment settings:

- `min_level: High` for zero-PHI shadow traffic.
- `action: Redact` for production cutover only after BAA chain sign-off.
- `action: Block` for any field that cannot be safely redacted.
- Custom patterns for design-partner identifiers, if supplied by the partner
  SOC team.

`High` is the safe M01 default because `spec/GUARDS.md` defines High as
definite PII/PHI, including SSN, credit card, and MRN. `Medium` may be enabled
after P3 schema negotiation for ICD-10 and email coverage.

## Receipt Fields

Treat these receipt fields as PHI-sensitive:

- `action.parameters`
- `action.parameter_hash`
- `decision.reason`
- guard evidence details
- `metadata`
- raw OCSF `raw_data`
- CEF `msg`
- CEF custom string values

`action.parameter_hash` is not PHI by itself, but it links to
`action.parameters` and must be handled as audit-sensitive evidence.

## PagerDuty Rule

PagerDuty summaries must contain only:

- receipt id
- checkpoint id
- policy hash
- guard id
- tool id
- redaction status

Never include patient name, MRN, SSN, ICD-10 code, address, phone number,
email, date of birth, or free-text clinical content in PagerDuty.

## Audit Export Rule

OCSF JSON remains the canonical export. CEF is the M01 SOC text format. Both
exports carry `redaction_status`.

Allowed `redaction_status` values:

- `clean`
- `redacted`
- `blocked`
- `unknown`

If redaction status is unknown for a PHI-bearing field, fail closed and open a
P1. If a PHI-bearing field reaches PagerDuty or an external SOC sink, open P0
and evaluate the canonical halt triggers.

## HIPAA Retention

The design-partner deployment retains Chio receipts for 6 years on its own
audit store. Chio M01 does not ship a long-retention storage tier. The export
schema records checkpoint ids so the design partner can bind retained receipts
to its HIPAA evidence chain.

## Cutover Checks

Production cutover requires:

1. Business Associate Agreement chain sign-off.
2. `ResponseSanitizationGuard` loaded at High or stricter.
3. Synthetic PHI input blocked or redacted as configured.
4. Synthetic deny receipt persisted with `redaction_status`.
5. OCSF export row accepted by the SOC sink.
6. CEF export row accepted by the SOC sink.
7. PagerDuty heartbeat confirmed PHI-free.

Until all checks pass, the pilot remains in zero-PHI shadow mode.
