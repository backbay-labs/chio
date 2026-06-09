# chio-siem Architecture

## Boundary

`chio-siem` is the SIEM export pipeline for Chio receipt audit logs. It reads kernel receipts through an explicit read boundary, wraps them as `SiemEvent` values, and fans them out to Splunk, Elasticsearch, Datadog, Sumo Logic, OCSF, CEF, webhook, alerting, and other exporter surfaces.

The manager owns polling configuration, cursor advancement, retry backoff, rate limiting, and dead-letter behavior. Invalid polling configuration must fail before the database is opened so a bad operator setting cannot start a hot loop or partial exporter.

`SiemEvent` keeps authorization semantics separate from raw receipt decisions. A receipt is exported as authorized only when its id, signature, parameter hash, and trusted kernel signer all verify.

This crate does not sign receipts, mutate revocation state, issue capabilities, enforce runtime policy, or own the receipt database schema. Its authority is read-only audit export plus egress to configured SIEM endpoints.

## Internal Surfaces

- `manager` owns polling, cursor advancement, exporter fan-out, retry, and dead-letter routing.
- `event` maps verified receipt material into SIEM-facing event records.
- `exporter` defines the async exporter contract and failure taxonomy.
- `exporters/*` adapt the common event model to Splunk HEC, Elasticsearch, Datadog, Sumo Logic, OCSF, CEF, and webhook protocols.
- `alerting`, `ratelimit`, `dlq`, and `redaction` keep operational controls separate from event construction.

## Trust Invariants

- SIEM polling requires explicit admin receipt read authority before opening the
  receipt database.
- Tenant-scoped read contexts are invalid for the manager because SIEM export
  is an operator-wide audit surface.
- Receipt authorization labels require verified id, signature, action parameter
  hash, and trusted kernel signer.
- Exporter endpoint validation must reject malformed URLs, implicit credentials,
  and unauthorized egress before dispatch.
- Dead-letter entries must preserve enough failure context for audit replay
  without leaking configured SIEM credentials.
- Rate limits and retry budgets must bound exporter failure loops.

## Verification Focus

Tests should prove the read boundary rejects tenant-scoped contexts, event mapping does not overstate authorization, exporter adapters serialize their protocol payloads deterministically, retry and rate-limit behavior is bounded, and dead-letter records retain sanitized failure evidence.

The integration tests in this crate intentionally use local mock HTTP servers for exporter paths. In sandboxes that deny local TCP bind, those tests must be treated as environment-blocked rather than silently skipped.

## Improvement Target

The next useful modularization step is to keep exporter endpoint validation centralized so Splunk, Elasticsearch, Datadog, Sumo Logic, and webhook exporters share the same egress-contract enforcement instead of drifting independently.
