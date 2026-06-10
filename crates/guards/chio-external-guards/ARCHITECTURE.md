# chio-external-guards Architecture

`chio-external-guards` owns concrete HTTP-backed guard integrations for cloud
guardrails and threat-intelligence services. It keeps provider-specific request
construction, response parsing, endpoint validation, and egress contracts out of
the generic guard infrastructure.

## Boundaries

- `chio-guards` owns the generic async adapter, retries, caching, token
  buckets, and circuit breaker.
- `chio-egress-contract` owns dispatch-time HTTP egress validation and pinned
  DNS checks.
- This crate owns provider adapters plus `ScopedAsyncGuard`, the synchronous
  bridge that lets the kernel evaluate an async external guard.

## Trust Invariants

- External guard URLs are validated before dispatch. Non-public targets are
  denied except explicit loopback test fixtures.
- HTTP requests are sent through an egress contract built from the validated
  endpoint authority and scheme.
- Provider responses fail closed on transport errors, malformed denial data, or
  explicit provider intervention signals.
- Tool-scoped guards return `Allow` outside their configured scope, so scope
  parsing must be conservative. Blank and padded patterns are normalized before
  matching so whitespace-only configuration cannot disable a guard.

## Testing Focus

Unit tests cover the synchronous bridge and local endpoint validation behavior.
Integration tests use local HTTP fixtures for cloud guardrails and threat-intel
providers so request shape, response classification, caching, and failure
mapping remain deterministic.
