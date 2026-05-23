# Observability Guide

Chio treats observability as a supported operator contract, not a best-effort
debugging convenience. The goal is that an operator can identify trust,
lifecycle, federation, and evidence problems without reading Rust source or
replaying raw traffic by hand.

> Version posture: this is a pre-release operator guide. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. Current protocol posture is v1-only.

## Principles

- fail closed and report why
- expose authoritative state, not just a binary ready/unready flag
- keep admin and health responses additive so new fields do not break old
  tooling
- leave invalid or unavailable registry state visible for diagnostics rather
  than hiding it

## Core Health Surfaces

### Trust-Control

`chio trust serve` exposes:

- `GET /health`
- `GET /v1/authority`
- `GET /v1/internal/cluster/status`

`/health` is the top-level production snapshot. It reports:

- `authority`: whether authority state is configured and readable, current
  backend, key generation, and trusted-key count
- `stores`: whether receipts, revocations, budgets, and verifier-challenge
  persistence are configured
- `federation.enterpriseProviders`: configured/available state plus counts for
  total, enabled, validated, invalid, and the currently loaded snapshot
- `federation.verifierPolicies`: configured/available state plus total and
  active policy counts, including the currently loaded runtime view
- `runtimeAssurancePolicyConfigured`: whether trust-control is currently
  enforcing runtime-assurance issuance tiers from policy
- `federation.certifications`: configured/available state plus active,
  superseded, and revoked certification counts
- `cluster`: peer totals, healthy/unhealthy/unknown counts, and the current
  leader/self URLs

Use `/v1/internal/cluster/status` when the problem is replica convergence or
leader visibility rather than general service health.

### Hosted MCP Edge

`chio mcp serve-http` exposes:

- `GET /admin/health`
- `GET /admin/authority`
- `GET /admin/sessions`
- `GET /admin/sessions/{session_id}/trust`

`/admin/health` reports the current runtime envelope:

- server identity and release metadata
- auth mode, scopes, and admin-token presence
- whether the edge is local-only or proxied to trust-control
- receipt, revocation, authority, budget, and session-tombstone store
  configuration
- active and terminal session counts plus lifecycle-policy timings
- authority status
- identity-federation and enterprise-provider summary
- OAuth metadata availability

`/admin/sessions` is the main lifecycle triage view. It returns active and
terminal sessions with:

- `sessionId`
- `authContext`
- `lifecycle`
- `ownership`
- capability ids plus issuer and subject keys

`/admin/sessions/{session_id}/trust` is the targeted trust-debug view for one
session. Use it when one user or principal is denied while the edge otherwise
looks healthy.

## Federation And Trust Diagnostics

Use the registry and federation surfaces directly instead of relying on log
scraping:

- `GET /v1/federation/providers`
- `GET /v1/federation/providers/{provider_id}`
- `GET /v1/certifications`
- `GET /v1/certifications/resolve/{tool_server_id}`
- `GET /v1/federation/evidence-shares`
- `GET /v1/reports/operator`
- `GET /v1/reports/behavioral-feed`
- `GET /v1/reports/settlements`
- `POST /v1/reputation/compare/{subject_key}`

These surfaces intentionally preserve invalid or incomplete state:

- provider records keep `validation_errors`
- verifier-policy counts distinguish configured versus available versus active
- certification status distinguishes `active`, `superseded`, and `revoked`
- shared-evidence reports keep upstream provenance instead of flattening remote
  history into local receipts

## A2A Diagnostics

`chio-a2a-adapter` does not ship a separate HTTP health server. Its production
diagnostic contract is:

- fail-closed discovery and invocation errors with explicit reason strings
- durable task-correlation state through `with_task_registry_file(...)`
- follow-up rejection when the task id, interface, tenant, binding, or tool
  context no longer matches recorded state

When long-running A2A follow-up must survive restart, treat the task registry
file as operator state and back it up with the rest of the deployment.

Common operator-visible A2A error classes:

- unsupported auth scheme declared by Agent Card
- required tenant / skill / interface-origin mismatch under partner policy
- missing `stateTransitionHistory` support for `history_length`
- malformed task, status-update, or artifact-update payloads
- unknown or mismatched follow-up task id after restart

## Triage Table

| Symptom | First surface | What to look for |
| --- | --- | --- |
| Trust-control is up but federation flows fail | `/health` | `federation.enterpriseProviders`, `verifierPolicies`, `certifications`, `issuancePolicyConfigured` |
| Cluster writes appear to vanish | `/health`, `/v1/internal/cluster/status` | `leaderUrl`, unhealthy peers, peer last-error counts |
| Hosted edge accepts auth but sessions are inconsistent | `/admin/health`, `/admin/sessions` | auth mode, session counts, lifecycle timings, missing session tombstones |
| One session denies unexpectedly | `/admin/sessions/{session_id}/trust` | subject key, auth context, per-capability revocation status |
| Passport or shared-evidence comparison looks wrong | `/v1/reputation/compare/{subject_key}` | subject mismatch, per-credential drift, shared-evidence provenance |
| Evidence export seems incomplete | `/v1/reports/operator`, `/v1/federation/evidence-shares` | checkpoint coverage, export readiness, referenced upstream shares |
| Behavioral feed or runtime assurance looks wrong | `/health`, `/v1/reports/behavioral-feed`, `/v1/reports/operator` | `runtimeAssurancePolicyConfigured`, feed filter scope, signed export envelope, settlement/governed breakdown |
| Certification status is unclear | `/v1/certifications/resolve/{tool_server_id}` | active vs superseded vs revoked |
| A2A follow-up after restart fails | task-registry file plus adapter error | task id was never recorded or binding/tenant/tool context no longer matches |

## Operational Rules

- treat `/health` and `/admin/health` as the primary entrypoints for smoke
  checks and alert enrichment
- treat `/admin/sessions` and session trust detail as the primary incident
  drill-down for hosted edges
- prefer registry and report APIs over interpreting SQLite tables directly
- when a response shows `configured: true` and `available: false`, assume an
  operator-state or filesystem problem before assuming a policy bug

See [OPERATIONS_RUNBOOK.md](./OPERATIONS_RUNBOOK.md) for deployment and
backup/restore procedures that use these surfaces directly.
