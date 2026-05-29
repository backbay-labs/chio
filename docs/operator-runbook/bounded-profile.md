# Bounded Operational Profile

This page imports the bounded release claim from
`docs/release/OPERATIONS_RUNBOOK.md` lines 13-26 and applies it to the
healthcare design-partner pilot. The constant name for this release gate is
BOUNDED_OPERATIONAL_PROFILE.

## Imported Ship Boundary

The current ship boundary is:

- **trust-control:** local or leader-local single-writer truth with
  deterministic leader selection and eventual repair; not consensus-backed HA
- **hosted auth:** single-node or dedicated-per-session hosted admission with
  explicit sender-constrained access tokens where available; static bearer,
  non-`cnf`, and `shared_hosted_owner` paths are compatibility-only
- **monetary budgets:** single-node atomic on one SQLite store; clustered mode
  admits the documented overrun bound and is not distributed-linearizable
- **receipts and checkpoints:** signed local audit evidence with checkpoint
  export and inclusion-proof material; not public transparency-log semantics

## Pilot Interpretation

For this pilot, the imported boundary means:

- Trust-control has one tenant-local writer for capability, revocation,
  receipt, and budget state.
- Hosted admission uses a dedicated healthcare-pilot sidecar endpoint.
- Sender-constrained tokens are required when the design-partner auth surface
  supports `cnf`.
- Static bearer or non-`cnf` compatibility auth is allowed only for zero-PHI
  shadow traffic.
- Monetary budgets are enforced on one SQLite store and are not claimed to be
  distributed-linearizable.
- Receipts are local audit evidence that can be checkpointed and exported.
- No public transparency-log claim is made.
- No consensus-backed HA claim is made.

## Explicit Non-Claims

The pilot does not claim:

- Multi-tenant isolation.
- Multi-region BFT safety.
- Public certification marketplace evidence.
- Public transparency-log inclusion.
- Consensus-backed trust-control availability.
- Distributed-linearizable monetary budgets.
- HIPAA certification by this pilot alone.

These are outside the current release boundary. HITRUST i1 evidence consumes
this runbook only after the pilot closes.

## Operating Rules

Operators must keep these rules true:

1. The deployment remains single-tenant.
2. `chio trust serve` starts before `chio mcp serve-http`.
3. The sidecar denies traffic when policy, guard evaluation, authentication,
   or receipt persistence fails.
4. The wrapped MCP server is not exposed directly to agents.
5. PagerDuty failures are incident telemetry failures, not access grants.
6. SOC export failures are incident telemetry failures, not access grants.
7. PHI-bearing production traffic waits for Business Associate Agreement chain
   sign-off.

## Acceptance Checks

Before cutover, record:

- `chio doctor` against the sidecar.
- Synthetic allow receipt persisted locally.
- Synthetic deny receipt persisted locally.
- SOC export accepted a synthetic audit row.
- PagerDuty service `chio-healthcare-pilot-prod` accepted a test event.
- Design-partner ops accepted the single-writer and sender-constrained token
  constraints.
