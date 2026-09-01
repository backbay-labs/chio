# Cognition Market: Research And Design Set

Implemented design and qualification set for the bounded agent-to-agent
cognition market (agents trading solved cognition: verified fixes and negative
results). This extends the original spike memo and retains the architecture,
mechanism, threat, planning, and release-boundary records.

Status: the cumulative implementation includes M0-M6 and M8-M10. M11 adds a
dark hosted listener, tenant-isolated PostgreSQL repositories, strict edge
authentication, remote custody and settlement ports, Firecracker workers,
hosted SDKs, deployment contracts, and exact-candidate qualification tooling.
It does not activate public or customer traffic, and SQLite remains local-only.
The named
bounded-profile integration, approved scoped claims, audited assumptions,
persisted transaction-passport golden, and
focused promoted-default gates pass on the recorded candidate. The focused
gate also records a captured single-operator dogfood purchase of the verified
same-second revocation-cursor fix found during closeout. Release
qualification additionally requires the complete local gate set and hosted CI
and Release Qualification workflows to pass on the exact promoted commit, with
the hosted evidence bundle validated before any release decision. M7 stays
conditional and unbuilt because no bilateral seller/buyer deployment has
triggered its ADR-C prerequisite. Usage-gated stochastic R&D extensions also
remain unbuilt.

Reading order:

1. [Spike memo](../agent-cognition-market.md) - the founding gap analysis:
   primitive-to-module map, Q1-Q8 verdicts with file-level evidence, minimal
   design, wedge recommendation (start with coding-agent verified fixes).
2. [ADR-0017](../../adr/ADR-0017-cognition-market-finding-artifacts.md)
   - the accepted single-operator decision set: finding artifacts, reveal as a
   governed tool call, predeclared fabrication slash lane, status feeds.
3. [ARCHITECTURE.md](ARCHITECTURE.md) - components, artifact schemas, flows,
   enforcement points, deployment topologies, crate-level integration map.
4. [MECHANISMS.md](MECHANISMS.md) - pricing/elicitation design and the
   prior-art survey (fair exchange, data markets, peer prediction,
   negative-results economics, market-based control), with citations.
5. [THREAT-MODEL.md](THREAT-MODEL.md) - adversaries, attack catalog with
   mitigations mapped to shipped primitives, residual-risk register.
6. [PLAN.md](PLAN.md) - milestone ladder, per-milestone work breakdown with
   crates and verification, formal/conformance hooks, decision backlog
   (future ADRs), risk register.
7. [Closeout](CLOSEOUT.md) - merged milestone inventory, exact-candidate
   qualification contract, scoped claims, audited assumptions, and M7
   disposition.
8. [M11 hosted-production plan](plans/2026-08-28-M11-hosted-production.md) -
   canonical deployment profile, tenant durability, remote custody,
   Firecracker isolation, qualification, and canary rollback.

Companion executable spec: `crates/economy/chio-open-market/tests/cognition_market_flow.rs`.
The single-operator flow is implemented in control-plane exits; the separate
`cognition_market_cross_org_escrow` test remains ignored and fail-first until
M7's bilateral-demand trigger is met.

House discipline carried over from the spike: every codebase claim cites a
real path; speculative design is labeled; proof claims stay inside the
verifier boundary (`ChioProofClaims`); the code wins over the taxonomy.
