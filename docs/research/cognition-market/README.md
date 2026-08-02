# Cognition Market: Research And Design Set

Working design set for the agent-to-agent cognition market (agents trading
solved cognition: verified fixes and negative results). This extends the
original spike memo and holds the architecture, mechanism, threat, and
planning documents as they mature.

Status: the cumulative implementation includes M0-M6, M8, and the M9
qualification boundary. The named bounded-profile integration, approved scoped
claims, audited assumptions, persisted transaction-passport golden, and
focused promoted-default gates pass. The production workspace build, Clippy,
formatting, code generation, formal proofs, and strict Rust verification pass.
The workspace test sweep remains blocked by five receipt-retention repair
fixtures that fail identically on the rebased `origin/main` baseline at
`a768ff73a`; the stack-owned tests pass. M7 stays conditional and unbuilt
because no bilateral seller/buyer deployment has triggered its ADR-C
prerequisite. Usage-gated stochastic R&D extensions also remain unbuilt.

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

Companion executable spec: `crates/economy/chio-open-market/tests/cognition_market_flow.rs`.
The single-operator flow is implemented in control-plane exits; the separate
`cognition_market_cross_org_escrow` test remains ignored and fail-first until
M7's bilateral-demand trigger is met.

House discipline carried over from the spike: every codebase claim cites a
real path; speculative design is labeled; proof claims stay inside the
verifier boundary (`ChioProofClaims`); the code wins over the taxonomy.
