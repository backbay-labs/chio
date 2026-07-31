# Cognition Market: Research And Design Set

Working design set for the agent-to-agent cognition market (agents trading
solved cognition: verified fixes and negative results). This extends the
original spike memo and holds the architecture, mechanism, threat, and
planning documents as they mature.

Status: research/design phase on branch `research/cognition-market`. Nothing
here is a shipped protocol surface or a roadmap commitment.

Reading order:

1. [Spike memo](../agent-cognition-market.md) - the founding gap analysis:
   primitive-to-module map, Q1-Q8 verdicts with file-level evidence, minimal
   design, wedge recommendation (start with coding-agent verified fixes).
2. [ADR-0017](../../adr/ADR-0017-cognition-market-finding-artifacts.md)
   (Proposed) - the compressed decision set: finding artifacts, reveal as a
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

Companion executable spec: `crates/economy/chio-open-market/tests/cognition_market_flow.rs`
(two tests pass today; one ignored test names the missing reveal seams).

House discipline carried over from the spike: every codebase claim cites a
real path; speculative design is labeled; proof claims stay inside the
verifier boundary (`ChioProofClaims`); the code wins over the taxonomy.
