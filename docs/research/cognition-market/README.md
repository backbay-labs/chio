# Cognition Market: Research And Design Set

Working design set for the agent-to-agent cognition market (agents trading
solved cognition: verified fixes and negative results). This extends the
original spike memo and holds the architecture, mechanism, threat, and
planning documents as they mature.

Status: the design set merged through PR #1025 at `9ec6814a2`. On this
execution branch, commits `015381975` through `04f5d3e66` implement M0/M1:
the pure `chio.finding.v1` type, validator, strict issuer verification,
public schema registration, normative protocol text, and golden fixture.
Commits `c679cce1c` and `e429963d8` provide and clarify the test-only
market-progress spec. The full workspace build, test, clippy, and formatting
gate passed at `88d4bde1f` under `umask 022`; the later spec-only edit passed
its focused test, clippy, and formatting checks, and later M1
diagnostic/documentation refinements through `ea105498d` passed the Finding
target and clippy.
Publish/search, evidence and liveness verification, reveal digest enforcement,
settlement, challenges, and status feeds remain M2+ design, not shipped market
surfaces or roadmap commitments.

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
(three tests pass; one ignored test clears M1 artifact integrity and names the
first missing reveal seam).

House discipline carried over from the spike: every codebase claim cites a
real path; speculative design is labeled; proof claims stay inside the
verifier boundary (`ChioProofClaims`); the code wins over the taxonomy.
