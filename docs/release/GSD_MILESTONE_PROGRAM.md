# GSD Milestone Program

This document maps the remaining Chio roadmap into GSD milestone cycles.

## Operating Rules

- `.planning/` is the execution source of truth for the active milestone.
- [STRATEGIC_ROADMAP.md](../STRATEGIC_ROADMAP.md), [FULL_VISION_EXECUTION_PROGRAM.md](FULL_VISION_EXECUTION_PROGRAM.md), and [V2_EXECUTION_BACKLOG.md](V2_EXECUTION_BACKLOG.md) remain the strategic reference set.
- Every phase exit must keep `cargo test --workspace` green.
- Every milestone exit must run audit before completion.
- Do not open the next milestone until the current milestone has either shipped or been explicitly re-scoped.
- Local Codex GSD subagents are intentionally pinned through the Codex skill adapter to `gpt-5.4` with `xhigh` reasoning unless explicitly overridden later.

## Milestone Cut

### v2.1 Federation and Verifier Completion

**Why this is one milestone:**
It finishes the portable-trust lane already shipped in alpha and closes the missing enterprise and verifier semantics before broader ecosystem and launch work.

**Scope:**
- enterprise federation administration beyond bearer/JWT
- verifier policy distribution and replay-resistant challenge state
- multi-issuer passport composition semantics
- shared remote evidence references and cross-org analytics

**Execution phases:**
- Phase 13: Enterprise Federation Administration
- Phase 14: Portable Verifier Distribution and Replay Safety
- Phase 15: Multi-Issuer Passport Composition
- Phase 16: Cross-Org Shared Evidence Analytics

### v2.2 A2A and Ecosystem Hardening

**Scope:**
- remaining A2A auth matrix
- deeper long-running lifecycle and task semantics
- certification registry/storage
- broader ecosystem and conformance hardening

### v2.3 Production and Standards

**Scope:**
- protocol specification v2
- deployment/runbook/performance hardening
- production qualification and standards submission

### v2.4 Commercial Trust Primitives

**Scope:**
- insurer-facing data feed
- marketplace trust primitives
- reputation federation
- broader networked trust surfaces

## GSD Command Sequence

### Current milestone execution

1. `\$gsd-progress`
2. `\$gsd-plan-phase 13`
3. `\$gsd-execute-phase 13`
4. `\$gsd-plan-phase 14`
5. `\$gsd-execute-phase 14`
6. Continue through phases 15 and 16 the same way

### Milestone closeout

1. `\$gsd-audit-milestone`
2. If gaps exist: `\$gsd-plan-milestone-gaps`
3. Execute any gap phases
4. `\$gsd-complete-milestone 2.1`

### Starting the next milestone

1. `\$gsd-new-milestone "v2.2 A2A and Ecosystem Hardening"`
2. Approve milestone requirements and roadmap
3. `\$gsd-plan-phase 17`

## Notes

- Do not use `\$gsd-autonomous` for the entire remaining vision in one shot.
- It is reasonable to use `\$gsd-autonomous --from 13` inside `v2.1` only after the milestone roadmap is reviewed and accepted.
- Keep milestone boundaries outcome-based, not calendar-based.
