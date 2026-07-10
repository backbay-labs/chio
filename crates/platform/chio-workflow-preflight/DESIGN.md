# chio-workflow-preflight Design

## D9 Crate Home Decision

`chio-workflow-preflight` stays in `crates/platform` because workflow preflight is a planning verifier shared by CLI and proof fixtures. It evaluates whether a planned workflow can proceed without claiming live runtime authority.

The default home considered was `chio-workflow`. That crate owns workflow execution surfaces. This crate remains separate so read-only planning checks can be used in proof generation without pulling execution state or runtimes.

## Boundary

This crate owns workflow preflight plan and report validation. It does not execute workflows, mint capabilities, dispatch tools, or mutate runtime stores.

## Invariants

Preflight reports are planning evidence only. Accepted checks can support proof claims about bounded child scope and planning-only status, but they cannot authorize side effects.
