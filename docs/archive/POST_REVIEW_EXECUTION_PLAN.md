# Post-Review Execution Plan

## Purpose

This document turns the current project review findings into an execution sequence.

The repo is no longer blocked on "can Chio speak enough MCP to be interesting?"

The new blocking question is:

- can Chio become deterministic, security-complete, and simple enough to operate and adopt?

This plan assumes the current repo state described in:

- [research/01-current-state.md](../research/01-current-state.md)
- [research/03-gap-analysis.md](../research/03-gap-analysis.md)
- [EXECUTION_PLAN.md](../operations/EXECUTION_PLAN.md)
- [epics/README.md](epics/README.md)

## What The Review Confirmed

- conformance is materially real: the live JS and Python harness waves are green
- the main risks are no longer basic protocol parity gaps
- the dominant remaining work is operational determinism, security-boundary completion, remote-hosting hardening, async ownership semantics, and product-surface simplification

## Findings To Address

### F1: HA trust-control is not deterministic enough yet

- `cargo test --workspace` was not reliably green under full load
- the visible failure was leader-side budget visibility in the clustered trust-control path
- the likely class of problem is timing-sensitive write visibility, replication ordering, or flaky failover semantics rather than total feature absence

### F2: roots exist as metadata, not as a hard security boundary

- roots are negotiated, refreshed, and available in session state
- roots are not yet enforced for filesystem-shaped tool access or filesystem-backed resources

### F3: policy authoring is still split

- the HushSpec path is richer and closer to canonical runtime truth
- the operator-facing YAML path still exposes a smaller guard surface
- this is now a product and operator simplicity problem, not only a compiler problem

### F4: remote hosting is useful but not deployment-hard

- authenticated remote Streamable HTTP hosting exists
- resumability, standalone GET/SSE streams, and broader hosted ownership are still missing

### F5: long-running semantics still have transport-dependent edge cases

- tasks, streams, cancellation, and async completion behavior are stronger than before
- they are not yet fully uniform across direct, wrapped, stdio, and remote paths

## Program Goals

The next execution cycle should optimize for five outcomes:

1. deterministic clustered trust behavior under load
2. enforce roots as a real trust boundary
3. harden hosted runtime semantics
4. unify async ownership semantics across transports
5. simplify the operator and developer surface

## Proposed Next Epics

| Epic | Name | Main finding addressed | Depends on |
| --- | --- | --- | --- |
| `E9` | HA Trust-Control Reliability | `F1` | `E7` |
| `E10` | Remote Runtime Hardening | `F4` | `E7`, `E9` recommended |
| `E11` | Cross-Transport Concurrency Semantics | `F5` | `E6`, `E7` |
| `E12` | Security Boundary Completion | `F2` | `E2`, `E5` |
| `E13` | Policy and Adoption Unification | `F3` | `E2`, `E8`; benefits from `E12` |
| `E14` | Hardening and Release Candidate | close-out | `E9` through `E13` |

Issue-ready specs for `E9` through `E14` live in [epics/README.md](epics/README.md).

## Recommended Execution Order

### Batch 1: regain determinism and complete the missing boundary

- `E9` first, because full-workspace reliability is a gating problem
- `E12` design can begin in parallel, but enforcement should land only after root semantics are frozen

### Batch 2: harden hosted and async behavior

- `E10` and `E11` should overlap once `E9` has stabilized trust/control assumptions
- `E10` owns remote transport and hosted-runtime lifecycle
- `E11` owns task, stream, cancellation, and async-completion semantics across all transports

### Batch 3: simplify what operators and adopters actually touch

- `E13` should converge policy, docs, examples, and authoring ergonomics after the runtime and security semantics above are stable enough

### Final wave: release qualification

- `E14` should remain a true release-quality epic, not a placeholder for unfinished core behavior

## Finding-To-Epic Mapping

| Finding | Primary epic | Secondary epics |
| --- | --- | --- |
| leader-side budget visibility / trust-control flake | `E9` | `E10`, `E14` |
| roots not enforced | `E12` | `E13`, `E14` |
| split policy surface | `E13` | `E12` |
| remote runtime not deployment-hard | `E10` | `E11`, `E14` |
| transport-dependent long-running edge cases | `E11` | `E10`, `E14` |

## E9 Qualification Commands

The regular CI lane stays the workspace suite:

- `cargo test --workspace`

The repeat-run proving path for clustered trust-control stays as an explicit qualification lane rather than a normal CI-on-every-PR step:

- `cargo test -p chio-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture`

That qualification command reruns the in-repo authority, receipt, revocation, budget, and leader-failover scenario five times through `trust_cluster.rs`.

## Milestone Gates

### Gate G1: workspace stability for E9

- `cargo test --workspace` is green in the normal CI lane, including the default single-run `trust_control_cluster_replicates_state_and_survives_leader_failover` coverage.
- `cargo test -p chio-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture` is green in E9 qualification, repeating the authority, receipt, revocation, budget, and leader-failover path five times in-repo.
- "Workspace stability" for this gate means no known flaky trust-control path remains in the clustered control-plane flow above; broader release hardening still belongs to `E14`.

### Gate G2: roots are enforceable

- root-aware denials exist for filesystem-shaped tool access
- filesystem-backed resource reads outside roots fail closed
- deny receipts preserve enough evidence to explain which root boundary triggered

### Gate G3: hosted runtime is resumable and reconnect-safe

- remote clients can reconnect to active sessions without losing ownership semantics
- GET-based SSE stream support exists where the compatibility surface expects it
- stale-session and drain rules are documented and tested

### Gate G4: async semantics are transport-consistent

- `tasks-cancel` is no longer `xfail`
- task, stream, and cancellation semantics are consistent across direct, wrapped, stdio, and remote paths
- durable async completion and late-event handling no longer depend on request-local scratch state

### Gate G5: policy and adoption are coherent

- one policy path is clearly documented as canonical
- all shipped guards are reachable through the supported path
- migration docs and a higher-level authoring surface exist for native Chio services

## Non-Goals For This Cycle

This execution cycle should not quietly absorb:

- consensus or Byzantine distributed-control design
- full multi-region trust replication
- theorem-prover completion for the full draft spec
- performance micro-optimization before semantic stability

Those may matter later, but they are not the next bottlenecks.

## Primary Artifacts

- [epics/E9-ha-trust-control-reliability.md](epics/E9-ha-trust-control-reliability.md)
- [epics/E10-remote-runtime-hardening.md](epics/E10-remote-runtime-hardening.md)
- [epics/E11-cross-transport-concurrency-semantics.md](epics/E11-cross-transport-concurrency-semantics.md)
- [epics/E12-security-boundary-completion.md](epics/E12-security-boundary-completion.md)
- [epics/E13-policy-and-adoption-unification.md](epics/E13-policy-and-adoption-unification.md)
- [epics/E14-hardening-and-release-candidate.md](epics/E14-hardening-and-release-candidate.md)

## Bottom Line

Chio has already crossed the line from "idea" to "real system."

The next step is not adding more breadth for its own sake.

The next step is turning the existing breadth into something deterministic, enforceable, and cheap to adopt.
