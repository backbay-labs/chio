# E9: HA Trust-Control Reliability

## Status

Proposed.

## Suggested issue title

`E9: make trust-control replication and failover deterministic under load`

## Problem

Chio now has a real trust-control service with shared authority, revocation, receipt, and budget state.

What it does not yet have is enough determinism to treat that path as fully reliable under load.

The current review found:

- a full-workspace failure on clustered leader-side budget visibility
- an isolated rerun that passed, which strongly suggests timing-sensitive or flaky behavior rather than a missing feature

That makes this epic a release blocker because the trust plane is now central to remote hosting, revocation guarantees, and shared budget semantics.

## Outcome

By the end of E9:

- leader-routed writes have explicit read-after-write visibility guarantees
- budget, receipt, revocation, and authority replication are deterministic enough for repeated full-suite runs
- failover behavior is observable and testable rather than timing-sensitive
- the trust-control cluster can be treated as a stable substrate for later hosted-runtime work

Concrete write guarantee:

- when a mutating request succeeds, the elected leader can immediately read its own durable state and observe the mutation that justified the response
- that leader guarantee is per request: it refers to the leader that actually handled and verified the successful write, not a node chosen earlier in the test or rollout
- the same guarantee applies whether the caller hit the leader directly or hit a follower that forwarded to the leader
- follower read convergence remains a separate replication concern and is not implied by the initial success response

## Scope

In scope:

- leader-routed write visibility semantics
- replication ordering and cursor correctness
- budget-state determinism
- failover and leader-change behavior
- control-plane observability needed to debug cluster convergence
- stress and repeatability coverage for the trust-control path

Out of scope:

- full consensus replication
- multi-region federation
- richer quota products beyond the current invocation-budget model

## Primary files and areas

- `crates/chio-control-plane/src/trust_control.rs`
- `crates/chio-kernel/src/budget_store.rs`
- `crates/chio-kernel/src/authority.rs`
- `crates/chio-kernel/src/receipt_store.rs`
- `crates/chio-kernel/src/revocation_store.rs`
- `crates/chio-cli/tests/trust_cluster.rs`
- `crates/chio-cli/tests/trust_revocation.rs`
- `docs/HA_CONTROL_AUTH_PLAN.md`

## Proposed implementation slices

### Slice A: flake reproduction and observability

Requirements:

- make the current clustered budget-visibility failure reproducible under stress
- expose enough cluster status to distinguish routing, persistence, and repair-sync failures

Responsibilities:

- avoid patching only the currently observed test symptom
- make future trust-plane regressions cheaper to localize

### Slice B: write visibility contract

Requirements:

- define what a successful forwarded control-plane write guarantees
- ensure budget increments, revocations, authority rotations, and receipt ingestion are durably visible in the leader's local durable view before success is returned

Responsibilities:

- keep semantics explicit for both leader and follower callers
- prefer simple leader-visible read-after-write guarantees over ambiguous eventual behavior where correctness matters
- keep follower replication wording separate so the API contract does not over-promise cluster-wide convergence

### Slice C: replication ordering and cursor hardening

Requirements:

- remove ordering ambiguities in budget delta propagation
- harden cursor design so repeated updates under load do not disappear or reorder incorrectly

Responsibilities:

- make ordering rules stable enough for both production behavior and tests
- document the monotonic fields that replication actually trusts

### Slice D: failover and repeated-run coverage

Requirements:

- add stress tests for leader failover, follower write forwarding, and post-failover visibility
- prove full-workspace stability across repeated runs, not only one green run

Responsibilities:

- keep fast tests separate from slower cluster stress coverage
- ensure CI can surface flake rates rather than only binary pass/fail

## Task breakdown

### `T9.1` Reproduce and instrument the current flake

- add a targeted repeat-run or stress harness around `trust_cluster`
- capture cluster state, leader identity, and budget cursor state on timeout
- make leader and follower visibility failures distinguishable in output

### `T9.2` Define and implement control-plane write semantics

- document read-after-write expectations for forwarded writes
- align handler behavior with that contract
- ensure returned success means the leader's durable local read path already reflects the mutation

### `T9.3` Harden replication ordering

- audit budget delta cursor and ordering semantics
- remove any timestamp granularity or cursor edge cases that can hide updates
- add regression tests for repeated same-key updates and fast failover windows

### `T9.4` Add failover and convergence coverage

- stress budget visibility before and after leader failover
- validate authority, revocation, and receipt convergence under the same conditions
- gate the full workspace on reliable cluster behavior

## Dependencies

- depends on E7
- should complete before E10 relies on the clustered trust plane for harder hosted-runtime guarantees

## Risks

- overfitting to one observed timeout instead of the actual consistency contract
- adding synchronization that improves determinism but quietly harms availability or throughput
- conflating leader-routed semantics with full distributed consensus

## Mitigations

- define the external contract before changing internals
- test the same guarantees through both leader and follower entry points
- keep the HA model explicit about what it does and does not promise

## Acceptance criteria

- `cargo test --workspace` is green in repeated runs without trust-cluster flakes
- targeted clustered stress coverage proves that successful leader-originated and follower-forwarded writes are immediately visible through a leader read
- failover preserves subsequent correctness for authority, revocations, receipts, and budgets
- trust-control APIs document that "stored", "revoked", "rotated", and "allowed" mean leader-visible durable state, while follower convergence remains eventual

## Definition of done

- implementation merged
- flaky trust-control behavior is either eliminated or reduced to an explicitly documented non-goal with tests matching that contract
- HA docs updated to describe the leader-visible write guarantee and its replication boundary
