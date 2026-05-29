# Chio Execution Plan

## Purpose

This document turns [ROADMAP_V1.md](../archive/ROADMAP_V1.md) into an execution plan.

It answers:

- what gets built first
- what can run in parallel
- which crates or modules are touched
- what each milestone must prove before the next one starts
- what the first 30, 60, and 90 days should look like

The roadmap describes destination and phases.

This plan describes execution order, dependency management, and deliverable boundaries.

Initial execution artifacts:

- ADRs: [adr/README.md](../adr/README.md)
- issue-ready epics: [epics/README.md](../archive/epics/README.md)
- post-review closing plan: [POST_REVIEW_EXECUTION_PLAN.md](../archive/POST_REVIEW_EXECUTION_PLAN.md)

## Planning Assumptions

- the repo remains a Rust workspace
- `chio-core`, `chio-kernel`, `chio-guards`, `chio-policy`, `chio-manifest`, and `chio-mcp-adapter` remain the base crates
- early work should prefer modules inside existing crates over immediate crate explosion
- compatibility at the edge and stronger trust in the core remain the primary strategy
- HushSpec becomes the canonical policy path before `v1`

## Success Conditions

Execution is on track if all of the following become true in order:

1. the runtime has a session abstraction instead of only ad hoc request handling
2. compiled HushSpec is the real runtime contract
3. a stock MCP client can talk to Chio for tool workflows
4. Chio supports resources and prompts as first-class concepts
5. nested sampling and elicitation flows are implemented safely
6. long-running operations have correct progress, cancellation, and receipt semantics
7. remote trust no longer depends on in-memory state
8. compatibility claims are backed by fixtures and conformance tests

## Program Structure

Use five execution lanes.

| Lane | Purpose | Primary repo areas |
| --- | --- | --- |
| `protocol` | session model, JSON-RPC, MCP edge, message evolution | `chio-core`, `chio-kernel`, new edge modules |
| `policy` | HushSpec runtime integration and policy fixtures | `chio-policy`, `chio-cli` |
| `runtime` | providers, dispatch, streaming, nested flows | `chio-kernel`, `chio-mcp-adapter` |
| `trust` | CA, revocation, receipt persistence, remote identity | new services plus `chio-kernel` |
| `interop` | adapters, fixtures, conformance, migration docs | `chio-mcp-adapter`, `tests`, `docs` |

## Current planning note

The repo has advanced far beyond the early E0-E8 bootstrap described in the original version of this plan.

The generic late-stage hardening bucket is no longer specific enough.

Post-review closing work is now split into focused epics:

- `E9` HA trust-control reliability
- `E10` remote runtime hardening
- `E11` cross-transport concurrency semantics
- `E12` security boundary completion
- `E13` policy and adoption unification
- `E14` hardening and release candidate

> Historical internal planning note. `v2.x` labels below are pre-release
> implementation milestones, not Chio-owned protocol, schema, SDK, or runtime
> versions. Current protocol posture is v1-only.

See [POST_REVIEW_EXECUTION_PLAN.md](../archive/POST_REVIEW_EXECUTION_PLAN.md) and the new epic specs in [epics/README.md](../archive/epics/README.md).

## Pre-Release v1 Implemented Features

The following items are implemented in the current pre-release v1 branch. They
are not public v2 protocol features. References to them as "planned" or
"proposed" in earlier sections are superseded by this note.

### Monetary budgets (implemented in current v1)

`MonetaryAmount`, `max_cost_per_invocation`, and `max_total_cost` on `ToolGrant` are implemented in `crates/chio-core/src/capability.rs`. `BudgetStore::try_charge_cost` enforces atomic monetary limits in `crates/chio-kernel/src/budget_store.rs`. `FinancialReceiptMetadata` is embedded in the receipt `metadata` field for every monetized invocation. See [AGENT_ECONOMY.md](../reference/AGENT_ECONOMY.md) for the full design; Phase 1 of that document is now implemented. Operator guide: [MONETARY_BUDGETS_GUIDE.md](../reference/MONETARY_BUDGETS_GUIDE.md).

### DPoP proof-of-possession (implemented in current v1)

`ToolGrant.dpop_required` enables per-grant DPoP enforcement. The kernel validates `chio.dpop_proof.v1` proofs with nonce replay prevention. Implementation is in `crates/chio-kernel/src/dpop.rs`. Operator guide: [DPOP_INTEGRATION_GUIDE.md](../reference/DPOP_INTEGRATION_GUIDE.md).

### Receipt query API (implemented in current v1)

`GET /v1/receipts/query` on the trust-control service supports eight filter dimensions and cursor-based pagination. The CLI exposes `chio receipt list` with equivalent filters. Capability lineage JOINs (`/v1/lineage/{capability_id}/chain`, `GET /v1/agents/{subject_key}/receipts`) are also available. See `crates/chio-kernel/src/receipt_query.rs` and `crates/chio-kernel/src/capability_lineage.rs`. Operator guide: [RECEIPT_QUERY_API.md](../reference/RECEIPT_QUERY_API.md).

### Velocity guard (implemented in current v1)

`VelocityGuard` token-bucket rate limiting per `(capability_id, grant_index)` is in `crates/chio-guards/src/velocity.rs`. It runs in the standard guard pipeline before any tool server invocation. Operator guide: [VELOCITY_GUARDS.md](../reference/VELOCITY_GUARDS.md).

### Merkle-committed receipt batches (implemented in current v1)

`KernelCheckpoint` commits batches of receipts to a Merkle root signed by the kernel key. See `crates/chio-kernel/src/checkpoint.rs`.

### SIEM exporters (implemented in current v1)

Splunk HEC and Elasticsearch bulk exporters with a bounded dead-letter queue ship in `crates/chio-siem`, enabled via `--features siem` on `chio-cli`.

### Receipt retention with time/size rotation (implemented in current v1)

`RetentionConfig` on `KernelConfig` supports automatic archival by age (days) and live database size. See `crates/chio-kernel/src/receipt_store.rs`.

### TypeScript SDK (implemented in current v1)

`@chio-protocol/sdk` v1.0.0 ships in `sdks/typescript/chio-ts/`. It covers capability invariants, receipt verification, DPoP proof construction, a receipt query client, and Streamable HTTP session management.

### Compliance documents (implemented in current v1)

Operator-facing compliance references are in `docs/compliance/`:

- `docs/compliance/colorado-sb-24-205.md`
- `docs/compliance/eu-ai-act-article-19.md`

## Decision Gates

These are blocking design decisions. They should be resolved explicitly and documented before dependent implementation proceeds.

### D1: Edge protocol shape

Decision:

- direct JSON-RPC all the way into runtime
- or JSON-RPC edge translated into a native internal session model

Recommendation:

- JSON-RPC at the edge, normalized internal session model underneath

Blocks:

- E1
- E3

### D2: Scope evolution timing

Decision:

- keep `ChioScope` tool-only until after tool parity
- or widen the grant model before resources/prompts land

Recommendation:

- keep `ToolGrant` in the first session and tool-parity milestone
- design `Grant` enum before resource/prompt implementation starts

Blocks:

- E4
- E5

### D3: Nested flow model

Decision:

- sampling/elicitation as child requests in the same session
- or separate nested sub-sessions

Recommendation:

- child requests inside the same session with lineage-aware receipts

Blocks:

- E5
- E6

### D4: First receipt backend

Decision:

- SQLite
- append-only local file
- remote service first

Recommendation:

- SQLite first, remote service second

Blocks:

- E7

### D5: MCP edge location

Decision:

- overload `chio-mcp-adapter`
- or introduce separate MCP edge runtime

Recommendation:

- keep `chio-mcp-adapter` as migration adapter
- add separate MCP edge module or crate

Blocks:

- E3
- E4

## Epic Overview

| Epic | Name | Depends on | Can overlap with |
| --- | --- | --- | --- |
| `E0` | Program setup and architectural decisions | none | none |
| `E1` | Session foundation | `E0` | `E2` |
| `E2` | Canonical policy runtime | `E0` | `E1` |
| `E3` | MCP tool edge parity | `E1`, `E2`, `D1`, `D5` | `E4` prep |
| `E4` | Resources, prompts, completion, logging | `E1`, `E2`, `E3`, `D2` | `E7` prep |
| `E5` | Nested flows: roots, sampling, elicitation | `E1`, `E2`, `E4`, `D3` | `E6` prep |
| `E6` | Long-running operations | `E1`, `E3`, `E5` | `E7` prep |
| `E7` | Trust plane and remote runtime | `E1`, `E2`, `D4` | `E8` prep |
| `E8` | Migration, conformance, SDKs | `E3`, `E4`, `E5`, `E6`, `E7` | `E13` prep |
| `E9` | HA trust-control reliability | `E7` | `E12` design |
| `E10` | Remote runtime hardening | `E7`, `E9` recommended | `E11` |
| `E11` | Cross-transport concurrency semantics | `E6`, `E7` | `E10` |
| `E12` | Security boundary completion | `E2`, `E5` | `E9` |
| `E13` | Policy and adoption unification | `E2`, `E8` | `E12` |
| `E14` | Hardening and release candidate | `E9`, `E10`, `E11`, `E12`, `E13` | none |

## Dependency Graph

```text
E0
|- E1
|  |- E3
|  |  |- E4
|  |  |  |- E5
|  |  |  |  \\- E12
|  |  |  \\- E6
|  \\- E7
\\- E2 ------/

E3 + E4 + E5 + E6 + E7 -> E8
E7 -> E9 -> E10
E6 + E7 -> E11
E2 + E5 -> E12
E2 + E8 -> E13
E9 + E10 + E11 + E12 + E13 -> E14
```

## Epic Details

## E0: Program Setup and Architectural Decisions

### Objective

Lock the foundational choices that unblock the rest of the work.

### Deliverables

- architecture decision record for D1 through D5
- repo tracking structure for epics, work packages, and milestone gates
- naming and packaging rules for new crates or modules
- test strategy split between compatibility and security suites

### Work packages

#### `WP0.1` ADRs

- write ADR for edge protocol shape
- write ADR for scope evolution timing
- write ADR for nested flow model
- write ADR for first receipt backend
- write ADR for MCP edge runtime location

#### `WP0.2` Tracking

- create issue labels or equivalent tags for `protocol`, `policy`, `runtime`, `trust`, `interop`
- define milestone names matching epics
- define "definition of done" template for protocol changes

### Exit criteria

- D1 through D5 are decided and written down
- no later epic has to reopen those questions by default

## E1: Session Foundation

### Objective

Create the session substrate that everything else will use.

### Primary repo areas

- `crates/chio-core`
- `crates/chio-kernel`

### Deliverables

- `session` module or crate
- session lifecycle model
- in-flight registry
- cancellation and progress bookkeeping hooks
- normalized internal operation model

### Work packages

#### `WP1.1` Session types

- add `SessionId`, `RequestId`, progress token, subscription identifiers
- define `SessionState`
- define `OperationContext`
- define `SessionOperation`

#### `WP1.2` Kernel session integration

- add session object creation and teardown
- wire request tracking into kernel entry points
- add session-bound capability cache design, even if disabled initially

#### `WP1.3` Transport boundary cleanup

- separate internal frame transport from higher-level session handling
- ensure future JSON-RPC edge can call stable internal interfaces

### Acceptance tests

- session can initialize, enter ready state, and close cleanly
- in-flight registry tracks request start and completion
- cancellation requests can target in-flight request IDs
- no tool-specific assumptions remain in the session scaffolding

### Exit criteria

- all future protocol work targets session APIs, not raw transport glue

## E2: Canonical Policy Runtime

### Objective

Make HushSpec and `chio-policy` the runtime truth.

### Primary repo areas

- `crates/chio-policy`
- `crates/chio-cli`
- `crates/chio-kernel`

### Deliverables

- `LoadedPolicy` or equivalent runtime type
- compiled HushSpec wired into kernel construction
- fixture policies for tool, resource, prompt, and nested-flow cases

### Work packages

#### `WP2.1` Policy loader unification

- replace HushSpec detect-and-discard flow
- preserve Chio YAML support as a compatibility input, not the core runtime model

#### `WP2.2` Receipt semantics

- define canonical compiled-policy hash
- embed it in receipts
- clarify difference between source document hash and compiled policy identity

#### `WP2.3` Guard coverage

- ensure all currently shipped guards can be configured from canonical policy
- add policy tests for guard compilation and default scope generation

### Acceptance tests

- HushSpec policy produces the same runtime behavior across CLI and direct kernel construction
- compiled policy changes alter receipt policy identity deterministically
- Chio YAML policies still load or fail with explicit migration guidance

### Exit criteria

- no mainline runtime path depends on the original `ChioPolicy` shape for new features

## E3: MCP Tool Edge Parity

### Objective

Support MCP-compatible tool workflows at the edge.

### Primary repo areas

- new MCP edge module or crate
- `crates/chio-core`
- `crates/chio-kernel`
- `crates/chio-mcp-adapter`

### Deliverables

- JSON-RPC tool session handling
- lifecycle handshake for tool-capable sessions
- `tools/list`, `tools/call`, pagination, list-changed notifications
- richer tool metadata parity

### Work packages

#### `WP3.1` JSON-RPC edge

- request parser and dispatcher
- response and notification helpers
- error mapping

#### `WP3.2` Tool metadata

- add title, annotations, output schema, execution metadata support
- map MCP-facing metadata to manifest or compatibility types

#### `WP3.3` Tool result parity

- support text, image, audio, resource links, embedded resources, and structured content

#### `WP3.4` MCP client fixtures

- add representative MCP clients to interop fixtures
- verify `tools/list` and `tools/call` behavior against expectations

### Acceptance tests

- a stock MCP client can connect and execute representative tool flows
- `chio-mcp-adapter` wrapping does not lose critical tool metadata
- notification and pagination semantics are stable

### Exit criteria

- Chio is a realistic secure MCP tool edge, not just a local demo kernel

## E4: Resources, Prompts, Completion, and Logging

### Objective

Implement non-tool server primitives.

### Primary repo areas

- new edge module or crate
- `crates/chio-core`
- `crates/chio-kernel`
- provider interfaces

### Deliverables

- resource provider interfaces and runtime dispatch
- prompt provider interfaces and runtime dispatch
- completion support
- structured logging support

### Work packages

#### `WP4.1` Scope and grant design

- finalize `ResourceGrant` and `PromptGrant`
- define URI normalization and matching rules
- define prompt retrieval authorization model

#### `WP4.2` Resources

- `resources/list`
- `resources/read`
- `resources/templates/list`
- subscriptions and updates

#### `WP4.3` Prompts

- `prompts/list`
- `prompts/get`
- argument validation
- prompt change notifications

#### `WP4.4` Completion and logging

- prompt and template argument completion
- edge-level structured logging notifications
- wrapped MCP subprocess parity for resources, prompts, and completion

### Acceptance tests

- resource listing, template listing, and reads work with policy and scope enforcement
- prompt retrieval works without pretending prompts are tools
- completion APIs return deterministic results for fixture providers
- `chio mcp serve` exposes wrapped resources, prompts, and completion when the upstream server advertises them

### Exit criteria

- Chio can host contextual MCP-style servers, not only action endpoints

## E5: Nested Flows

### Objective

Implement roots, sampling, and elicitation with safe lineage.

### Primary repo areas

- session module
- edge runtime
- `chio-core`
- `chio-kernel`
- `chio-policy`

### Deliverables

- roots support
- sampling child-request flow
- elicitation child-request flow
- lineage-aware receipts

### Work packages

#### `WP5.1` Roots

- add root tracking to session
- root change notifications
- connect roots to resource and path enforcement

#### `WP5.2` Sampling

- child request object model
- approval policy hooks
- client credential preservation

#### `WP5.3` Elicitation

- structured user-input requests
- accept/decline/cancel flow
- child request linkage and evidence

#### `WP5.4` Receipt lineage

- add parent request identifiers
- add nested-flow evidence and approval state

### Acceptance tests

- nested requests are attributable to parent flows
- denied nested requests do not bypass policy
- child receipts can be correlated with final parent receipts

### Exit criteria

- Chio supports agentic server workflows without trust blind spots

## E6: Long-Running Operations

### Objective

Make long-running work first-class.

### Primary repo areas

- session module
- `crates/chio-core`
- `crates/chio-kernel`

### Deliverables

- stream state machine
- progress notifications
- cancellation semantics
- incomplete and cancelled receipts

### Work packages

#### `WP6.1` Stream lifecycle

- introduce stream state tracking
- define chunk hashing and terminal outcome rules

#### `WP6.2` Progress

- progress token handling
- session-side notification fanout

#### `WP6.3` Cancellation

- request cancellation notification handling
- kernel termination semantics
- race handling and terminal state ownership

### Acceptance tests

- cancellable request stops processing or exits gracefully
- interrupted streams produce incomplete receipts
- progress notifications only reference live requests

### Exit criteria

- single-shot only is no longer a hard limitation

## E7: Trust Plane and Remote Runtime

### Objective

Replace local-only trust assumptions with service-backed trust.

### Primary repo areas

- new trust services or crates
- `crates/chio-kernel`
- `crates/chio-core`

### Deliverables

- capability authority interface and initial implementation
- persistent revocation backend
- persistent receipt store
- authenticated remote transport

### Work packages

#### `WP7.1` CA service

- issue, revoke, and check APIs
- local implementation first
- key rotation support scaffolding

#### `WP7.2` Receipt store

- SQLite backend first
- append-only semantics at application layer
- receipt query API for verification and ops, implemented in current v1 as `GET /v1/receipts/query` on the trust-control service and `chio receipt list` CLI; see `crates/chio-kernel/src/receipt_query.rs`

#### `WP7.3` Remote runtime

- authenticated remote sessions
- server identity binding to manifests and keys

### Acceptance tests

- revocation survives process restart
- receipts survive process restart and verify later
- remote sessions authenticate correctly and preserve capability checks

### Exit criteria

- security guarantees are no longer primarily in-memory and local

## E8: Migration, Conformance, and SDKs

### Objective

Make adoption cheap and claims test-backed.

### Primary repo areas

- `crates/chio-mcp-adapter`
- `tests`
- `docs`
- generated schema or SDK areas if added

### Deliverables

- MCP compatibility gateway polish
- conformance suite
- compatibility matrix
- migration guide

### Work packages

#### `WP8.1` Compatibility suite

- method-level fixture coverage
- edge-case coverage for notifications, pagination, and nested flows

#### `WP8.2` Security suite

- denial receipts
- revocation propagation
- nested-flow lineage
- stream terminal states

#### `WP8.3` Migration docs and examples

- MCP deployment replacement guide
- examples for wrapped MCP servers and native Chio providers

### Acceptance tests

- compatibility matrix is generated from tests, not hand-written optimism
- at least one realistic MCP deployment path is documented end to end

### Exit criteria

- Chio can be adopted incrementally by teams that already use MCP

## E9: HA Trust-Control Reliability

### Objective

Make the clustered trust-control path deterministic enough for repeated full-suite use.

### Primary repo areas

- `crates/chio-control-plane/src/trust_control.rs`
- `crates/chio-kernel/src/budget_store.rs`
- authority, receipt, and revocation store implementations
- clustered trust-control tests

### Deliverables

- read-after-write visibility contract for leader-routed writes
- hardened replication ordering and cursor semantics
- failover and convergence observability
- repeated-run cluster stress coverage

### Work packages

#### `WP9.1` Reproduction and instrumentation

- make current flaky cluster behavior reproducible under stress
- expose enough state to localize routing, visibility, or cursor failures

#### `WP9.2` Write visibility semantics

- define what successful forwarded writes guarantee
- align budget, receipt, revocation, and authority mutation handlers to that contract

#### `WP9.3` Replication ordering

- audit monotonic ordering assumptions
- harden budget and other delta cursor behavior under rapid updates and failover

### Acceptance tests

- repeated `cargo test --workspace` runs are green
- dedicated trust-cluster stress tests validate budget, revocation, receipt, and authority visibility before and after failover

### Exit criteria

- clustered trust-control behavior is stable enough to stop being a known release blocker

## E10: Remote Runtime Hardening

### Objective

Turn the authenticated remote MCP edge into a reconnect-safe, deployment-hard runtime.

### Primary repo areas

- `crates/chio-mcp-remote/src/remote_mcp/`
- `crates/chio-mcp-adapter`
- `crates/chio-core`
- `crates/chio-kernel`

### Deliverables

- resumable remote session contract
- standalone GET/SSE support
- explicit stale-session, drain, and reconnect rules
- broader hosted ownership model than one subprocess per session

### Work packages

#### `WP10.1` Resume and reconnect contract

- define resumable versus terminal session and task states
- preserve auth and capability correctness across reconnects

#### `WP10.2` GET/SSE support

- add GET-based SSE where required by the compatibility surface
- define stream ownership between POST and GET channels

#### `WP10.3` Hosted ownership

- reduce dependence on one wrapped subprocess per remote session
- harden lifecycle and operator visibility for hosted workers

### Acceptance tests

- remote harness coverage includes reconnect and GET/SSE cases
- stale-session cleanup and remote drain behavior are deterministic and documented

### Exit criteria

- hosted remote runtime is no longer primarily a harness-oriented deployment story

## E11: Cross-Transport Concurrency Semantics

### Objective

Finish one coherent ownership model for tasks, streams, cancellation, and async completion.

### Primary repo areas

- `crates/chio-core`
- `crates/chio-kernel`
- `crates/chio-mcp-adapter`
- `crates/chio-mcp-remote/src/remote_mcp/`
- conformance and integration tests

### Deliverables

- transport-neutral ownership model
- aligned task lifecycle semantics
- explicit cancellation race rules
- durable async completion/event-source behavior

### Work packages

#### `WP11.1` Ownership model

- define active owner, terminal owner, and stream owner rules
- map them into normalized session state

#### `WP11.2` Task and cancellation unification

- align task semantics across direct, wrapped, stdio, and remote paths
- remove the remaining `tasks-cancel` `xfail`

#### `WP11.3` Async completion hardening

- add durable late-event and completion behavior for native direct paths
- keep session attribution and receipts correct

### Acceptance tests

- task, stream, and cancellation outcomes are consistent across transports
- no known `xfail` remains for the current long-running task surface

### Exit criteria

- async ownership debt is no longer an open semantic blocker

## E12: Security Boundary Completion

### Objective

Turn negotiated roots into an enforced boundary for filesystem-shaped tool and resource access.

### Primary repo areas

- `crates/chio-core`
- `crates/chio-kernel`
- `crates/chio-guards`
- `crates/chio-policy`
- `crates/chio-cli`

### Deliverables

- normalized root semantics
- root-aware filesystem tool enforcement
- root-aware filesystem-backed resource enforcement
- deny receipts with root-boundary evidence

### Work packages

#### `WP12.1` Root model

- define normalized root behavior across platforms and transports
- define how missing roots behave

#### `WP12.2` Tool enforcement

- connect root checks to filesystem-shaped tool access
- preserve fail-closed behavior when path proof is ambiguous

#### `WP12.3` Resource enforcement

- enforce roots for filesystem-backed resources
- keep non-filesystem resources out of inappropriate boundary logic

### Acceptance tests

- out-of-root filesystem-shaped tool requests deny with signed evidence
- out-of-root filesystem-backed resource reads deny with signed evidence

### Exit criteria

- roots are no longer merely session metadata in the parts of the runtime where they should be a security boundary

## E13: Policy and Adoption Unification

### Objective

Make the policy story and native adoption story coherent for operators and developers.

### Primary repo areas

- `crates/chio-cli/src/policy.rs`
- `crates/chio-policy`
- `crates/chio-guards`
- `examples`
- `docs`
- new SDK/helper crate if added

### Deliverables

- canonical policy authoring path
- full guard-surface exposure through the supported path
- migration docs and examples
- higher-level native authoring surface

### Work packages

#### `WP13.1` Policy-path convergence

- declare the canonical authoring path
- define compatibility behavior for the non-canonical path

#### `WP13.2` Guard-surface completion

- expose all shipped guards through the supported path
- add regression coverage for configuration parity

#### `WP13.3` Adoption surface

- add migration docs and examples
- ship a higher-level authoring SDK or helper layer

### Acceptance tests

- one supported policy story is explicit in docs and examples
- all shipped guards are reachable through that story
- at least one higher-level native service example is test-covered

### Exit criteria

- teams can tell what to author, how to migrate, and how to build a native service without reverse-engineering internal crates

## E14: Hardening and Release Candidate

### Objective

Convert the post-E8 closing epics into reliable release quality.

### Deliverables

- release qualification matrix
- documented supported limits
- failure-mode tests
- release-facing docs
- final milestone audit and go/no-go evidence

### Work packages

#### `WP14.1` Performance and limits

- define supported defaults and size limits
- wire one local qualification path and one hosted CI qualification path

#### `WP14.2` Failure-mode testing

- malformed JSON-RPC
- revoked or expired capability paths
- stream interruption
- nested-flow denial and cancellation races

#### `WP14.3` Release docs

- supported feature matrix
- release qualification matrix
- explicit non-goals
- migration story
- extension policy

### Exit criteria

- the remaining open questions are product choices, not architectural blockers
- the release story is backed by named artifacts, not generic hardening language

## Milestones

Use milestone gates instead of calendar promises until team capacity is known.

| Milestone | Must complete |
| --- | --- |
| `M0` | E0 |
| `M1` | E1 + E2 |
| `M2` | E3 |
| `M3` | E4 |
| `M4` | E5 + E6 |
| `M5` | E7 |
| `M6` | E8 |
| `M7` | E9 + E12 |
| `M8` | E10 + E11 |
| `M9` | E13 |
| `M10` | E14 |

## Parallelization Rules

These tasks can run in parallel once dependencies are satisfied:

- E1 and E2 after E0
- policy fixtures in E2 while session internals in E1 are underway
- tool metadata parity in E3 while result parity and fixture work also proceed
- E7 trust-service interface design can start during late E4 if it does not block feature epics
- migration docs in E8 can begin as soon as E3 has stable behavior
- E12 design can overlap with E9 reliability work
- E10 and E11 can overlap once trust and session assumptions are stable enough
- E13 documentation and example preparation can start before the SDK slice lands

These tasks should not run ahead of prerequisites:

- E5 before session lineage model exists
- E6 before cancellation bookkeeping exists
- E7 implementation before D4 is decided
- E8 compatibility claims before conformance fixtures exist
- E10 before E7 remote runtime and E9 trust reliability are stable enough
- E12 before E5 roots substrate exists
- E13 before E2 canonical policy runtime exists

## First 30 Days

The 30/60/90-day sections below capture the original bootstrap sequence for E0 through E5.

For the current next-phase execution order after the latest review, use [POST_REVIEW_EXECUTION_PLAN.md](../archive/POST_REVIEW_EXECUTION_PLAN.md) plus epic specs `E9` through `E13`.

### Primary target

Finish E0 and make E1 and E2 real.

### Concrete outcomes

- ADRs for D1 through D5
- session module skeleton
- normalized operation types
- `LoadedPolicy` runtime type
- HushSpec integrated into actual kernel construction path

### Suggested task list

1. add `docs/adr/` and write D1 through D5
2. add `session` module skeleton under `chio-kernel`
3. introduce internal operation and context types in `chio-core` or `chio-kernel`
4. refactor CLI policy loading to keep compiled HushSpec alive
5. add fixture policies for tool-only and deny-by-default cases
6. add tests proving HushSpec drives runtime behavior

## Days 31 to 60

### Primary target

Ship E3.

### Concrete outcomes

- MCP-compatible JSON-RPC edge for tools
- richer tool metadata
- tool result parity improvements
- first compatibility fixtures against representative MCP clients

### Suggested task list

1. implement JSON-RPC dispatcher and lifecycle handshake
2. map tool list and call methods into normalized operations
3. expand manifest and compatibility metadata
4. improve MCP result block coverage
5. stand up tool-only interoperability fixtures

## Days 61 to 90

### Primary target

Start E4 and prepare E5.

### Concrete outcomes

- provider interfaces for resources and prompts
- grant-shape decision for non-tool operations
- initial resource and prompt fixture providers
- lineage design frozen for nested flows

### Suggested task list

1. finalize grant model direction for resources/prompts
2. add resource provider trait and list/read paths
3. add prompt provider trait and list/get paths
4. define receipt lineage fields for nested requests
5. write sampling and elicitation sequence docs before implementation

## Tracking Format

Each epic should be tracked as:

- epic issue
- milestone
- ordered work packages
- acceptance checklist
- demo artifact or fixture proving the milestone

Each work package should record:

- repo areas touched
- blocking dependencies
- acceptance tests added
- docs updated

## Definition of Done

A work package is done only if:

- implementation merged
- tests added or updated
- docs updated
- compatibility impact documented
- security impact documented

## Final Note

The critical path is:

- session model
- canonical policy runtime
- MCP-compatible edge
- first-class non-tool primitives
- nested-flow safety

Everything else matters, but if that path stalls, the project will accumulate impressive components without becoming a real replacement.
