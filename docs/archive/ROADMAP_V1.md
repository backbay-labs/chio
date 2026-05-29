# Chio Roadmap to v1

Detailed sequencing, work packages, and milestone gates live in [EXECUTION_PLAN.md](../operations/EXECUTION_PLAN.md).

## Goal

Make Chio the default way to run MCP-class agent integrations when teams need stronger trust boundaries, least-privilege access, and verifiable audit receipts.

The target end state is not "different from MCP."

The target end state is:

- compatible enough to replace MCP in real deployments
- stronger than MCP where trust and security matter
- simple enough to adopt incrementally

## V1 Definition

Chio `v1.0` should satisfy all of the following:

### Protocol

- exposes an MCP-compatible session edge for the core primitives required by modern clients and servers
- supports tools, resources, prompts, roots, sampling, elicitation, and long-running operation handling
- supports capability negotiation, session initialization, notifications, and pagination

### Security

- enforces capability-scoped authorization at action time
- supports revocation beyond local in-memory state
- signs receipts for allow, deny, and interrupted or incomplete outcomes
- binds remote identities to manifests, keys, and transport-level trust

### Runtime

- supports local and remote transports
- supports persistent receipt storage
- supports streaming, progress, and cancellation semantics
- supports production-grade policy evaluation

### Adoption

- ships with MCP compatibility gateways and migration tooling
- has one canonical policy path
- has conformance and interoperability tests
- has example servers, clients, and operator docs

## Cross-Cutting Workstreams

These should run across multiple phases rather than being treated as one-off tasks.

### Workstream A: Session protocol

Owns:

- initialization
- negotiated features
- in-flight request tracking
- request lineage
- notifications
- progress and cancellation

Likely home:

- `chio-kernel::session` first
- dedicated `chio-session` crate later if needed

### Workstream B: Policy unification

Owns:

- HushSpec promotion
- compiled policy as runtime truth
- policy hash and receipt semantics
- examples and compatibility fixtures

Likely home:

- `chio-policy`
- `chio-cli`
- kernel construction path

### Workstream C: MCP-compatible edge

Owns:

- JSON-RPC edge
- lifecycle and capability negotiation
- tools, resources, prompts compatibility
- pagination and notifications

Likely home:

- new edge module or crate
- not inside `chio-mcp-adapter` alone

### Workstream D: Trust plane

Owns:

- capability authority
- revocation propagation
- receipt persistence
- key lifecycle
- remote identity binding

Likely home:

- new services or crates beside the current kernel

### Workstream E: Conformance and migration

Owns:

- MCP compatibility fixtures
- Chio security fixtures
- migration guides
- adapter hardening

## Suggested Repository Evolution

The current repository can absorb early work without a massive rewrite, but `v1` likely wants these major seams:

| Area | Current home | Likely future home |
| --- | --- | --- |
| session state | `chio-kernel` | `chio-kernel::session` or `chio-session` |
| JSON-RPC edge | none | new MCP edge crate/module |
| trust services | `chio-kernel` in-memory | new CA and receipt-store services |
| policy runtime contract | split between `chio-cli` and `chio-policy` | `chio-policy` as canonical source |
| MCP migration | `chio-mcp-adapter` | adapter plus separate MCP-compatible edge |

## Release Strategy

Use a staged roadmap where each phase can ship value on its own.

## Current closing-phase update

The repo has advanced beyond the original "one final hardening phase" shape.

The next closing work is now better modeled as five focused epics plus a final release candidate gate:

- `E9` HA trust-control reliability
- `E10` remote runtime hardening
- `E11` cross-transport concurrency semantics
- `E12` security boundary completion
- `E13` policy and adoption unification
- `E14` hardening and release candidate

See [POST_REVIEW_EXECUTION_PLAN.md](POST_REVIEW_EXECUTION_PLAN.md), [EXECUTION_PLAN.md](../operations/EXECUTION_PLAN.md), and the new issue-ready specs in [epics/README.md](epics/README.md).

## Phase 1: `v0.2` Protocol Foundation

### Objective

Move from a narrow internal tool-call protocol to a real session model.

### Deliverables

- add initialization and negotiated feature capability exchange
- define a session abstraction above the current framed transport
- separate internal transport framing from external protocol shape
- formalize an error model for session-level failures
- define request and notification correlation rules
- add normalized operation types beyond raw transport messages
- add in-flight request registry with cancellation and progress hooks

### Required design choices

- whether the external edge is directly JSON-RPC or an adapter over the current internal messages
- how Chio capability tokens coexist with session capability negotiation

### Exit criteria

- kernel can host a durable session object
- runtime can negotiate supported features and protocol revision
- protocol docs clearly distinguish session auth from action auth
- future MCP JSON-RPC edge work has a stable internal target to call into

## Phase 2: `v0.3` Canonical Policy and Guard Integration

### Objective

Make one policy model real.

### Deliverables

- promote HushSpec plus `chio-policy` compilation to the main runtime path
- retire or de-emphasize the original Chio YAML format as the primary runtime path
- wire compiled policies into CLI and runtime behavior
- add docs and examples for real policy authoring
- add policy compatibility tests
- introduce a `LoadedPolicy` or equivalent runtime type so compiled HushSpec is no longer discarded
- embed compiled policy identity into receipt generation semantics

### Exit criteria

- CLI no longer validates HushSpec and then drops back to an empty Chio YAML placeholder
- all current shipped guards can be configured through the canonical policy path
- policy hash and receipt generation remain stable and test-covered

## Phase 3: `v0.4` MCP Tool Parity at the Edge

### Objective

Become a serious secure MCP tool runtime rather than a partial adapter.

### Deliverables

- JSON-RPC edge transport for MCP-compatible tool sessions
- support for `tools/list`, `tools/call`, pagination, and list-changed notifications
- richer tool metadata parity:
  - title
  - annotations
  - output schema
  - execution metadata where practical
- compatibility test fixtures against representative MCP clients
- expand result compatibility to cover resource links, embedded resources, and richer content blocks

### Exit criteria

- a stock MCP client can use Chio as a secure tool server edge for common tool workflows
- Chio can wrap MCP tool servers without dropping important tool metadata

## Phase 4: `v0.5` Resources, Prompts, Completion, and Logging

### Objective

Close the non-tool parity gap for mainstream integrations.

### Deliverables

- first-class resource model:
  - list
  - read
  - templates
- first-class prompt model:
  - list
  - get
  - prompt arguments
- completion support for prompts and resource templates
- edge-level structured logging support
- add provider traits for resources and prompts so they do not piggyback on tool semantics
- define capability grant shapes for resources and prompts
- wrapped MCP subprocess parity for resources, prompts, and completion when the upstream server advertises those features

Follow-on work after this phase:

- resource subscriptions and update notifications
- prompt change notifications
- passthrough of upstream MCP logging notifications

### Exit criteria

- Chio can host MCP-style contextual servers, not only action servers
- prompts and resources are no longer forced through tool semantics

## Phase 5: `v0.6` Nested Flows: Roots, Sampling, and Elicitation

### Objective

Support the workflows that make MCP servers agentic.

### Deliverables

- root discovery and root change notifications
- server-initiated sampling requests via the client
- server-initiated elicitation requests via the client
- clear approval and denial model for nested requests
- security model for re-entrant flows
- policy hooks for sampling and elicitation approval rules
- lineage-aware receipts linking parent and child requests
- explicit policy defaults for nested-flow denial when capability or session support is absent

### Exit criteria

- a server can safely request model execution through the client
- a server can request structured user input without bypassing the client UX
- nested flows produce receipts and policy evidence

### Note

This is the hardest architectural phase. It should not be rushed.

## Phase 6: `v0.7` Long-Running Operations

### Objective

Handle real workloads instead of single-shot RPCs only.

### Deliverables

- streaming result protocol in the shipped runtime
- progress notifications
- cancellation support
- interrupted and partial receipt semantics
- backpressure, size limits, and duration limits
- optional task-oriented execution model if it materially simplifies long-running work
- stable in-memory stream state machine before any remote-distributed stream design

### Exit criteria

- long-running tools can be observed, interrupted, and audited correctly
- receipts remain correct for complete and incomplete executions

## Phase 7: `v0.8` Trust Plane and Remote Runtime

### Objective

Make the security story real outside local tests.

### Deliverables

- remote transport support with authenticated sessions
- capability authority service or equivalent trust service
- persistent revocation store and propagation strategy
- persistent receipt log backend
- key rotation and trust bootstrap
- remote server identity binding to manifests
- local single-binary mode that reuses the same service interfaces for development

### Exit criteria

- multi-process and remote deployments no longer depend on in-memory trust state
- receipts survive process restarts and can be independently verified later

## Phase 8: `v0.9` Migration, SDKs, and Conformance

### Objective

Make adoption cheap.

### Deliverables

- first-class MCP compatibility gateways
- better MCP adapter coverage beyond tools where feasible
- language bindings or generated schemas for common platforms
- protocol conformance suite
- interoperability fixtures for both MCP-facing and Chio-native flows
- operator and migration guides
- compatibility matrix that explicitly states which MCP features are complete, partial, or intentionally unsupported

### Exit criteria

- teams can adopt Chio incrementally without rewriting everything
- compatibility claims are test-backed, not aspirational

## Phase 9: `v1.0-rc` Hardening

### Objective

Prove the system, not just the design.

### Deliverables

- release qualification matrix
- documented supported defaults and limits
- failure-mode testing
- generated conformance evidence against the maintained JS and Python peers
- release docs covering guarantees, non-goals, migration path, and extension policy
- final milestone audit and go/no-go evidence
- explicit extension policy for Chio-native features

### Exit criteria

- no major unresolved architectural questions remain in the protocol draft
- `v1` surface is intentionally smaller than "everything" but complete for the chosen replacement claim
- release claims point to concrete artifacts instead of scattered tribal knowledge

## `v1.0`

### What ships

- MCP-compatible session edge for the selected feature set
- Chio-native security core with capability enforcement and signed receipts
- canonical policy system
- persistent trust infrastructure
- compatibility and conformance test suites
- clear migration path for MCP deployments

### What should be true on launch day

- users can say "replace our MCP deployment with Chio" without re-architecting core workflows
- security teams can say "Chio gives us stronger controls than MCP alone"
- developers can say "Chio is understandable and testable"

## Scope Boundaries for `v1`

Not every possible feature needs to land before `v1`.

Reasonable non-goals for `v1`:

- solving every distributed coordination problem perfectly
- replacing every MCP extension immediately
- proving the entire distributed system formally

Reasonable must-haves for `v1`:

- protocol completeness for core workflows
- secure nested flows
- durable trust and receipts
- compatibility and migration
- one coherent operator story

## Recommended Near-Term Execution Order

If work starts immediately, the highest-leverage order is:

1. session model
2. canonical policy path
3. MCP tool parity at the edge
4. resources and prompts
5. roots, sampling, and elicitation
6. streaming, progress, and cancellation
7. trust plane and remote runtime
8. migration tooling and conformance

That order keeps the project from polishing local crypto while the ecosystem-facing contract is still underspecified.

## Decisions To Force Early

The following questions should be answered in the next design cycle, not deferred to late implementation:

1. Is the public edge protocol directly JSON-RPC, or is there a thin translation layer from JSON-RPC into a native Chio session model?
2. Does `ChioScope` stay tool-centric for one more iteration, or do resource and prompt grants arrive before `v0.5`?
3. Is sampling implemented as a child request inside the same session state machine, or as a separate nested session abstraction?
4. What is the first durable receipt backend: SQLite, file append-only log, or remote service?
5. Does `chio-mcp-adapter` stay a migration adapter only, or does the repo add a separate first-class MCP edge runtime?

## The One-Sentence Roadmap

Chio gets to `v1` by becoming an MCP-compatible session protocol at the edge, a capability-enforced trust kernel at the core, and an adoption-friendly migration path in practice.
