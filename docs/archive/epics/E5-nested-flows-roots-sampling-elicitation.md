# E5: Nested Flows, Roots, Sampling, and Elicitation

## Status

In progress.

Implemented in the first slice:

- session-owned root snapshots
- client roots capability capture during MCP initialization
- server-initiated `roots/list` refresh after `notifications/initialized`
- root refresh on `notifications/roots/list_changed`
- internal `ListRoots` session operation for session-scoped root inspection

Implemented in the second slice:

- parent-child request lineage in session in-flight tracking
- explicit child-request helpers in the kernel for nested flows
- negotiated sampling capability capture during MCP initialization
- policy-gated nested sampling flags in the runtime policy and kernel config
- normalized `sampling/createMessage` request and result types in `chio-core`
- edge-owned `sampling/createMessage` child-request plumbing with fail-closed validation

Implemented in the third slice:

- kernel-owned nested-flow bridge for wrapped tool calls
- wrapped-server propagation of `roots/list` and `sampling/createMessage` through the adapted MCP transport
- proxy client capability advertisement to wrapped MCP servers during adapter initialization
- end-to-end `chio mcp serve` coverage for wrapped sampling and roots roundtrips

Still pending:

- root-aware enforcement for tools and filesystem-backed resources
- elicitation child-request flow
- lineage-aware receipts for nested child requests

## Suggested issue title

`E5: implement roots, sampling, and elicitation with safe nested-flow lineage`

## Problem

Chio now has strong coverage for tools, resources, prompts, completion, and logging, but it still lacks the client-feature flows that make MCP servers agentic.

Without E5, Chio can mediate actions and context, but it cannot safely support:

- client workspace roots as a negotiated security boundary
- server-initiated model execution through the client
- server-initiated structured user input through the client

## Outcome

By the end of E5:

- roots are tracked as first-class session state
- nested child requests preserve attribution to a parent request
- sampling and elicitation default to deny unless negotiated and allowed by policy
- nested flows generate evidence suitable for receipts and audit

## Scope

In scope:

- root discovery and refresh
- child-request substrate for client-feature calls
- sampling and elicitation request models
- nested-flow policy hooks and denial defaults
- lineage fields needed for nested receipts

Out of scope:

- long-running stream state
- cancellation races beyond what is required for nested-flow correctness
- remote trust-plane work

## Primary files and areas

- `crates/chio-core/src/session.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-kernel/src/lib.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `crates/chio-cli/src/policy.rs`

## Implementation slices

### Slice A: roots substrate

- add root types to `chio-core`
- track negotiated roots capability in session state
- refresh root snapshots from the MCP client after initialization and on list-changed notifications
- expose root snapshots through the kernel session model

### Slice B: child-request substrate

- define nested request records with parent request linkage
- give child requests their own request IDs within the same session
- establish a fail-closed approval model when peer capability or policy support is absent

### Slice C: sampling

- add server-initiated sampling requests through the client
- preserve client control of model credentials
- record explicit approval or denial state

### Slice D: elicitation

- add structured user-input requests through the client
- support accept, decline, and cancellation outcomes
- link outcomes back to parent requests

## Task breakdown

### `T5.1` Roots discovery and refresh

- capture client `roots` capability during initialization
- request `roots/list` after the initialized notification
- refresh root snapshots on `notifications/roots/list_changed`
- add tests for bidirectional stdio handling and root state updates

### `T5.2` Child request substrate

- formalize child request identifiers and parent request linkage
- decide how nested request state is stored in session state
- add conservative denial defaults when nested support is absent

Status:

- implemented through session lineage fields and kernel child-request helpers
- implemented for the wrapped transport path used by `chio mcp serve`
- follow-on still needed for elicitation and receipt lineage

### `T5.3` Sampling

- define normalized sampling request and response types
- add edge plumbing for server-to-client sampling requests
- connect policy hooks and evidence capture

Status:

- implemented for the MCP edge as a typed child-request path
- implemented for wrapped MCP servers over the stdio adapter path
- follow-on still needed for receipt lineage and future non-stdio transports

### `T5.4` Elicitation

- define normalized elicitation request and response types
- add edge plumbing for structured user-input requests
- connect approval and denial evidence to parent flows

## Dependencies

- depends on E1 session foundation
- depends on E2 canonical policy runtime
- depends on E4 resources/prompts/completion/logging
- depends on ADR-0003 nested flow model

## Risks

- adding ad hoc bidirectional RPC handling that cannot scale to sampling and elicitation
- losing parent-child attribution under nested requests
- letting nested flows bypass policy or user approval

## Mitigations

- reuse the session substrate instead of inventing nested sub-sessions
- keep child requests explicit and attributable
- default deny when support is not negotiated or policy is absent

## Acceptance criteria

- roots are discoverable and refreshable over the MCP edge
- nested child requests can be represented without losing parent lineage
- sampling and elicitation cannot execute unless negotiated and allowed
- nested denials are observable and attributable

## Definition of done

- roots support merged and tested
- child-request substrate merged
- sampling and elicitation paths merged with policy hooks
- receipt lineage design is implemented rather than only documented
