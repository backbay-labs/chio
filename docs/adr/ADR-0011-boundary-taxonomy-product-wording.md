# ADR-0011: Boundary Taxonomy And Product Wording

- Status: Accepted
- Decision owner: protocol strategy and product
- Related plan items: PR 652 boundary matrix, current v1 receipt-kind trace semantics, adapter ticket gates

## Context

PR 652 reviewed many external surfaces with different control points. Some are
fully mediated by Chio, some are provider-executed but observable, some are only
advisory discovery data, and some are outside Chio's layer entirely. The same
document previously used planning readiness, security boundary, and product
wording as if they were one axis. That made bridge plans sound stronger than
the evidence supports.

## Decision

Every planning artifact and implementation ticket that touches a trust boundary
must use two separate fields.

`boundary_class`:

- `prevent`: Chio is in the decision path before effect.
- `detect_only`: Chio records activity after or outside the effect path.
- `advisory_only`: Chio uses data for discovery, ranking, or operator guidance,
  and the data never grants capability scope.
- `cannot_see`: The activity is below or outside Chio's mediation layer.

`planning_status`:

- `ready_after_adr`: Planning can proceed after the named ADRs are accepted.
- `blocked_by_adr`: Planning is blocked on unresolved semantics.
- `deferred`: Deliberately postponed.
- `hard_skip`: Out of scope for this strategy.

Product and receipt wording must follow the boundary class:

| boundary_class | Allowed wording | Forbidden wording |
|---|---|---|
| `prevent` | mediated, authorized, denied, fail-closed, pre-effect | observed only, advisory only |
| `detect_only` | observed, provider-reported, trace-only, post-effect | mediated, authorized, protected before effect |
| `advisory_only` | advisory, discovery, operator-pinned, non-authorizing | capability grant, scope expansion, trusted directory import |
| `cannot_see` | out of layer, not covered, external to Chio | blocked by Chio, mediated by Chio |

Ticket defaults from PR 652:

- OpenAI function tools executed by the caller runtime:
  `boundary_class = prevent`, `planning_status = ready_after_adr`.
- OpenAI hosted tools other than caller-executed functions:
  `boundary_class = detect_only`, `planning_status = deferred`.
- OpenAI remote MCP and connectors:
  `boundary_class = detect_only`, `planning_status = blocked_by_adr`, unless a
  later ADR proves a specific approval step is preventable without claiming
  remote execution mediation.
- OpenAI computer actions in a caller harness:
  `boundary_class = prevent`, `planning_status = blocked_by_adr`, separate from
  the function-tools MVP.
- Bedrock `RETURN_CONTROL` action groups:
  `boundary_class = prevent`, `planning_status = ready_after_adr`.
- Bedrock Lambda action groups:
  `boundary_class = detect_only`, `planning_status = deferred`.
- AGNTCY directory data:
  `boundary_class = advisory_only`, `planning_status = ready_after_adr` only
  when static and operator-pinned.
- n8n Chain C agent-to-webhook egress:
  `boundary_class = prevent`, `planning_status = ready_after_adr`.
- n8n Chain D unauthenticated webhook ingress:
  `boundary_class = cannot_see`, `planning_status = hard_skip`.

SIEM and UI labels must display `receipt_kind` and `boundary_class` together.
`trace_observation` and `advisory_evaluation` records must not be summarized as
authorized tool calls.

## Rationale

Separating boundary class from planning status keeps product claims honest while
still allowing research to be sequenced. A surface can be a clean future
implementation candidate but still blocked on semantics. A surface can also be
observable and useful for forensics without being a Chio-mediated security
control.

## Consequences

### Positive

- Adapter tickets are forced to name exactly what Chio prevents.
- Product wording cannot silently upgrade trace-only evidence into mediation.
- Directory and ecosystem research can continue without expanding capability
  scope.

### Negative

- Older research docs need banners or errata so historical language is not read
  as current product positioning.
- Some previously attractive bridge stories become smaller and slower to ticket.

## Required Follow-up

- Add a ticket template field for `boundary_class` and `planning_status`.
- Add UI and SIEM copy tests for trace-only and advisory-only records.
- Update protocol-strategy docs that still imply Bedrock Lambda or OpenAI
  hosted-tool mediation.
- Keep `boundary_class` and `planning_status` out of free-form prose in tickets
  when structured metadata is available.
