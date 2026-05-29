# 18 - PR 652 decision packet

## Purpose

This packet converts the protocol-strategy research into decisions that must be
settled before implementation tickets are written. It is intentionally narrower
than the research corpus:

- [00-overview-v2.md](00-overview-v2.md) is the plan of record for PR 652.
- Earlier wave docs remain historical research with errata.
- This file is the bridge from research to implementation planning.
- This PR still makes no public API, schema, or code changes.

## Grounding Corrections

The review pass found four places where research wording was stronger than the
current code supports:

| Claim area | Correct grounding | Planning implication |
|---|---|---|
| Benchmarks | 11 kernel Criterion benches previously used `black_box(0_u64)` stubs; they now carry real bodies driven through `dispatch_request_fixture`. | Latency-sensitive plans for voice, Cedar overhead, hybrid signing, and fast paths can now be measured against the new bodies; remaining work is `required-features` gating per bench. |
| Receipt fields | `ChioReceiptBody` has `policy_hash`, `metadata`, `trust_level`, and `tenant_id`, but not `policy_version` or `manifest_id`. | Treat `policy_version` and `manifest_id` as proposed current v1 fields or signed metadata, not current fields. |
| Workflow manifests | `SkillStep` uses `input_contract` / `output_contract`, not `args_schema`. | Orchestrator examples using `args_schema` are desired constraint shape, not current schema. |
| Manifest event actions | Current manifests do not yet carry first-class event publish/consume actions. | Fold `EventPublish` / `EventConsume` into current v1 manifest planning after receipt/read-boundary gates exist; do not add a manifest schema limit field before release. |

CI health is also not research signal yet. The PR checks failed before job
startup because of GitHub Actions billing or spending-limit state. Rerun after
that account issue is cleared.

## Required ADRs

Use the ADRs below before implementation tickets:

| ADR | Default stance | Locks |
|---|---|---|
| [ADR-0010 Current V1 Receipt-Kind And Trace Semantics](../../adr/ADR-0010-current-v1-receipt-kind-trace-semantics.md) | Receipt-kind semantics are folded into unreleased v1. Trace/advisory records are not allow-shaped receipts. | `receipt_kind`, `boundary_class`, verifier behavior, `tool_origin`, redaction, `ActorRef`, and current `policy_hash` handling. Extension signing, extension hashes, and `must_understand` remain blocked until a separate accepted extension-binding design lands. |
| [ADR-0011 Boundary Taxonomy And Product Wording](../../adr/ADR-0011-boundary-taxonomy-product-wording.md) | Every surface must say what Chio prevents, only detects, only advises on, or cannot see. | `boundary_class`, `planning_status`, mediated versus trace-only wording, and SIEM/UI labels. |
| [ADR-0012 Current V1 Manifest Event-Action Planning](../../adr/ADR-0012-current-v1-manifest-event-actions.md) | `EventPublish` / `EventConsume` are current v1 planning work, not a new manifest generation. | Broker identity, rejection behavior, `RequiredPermissions` unknown-field behavior, SDK migration window, and enforcement location. |
| [ADR-0013 Async Receipt Durability](../../adr/ADR-0013-async-receipt-durability.md) | Durable-before-allow remains default; async requires WAL-backed recovery. | WAL versus bounded loss, queue saturation deny behavior, sequence gaps, replay detection, and audit wording. |
| OAuth AS posture | Block implementation tickets until a dedicated ADR or equivalent decision note is accepted. | Accepted scope / RAR grammar, migration behavior, telemetry need, and whether the AS is product surface or reference bridge. |

## Boundary Matrix

This matrix is the minimum wording discipline for adapter planning. A bridge may
only be described as mediated when Chio is in the decision path before the
effect crosses the boundary.

Use two fields, not one overloaded status:

- `boundary_class`: `prevent`, `detect_only`, `advisory_only`, or `cannot_see`.
- `planning_status`: `ready_after_adr`, `blocked_by_adr`, `deferred`, or `hard_skip`.

| Surface | boundary_class | planning_status | Planning note |
|---|---|---|---|
| Python `chio-streaming` event publish / consume | `prevent` | `ready_after_adr` | Add typed `EventPublish` / `EventConsume`, broker contract, and current v1 manifest event-action shape before more broker expansion. |
| OpenAI Responses `function` tools executed by caller runtime | `prevent` | `ready_after_adr` | Function-tools-only MVP can be planned after current v1 receipt-origin semantics are frozen and official tool taxonomy is refreshed. |
| OpenAI hosted tools and built-ins other than caller-executed functions | `detect_only` | `deferred` | Refuse in MVP. Current OpenAI tool taxonomy includes more surfaces than the original research; trace semantics must be refreshed before ticketing. |
| OpenAI remote MCP / connectors | `detect_only` | `blocked_by_adr` | Approval may be a preventable control point, but execution remains outside Chio unless the caller owns the dispatch path. Keep blocked until a surface-specific ticket proves a Chio-owned approval boundary. |
| OpenAI computer use caller harness | `prevent` | `blocked_by_adr` | Current docs describe caller-executed computer actions. Treat separately from hosted tools; do not implement until receipt semantics distinguish action mediation from model planning. |
| Bedrock Agents `RETURN_CONTROL` action groups | `prevent` | `ready_after_adr` | Clean mediation seam: Chio executes returned invocation inputs and sends results back. |
| Bedrock Lambda action groups | `detect_only` | `deferred` | AWS executes outside Chio. Receipts must say trace-only, with redaction mode signed separately. |
| n8n agent-to-webhook exfiltration (Chain C) | `prevent` | `ready_after_adr` | Workflow allowlist + typed input constraints + HTTP egress contract are the value prop. |
| n8n unauthenticated webhook ingress abuse (Chain D) | `cannot_see` | `hard_skip` | Do not cite the Talos 686 percent spike as a blocked chain. |
| AGNTCY Directory + Identity, static/operator-pinned | `advisory_only` | `ready_after_adr` | Directory data may help discovery, but must never widen local capability scope. |
| LiveKit function tools | `prevent` | `blocked_by_adr` | Wrapper is plausible; voice implementation waits on async receipt SLO and voice-tier guard rules. |
| Vapi / Retell shims | `prevent` | `deferred` | Needs fresh webhook/auth contract research and durability rules. |
| Cedar engine behind Chio guard pipeline | `prevent` | `ready_after_adr` | Cedar is a collaborator, not a replacement substrate; start with selected list/branch guards after real latency measurements. |
| OPA / OpenFGA / Tetragon | `prevent` | `deferred` | Keep as research until Cedar pattern and latency measurements are real. |
| Below-L7 mediation, DNS, TLS interception, SOCKS5, DB wire proxies | `cannot_see` | `hard_skip` | Out of this PR's scope and outside the core Chio boundary. |

## Planning Sequence

1. **Measurement foundation**
   - The bench-stub engineering plan has shipped: the 11
     `black_box(0_u64)` bodies are replaced in-tree
     with real bodies driven through `dispatch_request_fixture`.
   - Remaining work in this area: add `required-features` gating per bench
     where needed, and re-baseline latency claims for voice, Cedar, and
     hybrid signing against the new bodies.

2. **Semantic foundation**
   - Use accepted ADRs for current v1 receipt-kind semantics, origin/redaction, boundary matrix, current v1 manifest event-action planning, and async durability.
   - Do not add receipt or manifest schema limit fields or legacy
     compatibility paths before release.
   - Manifest constraints are enforced through manifest admission, typed guard/action evaluation, and SDK/bridge wire checks.
   - OAuth AS implementation tickets remain blocked until a dedicated ADR or equivalent decision note is accepted.

3. **Plan-ready protocol work**
   - `EventPublish` / `EventConsume` in the current v1 manifest shape.
   - Hybrid signing parallelization.

4. **Blocked protocol work**
   - OAuth AS feature gate + rename + scope clamp remains blocked until an
     accepted OAuth AS ADR or equivalent decision note resolves scope / RAR
     grammar, migration behavior, telemetry, and product-surface posture.

5. **Bridge planning after foundations**
   - OpenAI Responses function-tools-only MVP.
   - Bedrock Agents `RETURN_CONTROL` adapter with real trace fixtures.
   - n8n Chain-C orchestrator-egress only.
   - Static/operator-pinned `chio-directory`.

6. **Deferred work**
   - AGNTCY ACP bridge, AGNTCY SLIM wire bridge, Agora, live directory import, broad Cedar migration, OPA / OpenFGA, Vapi / Retell, Pipecat, below-L7 mediation, and voice implementation before async durability is settled.

## Parallel Research Queue

These tracks can run while bench repair and semantic ADRs proceed. They should
produce grounding notes, not bridge tickets:

- OAuth AS posture: keep feature-gated and seed-file gated; collect evidence
  before any IdP expansion or product-surface claim.
- Cedar cache-key threat model: identify cache key inputs, invalidation rules,
  and timing claims after real bench data exists.
- OpenAI tool taxonomy: refresh function calling, computer actions, remote MCP,
  connectors, and hosted tools against official docs before adapter tickets.
- Bedrock fixtures: collect `RETURN_CONTROL` and Lambda action-group fixtures,
  preserving the prevent versus trace-only boundary split.
- LiveKit MCPToolset and function tools: confirm wrapper control points before
  any voice planning.
- GitHub Agentic Workflows naming: refresh `gh-aw` and Agent Workflow Firewall
  wording from official docs before Actions planning.
- n8n adapter facts: refresh webhook auth modes, self-hosted assumptions, and
  Chain C versus Chain D language from official or primary sources.

## External Fact Refresh

Before any adapter implementation, refresh facts from official sources:

- OpenAI tool semantics: <https://developers.openai.com/api/docs/guides/tools>
- OpenAI function calling: <https://developers.openai.com/api/docs/guides/function-calling>
- OpenAI computer use: <https://developers.openai.com/api/docs/guides/tools-computer-use>
- OpenAI MCP / connectors: <https://developers.openai.com/api/docs/guides/tools-connectors-mcp>
- AWS Bedrock `RETURN_CONTROL`: <https://docs.aws.amazon.com/bedrock/latest/userguide/agents-returncontrol.html>
- AWS Bedrock action-group executor shape: <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ActionGroupExecutor.html>
- LiveKit function tools: <https://docs.livekit.io/agents/logic/tools/definition/>
- AGNTCY ACP archive state: <https://api.github.com/repos/agntcy/acp-spec>
- GitHub Agentic Workflows: <https://github.github.io/gh-aw/>
- Cisco Talos n8n research: <https://blog.talosintelligence.com/the-n8n-n8mare/>

## Acceptance Criteria For Ticketing

Implementation tickets can be written only when all of the following are true:

- The ticket names both `boundary_class` and `planning_status`.
- The ticket references an accepted ADR for any new schema or trust-boundary behavior.
- Receipt-affecting tickets state `receipt_kind`, boundary class, durability state, verifier behavior, and UI/SIEM wording.
- The ticket states whether the surface is mediated, trace-only, or advisory-only.
- Adapter tickets cite refreshed official docs for every external API fact they rely on.
- OAuth AS tickets are blocked until a dedicated ADR or equivalent decision note is accepted.
- Latency-sensitive tickets cite real bench data, not the current stubbed CI benches.
