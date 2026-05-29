# Chio protocol strategy research, round 2 (May 2026)

## Context

Ten parallel research agents extended the May 2026 swarm: five **refine** passes that deepened doc-03/04/05 gating questions plus added concrete designs for AGNTCY ACP and the event-action vocabulary, three **expand** passes that filled the Tier-1 surfaces missing from the first round (OpenAI Responses, Bedrock Agents, voice), and two **cross-cutting** passes that stress-tested the receipt schema and audited hot-path latency.

Output: docs `07-` through `16-` on `research/protocol-strategy-2026`. First-round docs (`00-` through `06-`) are preserved as historical research with errata.

> **Plan-of-record status (PR 652 review):** This file is the synthesis of record for the research branch. The earlier [00-overview.md](00-overview.md) remains useful historical context, but follow-on planning should start here and then use [18-decision-packet.md](18-decision-packet.md) for architecture decisions before implementation tickets.

> **Erratum (subsequent reviews)**:
> - AGNTCY ACP is dead. `agntcy/acp-spec` was archived 2026-04-11 (the date doc 08 cited was the *archival* date, not a stabilization freeze). The bridge plan in phase C is struck; only the consume-only `chio-directory` integration survives. See [17-agntcy-revisited.md](17-agntcy-revisited.md).
> - The n8n priority-1 framing here originally referenced the Talos 686% abuse spike, which is **Chain D** (NOT blocked by Chio). The actually-blocked attack is **Chain C** (prompt-injection agent-to-webhook). See [11-n8n-threat-mapping.md](11-n8n-threat-mapping.md).
> - Bench-stub coverage is broader than originally reported: not 4 stubs, but **11+** ([reviews/04-receipts-kernel-latency-review.md](reviews/04-receipts-kernel-latency-review.md)). Doc 16's `responses.rs:1506` citation is also a wrong file path; the function lives at `crates/chio-kernel/src/kernel/responses.rs:1459-1517`.
> - Canonical type forms: the current signed receipt field is `policy_hash`, encoded as a hex or operator-pinned `String` (matches existing code, RFC 8785 friendly). Historical `policy_digest` references are per-engine digest sketches, not a current core receipt field. ADR-0010 folds `tool_origin` (`CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`) and `redaction_mode` into the current v1 receipt shape as separate signed fields; `human_principal` is the typed enum on `CallerIdentity` (doc 14) referenced by historical extension sketches, not duplicated.
> - `ActorRef` (the actor-chain element type formerly planned as a later receipt schema field) needs a concrete definition stub before receipt-kind work begins. Captured in doc 15.
> - Follow-up grounding corrections from PR 652 review: doc 05's `policy_version` / `manifest_id` receipt fields and `args_schema` examples are design intent, not current code; doc 09's event-action plan is folded into current v1 manifest planning, not a new manifest-generation rollout.

## TL;DR

Two findings change the immediate priorities:

1. **Per-stage kernel benches were `black_box(0_u64)` stubs (resolved).** ([X2](16-latency-budget-audit.md), with follow-up verification at [reviews/04](reviews/04-receipts-kernel-latency-review.md) expanding the list to 11+: `single_guard`, `cap_verify_ed25519`, `receipt_sign`, `guard_pipeline_5`, `scope_match`, `time_bound`, `revocation_lookup`, `budget_decrement`, `receipt_append`, `session_lookup`, `dispatch_deny`.) CI runs them at [`.github/workflows/bench-regression.yml:101-108`](../../../.github/workflows/bench-regression.yml#L101). The bench bodies now drive real dispatch through `dispatch_request_fixture` rather than constants, so earlier latency claims can be re-measured against the current bench tree.
2. **`tool_origin` is a current v1 receipt field, separate from redaction.** It surfaced independently in E1 (OpenAI built-in tools) and E2 (Bedrock Lambda action groups). PR 652 review tightened the rule: execution origin and redaction stay orthogonal. The planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated` plus a separate redaction mode.

Everything else is incremental but coherent: Cedar, OpenAI Responses, Bedrock Agents, voice (LiveKit-first) all fit. AGNTCY ACP is dead but AGNTCY Directory + Identity consumption survives. n8n priority restricted to Chain C. OAuth AS stays live but blocked for product work until a dedicated ADR or equivalent decision note is accepted.

## Per-doc headlines

| # | Agent | Headline | Recommendation |
|---|---|---|---|
| [07](07-oauth-as-usage-audit.md) | R1 OAuth AS audit | **Live but opt-in.** Real product code, 5 integration tests, conformance runner support, normative profile in [`spec/PROTOCOL.md:1351-1453`](../../../spec/PROTOCOL.md#L1351). Dead-by-default at runtime (handlers 404 without `--auth-server-seed-file`). No telemetry. | Block product tickets until an OAuth AS ADR or equivalent decision note settles feature gating, naming, scope clamp, telemetry, and posture. |
| [08](08-agntcy-acp-bridge-spec.md) | R2 AGNTCY ACP | **SUPERSEDED.** ACP archived 2026-04-11; doc 08's "frozen v0.2.3" framing was wrong. See [17-agntcy-revisited.md](17-agntcy-revisited.md). | Drop `chio-bridge-agntcy`. Keep `chio-directory` (DirectoryProvider trait + StaticAgntcyDirectoryProvider) for consume-only Directory + Identity integration. |
| [09](09-event-action-schema.md) | R3 Event actions | Unified `EventDestination` / `EventSource` with `BrokerKind` enum, not per-broker variants. | Fold into current `chio.manifest.v1` planning once the receipt/read-boundary gates exist. No manifest-generation bump before release. |
| [10](10-cedar-first-guard.md) | R4 Cedar first-guard | `McpToolGuard` ([`chio-guards/src/mcp_tool.rs`](../../../crates/chio-guards/src/mcp_tool.rs), 429 LOC) is the right port. Only ~6 of ~30 guards are pure list-and-branch; the rest are journal-stateful or ML/heuristic. | **Option A': greenfield + two flagship ports** (`McpToolGuard` and `EgressAllowlistGuard`). Not full migration. |
| [11](11-n8n-threat-mapping.md) | R5 n8n threat map | Priority-1 is **partially justified**. Chio blocks Chain C (prompt-injection webhook exfil) cleanly; does NOT block Chain D (the 686% ingress-abuse spike, which is below Chio's layer). | Keep n8n in the priority list; restrict the value-prop framing to Chain C. |
| [12](12-openai-responses-adapter.md) | E1 OpenAI Responses | Future adapter research only. **Potential MVP: caller-executed `function` tools only over streaming SSE on non-reasoning models.** Refuses built-in-tool or reasoning requests. | Blocked until v1 receipt/read-boundary gates land, then needs an API refresh against official Responses docs before ticketing or codegen. |
| [13](13-bedrock-agents-bridge.md) | E2 Bedrock Agents | New crate `chio-bedrock-agents-adapter`. **MVP: RETURN_CONTROL action groups full mediation**, Lambda actions receipt-logged only (AWS trust boundary). | Trace redaction default: `summary` (salted SHA-256 hashes preserving structural metadata). Opt-in `redacted` and `full` (full gated by separate IAM scope). |
| [14](14-voice-agent-bridges.md) | E3 Voice agents | **MVP: `chio-livekit-py` Python middleware** (`@chio_function_tool` decorator wrapping LiveKit's `@function_tool`). Pipecat FrameProcessor second; paired Vapi+Retell HTTP shim third. Signing fits the budget; **durability writes (5-50ms) are the limiter**. | Sign synchronously, write asynchronously, fail-closed bounded queue, sequence-numbered receipts. Needs current v1 async durability state (coordinate with X1). |
| [15](15-receipt-kind-v1.md) | X1 Current v1 receipt-kind semantics | **Option D core fields, folded into unreleased v1.** Promote the security-critical semantic fields into the signed receipt body. | Implement through ADR-0010: separate `tool_origin` and redaction, structural receipt kinds, and current `policy_hash` encoding. Extension signing, `must_understand`, and extension hashes are deferred until a separate accepted extension-binding design lands. No receipt-generation bump before release. |
| [16](16-latency-budget-audit.md) | X2 Latency audit | Estimated median verdict latency: **~2-4ms Ed25519-only, ~6-10ms hybrid**. Voice sub-200ms is **conditional**: yes with Ed25519 + in-process guards + async receipt write + per-bridge fast paths; no with hybrid + remote guards + sync SQLite. | Bench stub bodies replaced with real dispatch (resolved). Parallelize hybrid signing (~50-100us savings). HTTP path does 3 signatures + 1 verify per request: voice fast-path should skip outer sign. |

## Cross-cutting threads that emerged

1. **`tool_origin` belongs on the current v1 receipt body, but redaction is orthogonal.** E1 and E2 both need execution-locus provenance. The planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`; Bedrock trace redaction is represented by a separate signed `redaction_mode` / `trace_redaction_mode`, not a fourth origin variant.

2. **Async receipt write + sequence numbering is now load-bearing for voice.** E3 needs it; X1's extensions map can hold a `deferred_durability` flag with a bounded-loss SLO. This needs a coordinated design across X1, X2, and E3 before E3 starts.

3. **Cedar looks plausible for selected guards, but latency is not proven.** R4 + X2 reconciliation estimated ~150us with entity cache, which would fit normal tiers if real workloads confirm it. The earlier bench-stub gap is resolved, so this can now be measured rather than asserted; voice-tier planning still needs a **policy tier classification on guards**: voice-tier guards must declare in-process + async-durability.

4. **Double-gating is functionally free.** [`HttpEgressContract::enforce_url`](../../../crates/chio-egress-contract/src/lib.rs) is pure-Rust URL parse + allowlist (20-80us). Doc 05's double-gating recommendation stands without latency caveat.

5. **Future crate sketches, not shipped surfaces** + one blocked existing-surface follow-up: `chio-directory` (consume-only), `chio-bedrock-agents-adapter`, a future OpenAI function-tools adapter name TBD, `chio-livekit-py`, plus a future OAuth AS posture ticket only after its ADR or equivalent decision note is accepted. The previously-counted `chio-bridge-agntcy` has been struck (see erratum block). Coherent footprint, no overlap. The `chio-bridge-*` prefix is not a workspace convention; existing pattern is `-edge` (expose) / `-adapter` (consume) / `-proxy` (variant).

## Naming-collision warning

Three protocols are named "ACP":

1. **Zed's Agent Client Protocol / Anthropic Compute Protocol**: covered today by [`chio-acp-edge`](../../../crates/chio-acp-edge/).
2. **IBM Agent Communication Protocol**: converging with A2A; no Chio bridge today.
3. **AGNTCY Agent Connect Protocol**: archived 2026-04-11; absorbed into A2A. No Chio bridge planned.

The `chio-acp-*` namespace is owned by Zed's ACP. Do not propose other crates with that prefix. Doc 02 used the name `chio-bridge-acp` for AGNTCY, which is doubly wrong (now-dead protocol + non-convention prefix) and is corrected in the erratum at the top of [doc 02](02-decentralized-agent-networks.md).

## Updated phased build queue

Before implementation tickets, use [18-decision-packet.md](18-decision-packet.md)
and the accepted ADRs it points to as the decision record for current v1
receipt-kind semantics, the boundary matrix, current v1 event-action planning, and async receipt
durability. OAuth AS product work stays blocked until a dedicated OAuth AS ADR
or equivalent decision note is accepted.

### Phase A: foundation (close gaps, unblock everything else)

- **Real bench bodies landed in CI (resolved).** The 11 per-stage kernel benches now drive real dispatch through `dispatch_request_fixture` rather than `black_box(0_u64)`; the remaining work is gating benches with `required-features` per bench file. ([16](16-latency-budget-audit.md), [reviews/04](reviews/04-receipts-kernel-latency-review.md))
- **Current v1 receipt-kind semantic gate**: implement the accepted ADR-0010 decisions for
  `receipt_kind`, `boundary_class`, verifier behavior, `tool_origin`,
  redaction, `ActorRef`, and current `policy_hash` handling. Extension
  signing, extension hashes, and `must_understand` remain deferred until a
  separate extension-binding ADR lands. ([15](15-receipt-kind-v1.md), [18](18-decision-packet.md))
- **`EventPublish` / `EventConsume` ToolAction variants** in the current
  `chio.manifest.v1` planning shape, following the accepted ADR-0012 broker
  identity decisions. ([09](09-event-action-schema.md))
- **OAuth AS posture ADR or equivalent decision note** before any feature-flag,
  rename, or scope-clamp product ticket. ([07](07-oauth-as-usage-audit.md),
  [03](03-oauth-oidc-issuer.md))
- **Boundary classification gate**: every bridge plan must carry the accepted
  ADR-0011 `boundary_class` (`prevent`, `detect_only`, `advisory_only`,
  `cannot_see`) and `planning_status` (`ready_after_adr`, `blocked_by_adr`,
  `deferred`, `hard_skip`). ([18](18-decision-packet.md))
- **Manifest event-action enforcement gate**: implement broker identity, strict
  unknown-field rejection, and the event enforcement layer before event-action
  rollout. ([09](09-event-action-schema.md),
  [18](18-decision-packet.md))
- **`tool_origin` current v1 receipt field** (execution locus only; redaction separate by
  default). ([12](12-openai-responses-adapter.md),
  [13](13-bedrock-agents-bridge.md), [15](15-receipt-kind-v1.md),
  [18](18-decision-packet.md))
- **Parallelize hybrid signing** (`crates/chio-core-types/src/pq.rs:166-170` per doc 16: verify the citation as part of this work). ~50-100us savings on every receipt. ([16](16-latency-budget-audit.md))

### Phase B: high-ROI new bridges

- **Future OpenAI function-tools adapter**: function-tools-only MVP, refuses built-in / reasoning at boundary; blocked until v1 receipt/read-boundary gates and official-doc refresh. ([12](12-openai-responses-adapter.md))
- **`chio-bedrock-agents-adapter`**: RETURN_CONTROL mediation, summary redaction default. ([13](13-bedrock-agents-bridge.md))
- **Cedar `PolicyEngineProvider`** + port `McpToolGuard` + `EgressAllowlistGuard` as flagship references. ([10](10-cedar-first-guard.md))
- **n8n orchestrator-egress, Chain C only**: prompt-injection agent-to-webhook exfiltration is the value-prop; do NOT cite the Talos 686% spike (Chain D is below Chio's layer). ([11](11-n8n-threat-mapping.md))

### Phase C: strategic expansions

- **`chio-directory`** (consume-only): `DirectoryProvider` trait + `StaticAgntcyDirectoryProvider`. Read-only AGNTCY Directory + Identity consumption, mirroring Webex's production pattern. NO `chio-bridge-agntcy` (ACP is archived). ([17](17-agntcy-revisited.md))
- **`chio-livekit-py`**: voice mediation, paired with async receipt write + sequence numbering + bounded-loss SLO. ([14](14-voice-agent-bridges.md))
- **Per-bridge fast paths + voice-tier policy classification**: voice fast-path skips outer signature; voice-tier guards declare in-process. ([14](14-voice-agent-bridges.md), [16](16-latency-budget-audit.md))

### Phase D: defer

- AMQP / SNS+SQS / WebSub additions to `chio-streaming` ([01](01-pubsub-coverage-audit.md))
- Pipecat FrameProcessor, Vapi+Retell shims, and voice implementation before async durability is settled ([14](14-voice-agent-bridges.md))
- OPA / OpenFGA `PolicyEngineProvider` implementations (engines 2 and 3) ([04](04-policy-engine-collaborators.md))
- CDP / WebDriver BiDi computer-use bridge design (its own swarm)
- `PresignedUrlGuard` in `chio-data-guards` ([06](06-below-l7-mediation.md))
- AGNTCY ACP bridge, AGNTCY SLIM wire bridge, Agora, live directory import, and broad Cedar migration. Static/operator-pinned `chio-directory` remains the only AGNTCY-aligned path. ([17](17-agntcy-revisited.md), [18](18-decision-packet.md))

## Open questions

1. **Voice-tier policy classification**: should guards declare a tier (`voice` | `standard` | `batch`) and the kernel refuse to compose incompatible chains? Decide before E3 lands.
2. **Extension-binding ADR**: define whether `must_understand`, extension
   hashes, or inline extension signing belong in a future current-v1 update.
   They are not current signed receipt fields.
3. **AGNTCY Directory + Identity consumption details**: what's the production wire format Webex uses? Replaces the prior "zero-securitySchemes" question, which was specific to the now-dead ACP. See [17](17-agntcy-revisited.md).
4. **Async receipt write bounded-loss SLO**: what's acceptable? 1 receipt per 10^6? Per-bridge or per-tier?
5. **Bench baseline citation policy** (in force, post-bench-stub remediation):
   latency claims must cite the exact bench commit, feature set, and command
   that produced the numbers.

## Files

All in `docs/research/protocol-strategy/`. Round 1: 00-overview, 01 through 06. Round 2: 07 through 16. Review passes: [reviews/](reviews/). AGNTCY follow-up: [17-agntcy-revisited.md](17-agntcy-revisited.md). PR 652 decision packet: [18-decision-packet.md](18-decision-packet.md). This file: `00-overview-v2.md`.
