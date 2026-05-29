# Chio bridge for AWS Bedrock Agents (`InvokeAgent`)

> **Historical research note (PR 652):** Use [00-overview-v2.md](00-overview-v2.md) and [18-decision-packet.md](18-decision-packet.md) for planning. This file remains research input, not an implementation ticket.
>
> **Erratum (PR 652 review):** `tool_origin` records execution locus, not redaction policy. Lambda action groups remain host-executed and outside Chio's mediation boundary; trace redaction should be captured by a separate signed current v1 `trace_redaction_mode` field.

## TL;DR

Add a `chio-bedrock-agents-adapter` crate (sibling, not extension, of `chio-bedrock-converse-adapter` at [`crates/chio-bedrock-converse-adapter/src/lib.rs:1`](../../../crates/chio-bedrock-converse-adapter/src/lib.rs#L1)). MVP: full `ToolServerConnection::invoke` mediation for `RETURN_CONTROL` action groups; trace-only logging for `LAMBDA` action groups (`boundary_class = detect_only`, AWS trust boundary); default-on trace redaction (free-form reasoning replaced by salted hashes; opt-in verbatim retention under stricter bounds); reuse the converse adapter's signed `IamPrincipalsConfig` for caller identity. KB citation gating and multi-agent collaboration deferred. Region: us-east-1 + us-west-2 at MVP, full thirteen-region list as a follow-on. The decision boundary is sharp: Chio mediates runtime parameters only for `RETURN_CONTROL`, because that is the only mode where the caller (and therefore Chio) executes the action.

## API shape

`bedrock-agent-runtime:InvokeAgent` posts to `POST /agents/{agentId}/agentAliases/{agentAliasId}/sessions/{sessionId}/text` with body `inputText`, `enableTrace`, `endSession`, `memoryId`, `sessionState`, `bedrockModelConfigurations`, `promptCreationConfigurations`, `streamingConfigurations` ([InvokeAgent reference](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_InvokeAgent.html)). `agentId` and `agentAliasId` are ten-char opaque IDs. `sessionId` is two-to-hundred chars. `x-amz-source-arn` is pinned to `arn:aws(-[^:]+)?:bedrock:[a-z0-9-]{1,20}:[0-9]{12}:agent/[0-9a-zA-Z]{10}`.

The response is an event stream multiplexing:

- `chunk` ([`PayloadPart`](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_PayloadPart.html)): `bytes` blob and optional `attribution.citations[]` (S3, Confluence/SharePoint/Salesforce, web, Kendra, custom IDs).
- `trace` ([`TracePart`](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_TracePart.html)): the agent's step-by-step reasoning record.
- `returnControl` ([`ReturnControlPayload`](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_ReturnControlPayload.html)): `invocationId` + up to five `invocationInputs[]`, each `apiInvocationInput` (OpenAPI schema: `actionGroup`, `apiPath`, `httpMethod`, `parameters[]`, `requestBody`, `actionInvocationType`) or `functionInvocationInput` (function-detail schema: `actionGroup`, `function`, `parameters[]`, `actionInvocationType`). `actionInvocationType` can be `RESULT`, `USER_CONFIRMATION`, or `USER_CONFIRMATION_AND_RESULT` and must be settled before implementation.
- `files` ([`FilePart`](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_FilePart.html)): `bytes`, `name`, `type` for code-interpreter artifacts.
- Error envelopes: `accessDeniedException` (403), `badGatewayException` (502), `conflictException` (409), `dependencyFailedException` (424), `internalServerException` (500), `modelNotReadyException` (424), `resourceNotFoundException` (404), `serviceQuotaExceededException` (400), `throttlingException` (429), `validationException` (400).

The continuation handshake matters: when an agent emits `returnControl`, the caller follows up with a *new* `InvokeAgent` whose `sessionState.invocationId` matches and whose `sessionState.returnControlInvocationResults[]` carries `apiResult.responseBody.application/json.body` or `functionResult.responseBody.TEXT.body`. With `returnControlInvocationResults` present, `inputText` is ignored. This is the seam where Chio mediates.

## `RETURN_CONTROL` boundary

`RETURN_CONTROL` is the mode where AWS deliberately hands tool parameters back to the caller for execution. Every `actionGroupInvocationInput` is labeled `executionType: LAMBDA | RETURN_CONTROL`. Two mediation profiles:

- `executionType == "LAMBDA"`: fulfillment is wired to a Lambda declared at agent-build time, executing *inside* AWS's trust boundary. Chio cannot interpose; it sees only the trace observation summarizing the Lambda's output. Receipt records: `action_group_kind = lambda`, `action_group_id`, `function` or `apiPath`, `parameter_hash` (SHA-256 over canonical-JSON `parameters[]` from the trace event), `boundary_class = detect_only`, and `mediation_scope = "trace_only"`. The receipt body must say "AWS reported Lambda action group X; Chio did not constrain runtime." Honest and audit-portable.
- `executionType == "RETURN_CONTROL"`: the agent stops and waits for `returnControlInvocationResults`. The caller is the policy-enforcement seam. Chio runs full `ToolServerConnection::invoke` evaluation (manifest validation, data guards, policy-hash check) on the parameters *before* the caller dispatches. On deny: either (a) synthesize `functionResult.responseBody.TEXT.body = "<denied by chio policy>"` and post it back as `returnControlInvocationResults`, ending the loop gracefully, or (b) cancel the session with `endSession: true` and emit a deny receipt. Recommendation: (a) default, (b) for hard-deny categories (data-exfiltration class).

Mediation scope is on every receipt regardless of mode. The "did Chio actually constrain this action?" question gets a binary answer with cryptographic backing.

## Trace event leakage and redaction

`enableTrace: true` is the largest leakage surface on this API. Per the [trace events guide](https://docs.aws.amazon.com/bedrock/latest/userguide/trace-events.html), a single trace event can include:

- `PreProcessingTrace.modelInvocationOutput.parsedResponse.rationale` (free-form reasoning).
- `OrchestrationTrace.rationale.text` (orchestration reasoning).
- `OrchestrationTrace.modelInvocationOutput.rawResponse.content` (verbatim FM output, often echoing customer input).
- `OrchestrationTrace.invocationInput.actionGroupInvocationInput.parameters[]` and `.requestBody.content` (action-group call parameters, often PII).
- `OrchestrationTrace.invocationInput.knowledgeBaseLookupInput.text` (the KB query text).
- `OrchestrationTrace.observation.knowledgeBaseLookupOutput.retrievedReferences[].content.text` (verbatim KB excerpts, the most directly customer-data-shaped field).
- `OrchestrationTrace.observation.actionGroupInvocationOutput.text` (JSON-stringified action return, frequently a structured customer record).
- `PostProcessingTrace.modelInvocationOutput.rawResponse.content` (final-stage FM output pre-parse).
- `GuardrailTrace.inputAssessments[].sensitiveInformationPolicy.piiEntities[].match` (the PII string Guardrails detected; turning on guardrails ironically *adds* a leakage field).

Default redaction mode: `summary`:

- Replace every free-form text field with `{"sha256": "<hex>", "byte_len": N, "redacted_at": <ISO 8601>}`.
- Salt inputs by `(sessionId, traceId)` to prevent cross-session correlation while preserving in-session replay equivalence. Salt held in `chio-credentials`.
- Preserve structural metadata: `traceId`, `type`, `invocationType`, `executionType`, foundation model name, token usage, guardrail verdicts (`GUARDRAIL_INTERVENED | NONE`).

Two opt-in modes:

- `redacted`: drop the offending fields entirely; structural metadata only. For zero-knowledge regulatory environments where even hashes are sensitive.
- `full`: verbatim, tagged `trace_redaction_mode: "full"`, with stricter retention bounds via `chio-data-guards` and a separate IAM gate.

Selector is per-session and per-action-group; the receipt always embeds the chosen mode so an auditor cannot be deceived about what they are reading.

Redaction is implemented as a `chio-data-guards`-registered redactor (sibling of `SqlQueryGuard`, `PresignedUrlGuard` from doc 06), matching the doc 04 pattern of out-of-process guard providers.

## Streaming response handling

Bedrock Agents `InvokeAgent` responses use event-stream framing. The
`streamingConfigurations.streamFinalResponse` setting controls final-response
streaming and must be set intentionally; the adapter implements
`ToolServerConnection::invoke_stream`
([`crates/chio-kernel/src/runtime.rs:292`](../../../crates/chio-kernel/src/runtime.rs#L292))
and returns `ToolServerStreamResult`
([`crates/chio-kernel/src/runtime.rs:136`](../../../crates/chio-kernel/src/runtime.rs#L136)).

Event mapping:

- `PayloadPart` -> `ToolCallChunk { data: { "kind": "chunk", "bytes": <base64>, "citations": [...] } }`.
- `TracePart` -> `ToolCallChunk { data: { "kind": "trace", "trace_id", "trace_type", "fields": <redacted-by-policy> } }`.
- `ReturnControlPayload` -> *sub-evaluation*: the stream pauses, the adapter runs `ToolServerConnection::invoke` on each entry in `invocationInputs[]` (one Chio sub-call per invocation input), then resumes by issuing the follow-up `InvokeAgent` with `returnControlInvocationResults`. Each sub-call gets its own receipt linked to the parent by `invocation_id`.
- `FilePart` -> `ToolCallChunk { data: { "kind": "file", "name", "media_type", "bytes_sha256" } }`. File bytes never appear in the chunk; the adapter materializes them to a kernel scratch store and surfaces only the hash. Egress goes through `chio-egress-contract` on a separate hop.
- Error envelopes -> `ToolServerStreamResult::Incomplete { stream, reason }` with the AWS exception name as `reason`.

The sub-evaluation pattern makes the streaming bridge non-trivial: a single user-facing `InvokeAgent` may fan out to N `RETURN_CONTROL` sub-invocations, each independently mediated, each with its own receipt, all linked in a tree rooted on the outer `invocation_id`. Structurally analogous to `NestedFlowBridge` ([`crates/chio-kernel/src/runtime.rs:156`](../../../crates/chio-kernel/src/runtime.rs#L156)); the same lineage discipline applies.

## IAM integration

The converse adapter already has the answer: `IamPrincipalsConfig` ([`crates/chio-bedrock-converse-adapter/src/iam_principals.rs:90`](../../../crates/chio-bedrock-converse-adapter/src/iam_principals.rs#L90)) is a Sigstore-signed TOML loader mapping STS `GetCallerIdentity` ARNs to Chio owner/team labels via ordered first-match wildcard patterns. Process-wide STS caching in `AwsStsCallerIdentityProvider` ([`crates/chio-bedrock-converse-adapter/src/iam_principals.rs:42`](../../../crates/chio-bedrock-converse-adapter/src/iam_principals.rs#L42)). Mapping yields `ResolvedBedrockPrincipal` ([`crates/chio-bedrock-converse-adapter/src/iam_principals.rs:117`](../../../crates/chio-bedrock-converse-adapter/src/iam_principals.rs#L117)) producing `Principal::BedrockIam { caller_arn, account_id, assumed_role_session_arn }` ([`crates/chio-tool-call-fabric/src/lib.rs:66`](../../../crates/chio-tool-call-fabric/src/lib.rs#L66)).

The new adapter consumes this identically. To avoid duplication: extract `iam_principals.rs` into a `chio-bedrock-iam` crate both adapters depend on (follow-on, not MVP-blocking). For MVP, the new adapter takes the same constructor inputs as `BedrockAdapter::new_with_signed_iam_principals_config` ([`crates/chio-bedrock-converse-adapter/src/lib.rs:145`](../../../crates/chio-bedrock-converse-adapter/src/lib.rs#L145)) and uses `pub use` re-exports.

Fail-closed property is preserved: an unsigned or unmapped principal cannot construct a `BedrockAgentsAdapter`, period.

## Receipt fields

Add the following to the receipt body emitted by this adapter (slotted into the existing `ChioReceiptBody` shape at [`crates/chio-core-types/src/receipt.rs:159`](../../../crates/chio-core-types/src/receipt.rs#L159), most likely inside a typed `provider_specific` payload to avoid widening the core schema):

- `agent_id: String` (ten-char Bedrock ID).
- `agent_alias_id: String` (ten-char alias ID).
- `session_id: String` (operator-chosen, two-to-hundred chars).
- `invocation_id: String` (Bedrock-generated UUID).
- `action_group_id: String` (the `actionGroup` name from the invocation input).
- `action_group_kind: enum { lambda, return_control }`.
- `action_group_schema_style: enum { openapi, function_detail }` (so the receipt encodes which `apiInvocationInput` vs `functionInvocationInput` shape was in play).
- `return_control_payload_hash: Option<[u8; 32]>` (SHA-256 over canonical-JSON of `invocationInputs[]`, present iff `action_group_kind = return_control`; supports forensic replay without storing parameter bodies).
- `trace_redaction_mode: enum { full, summary, redacted }` (matches the redaction policy used; required field).
- `trace_redaction_salt_id: String` (salt key ID, *not* salt value; for replay of summary hashes when the operator possesses the salt).
- `knowledge_base_citations: Vec<HashedCitation>` where `HashedCitation { kb_id: String, location_hash: [u8; 32], excerpt_hash: [u8; 32], confidence: Option<f32> }`. Hashes-of-S3-URIs / hashes-of-Confluence-URLs avoid leaking source paths into receipts; raw locations are recoverable under stricter retention bounds via the trace itself when in `full` mode.
- `caller_chain: Vec<String>` (the `callerChain[].agentAliasArn` list from `TracePart`; in multi-agent collaboration this captures the supervisor path).
- `mediation_scope: enum { trace_only, full_runtime }` (`trace_only` for Lambda, `full_runtime` for RETURN_CONTROL).

The `policy_hash` and `evidence` fields on `ChioReceiptBody` ([`crates/chio-core-types/src/receipt.rs:168`](../../../crates/chio-core-types/src/receipt.rs#L168)) are unchanged. The Bedrock Agents-specific block sits alongside, addressable by `body_hash`.

## Manifest mapping

Bedrock action groups are declared at agent-build time as either OpenAPI 3.0 (`apiInvocationInput` shape) or function-detail (`functionInvocationInput` shape: `name`/`description`/`parameters` per function). The adapter:

- At boot, calls `bedrock-agent:GetAgent` / `:GetAgentActionGroup` to fetch definitions for the configured `(agentId, agentAliasId)`.
- Caches by `(agentId, agentAliasId, agentVersion)`, refreshed on alias-version change. AWS does not sign action-group schemas, so integrity is from the SigV4 response and the cached tuple is then signed by the adapter's runtime key before being passed to the kernel.
- Generates one Chio `ToolDefinition` per action-group operation. Tool ID: `bedrock-agents:<agentAliasId>:<actionGroupName>:<operationIdOrFunctionName>`. OpenAPI uses `operationId` if present and `<method>:<apiPath>` otherwise; function-detail uses `function`.
- Translates parameter schemas: OpenAPI maps directly to JSON Schema; function-detail (`name`, `type`, `description`, `required`) is lifted via a small `chio-manifest` helper.
- Adds a synthetic `bedrock-agents:<agentAliasId>:__agent__:invoke` tool definition wrapping the outer `InvokeAgent` call. Action-group sub-tools are only reachable via the `RETURN_CONTROL` sub-evaluation path.

If the agent emits `RETURN_CONTROL` for an action group with no matching `ToolDefinition` (added in AWS console, adapter not yet rebooted), the adapter fails closed by synthesizing `functionResult.responseBody.TEXT.body = "<unknown action group; chio manifest stale>"` and refusing dispatch.

## MVP scope

In scope:

- Streaming event-stream consumption with the chunk / trace / returnControl / files event mapping above.
- `RETURN_CONTROL` action groups with full `ToolServerConnection::invoke` mediation and the sub-evaluation tree pattern.
- Trace redaction with `summary` default, `redacted` and `full` opt-ins.
- IAM principal mapping reusing `IamPrincipalsConfig`.
- Receipt fields enumerated above (Bedrock-specific block + `mediation_scope`).
- Manifest generation via `bedrock-agent:GetAgentActionGroup` at boot.
- Regions: `us-east-1` and `us-west-2` (the two FIPS-eligible regions; all other regions only support standard endpoints).

Out of scope for MVP:

- Lambda-resident action groups beyond passive receipt logging. Chio cannot mediate the action's runtime; pretending otherwise would be dishonest. Receipts will record what AWS reports in trace observations, but the receipt explicitly notes `boundary_class = detect_only` and `mediation_scope = trace_only`.
- Knowledge-base citation gating (deciding whether a KB excerpt is allowed to appear in the final response). This belongs in `chio-data-guards` as a `KnowledgeBaseCitationGuard`, and the same guard can be reused by the converse adapter when it eventually surfaces RAG content. Track as a follow-on.
- Multi-agent collaboration (`callerChain` length > 1, `collaboratorName` populated, `AGENT_COLLABORATOR` invocation type). The adapter should *record* the `callerChain` on every receipt but should not yet attempt to gate collaborator-agent invocations as if they were tools. Multi-agent collaboration deserves its own design pass; it is structurally a federated-agent problem and rhymes with `DirectoryProvider` from doc 02.
- Code-interpreter file egress beyond hash recording. File bytes are surfaced to the kernel by hash only; full egress goes through `chio-egress-contract`.
- `RoutingClassifierTrace`, `CustomOrchestrationTrace`. Surfaced verbatim in receipts only when `trace_redaction_mode = full`; otherwise treated as structural metadata only.

Out of scope, period:

- The `bedrock-agent:*` control-plane build operations (create/update agent, create/update action group). Chio is a runtime mediator, not a Bedrock provisioning system.

## Crate structure

Name: `chio-bedrock-agents-adapter`.

Shared with `chio-bedrock-converse-adapter`: proposed `chio-bedrock-iam` (extraction of `iam_principals.rs`), `chio-attest-verify` (Sigstore bundle verification), `chio-tool-call-fabric` (`Principal::BedrockIam`, `ProviderId::Bedrock`), `chio-provider-adapter-core::Provider`, and the `transport::Transport` trait shape (different operation set).

Separate: wire types (`aws_sdk_bedrockagentruntime` vs `aws_sdk_bedrockruntime`); the streaming model (Converse's `ConverseStream` vs Agents' event-stream multiplex are structurally different); the trace-redaction subsystem (new); the action-group manifest generator (Converse takes tools verbatim from the caller, Agents lifts them from AWS).

The two crates share *intent* (Bedrock IAM principals, region pinning, fail-closed config) but not *wire surface*. Co-locating would inflate the dependency cone and make per-API region pinning harder. Two crates.

Layout: `crates/chio-bedrock-agents-adapter/src/{lib.rs, adapter.rs, transport.rs, streaming.rs, trace_redaction.rs, manifest.rs, native.rs}`. The same anti-network-on-build discipline from the converse adapter applies: no AWS client construction in normal builds.

## Regions

Bedrock Agents runtime is available in thirteen regions: us-east-1, us-west-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, ap-south-1, ca-central-1, eu-central-1, eu-west-1, eu-west-2, eu-west-3, sa-east-1 ([endpoints reference](https://docs.aws.amazon.com/general/latest/gr/bedrock.html)). FIPS endpoints exist only in us-east-1 and us-west-2 (`bedrock-agent-runtime-fips.{us-east-1,us-west-2}.amazonaws.com`).

This is materially different from the Converse adapter, which is pinned to `us-east-1` at v1 ([`BEDROCK_REGION`](../../../crates/chio-bedrock-converse-adapter/src/transport.rs#L1)). The Agents adapter should not inherit that pin. MVP recommendation:

- MVP: accept `us-east-1` and `us-west-2` only. These are the two FIPS regions and the only two with mature multi-model availability.
- Follow-on: add the eleven remaining regions in a single PR once the EU and AP behavior is validated against real account billing. Each region needs a smoke test under a real Bedrock account because feature parity has historically lagged (e.g. Claude availability differed across regions through 2024).
- The region allowlist is operator-configured per-adapter-instance, not hard-coded in a constant. The converse adapter's pin pattern is too restrictive for Agents.
- Cross-region failover is out of scope. If an operator wants resilience, they configure two adapter instances against two regions and let the kernel route.

## Summary

(1) `chio-bedrock-agents-adapter`: MVP scope is RETURN_CONTROL action groups with full `ToolServerConnection::invoke` mediation, Lambda action groups recorded but explicitly not mediated, default-on trace redaction, IAM principal reuse from the converse adapter, regions us-east-1 and us-west-2.

(2) Trace redaction default is `summary` (free-form reasoning, KB excerpts, action-group parameter bodies, and FM raw outputs replaced by salted SHA-256 hashes; structural metadata preserved); opt-in modes are `redacted` (drop entirely) and `full` (verbatim under stricter retention bounds and IAM gate).

(3) File path: this file.
