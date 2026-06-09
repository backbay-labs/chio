# Agent C - Swarm Authority Contract And Recursive Delegation

Confidence: high for the current-source inventory and gap analysis, moderate for the phased architecture because it introduces new receipt and authority artifacts that still need protocol review.

## Scope

This draft focuses on recursive agent swarms where a root agent delegates bounded authority to child agents, child agents delegate again, and fan-in joins combine results from multiple parents. The design goal is not to bypass the existing Chio kernel. The design goal is to make recursive delegation explicit enough that the existing kernel can verify every hop, every budget allocation, every route decision, and every receipt lineage transition with fail-closed behavior.

The core conclusion is direct: Chio already has strong primitives for capability attenuation, kernel verification, route evidence, continuation tokens, revocation snapshots, budget splits, and receipt lineage. It does not yet have a first-class swarm authority contract. Recursive swarms currently have to compose several single-parent or per-call primitives by convention, which is not good enough for launch-grade delegation.

## Current Assets

| Area | Current asset | File refs | How it should be reused |
| --- | --- | --- | --- |
| Capability attenuation model | Capability tokens already carry caveats, scope attenuations, attenuation proof, delegation chain, and optional budget share basis points. | `crates/chio-core-types/src/capability/token.rs:50-89` | Use this as the child capability envelope. Do not invent a parallel authority token. |
| Capability schema validation | Token validation rejects unenforced caveats, validates attenuation proofs, validates `budget_share_bps`, and verifies witness hashes. | `crates/chio-core-types/src/capability/token.rs:178-211` | Keep this as the first local sanity gate for swarm child capabilities. |
| Chain binding | Production verification requires delegation chain binding and defines trust-root or last-link parent scope hash matching. | `spec/PROTOCOL.md:373-415`, `crates/chio-core-types/src/capability/token.rs:214-331` | Swarm continuation must bind to the same parent scope chain, not just to a task id. |
| Attenuation witness | `AttenuationWitness` records parent scope hash, child scope hash, normalized parent and child scope, and subset relations. | `crates/chio-core-types/src/capability/attenuation.rs:19-39`, `crates/chio-core-types/src/capability/attenuation.rs:293-415` | This is the right primitive for per-hop attenuation witnesses. It needs to be carried on every recursive hop. |
| Delegation chain shape | `DelegationLink` records delegator, delegatee, attenuations, timestamp, optional scope hash, and signature. | `crates/chio-core-types/src/capability/attenuation.rs:41-77`, `crates/chio-core-types/src/capability/attenuation.rs:177-226` | Keep the link as the signed edge, but add witness binding for recursive chains. |
| Multi-hop restriction | The current trust-root chain validator explicitly rejects multi-hop attenuated chains because per-hop child-scope witnesses are missing. | `crates/chio-core-types/src/capability/attenuation.rs:228-291` | This is the cleanest source-backed reason to add swarm per-hop witnesses before supporting recursive delegation. |
| Delegation receipts | `DelegationReceipt` signs the parent chain, attenuation, nonce, link, and parent capability id for recursive `delegate` minting. | `crates/chio-core-types/src/delegation_receipt.rs:1-32`, `crates/chio-core-types/src/delegation_receipt.rs:90-160` | Reuse the receipt shape, but extend the authority record to bind witnesses, route plan, revocation epoch, and budget allocation. |
| Kernel verifier | `verify_capability_full` runs base validation, chain shape validation, chain binding validation, and budget admission. | `crates/chio-kernel-core/src/capability_verify.rs:342-357` | Swarm admission must call the same verifier. A swarm token is evidence, not a substitute verifier. |
| Side-effecting budget admission | Protocol splits pure pre-admit verification from authoritative budget admission for side-effecting dispatch and nested flows. | `spec/PROTOCOL.md:417-436`, `crates/chio-kernel/src/kernel/validation.rs:258-322` | Swarm planning may use pre-admit checks, but dispatch and recursive child minting must use authoritative admission. |
| Revocation checks | Kernel revocation checks cover leaf capability id and delegation-chain ancestor ids. | `crates/chio-kernel/src/kernel/validation.rs:438-453` | Swarm dispatch must retain leaf and ancestor checks and additionally bind the revocation epoch used at admission. |
| Runtime nested flows | `NestedFlowBridge` and `NestedFlowClient` let the kernel own lineage, policy, and in-flight bookkeeping for nested sampling, elicitation, and roots. | `crates/chio-kernel/src/runtime.rs:162-241`, `crates/chio-kernel/src/request_matching.rs:22-132` | Use nested-flow hooks as the local child-flow execution path, but attach explicit continuation authority. |
| Session lineage | Session request lineage records currently track a single `parent_request_id` and session anchor. | `crates/chio-kernel/src/session.rs:106-117`, `crates/chio-kernel/src/session.rs:519-568`, `crates/chio-kernel/src/session.rs:634-662` | Keep the session anchor, but add multi-parent join receipts for fan-in. |
| Governed continuation tokens | `CallChainContinuationToken` binds chain id, parent request id, parent receipt data, session anchor, subject, capability lineage, audience, intent hash, nonce, and time bounds. | `crates/chio-core-types/src/capability/governance.rs:247-312`, `crates/chio-core-types/src/capability/governance.rs:314-431` | This is the closest existing model for `SwarmContinuationToken`, but it is single-parent and governed-call-chain specific. |
| Continuation validation | Kernel validation checks call-chain shape, parent context, session anchor, trusted signer, audience, intent hash, subject, and parent capability id. | `crates/chio-kernel/src/kernel/governed_validation.rs:353-555` | Reuse the validation posture for swarm continuation: signed, contextual, audience-bound, short-lived, and fail-closed. |
| Receipt DAG spec | The protocol specifies `chainId`, sorted `parentReceiptIds`, `parentSetHash`, `dagOrdinal`, and HLC fields for multi-parent receipt lineage. | `spec/PROTOCOL.md:801-811` | This is the right contract for fan-in, but it is not fully present in `ChioReceipt` yet. |
| Receipt lineage helpers | Helpers exist for canonical parent id ordering and parent-set hashing, and lineage statements can be signed. | `crates/chio-core-types/src/receipt/lineage.rs:62-118`, `crates/chio-core-types/src/receipt/lineage.rs:210-402` | Use these helpers for join receipts, but do not rely on pairwise statements as the only join proof. |
| Current receipt body | `ChioReceipt` contains receipt id, agent, capability, tool, decision, guard results, timestamps, hash fields, and evidence metadata. | `crates/chio-core-types/src/receipt/body.rs:33-102` | Add references to swarm join and route-plan artifacts through signed metadata until receipt-body migration is complete. |
| Route selection | Cross-protocol routing has candidates, selected decisions, attenuation decisions, bridge ids, and route evidence metadata. | `crates/chio-cross-protocol/src/routing.rs:12-20`, `crates/chio-cross-protocol/src/routing.rs:49-88`, `crates/chio-cross-protocol/src/routing.rs:97-260` | Promote route-selection evidence from receipt metadata to a signed route-plan receipt. |
| Cross-protocol orchestration | The orchestrator validates requests, extracts capability references, creates attenuated route scope, plans routes, executes selected targets, and writes route metadata into kernel receipts. | `crates/chio-cross-protocol/src/orchestrator.rs:27-42`, `crates/chio-cross-protocol/src/orchestrator.rs:137-367` | Make the orchestrator consume a route-plan receipt and continuation token rather than recomputing authority by convention. |
| MCP edge | MCP target execution forwards route selection metadata into the kernel request. | `crates/chio-mcp-edge/src/runtime/tool_calls.rs:4-17`, `crates/chio-mcp-edge/src/runtime/tool_calls.rs:46-112` | MCP should reject caller-supplied swarm route metadata unless it is backed by a signed route-plan receipt. |
| A2A edge | A2A edge binds skills to capabilities and stores deferred execution requests. | `crates/chio-a2a-edge/src/edge.rs:15-25`, `crates/chio-a2a-edge/src/edge.rs:300-326`, `crates/chio-a2a-edge/src/edge.rs:372-420` | Deferred A2A tasks must persist the swarm continuation token, revocation epoch, and budget lease. |
| ACP edge | ACP edge binds capabilities, runs orchestrated invokes, and supports deferred stream tasks with owner checks. | `crates/chio-acp-edge/src/edge.rs:13-24`, `crates/chio-acp-edge/src/edge.rs:169-194`, `crates/chio-acp-edge/src/edge.rs:360-381`, `crates/chio-acp-edge/src/edge.rs:826-940` | ACP stream resume must verify continuation freshness and budget lease validity, not just task ownership. |
| Protocol registry | Cross-protocol discovery resolves Native, HTTP, MCP, A2A, ACP, and OpenAI targets. | `crates/chio-cross-protocol/src/discovery.rs:10-27`, `crates/chio-cross-protocol/src/discovery.rs:49-98` | Route-plan receipts should bind to a registry snapshot hash so the selected target cannot drift silently. |
| Revocation oracle | `RevocationSnapshot` contains epoch, root hash, issued timestamp, and revoked ids; `RevocationView` installs newer snapshots monotonically. | `crates/chio-kernel-core/src/revocation_view.rs:1-35`, `crates/chio-kernel-core/src/revocation_view.rs:75-118`, `crates/chio-kernel-core/src/revocation_view.rs:148-218` | Bind every swarm authority artifact to revocation epoch and root hash. |
| Legacy revocation store | Runtime revocation store exposes leaf id lookup and mutation. | `crates/chio-kernel/src/revocation_runtime.rs:6-45` | Keep it for local checks, but launch-grade recursive delegation needs epoch-bound evidence. |
| Budget split | Kernel-core budget split supports sibling-sum enforcement, budget share basis points, and per-parent admission accounting. | `crates/chio-kernel-core/src/budget_split.rs:1-20`, `crates/chio-kernel-core/src/budget_split.rs:153-213`, `crates/chio-kernel-core/src/budget_split.rs:242-419` | Use this as the minimum invariant under swarm budget pools. |
| Budget mutation store | Budget store supports hold, release, reverse, reconcile, guarantee levels, authority metadata, and mutation records. | `crates/chio-kernel/src/budget_store.rs:16-31`, `crates/chio-kernel/src/budget_store.rs:65-157`, `crates/chio-kernel/src/budget_store.rs:175-217` | Build pool leases on top of this store instead of adding a second accounting system. |
| Metering semantics | Metering spec defines fail-closed budget admission for operations and nested tool calls. | `spec/METERING.md:80-130` | Swarm fan-out and fan-in must preserve these semantics across multiple children. |
| Runtime contracts | Tool calls and responses are mediated by kernel request and response types, including attached receipts. | `crates/chio-kernel/src/runtime.rs:40-118` | Swarm execution should remain a kernel-mediated tool call path. |
| HTTP egress contracts | OpenAPI MCP bridge has explicit HTTP egress constraints, route bindings, and single-hop no-redirect behavior. | `crates/chio-openapi-mcp-bridge/src/lib.rs:80-131`, `crates/chio-openapi-mcp-bridge/src/lib.rs:246-305`, `spec/PROTOCOL.md:1257-1290` | Route plans should commit to egress contract id and route binding for HTTP hops. |

## Exact Gaps

1. Multi-hop attenuated delegation is not launch-ready. The current chain validator explicitly rejects chains longer than one link when attenuated delegation requires per-hop child-scope witnesses. This is correct fail-closed behavior, but it means recursive swarm authority cannot be represented by the current chain alone.

2. `DelegationReceipt` proves a newly minted delegation link and its parent chain, but it does not bind revocation epoch, route plan, budget pool allocation, graph task id, or a per-hop witness set. It is a mint receipt, not a full recursive swarm authority contract.

3. `CallChainContinuationToken` is valuable but too narrow. It has one parent request id and optional one parent receipt, while swarms need parent sets, join receipts, graph task ids, route-plan commitments, and budget allocation leases.

4. Receipt DAG support is split between protocol intent and helper types. The protocol describes multi-parent receipt lineage, and helper functions exist for canonical parent sets, but `ChioReceipt` does not yet carry the top-level DAG fields, and signed lineage statements are pairwise rather than a join receipt over a parent set.

5. Route selection evidence is still metadata attached to execution receipts. It is not a signed route-plan artifact that downstream kernels, edges, or deferred-task resumes can verify independently.

6. Revocation validation is strong at local admission time but weak as portable evidence. The kernel can check a leaf and ancestor ids, and `RevocationView` exposes epoch and root hash, but current delegation and continuation artifacts do not bind the exact revocation epoch under which they were admitted.

7. Budgets are per-parent splits and operation holds, not graph pools. There is no first-class pool that can reserve budget across a fan-out, release unused budget at fan-in, and prove that children never collectively exceeded the root allocation.

8. A2A and ACP deferred tasks store execution requests and enforce ownership, but they do not persist swarm continuation tokens, revocation epochs, or budget leases as authority-bearing artifacts.

9. MCP route metadata can be forwarded into the kernel request, but the edge currently lacks a contract saying route metadata must come from a signed route-plan receipt rather than from caller-provided decoration.

10. Runtime nested flows track a single parent request within a session anchor. That works for sampling, elicitation, and local child requests, but it does not model multi-parent joins or recursive delegated capability minting across protocol edges.

11. HTTP egress contracts are per dispatcher and per route binding. They do not yet participate in a graph-level route plan that signs the selected chain across Native, HTTP, MCP, A2A, ACP, and OpenAI hops.

12. There is no explicit cycle, duplicate-parent, stale-epoch, or cross-chain fan-in gate for swarm task graphs. Those checks are implied by future DAG semantics, not enforced by a current swarm verifier.

## Proposed Architecture

### SwarmTaskGraph

`SwarmTaskGraph` should be a signed planning and authority manifest. It should not execute anything by itself. It should describe the allowed recursive structure so kernels and edges can verify that every delegated child action belongs to a bounded graph.

Required fields:

| Field | Requirement |
| --- | --- |
| `schema` | Fixed value such as `chio.swarm_task_graph.v1`. |
| `graph_id` | Content-addressed id over the canonical graph body. |
| `root_request_id` | The kernel request that caused graph creation. |
| `root_capability_id` | Capability id from which all child authority descends. |
| `chain_id` | Shared receipt lineage chain for this swarm execution. |
| `issuer_kernel_id` | Kernel or authority that signed the graph. |
| `planner_subject` | Subject that requested or generated the plan. |
| `created_at_unix_ms` and `expires_at_unix_ms` | Hard time bounds. |
| `revocation_epoch` and `revocation_root_hash` | Oracle snapshot used for graph admission. |
| `max_depth` | Maximum delegation depth. |
| `max_fanout` | Maximum children per node. |
| `max_concurrency` | Maximum active child tasks. |
| `budget_pool_root_id` | Root swarm budget pool. |
| `registry_snapshot_hash` | Discovery or route registry snapshot used during planning. |
| `nodes` | Task nodes with requested scopes, protocol targets, joins, and budgets. |
| `edges` | Parent-child delegation edges with witness and continuation references. |
| `joins` | Fan-in joins with sorted parent task and receipt sets. |
| `signature` | Signature over the canonical body. |

Each `nodes` entry should include:

- `task_id`: stable graph-local id.
- `role`: planner, executor, reducer, verifier, summarizer, bridge, or external-tool hop.
- `protocol_surface`: Native, HTTP, MCP, A2A, ACP, OpenAI, or local nested flow.
- `target`: registry target, tool server id, skill binding, capability binding, or HTTP route binding.
- `requested_scope_hash`: hash of the requested child scope before attenuation.
- `child_scope_hash`: hash of the approved child scope after attenuation.
- `required_operations`: allowed operations, tools, methods, or routes.
- `parent_task_ids`: sorted direct parent task ids.
- `parent_receipt_ids`: sorted receipt ids required before this node can run.
- `join_policy`: none, all, quorum, first-success, reducer-verified, or explicit predicate hash.
- `route_plan_id`: signed route plan selected for this node.
- `budget_allocation_ids`: pool leases reserved for this node.
- `continuation_token_id`: token expected by the child executor.
- `evidence_class`: asserted, observed, or verified.
- `cancellation_policy`: timeout, parent-failure, budget-exhaustion, revocation-change, or manual cancel.

Each `edges` entry should include:

- `parent_task_id` and `child_task_id`.
- `parent_capability_id` and `child_capability_id`.
- `delegation_receipt_id`.
- `per_hop_witness_id`.
- `continuation_token_id`.
- `route_plan_id`.
- `budget_allocation_ids`.
- `revocation_epoch`.

Each `joins` entry should include:

- `join_id`.
- `child_task_id`.
- `parent_task_ids`.
- `parent_receipt_ids`, sorted and deduplicated.
- `parent_set_hash`, computed using the current canonical parent-set helper.
- `required_chain_id`.
- `dag_ordinal_floor`.
- `join_predicate_hash`.
- `output_scope_hash`.
- `budget_release_policy`.
- `join_receipt_id`.

Core invariant: the graph is an upper bound. A child may receive less scope, less budget, a narrower route, and shorter lifetime than the graph allows. A child may never receive more.

### SwarmContinuationToken

`SwarmContinuationToken` should be the portable child-execution authority context. It should not be the capability token and should not replace capability verification. It should bind a specific child execution to a parent set, route plan, budget allocation, revocation epoch, and session anchor.

Required body fields:

| Field | Requirement |
| --- | --- |
| `schema` | Fixed value such as `chio.swarm_continuation_token.v1`. |
| `token_id` | Content-addressed id over canonical body. |
| `graph_id` | Swarm task graph id. |
| `chain_id` | Receipt lineage chain id. |
| `task_id` | Child task that may execute. |
| `signer` | Kernel, authority, or trusted lineage signer. |
| `subject` | Subject allowed to present the token. |
| `audience` | Target edge, kernel, tool server, or protocol binding. |
| `parent_task_ids` | Sorted direct parent task ids. |
| `parent_request_ids` | Parent request ids when available. |
| `parent_receipt_ids` | Sorted direct parent receipt ids. |
| `parent_set_hash` | Hash over sorted parent receipt ids and chain id. |
| `parent_capability_ids` | Parent capability ids used for authority derivation. |
| `child_capability_id` | Capability id expected for this task. |
| `parent_scope_hash` and `child_scope_hash` | Scope hashes for the immediate attenuation hop. |
| `attenuation_witness_hash` | Hash of the per-hop witness. |
| `delegation_receipt_id` | Delegation receipt for the child capability. |
| `route_plan_id` and `route_plan_hash` | Route commitment for this task. |
| `budget_allocation_ids` | Budget leases this task may consume. |
| `revocation_epoch` and `revocation_root_hash` | Snapshot bound at mint time. |
| `session_anchor_id` and `session_anchor_hash` | Local or remote session anchor. |
| `intent_hash` | Hash of task intent and allowed operation set. |
| `nonce` | Replay protection. |
| `issued_at_unix_ms` and `expires_at_unix_ms` | Short lifetime. |
| `signature` | Signature over canonical body. |

Validation sequence:

1. Verify the token signature and canonical id.
2. Verify token time bounds and nonce replay status.
3. Verify audience, subject, graph id, task id, and intent hash.
4. Verify parent set hash from sorted parent receipt ids and expected chain id.
5. Verify route plan id and hash.
6. Verify budget allocation ids are live, unspent beyond limit, and bound to this task.
7. Verify revocation epoch and root hash against the current `RevocationView` policy.
8. Verify child capability id matches the presented capability.
9. Run `verify_capability_full` with the authoritative trust-root resolver and budget registry for side-effecting dispatch.

The continuation token should be single-use for side-effecting execution unless the graph node explicitly marks it as resumable. Deferred A2A and ACP tasks should store the resumable token id and require a fresh epoch check on resume.

### Per-Hop Attenuation Witness Design

The recursive delegation blocker is not conceptual. It is concrete: the validator rejects multi-hop attenuated chains because it cannot verify per-hop child-scope witnesses. The fix should be explicit and narrow.

Add a per-hop witness record with these fields:

| Field | Requirement |
| --- | --- |
| `witness_id` | Content-addressed id over canonical witness body. |
| `parent_capability_id` | Capability being attenuated. |
| `child_capability_id` | Capability produced by this hop. |
| `parent_scope_hash` | Scope hash before this hop. |
| `child_scope_hash` | Scope hash after this hop. |
| `attenuation_witness` | Existing normalized parent and child scope witness. |
| `budget_share_bps` | Child share granted by this hop. |
| `delegator` and `delegatee` | Subjects from the delegation link. |
| `delegation_link_hash` | Hash of the signed delegation link. |
| `route_plan_hash` | Optional route-plan hash if this hop targets a protocol edge. |
| `revocation_epoch` and `revocation_root_hash` | Epoch bound at witness mint time. |
| `issued_at_unix_ms` | Witness mint time. |
| `signature` | Delegator or authority signature. |

Verifier rules:

1. Every delegated hop after the root must have a witness.
2. The first witness parent scope hash must match the trust-root scope hash.
3. Each later witness parent scope hash must equal the previous witness child scope hash.
4. Each delegation link scope hash must equal the witness child scope hash.
5. The token-level `attenuation_proof.parent_scope_hash` must match the last parent scope in the chain.
6. The token-level `attenuation_proof.child_scope_hash` must match the final child scope.
7. Any missing, duplicated, reordered, or mismatched witness rejects.
8. Any hop whose revocation epoch is stale under policy rejects unless the verifier is in explicit historic audit mode.

This lets the current validator move from "reject all recursive attenuated chains" to "accept only recursive chains with a complete per-hop witness chain."

### Multi-Parent Join Receipts

Fan-in requires a receipt that proves a child task is allowed to proceed from several parent results. Pairwise lineage statements are not enough because they cannot prove the exact set of parents used for a join or exclude omitted parents under quorum rules.

Define `SwarmJoinReceipt`:

| Field | Requirement |
| --- | --- |
| `schema` | Fixed value such as `chio.swarm_join_receipt.v1`. |
| `join_id` | Graph-local join id. |
| `receipt_id` | Content-addressed id of the join receipt. |
| `graph_id` | Swarm graph id. |
| `chain_id` | Receipt lineage chain id. |
| `child_task_id` | Task unlocked by the join. |
| `parent_task_ids` | Sorted parent tasks. |
| `parent_receipt_ids` | Sorted and deduplicated parent receipt ids. |
| `parent_set_hash` | Canonical hash over chain id and parent receipt ids. |
| `dag_ordinal` | One greater than the maximum accepted parent ordinal. |
| `hlc` | Hybrid logical clock tuple for deterministic order. |
| `join_policy` | all, quorum, first-success, reducer-verified, or predicate hash. |
| `aggregation_hash` | Hash of normalized join inputs and reducer output. |
| `input_receipt_summaries` | Minimal signed summaries of decision, capability id, tool id, and result hash. |
| `route_plan_hash` | Route plan for the next child task if selected at join. |
| `budget_releases` | Unused child allocations returned to the parent or join pool. |
| `budget_rollups` | Consumed budget totals by dimension. |
| `revocation_epoch` and `revocation_root_hash` | Epoch used at join admission. |
| `signature` | Kernel or join authority signature. |

Verifier rules:

1. Parent receipt ids must be sorted and deduplicated before hashing.
2. Parent receipts must share the expected `chain_id`.
3. Parent receipt ids must not include the child receipt id.
4. The join must not create a cycle in the graph.
5. `dag_ordinal` must increase.
6. HLC must be monotonic for the local chain.
7. Join policy must be satisfied by the parent set and receipt decisions.
8. Budget release and rollup records must match the budget store.
9. Revocation epoch must be acceptable at join time.

The join receipt should be the parent receipt for the next task whenever a fan-in node continues execution. That avoids pretending a multi-parent join is just another single-parent call-chain continuation.

### Route-Plan Receipt

Route selection should be promoted from metadata to a signed artifact before cross-protocol dispatch.

Define `RoutePlanReceipt`:

| Field | Requirement |
| --- | --- |
| `schema` | Fixed value such as `chio.route_plan_receipt.v1`. |
| `plan_id` | Content-addressed id over canonical body. |
| `graph_id` and `task_id` | Swarm context. |
| `issuer_kernel_id` | Kernel or authority that selected the route. |
| `source_protocol` | Protocol surface that received the task. |
| `target_protocol` | Selected target protocol. |
| `source_capability_hash` | Hash of presented capability reference or envelope. |
| `child_scope_hash` | Scope authorized for the route. |
| `governed_intent_hash` | Hash of tool intent, operation, and request class. |
| `registry_snapshot_hash` | Snapshot of target registry used for candidate selection. |
| `candidate_hashes` | Hashes of all considered route candidates. |
| `decision` | select, attenuate, or deny. |
| `selected_route` | Target id, executor id, protocol, and route binding. |
| `egress_contract_id` | Required for HTTP or OpenAPI bridge hops. |
| `route_evidence_hash` | Hash of the detailed route-selection evidence. |
| `budget_allocation_ids` | Budget leases authorized for this route. |
| `revocation_epoch` and `revocation_root_hash` | Oracle snapshot at route selection. |
| `issued_at_unix_ms` and `expires_at_unix_ms` | Time bounds. |
| `signature` | Signature over canonical route plan. |

Dispatch rule: every A2A, ACP, MCP, HTTP, and OpenAI cross-protocol dispatch must reference a route-plan receipt. The executor may attach route evidence metadata for observability, but the signed route plan is the authority artifact. If metadata and route-plan receipt disagree, dispatch rejects.

### Revocation Epoch Binding

Recursive delegation must bind to a revocation oracle epoch because child tasks may run later, on another edge, or after a deferred resume.

Required binding:

- `revocation_epoch`
- `revocation_root_hash`
- `revocation_issued_at_unix_ms`
- `max_revocation_staleness_ms`
- `revocation_view_id` when multiple views are supported

These fields must appear in:

- `SwarmTaskGraph`
- `SwarmContinuationToken`
- per-hop attenuation witness
- `DelegationReceipt` extension or swarm authority wrapper
- `RoutePlanReceipt`
- `SwarmJoinReceipt`
- budget allocation lease

Verifier policy:

1. If the current view has an older epoch than the artifact, reject unless the verifier explicitly supports future-epoch gossip.
2. If the current view has the same epoch but a different root hash, reject.
3. If the current view has a newer epoch, recheck leaf and ancestor revocation under the newer view.
4. If the artifact age exceeds `max_revocation_staleness_ms`, reject side-effecting dispatch.
5. Historic audit mode may verify old signatures against old epochs, but it must not authorize new execution.

This makes deferred A2A and ACP task resume safe: ownership is necessary, but ownership alone is not authority.

### Swarm Budget Pools

The existing budget split and budget mutation store should remain the accounting substrate. Swarm budget pools should add graph-level allocation, leasing, fan-out reservation, and fan-in release semantics.

Define `SwarmBudgetPool`:

| Field | Requirement |
| --- | --- |
| `pool_id` | Content-addressed id or authority-generated id. |
| `graph_id` | Swarm graph id. |
| `parent_capability_id` | Capability from which the pool descends. |
| `authority` | Kernel or budget authority. |
| `dimensions` | invocations, cost, tokens, bytes, wall-clock ms, concurrency, custom meters. |
| `total_limits` | Maximum per dimension. |
| `reserved_totals` | Sum of active allocations. |
| `consumed_totals` | Confirmed usage. |
| `released_totals` | Returned unused budget. |
| `guarantee_level` | Same vocabulary as budget store. |
| `revocation_epoch` | Epoch at pool creation. |
| `expires_at_unix_ms` | Pool lifetime. |
| `signature` | Budget authority signature. |

Define `SwarmBudgetAllocation`:

| Field | Requirement |
| --- | --- |
| `allocation_id` | Unique lease id. |
| `pool_id` and `graph_id` | Pool context. |
| `task_id` | Task that may spend the lease. |
| `continuation_token_id` | Token bound to the lease. |
| `route_plan_id` | Route authorized to spend the lease. |
| `limits` | Per-dimension allocation. |
| `state` | reserved, active, released, consumed, expired, reversed. |
| `issued_at_unix_ms` and `expires_at_unix_ms` | Time bounds. |
| `revocation_epoch` | Epoch at allocation. |
| `signature` | Budget authority signature. |

Budget rules:

1. Child allocations must never exceed parent remaining budget.
2. Sibling allocations must preserve existing sibling-sum basis-point constraints.
3. Side-effecting dispatch must move an allocation from reserved to active or consumed.
4. Duplicate allocation use rejects.
5. Fan-in join releases unused child allocations according to the join policy.
6. Deferred task resume must revalidate the allocation lease and revocation epoch.
7. Budget rollups must be included in join receipts and terminal graph receipts.

This gives Chio a graph budget model without weakening the existing kernel-core split accounting.

### Cross-Protocol Flow

1. The root agent submits a task to the kernel with a root capability.
2. The kernel runs current capability verification, including schema validation, chain checks, revocation checks, and pre-admit evaluation.
3. The planner builds a `SwarmTaskGraph` with bounded depth, fan-out, route candidates, task scopes, join policies, revocation epoch, and root budget pool.
4. For each child node, the authority mints or selects a child capability, per-hop attenuation witness, delegation receipt, budget allocation lease, route-plan receipt, and swarm continuation token.
5. For a local nested flow, the kernel uses `NestedFlowClient` and stores the continuation token with the child request lineage.
6. For MCP, the edge receives the child capability, route-plan receipt, and continuation token. It verifies the signed route plan before passing route metadata into the kernel request.
7. For A2A, the edge verifies the skill binding, continuation token, route-plan receipt, revocation epoch, and budget lease. Deferred tasks persist all of those authority artifacts and revalidate them on resume.
8. For ACP, invoke and stream flows follow the same rule. Resume requires owner match, fresh continuation validation, revocation epoch acceptance, and live budget allocation.
9. For HTTP or OpenAPI bridge hops, the route-plan receipt binds the selected route binding and egress contract id before dispatch.
10. Each child execution emits a normal Chio receipt plus swarm metadata references to the continuation token, route-plan receipt, delegation receipt, witness id, and allocation id.
11. Fan-in nodes produce a `SwarmJoinReceipt` over sorted parent receipt ids and release unused budget.
12. The next child after a fan-in uses the join receipt as its immediate parent artifact, not an arbitrary parent receipt from the set.
13. Terminal graph completion emits a graph summary receipt with final budget rollups, route-plan ids, join ids, and revocation epoch evidence.

### Verification Surface

Every verifier should answer five questions before allowing a child task to run:

1. Authority: does the child capability verify under `verify_capability_full` with the proper trust root, chain binding, revocation checks, and budget admission?
2. Attenuation: does every recursive hop carry a valid per-hop witness proving the child scope is a subset of the parent scope?
3. Lineage: does the parent set match the graph, receipt chain id, parent-set hash, and join policy?
4. Route: does the signed route-plan receipt match the protocol edge, target, egress contract, and intent hash?
5. Budget: does the allocation lease belong to this graph, task, continuation token, route plan, and revocation epoch?

If any answer is unavailable, the verifier rejects. Unknown is deny.

## Tests And Gates

1. Capability-chain unit tests: accept a two-hop attenuated chain only when each hop has a valid witness; reject missing witness, reordered witness, mismatched parent scope hash, mismatched child scope hash, mismatched delegation link hash, and stale revocation epoch.

2. Recursive attenuation conformance tests: generate fan-out trees of depth 1 through the configured maximum and assert that no child can widen tool scope, route scope, time bounds, caveats, or budget share.

3. Kernel admission tests: prove `SwarmContinuationToken` validation still calls `verify_capability_full` for side-effecting dispatch, and prove a pre-admit-only path cannot execute an external tool call.

4. Revocation tests: revoke the leaf after continuation mint and before dispatch; revoke an ancestor; install a newer epoch with the same leaf still live; install the same epoch with a different root hash. Expected behavior should be explicit and fail-closed.

5. Route-plan tests: reject unsigned route plans, route metadata without a matching plan, target protocol mismatch, registry snapshot mismatch, egress contract mismatch, and candidate-set tampering.

6. Receipt DAG tests: verify parent receipt sorting, deduplication, parent-set hash calculation, cross-chain parent rejection, cycle rejection, `dag_ordinal` increase, and HLC monotonicity.

7. Join policy tests: cover all, quorum, first-success, reducer-verified, and predicate-hash joins. Confirm omitted required parents reject and extra parents change the parent-set hash.

8. Budget-pool tests: reject oversubscription, duplicate allocation spend, expired allocation, allocation for the wrong task, route-plan mismatch, and fan-in release totals that do not match child usage.

9. A2A deferred-task tests: start a deferred task, revoke the ancestor, then resume. Resume must reject. Repeat with stale epoch, expired continuation, and exhausted budget.

10. ACP stream tests: verify owner match is insufficient without continuation validation, route-plan validation, revocation epoch acceptance, and live budget allocation.

11. MCP edge tests: ensure caller-provided route metadata is ignored or rejected unless backed by a signed route-plan receipt.

12. Nested-flow tests: sampling and elicitation child requests must bind to a continuation token when they cross a delegated authority boundary.

13. Fuzz and property tests: arbitrary task graphs should reject cycles, duplicate task ids, duplicate parent receipts, stale epochs, parent-set collisions, and depth or fan-out limit violations.

14. Static gates: add lint or conformance checks that forbid new cross-protocol executors from dispatching without route-plan receipt validation and forbid side-effecting dispatch with `NoopBudgetRegistry`.

## Phased Plan

### Phase 0 - Spec And Type Contracts

Write protocol sections for `SwarmTaskGraph`, `SwarmContinuationToken`, per-hop attenuation witness, `SwarmJoinReceipt`, `RoutePlanReceipt`, and `SwarmBudgetPool`. Add canonical JSON field ordering rules and versioning rules before implementation. This phase should not change runtime behavior.

Exit gate: schema review passes, canonical test vectors exist, and every new artifact has a fail-closed verifier contract.

### Phase 1 - Per-Hop Witness Verification

Extend delegation-chain validation to accept multi-hop attenuated chains only when a complete per-hop witness chain exists. Keep the current rejection for missing or incomplete witnesses. Bind witness hashes to delegation receipts and child capabilities.

Exit gate: current one-hop behavior is unchanged, multi-hop without witnesses still rejects, and multi-hop with valid witnesses passes only under the configured feature gate.

### Phase 2 - Swarm Continuation And Join Receipts

Implement `SwarmContinuationToken` validation by adapting governed-call-chain token validation. Add parent-set hashing and join receipt verification. Do not require immediate `ChioReceipt` body migration if signed join receipts can be referenced from receipt metadata during transition.

Exit gate: single-parent continuations still work, multi-parent joins produce signed join receipts, and pairwise lineage statements remain available as compatibility evidence.

### Phase 3 - Route-Plan Receipts

Promote cross-protocol route selection to signed route-plan receipts. Make MCP, A2A, ACP, HTTP, and OpenAI execution paths verify route-plan receipts before dispatch. Route metadata remains useful for observability, but it is no longer authority.

Exit gate: every cross-protocol side-effecting dispatch has a route-plan receipt id in its receipt metadata, and tampered route metadata rejects.

### Phase 4 - Revocation Epoch And Budget Pools

Bind revocation epoch and root hash into all swarm artifacts. Add swarm budget pools and allocation leases on top of the existing budget store and sibling-sum registry. Add fan-in release and rollup records to join receipts.

Exit gate: deferred task resume rejects stale epochs and expired allocations, and graph completion can reconcile reserved, consumed, released, and reversed budget totals.

### Phase 5 - Edge Integration And Conformance

Integrate the swarm authority contract with local nested flows, MCP, A2A, ACP, HTTP/OpenAPI bridge, and cross-protocol orchestration. Add conformance scenarios for recursive A2A to MCP to HTTP flows, ACP deferred streams, and nested local sampling.

Exit gate: conformance suite proves no child can widen authority through recursion, route changes, deferred resume, fan-in, or protocol translation.

### Phase 6 - Launch Hardening

Run adversarial tests against deep graphs, high fan-out, join races, stale revocation views, budget exhaustion, duplicate resumes, and route registry drift. Add operational dashboards for rejected swarm artifacts by reason.

Exit gate: launch decision is blocked unless recursive delegation has green conformance, fuzz coverage, deterministic canonical vectors, and receipts proving route, revocation, lineage, and budget for every executed child.

## Strongest Recommendations

1. Treat per-hop attenuation witnesses as the mandatory unlock for recursive delegation. Do not weaken the current multi-hop rejection until witness coverage is complete.

2. Create `SwarmContinuationToken` as an authority-context token, not as a replacement for capability tokens. The kernel must still run `verify_capability_full`.

3. Promote route selection to signed route-plan receipts before relying on A2A, ACP, MCP, or HTTP nested flows. Metadata is observability, not authority.

4. Bind every swarm artifact to a revocation epoch and root hash. Deferred execution without epoch revalidation is not acceptable for recursive authority.

5. Add swarm budget pools as leases layered over the existing budget store and sibling-sum registry. Fan-out must reserve budget, and fan-in must release or roll up unused allocation with signed evidence.
