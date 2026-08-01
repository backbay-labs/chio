// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.
//
// Source:     spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:       json-schema-to-typescript 15.0.4 (see xtask/codegen-tools.lock.toml)
// Pin file:   sdks/typescript/scripts/package.json
// Schema SHA: 582094cbf4cb918a2be49620a49e069724971ff99732340623d2f7b24082442e
//
// The schema-sha above is sha256 of `<rel-path>\0<bytes>\0` for every
// schema in lex order. It changes whenever any schema under
// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane
// asserts byte-equality of this entire file via `--check` mode.

/* eslint-disable */

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/active-response-governed-intent.schema.json
export namespace Agent_ActiveResponseGovernedIntent {
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/governed-transaction-intent.schema.json
export namespace Agent_GovernedTransactionIntent {
  export interface ChioGovernedTransactionIntent {
    id: string;
    server_id: string;
    tool_name: string;
    purpose: string;
    max_amount?: {
      units: number;
      currency: string;
    };
    commerce?: {};
    metered_billing?: {};
    runtime_attestation?: {};
    call_chain?: {};
    autonomy?: {};
    context?: unknown;
    body?:
      | {
          kind: "tool_invocation";
        }
      | {
          kind: "active_response_plan";
          value: ChioGovernedActiveResponseIntentBody;
        };
  }
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/heartbeat.schema.json
export namespace Agent_Heartbeat {
  export interface ChioAgentMessageHeartbeat {
    type: "heartbeat";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/list_capabilities.schema.json
export namespace Agent_ListCapabilities {
  export interface ChioAgentMessageListCapabilities {
    type: "list_capabilities";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/agent/tool_call_request.schema.json
export namespace Agent_ToolCallRequest {
  export type ChioAgentMessageToolCallRequest = {
    [k: string]: unknown;
  } & {
    type: "tool_call_request";
    id: string;
    capability_token: ChioCapabilityToken;
    server_id: string;
    tool: string;
    params: unknown;
    governed_intent?: ChioGovernedTransactionIntent;
    approval_token?: ChioGovernedApprovalToken;
    /**
     * @maxItems 32
     */
    approval_tokens?: ChioGovernedApprovalToken[];
    threshold_approval_proposal?: ChioThresholdApprovalProposal;
    supplemental_authorization?: ChioOpaqueSupplementalAuthorization;
    execution_nonce?: ChioSignedExecutionNonce;
  };
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
    constraints?: (
      | GenericConstraint
      | LegacyApprovalConstraint
      | CumulativeApprovalDirectConstraint
      | CumulativeApprovalDelegableConstraint
    )[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind: "restrict_tool" | "bind_session" | "restrict_audience" | "restrict_geo" | "restrict_time_window";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
  export interface ChioGovernedTransactionIntent {
    id: string;
    server_id: string;
    tool_name: string;
    purpose: string;
    max_amount?: {
      units: number;
      currency: string;
    };
    commerce?: {};
    metered_billing?: {};
    runtime_attestation?: {};
    call_chain?: {};
    autonomy?: {};
    context?: unknown;
    body?:
      | {
          kind: "tool_invocation";
        }
      | {
          kind: "active_response_plan";
          value: ChioGovernedActiveResponseIntentBody;
        };
  }
  export interface ChioGovernedActiveResponseIntentBody {
    plan_schema: "chio.governed-response-plan.v1";
    plan_id: string;
    operator_capability_id: string;
    operator_capability_hash: string;
    operator_capability_expires_at: number;
    executor_subject: string;
    canonical_plan_body: {};
    plan_body_hash: string;
    target_binding: {};
    /**
     * @minItems 1
     * @maxItems 32
     */
    ordered_effects: [
      "throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance",
      ...("throttle_session" | "restrict_egress" | "suspend_session" | "suspend_capability_set" | "freeze_issuance")[]
    ];
    expires_at: number;
    rollback_binding: {};
  }
  export interface ChioGovernedApprovalToken {
    id: string;
    approver: string;
    subject: string;
    governed_intent_hash: string;
    request_id: string;
    threshold_proposal_hash?: string;
    issued_at: number;
    expires_at: number;
    decision: "approved" | "denied";
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: string;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface ChioOpaqueSupplementalAuthorization {
    /**
     * Opaque authenticated extension bytes. Adapters must not interpret these bytes as quota authority.
     */
    signed_extension: string;
  }
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/anchor/batch.schema.json
export namespace Anchor_Batch {
  /**
   * W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
   */
  export type WitnessState =
    | {
        kind: "pending";
      }
    | {
        kind: "witnessed";
        receipt: WitnessReceipt;
        observed_at: number;
      }
    | {
        kind: "stale";
        last_verified: number;
        error: string;
      };

  /**
   * Signed additive Merkle batch over receipts or checkpoints. Local receipt signatures remain authoritative; the batch adds continuity and public-witness timestamping.
   */
  export interface ChioAnchorBatchV1 {
    body: Body;
    signature: string;
  }
  export interface Body {
    schema: "chio.anchor_batch.v1";
    treeRoot: string;
    /**
     * @minItems 1
     */
    checkpointIds: [string, ...string[]];
    /**
     * @minItems 1
     */
    inclusions: [Inclusion, ...Inclusion[]];
    witness: Witness;
    issuedAt: number;
    signerKey: string;
    witnessState?: WitnessState;
  }
  export interface Inclusion {
    checkpointId: string;
    leafHash: string;
    proof: {
      [k: string]: unknown;
    };
  }
  export interface Witness {
    kind: "rekor" | "ots" | "solana_memo";
    witnessId: string;
    root: string;
    observedAt?: number;
  }
  /**
   * Verifier-bound receipt returned by a public-witness lane. OTS receipts remain advisory until the lane carries trusted Bitcoin header or calendar-backed commitment evidence.
   */
  export interface WitnessReceipt {
    kind: "rekor" | "ots" | "solana_memo";
    externalUuid: string;
    publishedAt: number;
    inclusionProof: string;
    witnessRoot: string;
    bodyHash: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-budget-root.schema.json
export namespace Capability_AggregateBudgetRoot {
  export type AggregateRootPublicKey = string;
  export type AggregateRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type AggregateRootSignature = string;

  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: AggregateRootPublicKey;
      root_subject: AggregateRootPublicKey;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: AggregateRootSigningAlgorithm;
    signature: AggregateRootSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/aggregate-invocation-budget.schema.json
export namespace Capability_AggregateInvocationBudget {
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/capabilities.schema.json
export namespace Capability_Capabilities {
  /**
   * Feature bitset exchanged during federation trust establishment, including aggregate budgets, cumulative approval, threshold approval, and governed active response. Malformed feature names and unsupported schema IDs fail closed.
   */
  export interface ChioCapabilityNegotiationV1 {
    schema: "chio.capabilities.v1";
    /**
     * String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.
     */
    features?: {
      [k: string]: boolean;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/cumulative-approval-root.schema.json
export namespace Capability_CumulativeApprovalRoot {
  export type CumulativeRootPublicKey = string;
  export type CumulativeRootSigningAlgorithm = "ed25519" | "p256" | "p384" | "hybrid";
  export type CumulativeRootSignature = string;

  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: CumulativeRootPublicKey;
      root_subject: CumulativeRootPublicKey;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: CumulativeRootSigningAlgorithm;
    signature: CumulativeRootSignature;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/governed-approval-token.schema.json
export namespace Capability_GovernedApprovalToken {
  export type GovernedApprovalPublicKey = string;
  export type GovernedApprovalSignature = string;

  export interface ChioGovernedApprovalToken {
    id: string;
    approver: GovernedApprovalPublicKey;
    subject: GovernedApprovalPublicKey;
    governed_intent_hash: string;
    request_id: string;
    threshold_proposal_hash?: string;
    issued_at: number;
    expires_at: number;
    decision: "approved" | "denied";
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: GovernedApprovalSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/grant.schema.json
export namespace Capability_Grant {
  /**
   * A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/core/chio-core-types/src/capability/scope.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.
   */
  export type ChioCapabilityGrant = ToolGrant | ResourceGrant | PromptGrant;
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";

  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    /**
     * Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
     */
    server_id: string;
    /**
     * Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
     */
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    constraints?: Constraint[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    /**
     * If true, the kernel requires a valid DPoP proof for every invocation under this grant.
     */
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
   */
  export interface Constraint {
    type: string;
    value?: unknown;
  }
  /**
   * A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/revocation.schema.json
export namespace Capability_Revocation {
  /**
   * A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/kernel/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.
   */
  export interface ChioCapabilityRevocationEntry {
    /**
     * The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.
     */
    capability_id: string;
    /**
     * Unix timestamp (seconds) at which the revocation took effect. Stored as a signed integer in the kernel store; negative values are not produced by the issuer but are not rejected here in order to match the Rust `i64` shape.
     */
    revoked_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/supplemental-authorization.schema.json
export namespace Capability_SupplementalAuthorization {
  export interface ChioOpaqueSupplementalAuthorization {
    /**
     * Opaque authenticated extension bytes. Adapters must not interpret these bytes as quota authority.
     */
    signed_extension: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/threshold-approval-proposal.schema.json
export namespace Capability_ThresholdApprovalProposal {
  export type ThresholdProposalPublicKey = string;
  export type ThresholdProposalSignature = string;

  export interface ChioThresholdApprovalProposal {
    schema: "chio.threshold-approval-proposal.v1";
    proposal_id: string;
    request_id: string;
    governed_intent_hash: string;
    subject: ThresholdProposalPublicKey;
    authorizing_capability_digest: string;
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    proposal_created_at: number;
    proposal_deadline: number;
    policy_authority: ThresholdProposalPublicKey;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: ThresholdProposalSignature;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/token.schema.json
export namespace Capability_Token {
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";
  export type Constraint =
    | GenericConstraint
    | LegacyApprovalConstraint
    | CumulativeApprovalDirectConstraint
    | CumulativeApprovalDelegableConstraint;
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
    constraints?: Constraint[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [Operation, ...Operation[]];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind: "restrict_tool" | "bind_session" | "restrict_audience" | "restrict_geo" | "restrict_time_window";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/verified-approval-set.schema.json
export namespace Capability_VerifiedApprovalSet {
  export interface ChioVerifiedApprovalSetBody {
    /**
     * @minItems 1
     * @maxItems 32
     */
    token_digests: [string, ...string[]];
    policy_hash: string;
    threshold: number;
    eligible_set_digest: string;
    request_id: string;
    governed_intent_hash: string;
    subject: string;
    authorizing_capability_digest: string;
    threshold_proposal_hash: string;
    proposal_id: string;
    proposal_created_at: number;
    proposal_deadline: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_denied.schema.json
export namespace Error_CapabilityDenied {
  export interface ChioToolCallErrorCapabilityDenied {
    code: "capability_denied";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_expired.schema.json
export namespace Error_CapabilityExpired {
  export interface ChioToolCallErrorCapabilityExpired {
    code: "capability_expired";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/capability_revoked.schema.json
export namespace Error_CapabilityRevoked {
  export interface ChioToolCallErrorCapabilityRevoked {
    code: "capability_revoked";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/internal_error.schema.json
export namespace Error_InternalError {
  export interface ChioToolCallErrorInternalError {
    code: "internal_error";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/policy_denied.schema.json
export namespace Error_PolicyDenied {
  export interface ChioToolCallErrorPolicyDenied {
    code: "policy_denied";
    detail: {
      guard: string;
      reason: string;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/error/tool_server_error.schema.json
export namespace Error_ToolServerError {
  export interface ChioToolCallErrorToolServerError {
    code: "tool_server_error";
    detail: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/federation/bilateral-signature-slice-envelope.schema.json
export namespace Federation_BilateralSignatureSliceEnvelope {
  /**
   * Top-level DSSE envelope for Chio bilateral signature-slice artifacts. The base64 payload is the canonical JSON in-toto Statement described by bilateral-signature-slice.schema.json.
   */
  export interface ChioBilateralDSSESignatureSliceEnvelope {
    payloadType: "application/vnd.in-toto+json";
    payload: string;
    /**
     * @minItems 2
     * @maxItems 2
     */
    signatures: [
      {
        keyid: string;
        sig: string;
      },
      {
        keyid: string;
        sig: string;
      }
    ];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json
export namespace Federation_BilateralSignatureSlice {
  /**
   * Bounded in-toto Statement payload for Chio bilateral DSSE signature slices. This is not the strict treaty-bound bilateral invocation predicate.
   */
  export interface ChioBilateralDSSESignatureSliceStatement {
    _type: "https://in-toto.io/Statement/v1";
    /**
     * @minItems 1
     * @maxItems 1
     */
    subject: [
      {
        name: string;
        digest: {
          sha256: string;
        };
      }
    ];
    predicateType: "chio.bilateral-signature-slice.v1";
    predicate: {
      schema: "chio.bilateral-signature-slice.v1";
      invocation_id: string;
      tool_server_a: KernelIdentity;
      tool_server_b: KernelIdentity;
      tool_name: string;
      co_sign: "bilateral_required" | "bilateral_if_cross_org";
      consistency_model: "crdt-commutative";
      cross_org_visibility: "private" | "treaty_only" | "federated" | "public";
      timestamp_unix_ms: number;
      receipt_canonical_json: string;
      capability_lease_ref?: CapabilityLeaseRef;
      policy_evaluation_summary?: PolicyEvaluationSummary;
      governance_receipt_ref?: GovernanceReceiptRef;
      consistency_anchor?: string;
    };
  }
  export interface KernelIdentity {
    kernel_id: string;
    passport_key_fingerprint: string;
    alg: "ed25519";
  }
  export interface CapabilityLeaseRef {
    lease_id: string;
    issuer: string;
    expires_at_unix_ms: number;
    scope_digest?: HashRecord;
  }
  export interface HashRecord {
    alg: "sha256";
    value: string;
  }
  export interface PolicyEvaluationSummary {
    server_a_verdict: PolicyVerdict;
    server_b_verdict: PolicyVerdict;
    joint_disposition?: "allow" | "deny";
  }
  export interface PolicyVerdict {
    verdict: "allow" | "deny";
    policy_id: string;
    policy_version: string;
    rationale_code?: string;
  }
  export interface GovernanceReceiptRef {
    receipt_id: string;
    kernel_id: string;
    digest: HashRecord;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/notification.schema.json
export namespace Jsonrpc_Notification {
  /**
   * JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed by `send_notification` in `crates/protocol/chio-mcp-adapter` and the streaming-chunk and cancellation notifications in `crates/protocol/chio-mcp-edge` and `crates/protocol/chio-mcp-adapter`. A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.
   */
  export interface ChioJSONRPC20Notification {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').
     */
    method: string;
    /**
     * Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.
     */
    params?: {} | unknown[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/request.schema.json
export namespace Jsonrpc_Request {
  /**
   * JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed by `send_request` in `crates/protocol/chio-mcp-adapter` and the typed `A2aJsonRpcRequest<T>` in `crates/protocol/chio-a2a-adapter`. The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
   */
  export interface ChioJSONRPC20Request {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.
     */
    id: number | string | null;
    /**
     * RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').
     */
    method: string;
    /**
     * Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.
     */
    params?: {} | unknown[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/jsonrpc/response.schema.json
export namespace Jsonrpc_Response {
  /**
   * JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed by `json_rpc_result` and `json_rpc_error` in `crates/protocol/chio-mcp-adapter` and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/protocol/chio-a2a-adapter`. Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in `crates/protocol/chio-mcp-adapter`). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
   */
  export type ChioJSONRPC20Response = {
    /**
     * Protocol version literal. Always the string '2.0'.
     */
    jsonrpc: "2.0";
    /**
     * Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
     */
    id: number | string | null;
    /**
     * Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.
     */
    result?: {
      [k: string]: unknown;
    };
    /**
     * Error payload. Present only on failure. Mutually exclusive with `result`.
     */
    error?: {
      /**
       * JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).
       */
      code: number;
      /**
       * Short human-readable error description.
       */
      message: string;
      /**
       * Optional structured detail. Shape is method- or code-specific.
       */
      data?: {
        [k: string]: unknown;
      };
    };
  } & {
    [k: string]: unknown;
  };
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_list.schema.json
export namespace Kernel_CapabilityList {
  /**
   * A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
   */
  export type ChioCapabilityToken = {
    [k: string]: unknown;
  } & {
    schema?: "chio.capability.v1";
    id: string;
    issuer: string;
    subject: string;
    scope: ChioScope;
    issued_at: number;
    expires_at: number;
    delegation_chain?: DelegationLink[];
    aggregate_invocation_budget?: ChioAggregateInvocationBudget;
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    caveats?: Caveat[];
    scope_attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    attenuation_proof?: AttenuationProof;
    /**
     * Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.
     */
    budget_share_bps?: number;
    signature: string;
  };
  export type ChioAggregateInvocationBudget =
    | {
        scope: "capability";
        max_invocations: number;
        root_binding?: never;
      }
    | {
        scope: "delegation_family";
        max_invocations: number;
        root_binding: ChioAggregateBudgetRootBinding;
      };

  export interface ChioKernelMessageCapabilityList {
    type: "capability_list";
    capabilities: ChioCapabilityToken[];
  }
  /**
   * What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
   */
  export interface ChioScope {
    grants?: ToolGrant[];
    resource_grants?: ResourceGrant[];
    prompt_grants?: PromptGrant[];
  }
  /**
   * Authorization to invoke a single tool. Mirrors `ToolGrant`.
   */
  export interface ToolGrant {
    server_id: string;
    tool_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
    constraints?: (
      | GenericConstraint
      | LegacyApprovalConstraint
      | CumulativeApprovalDirectConstraint
      | CumulativeApprovalDelegableConstraint
    )[];
    max_invocations?: number;
    max_cost_per_invocation?: MonetaryAmount;
    max_total_cost?: MonetaryAmount;
    dpop_required?: boolean;
  }
  /**
   * Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
   */
  export interface GenericConstraint {
    type: string;
    value?: unknown;
  }
  export interface LegacyApprovalConstraint {
    type: "require_approval_above";
    value: {
      threshold_units: number;
    };
  }
  export interface CumulativeApprovalDirectConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding?: never;
    };
  }
  /**
   * A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
   */
  export interface MonetaryAmount {
    units: number;
    currency: string;
  }
  export interface CumulativeApprovalDelegableConstraint {
    type: "require_cumulative_approval_above";
    value: {
      threshold: MonetaryAmount;
      approval_budget_id: string;
      approval_budget_epoch: number;
      cumulative_approval_root_binding: ChioCumulativeApprovalRootBinding;
    };
  }
  export interface ChioCumulativeApprovalRootBinding {
    body: {
      schema: "chio.cumulative-approval-root.v1";
      signer_key_epoch: number;
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      root_scope_hash: string;
      root_grant_hash: string;
      approval_budget_id: string;
      approval_budget_epoch: number;
      threshold: CumulativeRootMonetaryAmount;
      root_expires_at: number;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface CumulativeRootMonetaryAmount {
    units: number;
    currency: string;
  }
  /**
   * Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
   */
  export interface ResourceGrant {
    uri_pattern: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
   */
  export interface PromptGrant {
    prompt_name: string;
    /**
     * @minItems 1
     */
    operations: [
      "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
      ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
    ];
  }
  /**
   * A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
   */
  export interface DelegationLink {
    capability_id: string;
    delegator: string;
    delegatee: string;
    attenuations?: {
      type: string;
      [k: string]: unknown;
    }[];
    timestamp: number;
    signature: string;
    /**
     * RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.
     */
    scope_hash: string;
  }
  export interface ChioAggregateBudgetRootBinding {
    body: {
      schema: "chio.aggregate-budget-root.v1";
      root_capability_id: string;
      root_capability_hash: string;
      root_issuer: string;
      root_subject: string;
      max_invocations: number;
      root_expires_at: number;
      root_scope_hash: string;
    };
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    signature: string;
  }
  export interface Caveat {
    kind: "restrict_tool" | "bind_session" | "restrict_audience" | "restrict_geo" | "restrict_time_window";
    predicate: string;
    sig?: string;
  }
  export interface AttenuationProof {
    parentScopeHash: string;
    childScopeHash: string;
    normalizedSubsetProof: AttenuationWitness;
  }
  export interface AttenuationWitness {
    normalizedParentScope: string;
    normalizedChildScope: string;
    subsetRelations?: GrantSubsetRelation[];
    restrictedPredicates?: string[];
  }
  export interface GrantSubsetRelation {
    grantKind: "tool" | "resource" | "prompt";
    childIndex: number;
    parentIndex: number;
    subset: true;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/capability_revoked.schema.json
export namespace Kernel_CapabilityRevoked {
  export interface ChioKernelMessageCapabilityRevoked {
    type: "capability_revoked";
    id: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/combined-capture-metadata.schema.json
export namespace Kernel_CombinedCaptureMetadata {
  export interface ChioCombinedAdmissionCaptureMetadata {
    schema: "chio.admission-capture-metadata.v1";
    operation_id: string;
    hold_id: string;
    /**
     * @minItems 1
     * @maxItems 8
     */
    quota_keys:
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ]
      | [
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          },
          {
            profile: string;
            owner_id: string;
            grant_index?: number;
          }
        ];
    revocation_set_digest: string;
    budget_commit_index: number;
    revocation_commit_index: number;
    leader_epoch: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/execution_nonce.schema.json
export namespace Kernel_ExecutionNonce {
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/heartbeat.schema.json
export namespace Kernel_Heartbeat {
  export interface ChioKernelMessageHeartbeat {
    type: "heartbeat";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/tool_call_chunk.schema.json
export namespace Kernel_ToolCallChunk {
  export interface ChioKernelMessageToolCallChunk {
    type: "tool_call_chunk";
    id: string;
    chunk_index: number;
    data: unknown;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/kernel/tool_call_response.schema.json
export namespace Kernel_ToolCallResponse {
  /**
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
   */
  export type ChioReceiptRecord = {
    [k: string]: unknown;
  } & {
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    action: ToolCallAction;
    decision?: Decision;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    /**
     * Kernel public key (for verification without out-of-band lookup). Supports Ed25519, uncompressed SEC1 P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes accepted by `PublicKey::from_hex`.
     */
    kernel_key: string;
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Supports Ed25519, byte-aligned DER P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes; cryptographic DER validity is checked by the verifier.
     */
    signature: string;
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        verdict: "deny";
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
      }
    | {
        verdict: "cancelled";
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
      }
    | {
        verdict: "incomplete";
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
      };

  export interface ChioKernelMessageToolCallResponse {
    type: "tool_call_response";
    id: string;
    result:
      | {
          status: "ok";
          value: unknown;
        }
      | {
          status: "stream_complete";
          total_chunks: number;
        }
      | {
          status: "cancelled";
          reason: string;
          chunks_received: number;
        }
      | {
          status: "incomplete";
          reason: string;
          chunks_received: number;
        }
      | {
          status: "err";
          error:
            | {
                code: "capability_denied";
                detail: string;
              }
            | {
                code: "capability_expired";
              }
            | {
                code: "capability_revoked";
              }
            | {
                code: "policy_denied";
                detail: {
                  guard: string;
                  reason: string;
                };
              }
            | {
                code: "tool_server_error";
                detail: string;
              }
            | {
                code: "internal_error";
                detail: string;
              };
        };
    receipt: ChioReceiptRecord;
    execution_nonce?: ChioSignedExecutionNonce;
  }
  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    schema: "chio.receipt.bbs_signature.v1";
    projection_version: "chio.bbs-projection.receipt.v1";
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    signature_hex: string;
  }
  export interface ChioSignedExecutionNonce {
    nonce: {
      schema: "chio.execution_nonce.v1";
      nonce_id: string;
      issued_at: number;
      expires_at: number;
      bound_to: {
        subject_id: string;
        request_id: string;
        capability_id: string;
        tool_server: string;
        tool_name: string;
        parameter_hash: string;
      };
      reserved_hold_id?: string;
      reserving_request_id?: string;
    };
    signature: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/attestation-bundle.schema.json
export namespace Provenance_AttestationBundle {
  /**
   * One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.
   */
  export interface ChioProvenanceAttestationBundle {
    /**
     * Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.
     */
    chainId: string;
    /**
     * Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`, which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
     */
    evidenceClass: "asserted" | "observed" | "verified";
    /**
     * Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.
     */
    assembledAt: number;
    /**
     * Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.
     *
     * @minItems 1
     */
    statements: [
      {
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
        };
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
      },
      ...{
        /**
         * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
         */
        schema: string;
        /**
         * Attestation verifier or relying party that accepted the evidence.
         */
        verifier: string;
        /**
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types`.
         */
        tier: "none" | "basic" | "attested" | "verified";
        /**
         * Unix timestamp (seconds) when this attestation was issued.
         */
        issued_at: number;
        /**
         * Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
         */
        expires_at: number;
        /**
         * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
         */
        evidence_sha256: string;
        /**
         * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
         */
        runtime_identity?: string;
        /**
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
           */
          credentialKind: "uri" | "x509_svid" | "jwt_svid";
          /**
           * Canonical workload identifier URI.
           */
          uri: string;
          /**
           * Stable trust domain resolved from the identifier.
           */
          trustDomain: string;
          /**
           * Canonical workload path within the trust domain.
           */
          path: string;
        };
        /**
         * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
         */
        claims?: {
          [k: string]: unknown;
        };
      }[]
    ];
    /**
     * Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.
     */
    issuer?: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/context.schema.json
export namespace Provenance_Context {
  /**
   * One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/core/chio-core-types` (`GovernedProvenanceEvidenceClass`). Mirrors the `GovernedCallChainContext` struct in `crates/core/chio-core-types`. The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
   */
  export interface ChioProvenanceCallChainContext {
    /**
     * Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.
     */
    chainId: string;
    /**
     * Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.
     */
    parentRequestId: string;
    /**
     * Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.
     */
    parentReceiptId?: string;
    /**
     * Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).
     */
    originSubject: string;
    /**
     * Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.
     */
    delegatorSubject: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/stamp.schema.json
export namespace Provenance_Stamp {
  /**
   * One provenance stamp attached by a Chio provider adapter to every tool-call response. Names the upstream `provider`, the upstream `request_id`, the wire `api_version`, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp. Field names are snake_case to match `RuntimeAttestationEvidence`.
   */
  export interface ChioProvenanceStamp {
    /**
     * Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`).
     */
    provider: string;
    /**
     * Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.
     */
    request_id: string;
    /**
     * Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.
     */
    api_version: string;
    /**
     * Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.
     */
    principal: string;
    /**
     * Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; Chio fails closed if the value is in the future relative to the kernel clock.
     */
    received_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/verdict-link.schema.json
export namespace Provenance_VerdictLink {
  /**
   * One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union. Field names are camelCase to match the governed call-chain context family this link binds to.
   */
  export type ChioProvenanceVerdictLink = {
    /**
     * Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
     */
    verdict: "allow" | "deny" | "cancel" | "incomplete";
    /**
     * Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.
     */
    requestId: string;
    /**
     * Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
     */
    receiptId?: string;
    /**
     * Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
     */
    chainId: string;
    /**
     * Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.
     */
    renderedAt: number;
    /**
     * Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.
     */
    reason?: string;
    /**
     * Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.
     */
    guard?: string;
    /**
     * Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.
     */
    evidenceClass?: "asserted" | "observed" | "verified";
  } & (Allow | Deny | Cancel | Incomplete);

  /**
   * Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.
   */
  export interface Allow {
    verdict: "allow";
  }
  /**
   * Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.
   */
  export interface Deny {
    verdict: "deny";
  }
  /**
   * Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.
   */
  export interface Cancel {
    verdict: "cancel";
  }
  /**
   * Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.
   */
  export interface Incomplete {
    verdict: "incomplete";
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/admission-metadata.schema.json
export namespace Receipt_AdmissionMetadata {
  export type Digest = string;
  export type Identifier = string;
  export type PositiveIJsonInteger = number;

  export interface ChioDurableAdmissionReceiptMetadata {
    schema: "chio.admission-receipt.v1";
    operation_id: Digest;
    request_id: Identifier;
    request_namespace_digest: Digest;
    request_binding_hash: Digest;
    projected_operation_version: PositiveIJsonInteger;
    projected_state:
      | "prepared"
      | "broker_attempt_registered"
      | "approval_required"
      | "budget_authorized"
      | "approval_reserved"
      | "ready_to_dispatch"
      | "capture_pending"
      | "dispatch_committed"
      | "finalizing"
      | "completed"
      | "compensated_before_dispatch"
      | "not_accepted_after_dispatch_commit"
      | "outcome_unknown_after_dispatch"
      | "mutation_ready"
      | "mutation_submitted"
      | "economic_mutation_applied"
      | "economic_mutation_not_applied";
    projected_dispatch_state:
      | "not_committed"
      | "capture_pending"
      | "committed"
      | "finalizing"
      | "terminal"
      | "not_applicable";
    trusted_time_unix_ms: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    coordinator_lease_epoch: PositiveIJsonInteger;
    store_fence: StoreFence;
    retained_dispatch_commit: null | DispatchCommit;
    compensation_status: "not_compensated" | "compensated_before_dispatch" | "not_accepted_after_dispatch_commit";
    tool_outcome_id: null | Digest;
    tool_outcome_version: null | PositiveIJsonInteger;
  }
  export interface StoreFence {
    store_uuid: Identifier;
    lease_id: Identifier;
    owner_epoch: PositiveIJsonInteger;
  }
  export interface DispatchCommit {
    committed_version: PositiveIJsonInteger;
    coordinator_lease_id: Identifier;
    coordinator_lease_epoch: PositiveIJsonInteger;
    store_fence: StoreFence;
    provider_attempt: null | ProviderAttempt;
  }
  export interface ProviderAttempt {
    operation_id: Digest;
    attempt_id: Identifier;
    transport_id: Identifier;
    transport_key_epoch: PositiveIJsonInteger;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json
export namespace Receipt_InclusionProof {
  /**
   * Merkle inclusion proof for a single receipt leaf in a receipt-log Merkle tree. Mirrors the serde shape of `MerkleProof` in `crates/core/chio-core-types/src/merkle.rs`. The proof allows an auditor, holding only the published Merkle root and the original leaf bytes, to verify that the leaf was included in a tree of the given size at the given position. The audit path is the ordered list of sibling hashes encountered when walking from the leaf up to the root; siblings whose subtree was carried upward without pairing (the right-edge of an unbalanced level) are omitted. Deterministic-replay consumes this schema as the contract for golden-bundle inclusion artifacts under `tests/replay/goldens/<family>/<name>/`.
   */
  export interface ChioReceiptMerkleInclusionProof {
    /**
     * Total number of leaves in the Merkle tree at the time the proof was issued.
     */
    tree_size: number;
    /**
     * Zero-based index of the leaf being proved. MUST satisfy `leaf_index < tree_size`.
     */
    leaf_index: number;
    /**
     * Ordered sibling hashes from leaf-level up to (but not including) the root. Siblings that were carried upward without pairing on the right edge of an unbalanced level are omitted, so the path length is not strictly `ceil(log2(tree_size))`. Each entry is a `chio-core-types::Hash` serialized via its transparent serde adapter (32-byte SHA-256 digest, hex-encoded with a `0x` prefix).
     */
    audit_path: string[];
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json
export namespace Receipt_LineageStatement {
  /**
   * Signed pairwise receipt lineage statement. Multi-parent lineage views are derived aggregates over these signed parent-child statements.
   */
  export interface ChioReceiptLineageStatement {
    schema: "chio.receipt_lineage_statement.v1";
    id: string;
    parentReceiptId: string;
    childReceiptId: string;
    parentRequestId: string;
    childRequestId: string;
    parentSessionAnchor: SessionAnchorReference;
    childSessionAnchor: SessionAnchorReference;
    relationKind: "local_child" | "continued";
    evidenceClass: "asserted" | "observed" | "verified";
    continuationTokenId?: string;
    issuedAt: number;
    kernelKey: string;
    signature: string;
  }
  export interface SessionAnchorReference {
    sessionAnchorId: string;
    sessionAnchorHash: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/receipt/record.schema.json
export namespace Receipt_Record {
  /**
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.
   */
  export type ChioReceiptRecord = {
    [k: string]: unknown;
  } & {
    /**
     * Authoritative content-addressed receipt id.
     */
    id: string;
    /**
     * Unix timestamp (seconds) when the receipt was created.
     */
    timestamp: number;
    /**
     * ID of the capability token that was exercised (or presented).
     */
    capability_id: string;
    /**
     * Tool server that handled the invocation.
     */
    tool_server: string;
    /**
     * Tool that was invoked (or attempted).
     */
    tool_name: string;
    action: ToolCallAction;
    decision?: Decision;
    /**
     * Signed semantic class for this v1 receipt.
     */
    receipt_kind: "mediated_decision" | "trace_observation" | "advisory_evaluation";
    /**
     * Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.
     */
    boundary_class: "prevent" | "detect_only" | "advisory_only";
    /**
     * Signed outcome for trace and advisory records. Omitted for mediated decisions.
     */
    observation_outcome?: "observed" | "evaluated" | "dropped";
    /**
     * Signed classification of where the tool effect executed relative to Chio.
     */
    tool_origin: "caller_executed" | "host_executed_provider_reported" | "host_executed_unmediated";
    /**
     * Signed redaction mode applied to receipt details.
     */
    redaction_mode: "none" | "summary" | "redacted";
    /**
     * Signed actor attribution chain. Omitted from the wire when empty.
     */
    actor_chain?: ActorRef[];
    /**
     * SHA-256 hex hash of the evaluated content for this receipt.
     */
    content_hash: string;
    /**
     * SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
     */
    policy_hash: string;
    /**
     * Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
     */
    evidence?: GuardEvidence[];
    /**
     * Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
     */
    metadata?: {
      [k: string]: unknown;
    };
    /**
     * Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.
     */
    trust_level: "mediated" | "verified" | "advisory";
    /**
     * Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.
     */
    tenant_id?: string;
    /**
     * Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.
     */
    bbs_projection_version?: "chio.bbs-projection.receipt.v1";
    /**
     * Kernel public key (for verification without out-of-band lookup). Supports Ed25519, uncompressed SEC1 P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes accepted by `PublicKey::from_hex`.
     */
    kernel_key: string;
    bbs_signature?: BbsReceiptSignature;
    /**
     * Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384" | "hybrid";
    /**
     * Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Supports Ed25519, byte-aligned DER P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes; cryptographic DER validity is checked by the verifier.
     */
    signature: string;
  };
  /**
   * The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
   */
  export type Decision =
    | {
        verdict: "allow";
      }
    | {
        verdict: "deny";
        /**
         * Human-readable reason for the denial.
         */
        reason: string;
        /**
         * The guard or validation step that triggered the denial.
         */
        guard: string;
      }
    | {
        verdict: "cancelled";
        /**
         * Human-readable reason for the cancellation.
         */
        reason: string;
      }
    | {
        verdict: "incomplete";
        /**
         * Human-readable reason for the incomplete terminal state.
         */
        reason: string;
      };

  /**
   * Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
   */
  export interface ToolCallAction {
    /**
     * The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
     */
    parameters: {
      [k: string]: unknown;
    };
    /**
     * SHA-256 hex hash of the canonical JSON of `parameters`.
     */
    parameter_hash: string;
  }
  export interface ActorRef {
    actor_id: string;
    actor_kind?: string;
  }
  /**
   * Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
   */
  export interface GuardEvidence {
    /**
     * Name of the guard (e.g. `ForbiddenPathGuard`).
     */
    guard_name: string;
    /**
     * Whether the guard passed (true) or denied (false).
     */
    verdict: boolean;
    /**
     * Optional details about the guard's decision.
     */
    details?: string;
  }
  /**
   * Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody.
   */
  export interface BbsReceiptSignature {
    schema: "chio.receipt.bbs_signature.v1";
    projection_version: "chio.bbs-projection.receipt.v1";
    algorithm: "bbs";
    ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    issuer_fingerprint: string;
    issuer_public_key_hex: string;
    message_count: 14;
    signature_hex: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/cancelled.schema.json
export namespace Result_Cancelled {
  export interface ChioToolCallResultCancelled {
    status: "cancelled";
    reason: string;
    chunks_received: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/err.schema.json
export namespace Result_Err {
  export interface ChioToolCallResultErr {
    status: "err";
    error:
      | {
          code: "capability_denied";
          detail: string;
        }
      | {
          code: "capability_expired";
        }
      | {
          code: "capability_revoked";
        }
      | {
          code: "policy_denied";
          detail: {
            guard: string;
            reason: string;
          };
        }
      | {
          code: "tool_server_error";
          detail: string;
        }
      | {
          code: "internal_error";
          detail: string;
        };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/incomplete.schema.json
export namespace Result_Incomplete {
  export interface ChioToolCallResultIncomplete {
    status: "incomplete";
    reason: string;
    chunks_received: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/ok.schema.json
export namespace Result_Ok {
  export interface ChioToolCallResultOk {
    status: "ok";
    value: unknown;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/result/stream_complete.schema.json
export namespace Result_StreamComplete {
  export interface ChioToolCallResultStreamComplete {
    status: "stream_complete";
    total_chunks: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/attestation.schema.json
export namespace TrustControl_Attestation {
  /**
   * One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/core/chio-core-types`. The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/platform/chio-control-plane` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
   */
  export interface ChioTrustControlRuntimeAttestationEvidence {
    /**
     * Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
     */
    schema: string;
    /**
     * Attestation verifier or relying party that accepted the evidence.
     */
    verifier: string;
    /**
     * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
     */
    tier: "none" | "basic" | "attested" | "verified";
    /**
     * Unix timestamp (seconds) when this attestation was issued.
     */
    issued_at: number;
    /**
     * Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.
     */
    expires_at: number;
    /**
     * Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
     */
    evidence_sha256: string;
    /**
     * Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
     */
    runtime_identity?: string;
    /**
     * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in `crates/core/chio-core-types` which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
     */
    workload_identity?: {
      /**
       * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` in `crates/core/chio-core-types`.
       */
      scheme: "spiffe";
      /**
       * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` in `crates/core/chio-core-types` which uses `serde(rename_all = snake_case)`.
       */
      credentialKind: "uri" | "x509_svid" | "jwt_svid";
      /**
       * Canonical workload identifier URI.
       */
      uri: string;
      /**
       * Stable trust domain resolved from the identifier.
       */
      trustDomain: string;
      /**
       * Canonical workload path within the trust domain.
       */
      path: string;
    };
    /**
     * Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims.
     */
    claims?: {
      [k: string]: unknown;
    };
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/budget-snapshot-anchor-provenance.schema.json
export namespace TrustControl_BudgetSnapshotAnchorProvenance {
  export type Digest = string;

  /**
   * Leader-signed inclusion chain authenticating the exact immutable migration-anchor set carried by a trust-control cluster budget snapshot.
   */
  export interface BudgetSnapshotAnchorProvenance {
    schema: "chio.budget-snapshot-anchor-provenance.v1";
    /**
     * @minItems 1
     */
    chain: [SignedCommitment, ...SignedCommitment[]];
    clusterAuthenticator: string;
  }
  export interface SignedCommitment {
    body: Commitment;
    signature: string;
  }
  export interface Commitment {
    schema: "chio.budget-snapshot-anchor-commitment.v1";
    commitSequence: number;
    previousChainDigest: Digest;
    chainDigest: Digest;
    anchorSetDigest: Digest;
    leaderUrl: string;
    electionTerm: number;
    committedAt: number;
    signerPublicKey: string;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/heartbeat.schema.json
export namespace TrustControl_Heartbeat {
  /**
   * One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. The contract is anchored by `spec/PROTOCOL.md` section 9 (the `/v1/internal/cluster/status` cluster lease lifecycle). Wire field names are camelCase to match the lease projection.
   */
  export interface ChioTrustControlLeaseHeartbeat {
    /**
     * Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.
     */
    leaseEpoch: number;
    /**
     * Normalized URL of the leader claiming continued ownership of the lease.
     */
    leaderUrl: string;
    /**
     * Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.
     */
    observedAt: number;
    /**
     * Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.
     */
    proposedExpiresAt?: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/lease.schema.json
export namespace TrustControl_Lease {
  /**
   * One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Wire field names are camelCase. `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix seconds (`unix_timestamp_now() + leaseTtlMs / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
   */
  export interface ChioTrustControlAuthorityLease {
    /**
     * Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.
     */
    authorityId: string;
    /**
     * Normalized URL of the cluster node that currently holds the authority lease.
     */
    leaderUrl: string;
    /**
     * Cluster election term that minted this lease. Monotonically non-decreasing.
     */
    term: number;
    /**
     * Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.
     */
    leaseEpoch: number;
    /**
     * Optional unix-second timestamp at which the current term began on this leader. Omitted when unknown (no quorum or no leader).
     */
    termStartedAt?: number;
    /**
     * Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + leaseTtlMs / 1000`. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.
     */
    leaseExpiresAt: number;
    /**
     * Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms. NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.
     */
    leaseTtlMs: number;
    /**
     * True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.
     */
    leaseValid: boolean;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/trust-control/terminate.schema.json
export namespace TrustControl_Terminate {
  /**
   * One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. The contract is anchored by `spec/PROTOCOL.md` section 9, where loss of quorum or a leader change clears the lease expiry and bumps the election term. Wire field names are camelCase to match the sibling lease projection so the families stay consistent on the wire.
   */
  export interface ChioTrustControlLeaseTermination {
    /**
     * Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.
     */
    leaseId: string;
    /**
     * Lease epoch carried alongside `leaseId`.
     */
    leaseEpoch: number;
    /**
     * Normalized URL of the leader releasing the lease.
     */
    leaderUrl: string;
    /**
     * Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
     */
    reason: "leader_handoff" | "quorum_lost" | "operator_stepdown" | "term_advanced";
    /**
     * Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.
     */
    observedAt: number;
    /**
     * Optional normalized URL of the successor leader, when termination is part of a planned handoff.
     */
    successorLeaderUrl?: string;
  }
}
