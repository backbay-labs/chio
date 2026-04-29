// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.
//
// Source:     spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:       json-schema-to-typescript 15.0.4 (see xtask/codegen-tools.lock.toml)
// Pin file:   sdks/typescript/scripts/package.json
// Schema SHA: 245eed29f21665ab1a611519bdd565a5c82f04d1811dc55bbce08461df9e8905
//
// The schema-sha above is sha256 of `<rel-path>\0<bytes>\0` for every
// schema in lex order. It changes whenever any schema under
// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane
// asserts byte-equality of this entire file via `--check` mode.

/* eslint-disable */

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
  export interface ChioAgentMessageToolCallRequest {
    type: "tool_call_request";
    id: string;
    capability_token: {
      id: string;
      issuer: string;
      subject: string;
      scope: {
        grants?: {
          server_id: string;
          tool_name: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          constraints?: {
            type: string;
            value?: unknown;
          }[];
          max_invocations?: number;
          max_cost_per_invocation?: {
            units: number;
            currency: string;
          };
          max_total_cost?: {
            units: number;
            currency: string;
          };
          dpop_required?: boolean;
        }[];
        resource_grants?: {
          uri_pattern: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
        }[];
        prompt_grants?: {
          prompt_name: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
        }[];
      };
      issued_at: number;
      expires_at: number;
      delegation_chain?: {
        capability_id: string;
        delegator: string;
        delegatee: string;
        attenuations?: {}[];
        timestamp: number;
        signature: string;
      }[];
      signature: string;
    };
    server_id: string;
    tool: string;
    params: unknown;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/capability/grant.schema.json
export namespace Capability_Grant {
  /**
   * A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/chio-core-types/src/capability.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.
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
   * A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.
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
// Source: spec/schemas/chio-wire/v1/capability/token.schema.json
export namespace Capability_Token {
  export type Operation = "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate";

  /**
   * A Chio capability token: an Ed25519-signed (or FIPS-algorithm), scoped, time-bounded authorization to invoke a tool. Mirrors the serde shape of `CapabilityToken` in `crates/chio-core-types/src/capability.rs`. The `signature` field covers the canonical JSON of all other fields except `algorithm`. The `algorithm` envelope field is informational (verification dispatches off the signature hex prefix) and is omitted for legacy Ed25519 tokens. PublicKey serde renders Ed25519 keys as bare 64-character lowercase hex (`PublicKey::to_hex` in `crates/chio-core-types/src/crypto.rs`), and renders FIPS keys with a self-describing prefix (`p256:<130-char hex>` for uncompressed SEC1 P-256, `p384:<194-char hex>` for P-384). Signatures follow the same convention: bare 128-char hex for Ed25519, `p256:<DER hex>` and `p384:<DER hex>` for FIPS algorithms. The grant `$defs` (`toolGrant`, `resourceGrant`, `promptGrant`, `operation`, `monetaryAmount`, `constraint`) are duplicated with `capability/grant.schema.json` because the current Rust codegen pipeline (`typify =0.4.3`) does not support cross-file `$ref`; both copies must be kept byte-identical when either file is edited until the M01 phase 3 codegen split lands.
   */
  export interface ChioCapabilityToken {
    /**
     * Unique token ID (UUIDv7 recommended), used for revocation.
     */
    id: string;
    /**
     * Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).
     */
    issuer: string;
    /**
     * Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.
     */
    subject: string;
    scope: ChioScope;
    /**
     * Unix timestamp (seconds) when the token was issued.
     */
    issued_at: number;
    /**
     * Unix timestamp (seconds) when the token expires.
     */
    expires_at: number;
    /**
     * Ordered list of delegation links from the root authority to this token. Omitted (or empty) for direct issuances.
     */
    delegation_chain?: DelegationLink[];
    /**
     * Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384";
    /**
     * Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
     */
    signature: string;
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
  /**
   * A single link in a delegation chain. Mirrors `DelegationLink`.
   */
  export interface DelegationLink {
    capability_id: string;
    /**
     * Delegating public key. Same encoding as the token-level `issuer`/`subject`.
     */
    delegator: string;
    /**
     * Receiving public key. Same encoding as the token-level `issuer`/`subject`.
     */
    delegatee: string;
    attenuations?: {
      type: string;
    }[];
    timestamp: number;
    /**
     * Delegation-link signature. Same encoding as the token-level `signature`.
     */
    signature: string;
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
// Source: spec/schemas/chio-wire/v1/jsonrpc/notification.schema.json
export namespace Jsonrpc_Notification {
  /**
   * JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_notification` (lines 770-774) and the streaming-chunk and cancellation notifications in `crates/chio-mcp-edge/src/runtime/protocol.rs` and transport.rs (lines 401-407, 1384-1392). A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.
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
   * JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_request` (lines 643-648) and the typed `A2aJsonRpcRequest<T>` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 234-241). The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
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
   * JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
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
  export interface ChioKernelMessageCapabilityList {
    type: "capability_list";
    capabilities: {
      id: string;
      issuer: string;
      subject: string;
      scope: {
        grants?: {
          server_id: string;
          tool_name: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
          constraints?: {
            type: string;
            value?: unknown;
          }[];
          max_invocations?: number;
          max_cost_per_invocation?: {
            units: number;
            currency: string;
          };
          max_total_cost?: {
            units: number;
            currency: string;
          };
          dpop_required?: boolean;
        }[];
        resource_grants?: {
          uri_pattern: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
        }[];
        prompt_grants?: {
          prompt_name: string;
          /**
           * @minItems 1
           */
          operations: [
            "invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate",
            ...("invoke" | "read_result" | "read" | "subscribe" | "get" | "delegate")[]
          ];
        }[];
      };
      issued_at: number;
      expires_at: number;
      delegation_chain?: {
        capability_id: string;
        delegator: string;
        delegatee: string;
        attenuations?: {}[];
        timestamp: number;
        signature: string;
      }[];
      signature: string;
    }[];
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
    receipt: {
      id: string;
      timestamp: number;
      capability_id: string;
      tool_server: string;
      tool_name: string;
      action: {
        parameters: unknown;
        parameter_hash: string;
      };
      decision:
        | {
            verdict: "allow";
          }
        | {
            verdict: "deny";
            reason: string;
            guard: string;
          }
        | {
            verdict: "cancelled";
            reason: string;
          }
        | {
            verdict: "incomplete";
            reason: string;
          };
      content_hash: string;
      policy_hash: string;
      evidence?: {
        guard_name: string;
        verdict: boolean;
        details?: string;
      }[];
      metadata?: unknown;
      kernel_key: string;
      signature: string;
    };
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
     * Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
     */
    evidenceClass: "asserted" | "observed" | "verified";
    /**
     * Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.
     */
    assembledAt: number;
    /**
     * Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.
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
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
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
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
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
         * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
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
         * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
         */
        workload_identity?: {
          /**
           * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
           */
          scheme: "spiffe";
          /**
           * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
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
   * One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/chio-core-types/src/capability.rs` (`GovernedProvenanceEvidenceClass`, lines 1303-1314). Mirrors the `GovernedCallChainContext` struct in `crates/chio-core-types/src/capability.rs` (lines 952-967). The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
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
     * Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.
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
     * Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; M07 fails closed if the value is in the future relative to the kernel clock.
     */
    received_at: number;
  }
}

// -----------------------------------------------------------------------------
// Source: spec/schemas/chio-wire/v1/provenance/verdict-link.schema.json
export namespace Provenance_VerdictLink {
  /**
   * One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union and the per-step verdict family `StepVerdictKind` in `crates/chio-core-types/src/plan.rs` (lines 110-138). NOTE: there is no live `VerdictLink` Rust struct on this branch; the link is drafted as the wire form of the verdict-to-provenance edge that M07's tool-call fabric and the M01 receipt-record schema reference indirectly today. The dedicated Rust struct is expected to land alongside the M07 phase that wires the tool-call fabric to the provenance graph and the schema will be re-pinned to that serde shape at that time. Field names are camelCase to match the `GovernedCallChainContext` family this link binds to.
   */
  export type ChioProvenanceVerdictLink = {
    /**
     * Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
     */
    verdict: "allow" | "deny" | "cancel" | "incomplete";
    /**
     * Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).
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
     * Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
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
// Source: spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json
export namespace Receipt_InclusionProof {
  /**
   * Merkle inclusion proof for a single receipt leaf in a receipt-log Merkle tree. Mirrors the serde shape of `MerkleProof` in `crates/chio-core-types/src/merkle.rs`. The proof allows an auditor, holding only the published Merkle root and the original leaf bytes, to verify that the leaf was included in a tree of the given size at the given position. The audit path is the ordered list of sibling hashes encountered when walking from the leaf up to the root; siblings whose subtree was carried upward without pairing (the right-edge of an unbalanced level) are omitted. M04 deterministic-replay consumes this schema as the contract for golden-bundle inclusion artifacts under `tests/replay/goldens/<family>/<name>/`.
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
// Source: spec/schemas/chio-wire/v1/receipt/record.schema.json
export namespace Receipt_Record {
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
   * A signed Chio receipt: proof that a tool call was evaluated by the Kernel. Mirrors the serde shape of `ChioReceipt` in `crates/chio-core-types/src/receipt.rs`. The `signature` field covers the canonical JSON of `ChioReceiptBody` (every field below except `algorithm` and `signature`). The `algorithm` envelope field is informational (verification dispatches off the self-describing hex prefix on the signature itself) and is omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Optional fields (`evidence`, `metadata`, `trust_level`, `tenant_id`, `algorithm`) are skipped on the wire when set to their default or unset values.
   */
  export interface ChioReceiptRecord {
    /**
     * Unique receipt ID. UUIDv7 recommended.
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
    decision: Decision;
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
     * Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.
     */
    trust_level?: "mediated" | "verified" | "advisory";
    /**
     * Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.
     */
    tenant_id?: string;
    /**
     * Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.
     */
    kernel_key: string;
    /**
     * Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
     */
    algorithm?: "ed25519" | "p256" | "p384";
    /**
     * Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
     */
    signature: string;
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
   * One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/chio-control-plane/src/attestation.rs` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
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
     * Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.
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
     * Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
     */
    workload_identity?: {
      /**
       * Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
       */
      scheme: "spiffe";
      /**
       * Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
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
// Source: spec/schemas/chio-wire/v1/trust-control/heartbeat.schema.json
export namespace TrustControl_Heartbeat {
  /**
   * One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. Drafted from `spec/PROTOCOL.md` section 9 prose around `/v1/internal/cluster/status` and the cluster lease lifecycle described in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 832-877). NOTE: this schema is drafted from prose plus the `ClusterAuthorityLeaseView` shape; there is no dedicated `LeaseHeartbeatRequest` Rust struct in the live trust-control surface yet, so wire field names follow the same `serde(rename_all = camelCase)` convention used by the lease projection. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3.
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
   * One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Mirrors the `ClusterAuthorityLeaseView` serde shape in `crates/chio-cli/src/trust_control/service_types.rs` (lines 1837-1848). The view uses `serde(rename_all = camelCase)` so wire field names are camelCase. The shape is constructed in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (`cluster_authority_lease_view_locked`, lines 841-862) from the live cluster consensus view; `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix **seconds** (computed in `cluster_and_reports.rs` lines 1580-1606 as `unix_timestamp_now() + lease_ttl_ms / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
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
     * Optional unix-second timestamp at which the current term began on this leader. Captured via `unix_timestamp_now()` in `cluster_and_reports.rs` line 1603. Omitted via `serde(skip_serializing_if = Option::is_none)` when unknown (no quorum or no leader).
     */
    termStartedAt?: number;
    /**
     * Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + lease_ttl_ms / 1000` in `cluster_and_reports.rs` lines 1580-1606. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.
     */
    leaseExpiresAt: number;
    /**
     * Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms by `authority_lease_ttl` (cluster_and_reports.rs lines 832-839). NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.
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
   * One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. Drafted from `spec/PROTOCOL.md` section 9 prose plus the lease invalidation paths in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 1595-1611) where loss of quorum or a leader change clears `lease_expires_at` and bumps the election term. NOTE: this schema is drafted from prose; there is no dedicated `LeaseTerminateRequest` Rust struct in the live trust-control surface yet. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3. Wire field names follow the `serde(rename_all = camelCase)` convention used by the sibling lease projection so the families stay consistent on the wire.
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
