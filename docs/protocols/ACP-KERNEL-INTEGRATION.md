# ACP-Client Proxy Kernel Integration

Technical design specification for integrating `chio-acp-proxy` with the Chio kernel's
receipt signing and capability validation infrastructure.

**Status**: [Partial] -- Tier 1 Priority  **Date**: 2026-04-13  **Crate**: `chio-acp-proxy`

> **Status**: Partially implemented. `ReceiptSigner`, `CapabilityChecker`,
> `KernelReceiptSigner`, `KernelCapabilityChecker`, and `AcpProxy::start_with_kernel`
> exist in `chio-acp-proxy`. Default `AcpProxy::start` remains unsigned standalone
> mode. This document specifies the full target architecture and deployment posture.

---

## 1. Problem Statement

The ACP-Client proxy produces **unsigned** `AcpToolCallAuditEntry` objects for tool-call events
observed in `session/update` notifications. These lack three properties that the MCP and
A2A adapters provide through kernel-mediated `ChioReceipt` objects:

1. **Non-repudiation.** No cryptographic binding to the kernel's signing key. An attacker
   with write access to the audit log can forge, reorder, or delete entries undetected.

2. **Compliance correlation.** Signed receipts carry `capability_id`, `policy_hash`, and
   `evidence` that tie decisions to the exact token and guard pipeline. Unsigned entries
   cannot be joined with MCP/A2A events in a unified compliance query.

3. **Cross-protocol audit continuity.** Unsigned entries cannot be appended to the
   kernel's `ReceiptStore` or included in Merkle checkpoint batches, breaking the
   commitment chain for organizations running ACP-Client agents alongside MCP tool servers.

This is the single largest security gap in the Chio protocol stack.

---

## 2. Design Goals

| Goal | Constraint |
|------|-----------|
| Signed `ChioReceipt` for ACP-Client tool-call events | Must not force proxy to implement `ToolServerConnection` |
| Capability-token validation for resource access | Preserve proxy's boundary architecture |
| Merkle receipt chain integration | Proxy must not hold private key material |
| Standalone proxy support (no kernel) | Preserve optional unsigned standalone mode, but label it as outside full attestation claims |
| Minimal coupling | Traits in `chio-acp-proxy`; impls in `chio-kernel` or bridge crate |

Core decision: **inject the kernel as a service, not as a trait implementation.** The
proxy accepts `ReceiptSigner` and `CapabilityChecker` via constructor injection. It
never implements `ToolServerConnection` -- it is an interposition proxy, not a tool
server.

### 2.1 Attestation Modes and Statuses

This design distinguishes **policy enforcement** from **attestation
completeness**. A request can be correctly guarded yet still fail to produce a
signed receipt. That must be surfaced explicitly; it cannot be silently treated
as equivalent to a fully attested ACP-Client event.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpAttestationMode {
    /// Default for Chio-governed deployments. Unsigned ACP-Client observations are
    /// treated as non-compliant evidence gaps.
    Required,
    /// Standalone compatibility mode only. Unsigned ACP-Client observations may still be written,
    /// but the session is not eligible for full cross-protocol attestation
    /// claims or compliance certificates.
    UnsignedCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpAttestationStatus {
    FullyAttested,
    PolicyEnforcedButUnsigned { reason: String },
    SignerUnavailable { reason: String },
    EvidenceIncomplete { reason: String },
}
```

Any ACP-Client session containing a status other than `FullyAttested` is outside Chio's
full cross-protocol attestation claim and must be excluded from compliance
certificate issuance unless a later repair flow closes the evidence gap.

---

## 3. Proposed Architecture

### 3.1 Injection Model

Both traits are `Option`-wrapped in `MessageInterceptor`. When `None`, the proxy uses
the existing unsigned `AcpToolCallAuditEntry` path.

> **Note on imports**: Types are imported from `chio_core`, which re-exports from
> `chio_core_types`. In Cargo.toml, depend on
> `chio-core = { package = "chio-core-types", path = "../chio-core-types" }`.

```rust
pub struct MessageInterceptor {
    // ... existing fields ...
    receipt_signer: Option<Box<dyn ReceiptSigner>>,
    capability_checker: Option<Box<dyn CapabilityChecker>>,
    attestation_mode: AcpAttestationMode,
}
```

### 3.2 Message Flow

```
Editor/IDE               ACP-Client Proxy                         ACP-Client Agent
    |                       |                                  |
    |-- JSON-RPC request -->|                                  |
    |                       |-- [CapabilityChecker::check] --> |
    |                       |-- [FsGuard / TerminalGuard] ---> |
    |                       |--- forward request ------------->|
    |                       |<-- session/update (tool_call) ---|
    |                       |-- [ReceiptSigner::sign] -------> |
    |<- forward + receipt --|                                  |
```

**Pre-forward:** For `fs/read_text_file`, `fs/write_text_file`, and `terminal/create`,
the interceptor consults `CapabilityChecker` (if present) before the existing guards.
Both layers must allow; either can deny (defense-in-depth).

**Post-observation:** On `session/update` with a tool-call event, the interceptor builds
an `AcpToolCallAuditEntry`, then promotes it to a signed `ChioReceipt` via
`ReceiptSigner`.

- In `Required` mode, signer failure emits an explicit attestation-gap artifact
  with `SignerUnavailable` or `EvidenceIncomplete` status and marks the session
  non-compliant for certificate purposes.
- In `UnsignedCompatibility` mode, the proxy may still persist the unsigned
  entry, but it must label the event `PolicyEnforcedButUnsigned` rather than
  treating it as equivalent to a signed receipt.

---

## 4. `ReceiptSigner` Trait Design

```rust
use chio_core::receipt::ChioReceipt;

/// Scope context for the resource or action being attested.
#[derive(Debug, Clone)]
pub enum AcpScopeContext {
    FilePath { path: String, operation: FileOperation },
    TerminalCommand { command: String, args: Vec<String> },
    ToolCall { tool_name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation { Read, Write }

/// Parameters for signing an ACP-Client tool-call event into a Chio receipt.
#[derive(Debug, Clone)]
pub struct AcpReceiptRequest {
    /// Unique tool call ID from the ACP-Client protocol.
    pub tool_call_id: String,
    /// Tool name (e.g. "fs/read_text_file", "terminal/create").
    pub tool_name: String,
    /// Session ID from the ACP-Client session/update notification.
    pub session_id: String,
    /// SHA-256 hex digest of the canonical JSON of the tool-call event.
    pub content_hash: String,
    /// Scope context for the resource being accessed.
    pub scope_context: AcpScopeContext,
    /// Server identity string (from `AcpProxyConfig::server_id`).
    pub server_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptSignError {
    #[error("signing key unavailable: {0}")]
    KeyUnavailable(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("signer error: {0}")]
    Internal(String),
}

/// Signs ACP-Client audit events into Chio receipts.
///
/// Implementations hold or delegate to the kernel's signing key.
/// The proxy never touches key material directly.
pub trait ReceiptSigner: Send + Sync {
    /// Promote an ACP-Client tool-call event into a signed `ChioReceipt`.
    ///
    /// Responsible for: generating receipt ID (UUIDv7), populating
    /// `capability_id` and `policy_hash`, building `ChioReceiptBody`,
    /// signing with the kernel keypair, and appending to `ReceiptStore`.
    ///
    /// Errors surface as explicit degraded-attestation states. Unsigned
    /// fallback is opt-in only.
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError>;
}
```

---

## 5. `CapabilityChecker` Trait Design

```rust
/// Capability check verdict (local to chio-acp-proxy to avoid kernel dependency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpVerdict {
    Allow,
    Deny { reason: String },
}

/// A request to validate scoped access against a capability token.
#[derive(Debug, Clone)]
pub struct AcpCapabilityRequest {
    pub session_id: String,
    pub agent_id: String,
    pub access: AcpAccessRequest,
}

#[derive(Debug, Clone)]
pub enum AcpAccessRequest {
    FileRead { path: String },
    FileWrite { path: String },
    TerminalExecute { command: String, args: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum CapabilityCheckError {
    #[error("no capability token bound to session: {0}")]
    NoToken(String),
    #[error("capability expired")]
    Expired,
    #[error("capability revoked: {0}")]
    Revoked(String),
    #[error("checker error: {0}")]
    Internal(String),
}

/// Validates ACP-Client resource access against Chio capability tokens.
///
/// Implementations consult the kernel's capability authority, revocation
/// store, and budget store. The proxy calls this before forwarding
/// guarded requests (filesystem, terminal) to the agent.
pub trait CapabilityChecker: Send + Sync {
    /// Check whether the requested access is authorized.
    ///
    /// Resolves the session's capability token, verifies time bounds,
    /// revocation status, scope matching, and budget limits.
    ///
    /// Returns `Err` on internal failures -- the proxy treats errors
    /// as deny (fail-closed).
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError>;
}
```

---

## 6. Implementation Rollout

**Phase 1 -- Additive.** Both traits are `Option`-wrapped. Existing `AcpProxy::start`
remains unchanged. A new `AcpProxy::start_with_kernel` constructor accepts the signer
and checker. `InterceptResult` gains explicit attestation artifacts:

```rust
pub enum InterceptResult {
    Forward(Value),
    Block(Value),
    ForwardWithAttestation(Value, AcpAttestationArtifact),
}

pub enum AcpAttestationArtifact {
    SignedReceipt(ChioReceipt),
    Gap(AcpAttestationGap),
    UnsignedObservation(AcpToolCallAuditEntry),
}

pub struct AcpAttestationGap {
    pub session_id: String,
    pub tool_call_id: String,
    pub status: AcpAttestationStatus,
    pub observed_entry_hash: String,
}
```

The result surface should converge on `ForwardWithAttestation(...)` as the
single outward representation, rather than keeping separate signed vs unsigned
result variants.

**Phase 2 -- Explicit degraded mode.** When signer integration is enabled, the
proxy defaults to `AcpAttestationMode::Required`. Downstream consumers begin
handling `Gap` artifacts explicitly instead of assuming unsigned == acceptable.

**Phase 3 -- Unsigned isolation.** The unsigned-only path remains available
only behind explicit standalone/compatibility configuration or feature flags.
Sessions containing `UnsignedObservation` events are ineligible for
cross-protocol compliance claims.

---

## 7. Security Properties

**Fail-closed capability checking.** `check_access` errors (`Err`) are treated as deny.
The proxy returns `InterceptResult::Block` and logs at `warn` level.

**Explicit attestation degradation.** Signer errors are not silently collapsed
into success. In required mode, signing failure produces an attestation-gap
artifact and marks the session non-compliant for certificate generation. In
unsigned-compatibility mode, unsigned entries are still labeled as degraded
evidence.

**Guard ordering.** When a `CapabilityChecker` is present: (1) capability check,
(2) existing guard (`FsGuard`/`TerminalGuard`), (3) forward. Both layers must allow.

**No key material in the proxy.** The `ReceiptSigner` trait is opaque. Implementations
may hold the key in-process or call out to the kernel over an authenticated channel.

**Receipt integrity.** Signed receipts carry the same properties as MCP/A2A
receipts: Ed25519 signature over canonical JSON, embedded `kernel_key`,
`content_hash` from the ACP-Client event, `policy_hash`, and inclusion in the Merkle
checkpoint chain when a `ReceiptStore` is configured.

**Compliance boundary honesty.** Chio may still enforce policy even when ACP-Client
attestation is degraded, but such sessions must not be described as fully
attested. This preserves the integrity of cross-protocol claims.

---

## 8. Example Usage

### 8.1 Kernel-Backed ReceiptSigner

```rust
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_core::crypto::sha256_hex;
use chio_acp_proxy::{AcpReceiptRequest, ReceiptSigner, ReceiptSignError};

pub struct KernelReceiptSigner {
    keypair: Keypair,
    policy_hash: String,
    capability_id: String,
}

impl ReceiptSigner for KernelReceiptSigner {
    fn sign_acp_receipt(
        &self,
        req: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError> {
        let action = ToolCallAction {
            parameters: serde_json::json!({
                "tool_call_id": req.tool_call_id,
                "scope": format!("{:?}", req.scope_context),
            }),
            parameter_hash: sha256_hex(req.tool_call_id.as_bytes()),
        };
        let body = ChioReceiptBody {
            id: format!("rcpt-acp-{}", uuid::Uuid::now_v7()),
            timestamp: current_unix_secs(),
            capability_id: self.capability_id.clone(),
            tool_server: req.server_id.clone(),
            tool_name: req.tool_name.clone(),
            action,
            decision: Decision::Allow,
            content_hash: req.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "protocol": "acp",
                "session_id": req.session_id,
            })),
            kernel_key: self.keypair.public_key(),
        };
        ChioReceipt::sign(body, &self.keypair)
            .map_err(|e| ReceiptSignError::Internal(e.to_string()))
    }
}
```

### 8.2 Constructing the Proxy

```rust
let signer = Box::new(KernelReceiptSigner::new(keypair, policy_hash, cap_id));
let checker = Box::new(KernelCapabilityChecker::new(/* ... */));

let config = AcpProxyConfig::new("claude-code", public_key_hex)
    .with_allowed_path_prefix("/home/dev/project")
    .with_allowed_command("cargo");

// With kernel integration:
let proxy = AcpProxy::start_with_kernel(config, signer, checker)?;

// Without kernel (unsigned standalone mode only; outside full attestation claims):
// let proxy = AcpProxy::start(config)?;
```

---

## Appendix: Decision Record

**Why not `ToolServerConnection`?** The proxy does not register tools, respond to
`invoke`, or produce tool outputs. Forcing it into that trait would require fabricating
`server_id`/`tool_names`/`invoke` with no meaningful semantics, polluting the kernel's
tool registry with a phantom server.

**Why `Option`-wrapped injection?** The proxy is useful standalone (path guards and
command allowlists without capability-token infrastructure). A hard kernel requirement
would eliminate that use case.

**Why define traits in `chio-acp-proxy`?** Dependency direction: the proxy should not
depend on `chio-kernel` at compile time. The kernel (or bridge crate) depends on the
proxy's trait definitions, keeping the proxy lightweight and avoiding the kernel's
dependency tree in editor integrations.
