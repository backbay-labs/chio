# Structural Security Fixes

> **Scope**: Three structural security gaps that guards cannot fix, plus three
> additional hardening measures.

---

## Executive Summary

Three gaps are architectural, not policy problems. No guard configuration, no
matter how strict, can close them:

1. **TOCTOU in the wrapper pattern** -- unbounded window between `evaluate()`
   and tool execution allows replay, substitution, and stale-verdict attacks.
2. **Sidecar bypass** -- nothing prevents agents from calling tool servers
   directly, skipping the kernel entirely.
3. **Ungoverned agent memory** -- writes to vector DBs, conversation history,
   and scratchpads happen outside the guard pipeline, enabling cross-session
   prompt injection.

This document designs concrete solutions for all three, plus three additional
red-team findings: WASM guard module signing, an emergency kill switch, and
multi-tenant receipt isolation.

---

## 1. TOCTOU Fix: Execution Nonces

### 1.1 Problem

In the wrapper integration pattern, `evaluate()` returns an allow verdict to
the framework middleware, which then calls the tool server. Between these two
steps there is an **unbounded time window**. During this window:

- The capability could be revoked.
- The invocation budget could be exhausted by a concurrent call.
- The agent could delay execution, replay the verdict, or substitute a
  different tool call with different arguments.

DPoP proofs bind the agent's identity to the invocation but do not bind the
kernel's verdict to the actual execution. The verdict is a one-shot assertion
that was true at evaluation time -- it says nothing about execution time.

### 1.2 Solution: ExecutionNonce

When `evaluate()` returns `Verdict::Allow`, the kernel issues a short-lived,
single-use `ExecutionNonce` bound to that specific verdict. The tool server
must present this nonce when the actual call arrives. The nonce is
replay-protected via an LRU store (reusing the `DpopNonceStore` pattern from
`crates/kernel/chio-kernel/src/dpop.rs`).

### 1.3 Type Signatures

```rust
/// Schema identifier for execution nonces.
pub const EXECUTION_NONCE_SCHEMA: &str = "chio.execution_nonce.v1";

/// A short-lived, single-use token binding a kernel verdict to a tool
/// execution. Issued by the kernel on Allow, consumed by the tool server
/// (or kernel verify endpoint) before dispatching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionNonce {
    /// Schema identifier. Must equal `EXECUTION_NONCE_SCHEMA`.
    pub schema: String,
    /// Unique nonce identifier (UUIDv7).
    pub nonce_id: String,
    /// The verdict/receipt ID this nonce is bound to.
    pub verdict_id: String,
    /// Tool name that was evaluated.
    pub tool_name: String,
    /// Tool server that was evaluated.
    pub server_id: String,
    /// SHA-256 hash of the canonical JSON of the evaluated arguments.
    /// The tool server checks this against the arguments it receives.
    pub argument_hash: String,
    /// Unix timestamp (seconds) when this nonce expires.
    /// Default: `now + 30`. Configurable via `ExecutionNonceConfig`.
    pub expires_at: u64,
    /// The kernel's Ed25519 signature over canonical JSON of all fields
    /// above. Tool servers verify this with the kernel's public key.
    pub signature: Signature,
}

/// The signable body (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionNonceBody {
    pub schema: String,
    pub nonce_id: String,
    pub verdict_id: String,
    pub tool_name: String,
    pub server_id: String,
    pub argument_hash: String,
    pub expires_at: u64,
}

/// Configuration for execution nonce issuance and verification.
#[derive(Debug, Clone)]
pub struct ExecutionNonceConfig {
    /// How many seconds a nonce is valid after issuance. Default: 30.
    pub nonce_ttl_secs: u64,
    /// Maximum entries in the replay-prevention LRU cache. Default: 16384.
    pub nonce_store_capacity: usize,
}

impl Default for ExecutionNonceConfig {
    fn default() -> Self {
        Self {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 16384,
        }
    }
}
```

### 1.4 Nonce Store

The nonce store reuses the exact LRU pattern from `DpopNonceStore`:

```rust
/// In-memory LRU store for execution nonce replay prevention.
///
/// Keys are `nonce_id` strings. Values are the `Instant` when the nonce
/// was consumed. A nonce is rejected if it has already been consumed
/// (single-use) or if it has expired (time-bounded).
pub struct ExecutionNonceStore {
    /// Consumed nonces. Presence in this cache means the nonce has been
    /// used and must be rejected on any subsequent presentation.
    consumed: Mutex<LruCache<String, Instant>>,
    ttl: Duration,
}

impl ExecutionNonceStore {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let nz = NonZeroUsize::new(capacity)
            .unwrap_or_else(|| NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN));
        Self {
            consumed: Mutex::new(LruCache::new(nz)),
            ttl,
        }
    }

    /// Consume a nonce. Returns `Ok(true)` if the nonce is fresh and has
    /// been marked consumed. Returns `Ok(false)` if the nonce was already
    /// consumed (replay). Returns `Err` on mutex poisoning (fail-closed).
    pub fn consume(&self, nonce_id: &str) -> Result<bool, KernelError> {
        let mut cache = self.consumed.lock().map_err(|_| {
            KernelError::Internal(
                "execution nonce store mutex poisoned; fail-closed".into(),
            )
        })?;

        if let Some(consumed_at) = cache.peek(&nonce_id.to_string()) {
            if consumed_at.elapsed() < self.ttl {
                return Ok(false); // replay
            }
            cache.pop(&nonce_id.to_string());
        }

        cache.put(nonce_id.to_string(), Instant::now());
        Ok(true)
    }
}
```

### 1.5 Kernel Integration

The kernel changes are minimal. `evaluate_tool_call_sync_with_session_roots`
gains one new step after the existing receipt-signing logic:

```rust
// After building the allow response and signing the receipt:
let execution_nonce = if self.execution_nonce_config.is_some() {
    let config = self.execution_nonce_config.as_ref()
        .expect("checked above");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = ExecutionNonceBody {
        schema: EXECUTION_NONCE_SCHEMA.to_string(),
        nonce_id: uuid7_string(),
        verdict_id: receipt.id.clone(),
        tool_name: request.tool_name.clone(),
        server_id: request.server_id.clone(),
        argument_hash: action.parameter_hash.clone(),
        expires_at: now + config.nonce_ttl_secs,
    };
    let (signature, _) = self.config.keypair.sign_canonical(&body)?;
    Some(ExecutionNonce {
        schema: body.schema,
        nonce_id: body.nonce_id,
        verdict_id: body.verdict_id,
        tool_name: body.tool_name,
        server_id: body.server_id,
        argument_hash: body.argument_hash,
        expires_at: body.expires_at,
        signature,
    })
} else {
    None
};
```

`ToolCallResponse` gains an optional field:

```rust
pub struct ToolCallResponse {
    // ... existing fields ...

    /// Execution nonce for tool-server-side verification.
    /// Present only when `ExecutionNonceConfig` is set on the kernel.
    pub execution_nonce: Option<ExecutionNonce>,
}
```

### 1.6 Tool Server Verification

Tool servers validate the nonce in one of two ways:

**Option A: Remote verification** -- call the kernel's `/verify-nonce`
endpoint. The kernel checks expiry, consumes the nonce (single-use), and
verifies signature + binding fields.

```
POST /verify-nonce
Content-Type: application/json

{
    "nonce": <ExecutionNonce>,
    "tool_name": "write_file",
    "server_id": "fs-server",
    "argument_hash": "a1b2c3..."
}

Response: 200 OK  |  403 Forbidden (expired/replayed/mismatched)
```

**Option B: Local verification** -- the tool server holds the kernel's public
key and validates locally. This avoids a network round-trip but requires key
distribution.

```rust
fn verify_execution_nonce(
    nonce: &ExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected_tool: &str,
    expected_server: &str,
    expected_arg_hash: &str,
    now: u64,
    nonce_store: &ExecutionNonceStore,
) -> Result<(), VerifyError> {
    // 1. Schema check
    if nonce.schema != EXECUTION_NONCE_SCHEMA {
        return Err(VerifyError::BadSchema);
    }
    // 2. Expiry check
    if now >= nonce.expires_at {
        return Err(VerifyError::Expired);
    }
    // 3. Binding check
    if nonce.tool_name != expected_tool
        || nonce.server_id != expected_server
        || nonce.argument_hash != expected_arg_hash
    {
        return Err(VerifyError::BindingMismatch);
    }
    // 4. Signature verification
    let body = ExecutionNonceBody { /* reconstruct from nonce fields */ };
    if !kernel_pubkey.verify_canonical(&body, &nonce.signature)? {
        return Err(VerifyError::InvalidSignature);
    }
    // 5. Replay check (single-use)
    if !nonce_store.consume(&nonce.nonce_id)? {
        return Err(VerifyError::Replayed);
    }
    Ok(())
}
```

### 1.7 Backward Compatibility

The execution nonce is **optional**. When `ExecutionNonceConfig` is `None` on
the kernel, no nonce is issued and `ToolCallResponse.execution_nonce` is
`None`. Legacy integrations continue to work but are classified as
`TrustLevel::Advisory` (see section 2). This is a documentation change, not
a breaking change.

### 1.8 Transport: HTTP Header

Framework integrations pass the nonce to the tool server via:

```
X-Chio-Execution-Nonce: <base64url-encoded canonical JSON of ExecutionNonce>
```

This avoids modifying tool call payloads and works across all transports
(HTTP, gRPC, WebSocket).

---

## 2. Sidecar Bypass Mitigation: Trust Level Taxonomy

### 2.1 Problem

In the wrapper integration pattern (all framework integrations: LangChain,
CrewAI, AutoGen, Vercel AI SDK, etc.), the agent framework calls
`chio_client.evaluate()` as middleware, then calls the tool server directly.
Nothing prevents the agent from skipping the middleware and calling the tool
server without evaluation. This is "governance by convention" -- it works only
if every code path is correctly instrumented.

### 2.2 Solution: Three-Layer Defense

The fix is not a single mechanism but three complementary layers. All three
should be implemented. Each raises the cost of bypass.

#### Solution A: Trust Level Taxonomy (documentation + type system)

Define three trust levels as a first-class enum:

```rust
/// Integration trust level. Declares how strongly the integration
/// guarantees that every tool call passes through the kernel.
///
/// Recorded in receipts and surfaced in dashboards. Operators choose
/// the minimum acceptable trust level per deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Kernel dispatches tool calls directly. The agent never touches
    /// the tool server. Bypass is architecturally impossible.
    ///
    /// Used by: native Chio transport, kernel-managed tool servers.
    Mediated,

    /// Wrapper pattern with execution nonce. The agent calls the tool
    /// server, but the tool server validates the kernel-issued nonce
    /// before executing. Bypass requires compromising the tool server.
    ///
    /// Used by: framework integrations with nonce-aware tool servers.
    Verified,

    /// Wrapper pattern without nonce. Governance by convention only.
    /// The agent could bypass the sidecar and call the tool server
    /// directly. No enforcement mechanism prevents this.
    ///
    /// Used by: legacy integrations, quick-start configurations.
    Advisory,
}
```

This enum is added to:

1. **`ChioReceipt`** -- new field `trust_level: TrustLevel`. Auditors can
   filter receipts by trust level and flag any `Advisory` invocations in
   production.

2. **Integration configuration** -- each framework adapter declares its
   trust level. The kernel records it in receipts automatically.

3. **`KernelConfig`** -- new optional field
   `minimum_trust_level: Option<TrustLevel>`. When set, the kernel rejects
   `evaluate()` calls from integrations below the minimum. This lets
   operators enforce `Verified` or `Mediated` in production while allowing
   `Advisory` in development.

```rust
// Addition to KernelConfig:
pub struct KernelConfig {
    // ... existing fields ...

    /// Minimum trust level for tool call evaluation. When set, the kernel
    /// rejects evaluate() requests from integrations below this level.
    /// Default: None (all trust levels accepted).
    pub minimum_trust_level: Option<TrustLevel>,
}

// Addition to ToolCallRequest:
pub struct ToolCallRequest {
    // ... existing fields ...

    /// Trust level declared by the calling integration.
    /// Default: Advisory (backward compatible).
    #[serde(default = "default_trust_level")]
    pub trust_level: TrustLevel,
}

fn default_trust_level() -> TrustLevel {
    TrustLevel::Advisory
}
```

#### Solution B: Network-Level Enforcement (Envoy ext_authz)

Tool servers behind an Envoy proxy configured with Chio as the ext_authz
backend (see `ENVOY-EXT-AUTHZ-INTEGRATION.md`) only accept traffic that has
been authorized by the kernel. This is infrastructure-level bypass prevention.

The Envoy filter checks for a valid `X-Chio-Execution-Nonce` header on every
request to the tool server. Requests without a nonce (or with an expired/
replayed nonce) are rejected at the proxy layer before reaching the tool
server.

```yaml
# Envoy filter configuration (simplified)
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: chio-kernel
      failure_mode_deny: true  # fail-closed
      with_request_body:
        max_request_bytes: 65536
        allow_partial_message: false
```

This makes bypass require compromising the network infrastructure, not just
the application code. When Envoy ext_authz is in place, the trust level is
effectively `Mediated` regardless of the integration pattern.

#### Solution C: Tool Server Authentication

Tool servers reject calls that do not carry a valid `X-Chio-Execution-Nonce`
header. This is application-level enforcement complementing the network layer.

```rust
/// Middleware for tool servers that validates execution nonces.
///
/// Rejects requests without a valid nonce unless running in
/// `permissive` mode (development only).
pub struct NonceValidationMiddleware {
    kernel_pubkey: PublicKey,
    nonce_store: ExecutionNonceStore,
    permissive: bool,
}

impl NonceValidationMiddleware {
    /// Validate the nonce from the request headers.
    ///
    /// In strict mode (production), missing or invalid nonces are rejected.
    /// In permissive mode (development), missing nonces log a warning but
    /// the request proceeds.
    pub fn validate(&self, headers: &HeaderMap) -> Result<(), VerifyError> {
        let nonce_header = headers.get("x-chio-execution-nonce");
        match nonce_header {
            None if self.permissive => {
                tracing::warn!("missing execution nonce; permissive mode, allowing");
                Ok(())
            }
            None => Err(VerifyError::MissingNonce),
            Some(value) => {
                let nonce: ExecutionNonce = decode_nonce(value)?;
                verify_execution_nonce(
                    &nonce,
                    &self.kernel_pubkey,
                    // tool_name and server_id extracted from the request path
                    &extract_tool_name(headers)?,
                    &self.server_id,
                    &compute_argument_hash(/* request body */)?,
                    now_unix_secs(),
                    &self.nonce_store,
                )
            }
        }
    }
}
```

### 2.3 Recommendation

Implement all three. They compose:

| Layer | What it prevents | Deployment cost |
|-------|-----------------|-----------------|
| Trust taxonomy (A) | Misclassification. Operators see exactly what level of enforcement is active. | Zero -- type system + receipt field |
| Network enforcement (B) | Bypass at the transport level. Agent cannot reach tool server without going through Chio. | Medium -- requires Envoy or equivalent proxy |
| Tool server auth (C) | Bypass at the application level. Even if the agent reaches the server, the server rejects unauthorized calls. | Low -- middleware in tool server |

Trust level is the **minimum viable fix**. Network enforcement is the
**strongest fix**. Tool server authentication is the **most practical fix**
for deployments that cannot run a proxy.

---

## 3. Agent Memory Governance

### 3.1 Problem

Chio governs tool calls but agents write to memory stores outside the guard
pipeline:

- **Vector databases** (Pinecone, Weaviate, Chroma) for RAG context
- **Conversation history** (Redis, PostgreSQL, file-backed stores)
- **Scratchpad files** (agent working memory, chain-of-thought caches)

These writes are invisible to Chio. A compromised or confused agent can:

1. Write poisoned context that persists across sessions.
2. Perform indirect prompt injection by planting instructions in RAG context.
3. Exfiltrate data by writing it to a shared memory store.
4. Exhaust storage without budget governance.

### 3.2 Solution: Memory Writes as Tool Calls

Treat memory writes as governed tool calls. The memory store is wrapped in a
tool server (or the write operation is wrapped in a tool) that goes through
the kernel's guard pipeline. The guard pipeline evaluates memory writes with
the same rigor as any other tool call: capability check, constraint
evaluation, guard execution, receipt signing.

### 3.3 New ToolAction Variant

Extend the `ToolAction` enum in `chio-guards/src/action.rs`:

```rust
pub enum ToolAction {
    // ... existing variants ...

    /// Memory write operation. The agent is writing to a persistent store
    /// that may be read in future sessions.
    MemoryWrite {
        /// Type of memory store being written to.
        store_type: MemoryStoreType,
        /// Collection, namespace, or table name within the store.
        collection: String,
        /// Key or document ID being written.
        key: String,
        /// SHA-256 hash of the content being written.
        content_hash: String,
        /// Requested retention TTL in seconds. `None` means indefinite.
        retention_ttl: Option<u64>,
    },

    /// Memory read operation. Optional governance for auditing reads.
    MemoryRead {
        /// Type of memory store being read from.
        store_type: MemoryStoreType,
        /// Collection, namespace, or table name.
        collection: String,
        /// Key, document ID, or query hash.
        key: String,
    },
}

/// Classification of memory stores for constraint matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStoreType {
    /// Vector database (Pinecone, Weaviate, Chroma, Qdrant, etc.)
    VectorDb,
    /// Conversation history (Redis, PostgreSQL, file-backed)
    ConversationHistory,
    /// Agent scratchpad / working memory
    Scratchpad,
    /// Structured knowledge base (graph DB, relational DB)
    KnowledgeBase,
    /// Custom / unclassified store
    Custom(String),
}
```

### 3.4 New Constraint Variants

Extend the `Constraint` enum in `chio-core-types/src/capability.rs`:

```rust
pub enum Constraint {
    // ... existing variants ...

    /// Only allow memory writes to these store types.
    MemoryStoreAllowlist(Vec<MemoryStoreType>),

    /// Maximum retention TTL for memory writes, in seconds.
    /// Writes requesting a longer TTL (or indefinite retention) are denied.
    MaxRetentionTtl(u64),

    /// Maximum number of memory entries an agent can write per session.
    /// Prevents storage exhaustion attacks.
    MaxMemoryEntries(u64),

    /// Memory collection allowlist. Only allow writes to collections
    /// matching these patterns (glob syntax).
    MemoryCollectionAllowlist(Vec<String>),

    /// Maximum content size for a single memory write, in bytes.
    MaxMemoryContentSize(u64),
}
```

### 3.5 Kernel Constraint Evaluation

The kernel evaluates memory constraints during grant matching, alongside
existing constraint checks. The evaluation is straightforward pattern
matching:

```rust
fn evaluate_memory_constraint(
    constraint: &Constraint,
    action: &ToolAction,
) -> Result<(), KernelError> {
    match (constraint, action) {
        (
            Constraint::MemoryStoreAllowlist(allowed),
            ToolAction::MemoryWrite { store_type, .. },
        ) => {
            if !allowed.contains(store_type) {
                return Err(KernelError::InvalidConstraint(format!(
                    "memory store type {:?} not in allowlist",
                    store_type
                )));
            }
        }
        (
            Constraint::MaxRetentionTtl(max_ttl),
            ToolAction::MemoryWrite { retention_ttl, .. },
        ) => {
            match retention_ttl {
                None => {
                    return Err(KernelError::InvalidConstraint(
                        "indefinite retention not allowed; specify a TTL".into(),
                    ));
                }
                Some(ttl) if *ttl > *max_ttl => {
                    return Err(KernelError::InvalidConstraint(format!(
                        "requested TTL {} exceeds maximum {}",
                        ttl, max_ttl
                    )));
                }
                _ => {}
            }
        }
        (
            Constraint::MaxMemoryEntries(max),
            ToolAction::MemoryWrite { .. },
        ) => {
            // Check against session-scoped counter in budget store.
            // Denied if session memory write count >= max.
        }
        _ => {} // constraint does not apply to this action
    }
    Ok(())
}
```

### 3.6 Memory Read Governance

Memory reads are optionally governed. When enabled, each read produces a
receipt recording what was read, by whom, and under which capability. This
adds latency (one `evaluate()` round-trip per read) and is therefore
configurable:

```rust
/// Memory governance configuration.
#[derive(Debug, Clone)]
pub struct MemoryGovernanceConfig {
    /// Whether memory writes go through the guard pipeline.
    /// Default: true. This is the primary defense.
    pub govern_writes: bool,

    /// Whether memory reads produce receipts.
    /// Default: false. Enable for high-security deployments where
    /// read-auditing justifies the latency cost.
    pub govern_reads: bool,

    /// Whether to verify the authorization chain on reads (see 3.7).
    /// Default: false. Enable for cross-session integrity.
    pub verify_write_chain_on_read: bool,
}

impl Default for MemoryGovernanceConfig {
    fn default() -> Self {
        Self {
            govern_writes: true,
            govern_reads: false,
            verify_write_chain_on_read: false,
        }
    }
}
```

### 3.7 Cross-Session Integrity: Write Authorization Chain

Each governed memory write produces a receipt. The receipt ID is stored
alongside the memory entry as provenance metadata. On read, if
`verify_write_chain_on_read` is enabled, the memory tool server verifies
that:

1. The receipt ID exists in the receipt store.
2. The receipt's decision was `Allow`.
3. The capability that authorized the write has not been revoked.

This creates a hash chain from memory content back to the capability that
authorized it. If the write was unauthorized (no receipt) or the capability
has since been revoked, the read returns an integrity error rather than
potentially poisoned content.

```rust
/// Provenance metadata stored alongside each governed memory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntryProvenance {
    /// Receipt ID of the write that created this entry.
    pub write_receipt_id: String,
    /// Capability ID that authorized the write.
    pub capability_id: String,
    /// Agent public key that performed the write.
    pub agent_key: PublicKey,
    /// SHA-256 hash of the content at write time.
    pub content_hash: String,
    /// Unix timestamp of the write.
    pub written_at: u64,
    /// Retention TTL in seconds from write time. `None` = indefinite.
    pub retention_ttl: Option<u64>,
}

/// Verify that a memory entry's provenance is valid.
fn verify_memory_provenance(
    provenance: &MemoryEntryProvenance,
    receipt_store: &dyn ReceiptStore,
    revocation_store: &dyn RevocationStore,
    current_content_hash: &str,
) -> Result<(), MemoryIntegrityError> {
    // 1. Content integrity -- hash must match
    if provenance.content_hash != current_content_hash {
        return Err(MemoryIntegrityError::ContentTampered);
    }

    // 2. Receipt exists and was Allow
    let receipt = receipt_store
        .get(&provenance.write_receipt_id)
        .map_err(|_| MemoryIntegrityError::ReceiptNotFound)?;
    if !matches!(receipt.decision, Decision::Allow) {
        return Err(MemoryIntegrityError::WriteWasDenied);
    }

    // 3. Capability not revoked
    if revocation_store.is_revoked(&provenance.capability_id)? {
        return Err(MemoryIntegrityError::CapabilityRevoked);
    }

    // 4. Retention TTL not expired
    if let Some(ttl) = provenance.retention_ttl {
        let now = now_unix_secs();
        if now > provenance.written_at + ttl {
            return Err(MemoryIntegrityError::RetentionExpired);
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum MemoryIntegrityError {
    #[error("content hash does not match write-time hash; entry may have been tampered")]
    ContentTampered,
    #[error("write receipt not found in receipt store")]
    ReceiptNotFound,
    #[error("write receipt decision was Deny, not Allow")]
    WriteWasDenied,
    #[error("capability that authorized the write has been revoked")]
    CapabilityRevoked,
    #[error("retention TTL has expired; entry should have been garbage collected")]
    RetentionExpired,
}
```

### 3.8 Integration Pattern

Framework integrations wrap memory operations in tool calls:

```python
# Python SDK example: wrapping a Chroma upsert
from chio_sdk import ChioClient, MemoryWriteAction

chio = ChioClient()

# Instead of:
#   collection.upsert(ids=["doc1"], documents=["..."])
# Do:
result = chio.governed_memory_write(
    store_type="vector_db",
    collection="agent-context",
    key="doc1",
    content=document_text,
    retention_ttl=86400,  # 24 hours
)
# result.receipt_id is stored as provenance alongside the upsert
if result.allowed:
    collection.upsert(
        ids=["doc1"],
        documents=[document_text],
        metadatas=[{"chio_receipt_id": result.receipt_id}],
    )
```

---

## 4. WASM Guard Module Signing

### 4.1 Problem

WASM guard modules are loaded from bytes (`load_module(&[u8], fuel_limit)`)
with no integrity verification. An attacker who can modify the `.wasm` binary
on disk or in transit can inject arbitrary policy logic into the guard
pipeline.

### 4.2 Solution

Require Ed25519 signatures on `.wasm` binaries. The signature is verified at
load time before compilation. Unsigned modules are rejected unless the kernel
is explicitly configured to allow them (development only).

### 4.3 Type Signatures

```rust
/// A signed WASM guard module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWasmModule {
    /// SHA-256 hash of the raw WASM bytes.
    pub module_hash: String,
    /// Human-readable module name (for logging and error messages).
    pub module_name: String,
    /// Version string (semver recommended).
    pub version: String,
    /// Ed25519 public key of the signer.
    pub signer: PublicKey,
    /// Ed25519 signature over canonical JSON of
    /// `{ module_hash, module_name, version, signer }`.
    pub signature: Signature,
}

/// Configuration for WASM guard module signing.
#[derive(Debug, Clone)]
pub struct WasmSigningConfig {
    /// Public keys of trusted WASM guard signers.
    /// Modules signed by any of these keys are accepted.
    pub trusted_signers: Vec<PublicKey>,
    /// Whether to allow unsigned modules. Default: false.
    /// Set to true only for development/testing.
    pub allow_unsigned: bool,
}
```

### 4.4 Verification at Load Time

The `WasmGuardBackend::load_module` method gains a verification step before
compilation:

```rust
fn load_module(
    &mut self,
    wasm_bytes: &[u8],
    fuel_limit: u64,
    signing_manifest: Option<&SignedWasmModule>,
    signing_config: &WasmSigningConfig,
) -> Result<(), WasmGuardError> {
    // 1. Module size check (existing)
    if wasm_bytes.len() > self.max_module_size {
        return Err(WasmGuardError::ModuleTooLarge { /* ... */ });
    }

    // 2. Signature verification (new)
    match signing_manifest {
        Some(manifest) => {
            // Verify hash matches bytes
            let actual_hash = sha256_hex(wasm_bytes);
            if actual_hash != manifest.module_hash {
                return Err(WasmGuardError::IntegrityCheckFailed {
                    expected: manifest.module_hash.clone(),
                    actual: actual_hash,
                });
            }
            // Verify signer is trusted
            if !signing_config.trusted_signers.contains(&manifest.signer) {
                return Err(WasmGuardError::UntrustedSigner(
                    manifest.signer.clone(),
                ));
            }
            // Verify signature
            let body = SignedWasmModuleBody {
                module_hash: manifest.module_hash.clone(),
                module_name: manifest.module_name.clone(),
                version: manifest.version.clone(),
                signer: manifest.signer.clone(),
            };
            if !manifest.signer.verify_canonical(&body, &manifest.signature)? {
                return Err(WasmGuardError::InvalidModuleSignature);
            }
        }
        None if signing_config.allow_unsigned => {
            tracing::warn!(
                "loading unsigned WASM guard module; \
                 this is allowed in development but must not reach production"
            );
        }
        None => {
            return Err(WasmGuardError::UnsignedModule);
        }
    }

    // 3. Compilation (existing)
    // ...
}
```

### 4.5 Signing Tooling

A CLI command signs WASM modules:

```
chio guard sign \
    --module path/to/guard.wasm \
    --name "pii-detector" \
    --version "1.2.0" \
    --key path/to/signing-key.pem \
    --output path/to/guard.wasm.sig
```

The `.wasm.sig` file is a JSON-serialized `SignedWasmModule`. It is loaded
alongside the `.wasm` binary at guard registration time.

---

## 5. Emergency Kill Switch

### 5.1 Problem

There is no mechanism to globally halt all agent activity. If a compromised
agent or a misconfigured policy is causing damage, the only option is to shut
down the kernel process. This is too coarse and too slow.

### 5.2 Solution

Add `emergency_stop()` and `emergency_resume()` methods to `ChioKernel`. When
the kill switch is engaged:

1. All active capabilities are logically revoked (added to the revocation
   store with reason `"emergency_stop"`).
2. All new `evaluate()` calls return `Deny` with reason
   `"kernel emergency stop active"`.
3. All in-flight streamed responses are terminated.
4. The kernel remains running and accepting health checks so orchestrators
   do not restart it.

The kill switch persists until `emergency_resume()` is called manually.

### 5.3 Implementation

```rust
impl ChioKernel {
    /// Engage the emergency kill switch.
    ///
    /// All active capabilities are revoked. All new evaluate() calls are
    /// denied. The kernel remains running but inert until `emergency_resume()`
    /// is called.
    ///
    /// Returns the number of capabilities that were revoked.
    pub fn emergency_stop(&self, reason: &str) -> Result<u64, KernelError> {
        // Set the atomic flag
        self.emergency_stopped.store(true, Ordering::SeqCst);

        // Record the stop event
        let stop_event = EmergencyStopEvent {
            timestamp: now_unix_secs(),
            reason: reason.to_string(),
            operator: "kernel_api".to_string(),
        };
        tracing::error!(
            reason = reason,
            "EMERGENCY STOP ENGAGED -- all evaluations will be denied"
        );

        // Revoke all active capabilities in the revocation store
        let revoked_count = {
            let mut rev_store = self.revocation_store.lock().map_err(|_| {
                KernelError::Internal("revocation store mutex poisoned".into())
            })?;
            rev_store.revoke_all("emergency_stop")?
        };

        Ok(revoked_count)
    }

    /// Disengage the emergency kill switch.
    ///
    /// New evaluate() calls will be accepted. Previously revoked capabilities
    /// remain revoked -- agents must obtain new capabilities.
    pub fn emergency_resume(&self) -> Result<(), KernelError> {
        self.emergency_stopped.store(false, Ordering::SeqCst);
        tracing::warn!("EMERGENCY STOP DISENGAGED -- evaluations will resume");
        Ok(())
    }

    /// Check the kill switch at the top of every evaluate() call.
    fn check_emergency_stop(&self) -> Result<(), KernelError> {
        if self.emergency_stopped.load(Ordering::SeqCst) {
            return Err(KernelError::GuardDenied(
                "kernel emergency stop is active; all evaluations denied".into(),
            ));
        }
        Ok(())
    }
}
```

New field on `ChioKernel`:

```rust
pub struct ChioKernel {
    // ... existing fields ...

    /// Emergency kill switch. When true, all evaluate() calls are denied.
    emergency_stopped: AtomicBool,
}
```

### 5.4 API Surface

The kill switch is exposed via the kernel's HTTP API:

```
POST /emergency-stop
Content-Type: application/json
Authorization: Bearer <operator-token>

{ "reason": "compromised agent detected in production" }

Response: 200 OK
{ "revoked_capabilities": 47, "timestamp": 1713100000 }
```

```
POST /emergency-resume
Authorization: Bearer <operator-token>

Response: 200 OK
{ "timestamp": 1713100300 }
```

Both endpoints require operator-level authentication (not agent-level). The
operator token is configured at kernel startup and is separate from the
capability authority's signing key.

---

## 6. Multi-Tenant Receipt Isolation

### 6.1 Problem

In multi-tenant deployments, receipts from different tenants are stored in the
same receipt store. There is no enforcement preventing one tenant from
querying another tenant's receipts. The `ReceiptStore` trait has no
tenant-scoping parameter.

### 6.2 Solution

Add `tenant_id` to receipts and enforce tenant isolation at the store level.

### 6.3 Type Changes

```rust
// Addition to ChioReceiptBody and ChioReceipt:
pub struct ChioReceipt {
    // ... existing fields ...

    /// Tenant identifier for multi-tenant deployments.
    /// `None` in single-tenant mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}
```

The `tenant_id` is derived from the capability token's issuer or from a
tenant claim in the session. The kernel populates it automatically during
receipt signing:

```rust
// During receipt construction:
let tenant_id = self.resolve_tenant_id(request)?;
```

### 6.4 Store-Level Enforcement

The `ReceiptStore` trait gains tenant-scoped methods:

```rust
pub trait ReceiptStore: Send + Sync {
    // ... existing methods ...

    /// Query receipts scoped to a specific tenant.
    /// Implementations MUST filter by tenant_id and MUST NOT return
    /// receipts belonging to other tenants.
    fn query_by_tenant(
        &self,
        tenant_id: &str,
        filter: &ReceiptQuery,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError>;

    /// Return the tenant_id that should be used for queries from
    /// the given authentication context.
    fn resolve_tenant(
        &self,
        auth_context: &AuthContext,
    ) -> Result<String, ReceiptStoreError>;
}
```

For the SQLite receipt store (`chio-store-sqlite`), this is a `WHERE` clause:

```sql
SELECT * FROM receipts
WHERE tenant_id = ?1
  AND timestamp >= ?2
  AND timestamp <= ?3
ORDER BY timestamp DESC
LIMIT ?4
```

For deployments using the receipt query API (`chio-cli`'s `trust serve`), the
HTTP handler extracts the tenant ID from the operator's authentication
context and passes it to the store. There is no query parameter for tenant
ID -- the tenant is determined by authentication, not by the caller's choice.

### 6.5 Backward Compatibility

`tenant_id` defaults to `None`. Single-tenant deployments are unaffected. The
SQLite store treats `None` as a single implicit tenant. When `tenant_id` is
first set on a deployment, existing receipts with `None` are accessible only
to operators with the `system` tenant role.

---

## Implementation Order

| Fix | Priority | Complexity | Dependencies |
|-----|----------|-----------|--------------|
| Trust level taxonomy (2A) | P0 | Low | None -- type + receipt field |
| Execution nonces (1) | P1 | Medium | Trust taxonomy (for level classification) |
| Tool server nonce validation (2C) | P1 | Low | Execution nonces |
| Emergency kill switch (5) | P1 | Low | None |
| WASM guard signing (4) | P1 | Medium | None |
| Multi-tenant receipt isolation (6) | P1 | Medium | None |
| Memory write governance (3) | P2 | High | New ToolAction + Constraint variants |
| Memory read governance (3.6) | P3 | Medium | Memory write governance |
| Cross-session integrity chain (3.7) | P3 | High | Memory write governance + receipt store queries |
| Envoy ext_authz enforcement (2B) | P2 | Medium | Execution nonces, existing Envoy integration |

Trust level taxonomy is P0 because it is zero-cost and unblocks honest
documentation of the current security posture. Everything else builds on it.

---

## Open Questions

1. **Nonce TTL tuning.** The default of 30 seconds is a guess. Too short
   and legitimate slow tool servers fail. Too long and the TOCTOU window
   remains wide. Should the TTL be per-tool-server rather than global?

2. **Memory governance scope.** Should memory governance be mandatory for
   all memory-capable integrations, or should it be opt-in? Mandatory is
   safer but adds friction. Opt-in risks the same "governance by convention"
   problem this document exists to solve.

3. **Kill switch persistence.** Should the emergency stop state survive
   kernel restarts? If the kernel crashes and restarts while stopped, should
   it come back in the stopped state? This requires persisting the flag to
   the receipt store or a separate state file.

4. **Tenant isolation in receipt Merkle tree.** If receipts are
   tenant-scoped, should the Merkle checkpoint tree be per-tenant or global?
   Per-tenant gives stronger isolation but increases checkpoint frequency.
   Global is simpler but means a tenant's checkpoint proof includes sibling
   hashes from other tenants (privacy concern for the tree structure, though
   not the receipt content).
