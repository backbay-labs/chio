use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::*;

/// Configuration for the Chio Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<chio_core::PublicKey>,

    /// Maximum allowed delegation depth.
    pub max_delegation_depth: u32,

    /// SHA-256 hash of the active policy (embedded in receipts).
    pub policy_hash: String,

    /// Whether nested sampling requests are allowed at all.
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests are allowed.
    pub allow_elicitation: bool,

    /// Maximum total wall-clock duration permitted for one streamed tool result.
    pub max_stream_duration_secs: u64,

    /// Maximum total canonical payload size permitted for one streamed tool result.
    pub max_stream_total_bytes: u64,

    /// Whether durable receipts and kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    pub require_web3_evidence: bool,

    /// Allow process-local receipt logs when no durable receipt store is
    /// installed. This is for tests and local scaffolds only; protocol
    /// deployments should leave it false so successful dispatch requires
    /// durable receipt persistence before any tool side effect.
    pub allow_ephemeral_receipt_log: bool,

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing for deployments that do not
    /// require web3 evidence.
    pub checkpoint_batch_size: u64,

    /// Optional receipt retention configuration.
    ///
    /// When `None` (default), retention is disabled and receipts accumulate
    /// indefinitely. When `Some(config)`, the kernel will archive receipts
    /// that exceed the time or size threshold.
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,
}

/// Boot-time configuration for the kernel-side hybrid signing path.
///
/// Mirrors the wire form of `chio_policy::CryptoFloor` (`allow_classical`,
/// `allow_hybrid`, `pq_required`) and pairs the floor with the operator's
/// 32-byte ML-DSA-65 keygen seed. Construct one of these from a parsed
/// HushSpec policy plus the boot-loaded PQ seed and pass it to
/// [`ChioKernel::with_hybrid_signing_backend`] with a verified self-quote
/// port to obtain a `Box<dyn SigningBackend>` for hybrid receipt signing.
///
/// A separate input from [`KernelConfig`]: the hybrid fields are not folded
/// into `KernelConfig`, so its wire form is unaffected.
#[derive(Debug, Clone, Default)]
pub struct HybridSigningConfig {
    /// Minimum cryptographic posture enforced on receipts, capability
    /// tokens, and compliance certificates. Default
    /// [`KernelCryptoFloor::AllowClassical`].
    pub crypto_floor: KernelCryptoFloor,

    /// Optional 32-byte ML-DSA-65 keygen seed. Required when
    /// `crypto_floor` is [`KernelCryptoFloor::AllowHybrid`] or
    /// [`KernelCryptoFloor::PqRequired`]; ignored under
    /// [`KernelCryptoFloor::AllowClassical`].
    pub pq_signing_seed: Option<[u8; 32]>,
}

pub(crate) fn capability_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::capability::crypto_floor::CapabilityCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::PqRequired
        }
    }
}

pub(crate) fn receipt_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::receipt::crypto_floor::ReceiptCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
        }
    }
}

pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10_737_418_240;

/// The Chio Runtime Kernel.
///
/// This is the central component of the Chio protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct ChioKernel {
    pub(super) config: KernelConfig,
    pub(super) guards: Vec<Box<dyn Guard>>,
    pub(super) post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline,
    pub(super) budget_store: Arc<dyn BudgetStore>,
    pub(super) budget_store_lock: Mutex<()>,
    pub(super) revocation_store: Arc<dyn RevocationStore>,
    pub(super) capability_authority: Box<dyn CapabilityAuthority>,
    pub(super) tool_servers: HashMap<ServerId, Box<dyn ToolServerConnection>>,
    pub(super) resource_providers: Vec<Box<dyn ResourceProvider>>,
    pub(super) prompt_providers: Vec<Box<dyn PromptProvider>>,
    pub(super) sessions: DashMap<SessionId, Arc<Session>>,
    pub(super) receipt_log: Mutex<ReceiptLog>,
    pub(super) child_receipt_log: Mutex<ChildReceiptLog>,
    pub(super) receipt_store: Option<Arc<dyn ReceiptStore>>,
    pub(super) receipt_store_write_lock: Mutex<()>,
    pub(super) payment_adapter: Option<Box<dyn PaymentAdapter>>,
    pub(super) price_oracle: Option<Box<dyn PriceOracle>>,
    pub(super) runtime_admission_hook: Option<Arc<dyn RuntimeAdmissionHook>>,
    pub(super) attestation_trust_policy: Option<AttestationTrustPolicy>,
    pub(super) capability_crypto_floor: KernelCryptoFloor,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    pub(super) checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    pub(super) checkpoint_seq_counter: AtomicU64,
    /// seq of the last receipt included in the previous checkpoint batch.
    pub(super) last_checkpoint_seq: AtomicU64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    pub(super) dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    pub(super) dpop_config: Option<dpop::DpopConfig>,
    /// Execution-nonce config (TTL, capacity, strict-mode flag).
    /// When `None`, no nonce is minted on allow and strict verification is
    /// disabled (legacy deployments keep working).
    pub(super) execution_nonce_config: Option<crate::execution_nonce::ExecutionNonceConfig>,
    /// Replay-prevention store for execution nonces. Shared with
    /// any tool server that delegates verification to the kernel. Boxed
    /// trait object so SQLite-backed stores can be plugged in.
    pub(super) execution_nonce_store: Option<Box<dyn crate::execution_nonce::ExecutionNonceStore>>,
    /// Replay store for governed approval tokens. Prevents a signed approval
    /// from being consumed more than once. Uses the same LRU + TTL pattern as
    /// DPoP nonce verification. Key: (request_id, governed_intent_hash).
    pub(super) approval_replay_store: Option<dpop::DpopNonceStore>,
    /// Emergency kill switch. When `true`, every evaluate entry point returns
    /// `Verdict::Deny` without performing capability validation or guard
    /// evaluation. Flipped by `emergency_stop` / `emergency_resume`.
    ///
    /// Reads use `Ordering::SeqCst` even on the hot path. The emergency check
    /// is a single atomic load per evaluate call (negligible cost relative to
    /// the guard pipeline) and `SeqCst` is the safest default for a rarely
    /// taken control path.
    pub(super) emergency_stopped: AtomicBool,
    /// Unix timestamp (seconds) at which the kill switch was last engaged.
    /// `0` means "never engaged" or "currently resumed". Written with
    /// `SeqCst` before `emergency_stopped` is set to `true`, cleared to `0`
    /// after `emergency_stopped` is set to `false`.
    pub(super) emergency_stopped_since: AtomicU64,
    /// Operator-supplied reason for the most recent emergency stop. Set on
    /// `emergency_stop`, cleared on `emergency_resume`. Stored behind
    /// ArcSwap so health probes can read the current reason without blocking.
    pub(super) emergency_stop_reason: ArcSwap<Option<String>>,
    /// Memory-provenance chain. When installed, every
    /// governed `MemoryWrite` action appends an entry after the allow
    /// receipt is signed, and every `MemoryRead` attaches the latest
    /// entry (or an `Unverified` marker) to its receipt as
    /// `memory_provenance` evidence metadata. `None` keeps the kernel
    /// backward-compatible: memory-shaped tool calls behave exactly as
    /// they do without a provenance chain installed.
    pub(super) memory_provenance: Option<Arc<dyn crate::memory_provenance::MemoryProvenanceStore>>,
    /// Cross-kernel federation peer set. When a request
    /// carries a `federated_origin_kernel_id` and that peer is pinned
    /// here (fresh), the kernel invokes `federation_cosigner` after
    /// locally signing the receipt to obtain the origin kernel's
    /// co-signature. Absent in non-federated deployments.
    pub(super) federation_peers:
        ArcSwap<HashMap<String, chio_federation::trust_establishment::FederationPeer>>,
    /// `ArcSwap` so trust-root rotations can land without holding a
    /// kernel mutex. Hex-keyed because `chio_core::PublicKey` does not
    /// implement `Hash`.
    pub(super) capability_trust_roots:
        ArcSwap<HashMap<String, chio_core::capability::attenuation::ScopeHash>>,
    /// Serializes read-modify-write updates to `capability_trust_roots`.
    /// Snapshot reads remain lock-free through ArcSwap.
    pub(super) capability_trust_roots_write_lock: Mutex<()>,
    /// Bilateral co-signer. Separate from the peer set so
    /// runtime can install it independently - for instance, a deployment
    /// can declare peers while still using a mock cosigner in tests.
    pub(super) federation_cosigner:
        Option<Arc<dyn chio_federation::bilateral::BilateralCoSigningProtocol>>,
    /// Locally-signed dual receipts, indexed by ChioReceipt.id.
    /// Populated only when the post-sign hook fires successfully. Kept
    /// in-memory; persistent storage plugs in via the federation-state
    /// APIs already in chio-federation.
    pub(super) federation_dual_receipts:
        DashMap<String, chio_federation::bilateral::DualSignedReceipt>,
    /// DSSE signature-slice envelopes, indexed by ChioReceipt.id.
    /// These are emitted through the federation cosigner protocol rather than
    /// by loading Org A private key material in the tool-host kernel.
    pub(super) federation_dsse_envelopes:
        DashMap<String, chio_federation::bilateral_dsse::DsseEnvelope>,
    /// Request-keyed tenant scope for receipts. Async evaluate futures
    /// can resume on a different worker after dispatch, so the scope is
    /// stored in this map rather than a thread-local.
    pub(super) receipt_tenant_ids: Arc<DashMap<String, String>>,
    /// Request-keyed copy of the receipt-version admission snapshot.
    /// Async evaluate futures may resume on a different Tokio worker
    /// after dispatch. This map keeps the admitted version and peer state
    /// available until the evaluation future finishes.
    pub(super) receipt_federation_admissions: Arc<DashMap<String, ReceiptFederationAdmission>>,
    /// Operator-declared kernel identifier used as the
    /// `org_b_kernel_id` in bilateral co-signing. Defaults to the hex
    /// encoding of the kernel's signing public key, but operators can
    /// override it to a stable DNS name via `with_federation_peers`.
    pub(super) federation_local_kernel_id: ArcSwap<Option<String>>,
    /// Mpsc-backed signing task handle. Owns a clone of `config.keypair` and
    /// pulls signing requests from a bounded channel; producers `.await` on
    /// backpressure rather than on a mutex. Spawned at [`ChioKernel::new`] and
    /// joined by [`ChioKernel::shutdown`]. Wrapped in `Arc` so shared kernel
    /// handles can pass the signing handle to in-flight evaluators without
    /// cloning the whole kernel.
    pub(super) signing_task: std::sync::Arc<signing_task::SigningTaskHandle>,
    /// Settlement observer slot. When `Some`, the kernel invokes the
    /// hook against every finalized receipt that carries a non-zero
    /// manifest price. Settlement runs strictly post-signing and never
    /// blocks dispatch; failures are surfaced through the retry/dead-
    /// letter machinery, not through this option.
    pub(super) settlement_observer: Option<std::sync::Arc<dyn chio_settle::SettlementHook>>,
    /// Recursive-delegation oracle handle. When `Some`, the verifier consults this
    /// arc-swap-backed snapshot on every delegated dispatch and denies
    /// the capability if any link in the chain (or the leaf) is in the
    /// revoked set. `None` falls back to the legacy per-row
    /// `RevocationStore` lookup. Field always present so the struct
    /// shape stays feature-flag agnostic.
    pub(super) revocation_view: Option<std::sync::Arc<chio_kernel_core::RevocationView>>,
    pub(super) budget_registry: Mutex<chio_kernel_core::InMemoryBudgetRegistry>,
}

impl ChioKernel {
    /// Construct the hybrid signing backend the kernel would use under
    /// `hybrid`'s configured floor and PQ key material after the kernel
    /// self-quote gate has run.
    ///
    /// Threads the kernel's classical Ed25519 keypair into a
    /// [`chio_core::crypto::Ed25519Backend`] under
    /// [`KernelCryptoFloor::AllowClassical`], or composes it with an
    /// [`chio_core::crypto::MlDsa65Backend`] derived from `hybrid.pq_signing_seed`
    /// into a [`chio_core::crypto::HybridBackend`] under
    /// [`KernelCryptoFloor::AllowHybrid`] or [`KernelCryptoFloor::PqRequired`],
    /// but only after [`crate::boot::load_kernel_signing_backend_after_self_quote`]
    /// accepts `self_quote_bytes`.
    ///
    /// Receipt body construction continues to flow through the existing
    /// inline path (`build_and_sign_receipt`); callers that opt in to
    /// hybrid signing pass the returned backend through
    /// [`crate::sign_receipt_body_with_backend`] (along with the canonical
    /// content preimage the body's `content_hash` was derived from) before
    /// persistence, so the hybrid path recomputes `content_hash` inside the
    /// trust boundary and is WYSIWYS fail-closed just like the inline
    /// classical path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::boot::KernelBootError::SelfQuoteRejected`] when the
    /// self-quote verifier rejects a non-classical floor, or
    /// [`crate::boot::KernelBootError::SigningBackend`] when the configured
    /// floor needs a PQ key but `hybrid.pq_signing_seed` is `None`. Mirrors
    /// the policy-level check in `chio_policy::CryptoFloor::validate_with_pq_key`
    /// so the boot path catches the misconfiguration even when the policy crate
    /// is bypassed.
    pub fn with_hybrid_signing_backend(
        &mut self,
        hybrid: &HybridSigningConfig,
        self_quote_bytes: &[u8],
        verifier: &dyn crate::boot::KernelSelfQuoteVerifier,
    ) -> Result<Box<dyn chio_core::crypto::SigningBackend>, crate::boot::KernelBootError> {
        let backend = crate::boot::load_kernel_signing_backend_after_self_quote(
            hybrid.crypto_floor,
            self.config.keypair.clone(),
            hybrid.pq_signing_seed.as_ref(),
            self_quote_bytes,
            verifier,
        )?;
        self.capability_crypto_floor = hybrid.crypto_floor;
        Ok(backend)
    }
}
