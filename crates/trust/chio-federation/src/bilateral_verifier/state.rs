use super::*;

// ---------------------------------------------------------------------------
// Pinned epoch + peer set (steps 8, 9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedEpoch {
    /// Verifier wall-clock at the moment of verification, in Unix ms.
    pub now_unix_ms: u64,
    pub epoch_height: u64,
}

/// One pinned peer in the verifier's trust store.
#[derive(Debug, Clone)]
pub struct PinnedPeer {
    /// `did:chio` identifier of the kernel.
    pub kernel_id: String,
    /// Pinned passport public key.
    pub public_key: PublicKey,
    /// Signed ladder manifest reference accepted during trust establishment.
    pub ladder_manifest_ref: Option<LadderManifestRef>,
}

impl PinnedPeer {
    /// SHA-256 fingerprint of the pinned passport public key, hex-lowercase.
    /// MUST match `KernelIdentity::passport_key_fingerprint` from the
    /// envelope predicate (spec §7 step 8).
    #[must_use]
    pub fn fingerprint(&self) -> Keyid {
        Keyid::from_public_key(&self.public_key)
    }
}

/// Verifier's pin set: which kernels (by `did:chio`) are trusted at
/// which passport keys.
#[derive(Debug, Clone, Default)]
pub struct PeerPinSet {
    by_kernel_id: HashMap<String, PinnedPeer>,
}

impl PeerPinSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, peer: PinnedPeer) {
        self.by_kernel_id.insert(peer.kernel_id.clone(), peer);
    }

    pub fn lookup(&self, kernel_id: &str) -> Option<&PinnedPeer> {
        self.by_kernel_id.get(kernel_id)
    }
}

// ---------------------------------------------------------------------------
// Step 7: ReceiptStore
// ---------------------------------------------------------------------------

/// Returning `None` is fail-closed (mapped to
/// `VerifierError::SubjectDigestMismatch`).
pub trait ReceiptStore: Send + Sync {
    /// Resolve a receipt by `invocation_id` (spec calls this the
    /// invocation id; chio uses `ChioReceipt::id` interchangeably).
    fn resolve(&self, invocation_id: &str) -> Option<ChioReceipt>;
}

#[derive(Debug, Default)]
pub struct InMemoryReceiptStore {
    receipts: HashMap<String, ChioReceipt>,
}

impl InMemoryReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, receipt: ChioReceipt) {
        self.receipts.insert(receipt.id.clone(), receipt);
    }
}

impl ReceiptStore for InMemoryReceiptStore {
    fn resolve(&self, invocation_id: &str) -> Option<ChioReceipt> {
        self.receipts.get(invocation_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Step 9: RevocationOracle
// ---------------------------------------------------------------------------

/// Step 9 surface: is a passport key revoked at the pinned epoch?
/// `true` means non-revoked (allowed); `false` triggers
/// `peer.revoked_at_epoch`.
pub trait RevocationOracle: Send + Sync {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, epoch_height: u64) -> bool;
}

/// Test-only revocation oracle that lets fixtures explicitly mark a
/// fingerprint revoked. Used by the conformance test for step 9.
#[derive(Debug, Clone, Default)]
pub struct DenyListRevocationOracle {
    revoked: HashSet<String>,
}

impl DenyListRevocationOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, fingerprint: &Keyid) {
        self.revoked.insert(fingerprint.0.clone());
    }
}

impl RevocationOracle for DenyListRevocationOracle {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, _epoch_height: u64) -> bool {
        !self.revoked.contains(&fingerprint.0)
    }
}

// ---------------------------------------------------------------------------
// Step 14: CapabilityLeaseRegistry
// ---------------------------------------------------------------------------

/// Resolved capability lease record returned by the registry. The
/// verifier (step 14) compares this against the predicate's
/// `capability_lease_ref` (issuer match, expires_at > now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLease {
    pub lease_id: String,
    pub issuer: String,
    pub expires_at_unix_ms: u64,
    pub scope_digest_hex: Option<String>,
}

/// Step 14 surface: resolve a capability lease id. Returning `None`
/// fails-closed with `VerifierError::CapabilityLeaseExpiredOrUnknown`.
pub trait CapabilityLeaseRegistry: Send + Sync {
    fn resolve(&self, lease_id: &str) -> Option<ResolvedLease>;
}

#[derive(Debug, Default)]
pub struct InMemoryLeaseRegistry {
    leases: HashMap<String, ResolvedLease>,
}

impl InMemoryLeaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, lease: ResolvedLease) {
        self.leases.insert(lease.lease_id.clone(), lease);
    }
}

impl CapabilityLeaseRegistry for InMemoryLeaseRegistry {
    fn resolve(&self, lease_id: &str) -> Option<ResolvedLease> {
        self.leases.get(lease_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Step 15: GovernanceReceiptStore
// ---------------------------------------------------------------------------

/// Resolved governance receipt record returned by the store. The
/// verifier (step 15) compares this against the predicate's
/// `governance_receipt_ref` (kernel_id match, digest match).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGovernanceReceipt {
    pub receipt_id: String,
    pub kernel_id: String,
    pub canonical_json: String,
}

/// Step 15 surface. Returning `None` fails-closed with
/// `VerifierError::GovernanceReceiptRequiredMissing` when the action
/// class is `receipt-backed`.
pub trait GovernanceReceiptStore: Send + Sync {
    fn resolve(&self, receipt_id: &str) -> Option<ResolvedGovernanceReceipt>;
}

#[derive(Debug, Default)]
pub struct InMemoryGovernanceReceiptStore {
    receipts: HashMap<String, ResolvedGovernanceReceipt>,
}

impl InMemoryGovernanceReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, r: ResolvedGovernanceReceipt) {
        self.receipts.insert(r.receipt_id.clone(), r);
    }
}

impl GovernanceReceiptStore for InMemoryGovernanceReceiptStore {
    fn resolve(&self, receipt_id: &str) -> Option<ResolvedGovernanceReceipt> {
        self.receipts.get(receipt_id).cloned()
    }
}
