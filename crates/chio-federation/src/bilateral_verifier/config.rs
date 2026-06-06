use super::*;

// ---------------------------------------------------------------------------
// Verifier configuration + output
// ---------------------------------------------------------------------------

/// Action-class declaration looked up by `tool_name` in the verifier's
/// local ladder manifest. Spec §7 step 15 requires
/// `governance_receipt_ref` only when the class is `receipt-backed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClassKind {
    /// Self-evident, low-stakes class. No governance receipt required.
    Routine,
    /// Receipt-backed class - requires `governance_receipt_ref` in the
    /// predicate body (§7 step 15).
    ReceiptBacked,
}

/// Fail-closed action-class invariant: policy controlling step 15's
/// reaction to an unknown `tool_name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownActionClassPolicy {
    /// Default. An unknown tool name is rejected with
    /// [`VerifierError::UnknownActionClass`]. Prevents a misspelled
    /// or missing registration from silently downgrading a
    /// receipt-backed class to `Routine` (fail-open).
    #[default]
    Reject,
}

/// Verifier configuration: the trait objects + pinned epoch +
/// per-tool action class. Constructed by the kernel at the boundary;
/// passed by reference to [`verify_bilateral_cosign_invocation`].
pub struct VerifierConfig<'a> {
    pub peer_pin_set: &'a PeerPinSet,
    pub receipt_store: &'a dyn ReceiptStore,
    pub lease_registry: &'a dyn CapabilityLeaseRegistry,
    pub governance_receipt_store: &'a dyn GovernanceReceiptStore,
    pub revocation_oracle: &'a dyn RevocationOracle,
    pub pinned_epoch: PinnedEpoch,
    /// Per-tool action-class table. The verifier (step 15) consults
    /// this with the predicate's `tool_name` to decide whether
    /// `governance_receipt_ref` is required.
    pub action_classes: BTreeMap<String, ActionClassKind>,
    /// Fail-closed action-class invariant: controls how step 15 reacts
    /// to a `tool_name` that is not present in `action_classes`.
    ///
    /// The only supported value is [`UnknownActionClassPolicy::Reject`]
    /// (default): the verifier returns [`VerifierError::UnknownActionClass`]
    /// so a misspelled or missing registration cannot silently downgrade
    /// a receipt-backed class to `Routine`.
    pub unknown_action_class_policy: UnknownActionClassPolicy,
}

/// Successful output of [`verify_bilateral_cosign_invocation`]
/// (mirrors §7 step 17).
#[derive(Debug, Clone)]
pub struct VerifiedBilateralCoSignInvocation {
    /// The parsed Statement (subject + predicate).
    pub statement: DsseStatement,
    /// The resolved receipt the subject digest pointed at.
    pub resolved_receipt: ChioReceipt,
    /// The resolved capability lease (step 14 always runs).
    pub resolved_lease: ResolvedLease,
    /// The resolved governance receipt, when the class is
    /// `ReceiptBacked` (step 15).
    pub resolved_governance_receipt: Option<ResolvedGovernanceReceipt>,
    /// The verdict both kernels agreed on (step 13).
    pub joint_verdict: String,
}

/// Strict Chio verifier wrapper over the local bilateral DSSE verifier.
///
/// The base verifier authenticates the DSSE envelope, receipt subject, lease,
/// governance receipt, and policy agreement. Strict Chio mode adds the
/// workflow-ladder requirement: both pinned peers must carry fresh signed
/// ladder manifest references at the pinned epoch.
pub struct ChioBilateralVerifierConfig<'a, 'b> {
    pub base: &'a VerifierConfig<'b>,
}

/// Inputs for strict buyer-review verification of a treaty-bound Chio
/// bilateral DSSE envelope.
pub struct TreatyBoundBilateralDsseReview<'a> {
    pub expected_treaty_binding: &'a TreatyBindingRef,
    pub expected_subject_name: &'a str,
    pub expected_subject_sha256: &'a str,
    pub expected_capability_lease_ref: &'a CapabilityLeaseRef,
    pub expected_governance_receipt_ref: &'a GovernanceReceiptRef,
    pub expected_consistency_anchor: &'a str,
    pub signer_public_keys: &'a BTreeMap<String, PublicKey>,
}
