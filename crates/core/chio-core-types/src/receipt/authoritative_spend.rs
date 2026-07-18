//! Frozen authoritative-spend contract (`chio.mediated_spend.v1`).
//!
//! This module defines the stable shape that the comptroller surface-report
//! and settlement-receipt consumers pin against. Any advisory or label-only
//! receipt fails `is_authoritative_spend_receipt`, making advisory-only
//! consumption a machine-visible conformance failure.

use alloc::string::{String, ToString};

use crate::crypto::PublicKey;
use crate::receipt::body::ChioReceipt;
use crate::receipt::kinds::{BoundaryClass, ReceiptKind, TrustLevel};

/// Receipt-profile identifier for a fully authoritative mediated-spend receipt.
pub const MEDIATED_SPEND_PROFILE: &str = "chio.mediated_spend.v1";

/// Projected budget-hold lineage carried by an authoritative spend receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorityReceiptRef {
    pub hold_id: String,
    pub authorize_event_id: Option<String>,
    pub reconcile_event_id: Option<String>,
    pub capability_id: String,
    pub grant_index: u32,
    pub exposed_units: u64,
    pub realized_units: u64,
    pub execution_nonce_id: Option<String>,
    pub guarantee_level: String,
}

impl BudgetAuthorityReceiptRef {
    /// Project the frozen linkage from a receipt's typed budget-authority
    /// metadata. Returns `None` when the receipt carries no budget-authority
    /// block (a label-only receipt).
    #[must_use]
    pub fn from_receipt(receipt: &ChioReceipt) -> Option<Self> {
        let authority = receipt.financial_budget_authority_metadata()?;
        let grant_index = receipt
            .financial_metadata()
            .map_or(0, |financial| financial.grant_index);
        // `reconcile_event_id` is `Some` only when the terminal mutation was a
        // reconcile (not a reverse/release), so `is_none()` means "not
        // reconciled".
        let (reconcile_event_id, realized_units) = match authority.terminal.as_ref() {
            Some(terminal) if terminal.disposition == "reconciled" => {
                (terminal.event_id.clone(), terminal.realized_spend_units)
            }
            _ => (None, 0),
        };
        let execution_nonce_id = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("budget_authority"))
            .and_then(|block| block.get("execution_nonce_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Some(Self {
            hold_id: authority.hold_id.clone(),
            authorize_event_id: authority.authorize.event_id.clone(),
            reconcile_event_id,
            capability_id: receipt.capability_id.clone(),
            grant_index,
            exposed_units: authority.authorize.exposure_units,
            realized_units,
            execution_nonce_id,
            guarantee_level: authority.guarantee_level.clone(),
        })
    }
}

/// Read-only view of a kernel-signed execution nonce, implemented by
/// `chio_kernel::execution_nonce::SignedExecutionNonce`. Keeps this contract in
/// the lowest crate without depending on the kernel.
pub trait PresentedNonceView {
    fn nonce_id(&self) -> &str;
    fn bound_capability_id(&self) -> &str;
    fn bound_tool_server(&self) -> &str;
    fn bound_tool_name(&self) -> &str;
    fn bound_parameter_hash(&self) -> &str;
    /// The reserved budget hold this nonce cryptographically names, or `None`
    /// when the nonce was minted on a non-reserving allow path. The
    /// reconcile-by-nonce path binds the settled hold's id into the signed nonce
    /// body, so an authoritative reconciled receipt built from such a nonce must
    /// commit that exact hold. Non-reserving allow paths (single-shot mediated
    /// spend, strict-retry completion) return `None` and bind the nonce to the
    /// receipt through the nonce-id link alone.
    fn bound_reserved_hold_id(&self) -> Option<&str>;
    fn verify_signed_by(&self, key: &PublicKey) -> bool;
}

/// Distinct rejection reasons; each of the (a)-(f) conjunction fragments maps to
/// at least one variant so a conformance matrix can flip them independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAuthoritativeReason {
    ReceiptSignatureInvalid,
    SignerNotAdmitted,
    NotMediatedDecision,
    NotPreventBoundary,
    ObservationOutcomePresent,
    NotMediatedTrustLevel,
    NotAllowDecision,
    MissingBudgetAuthority,
    HoldNotReconciled,
    ExposureNotCommitted,
    NonceLinkMissing,
    NonceLinkMismatch,
    /// The presented nonce cryptographically names a reserved budget hold that
    /// differs from the receipt's committed `budget_authority.hold_id`. The
    /// nonce id links the two artifacts, but the hold the nonce reserved is not
    /// the hold this receipt settled, so the receipt is not authoritative for
    /// the presented nonce. Fail-closed on this cross-binding inconsistency.
    ReservedHoldMismatch,
    NonceBindingMismatch {
        field: &'static str,
    },
    NonceSignatureInvalid,
    /// The receipt's budget-authority block does not pin the frozen
    /// `MEDIATED_SPEND_PROFILE`, so its contract shape is unversioned or a
    /// different version than the consumer requires.
    MissingOrWrongMediatedSpendProfile,
    /// The receipt's guarantee level is weaker than the operator-configured
    /// floor (R4 truthfulness). Unrelated to `TrustLevel::Mediated`.
    GuaranteeLevelBelowFloor {
        minimum: String,
        actual: String,
    },
    /// The operator-configured guarantee floor is not a recognized level, so it
    /// cannot be ranked. Fail-closed rather than admitting every receipt.
    UnknownGuaranteeFloor {
        minimum: String,
    },
    /// The receipt's own guarantee level is not a recognized level, so its
    /// truthfulness claim cannot be ranked. An unrecognized level ranks as the
    /// weakest, which would silently clear the weakest valid floor; fail-closed
    /// instead so a typoed or forged level never passes as authoritative.
    UnknownGuaranteeLevel {
        actual: String,
    },
}

/// Project the raw `budget_authority.mediated_spend.profile` string from a
/// receipt's metadata. `None` when any level of that path is absent or the
/// leaf is not a string.
fn mediated_spend_profile(receipt: &ChioReceipt) -> Option<&str> {
    receipt
        .metadata
        .as_ref()?
        .get("budget_authority")?
        .get("mediated_spend")?
        .get("profile")?
        .as_str()
}

/// Structurally checkable conjunction over the kernel signature. Fail-closed:
/// any missing or invalid element is an `Err`.
pub fn is_authoritative_spend_receipt(
    receipt: &ChioReceipt,
    admitted_kernel_keys: &[PublicKey],
    presented_nonce: &dyn PresentedNonceView,
) -> Result<(), NotAuthoritativeReason> {
    // The receipt body must be signed by the embedded kernel key. The execution
    // nonce signature covers only the nonce, so without this a holder of a
    // signed nonce could forge receipt fields (invented reconciled-budget
    // metadata) under an admitted key. Fail-closed on a verification error or a
    // false result.
    if !matches!(receipt.verify_signature(), Ok(true)) {
        return Err(NotAuthoritativeReason::ReceiptSignatureInvalid);
    }
    // (e) signer must be an admitted kernel key.
    if !admitted_kernel_keys.contains(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::SignerNotAdmitted);
    }
    // (a) mediated-decision semantics (mirrors sidecar.rs:796-799 verify side).
    if receipt.receipt_kind != ReceiptKind::MediatedDecision {
        return Err(NotAuthoritativeReason::NotMediatedDecision);
    }
    if receipt.boundary_class != BoundaryClass::Prevent {
        return Err(NotAuthoritativeReason::NotPreventBoundary);
    }
    if receipt.observation_outcome.is_some() {
        return Err(NotAuthoritativeReason::ObservationOutcomePresent);
    }
    if receipt.trust_level != TrustLevel::Mediated {
        return Err(NotAuthoritativeReason::NotMediatedTrustLevel);
    }
    if !receipt.is_allowed() {
        return Err(NotAuthoritativeReason::NotAllowDecision);
    }
    // (b) an atomically committed, reconciled hold that actually moved exposure.
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    if budget.hold_id.is_empty() {
        return Err(NotAuthoritativeReason::MissingBudgetAuthority);
    }
    // The budget-authority block must pin the frozen contract profile exactly.
    // A missing or differently versioned profile means the consumer would be
    // accepting an unversioned or foreign contract shape.
    if mediated_spend_profile(receipt) != Some(MEDIATED_SPEND_PROFILE) {
        return Err(NotAuthoritativeReason::MissingOrWrongMediatedSpendProfile);
    }
    if budget.reconcile_event_id.is_none() {
        return Err(NotAuthoritativeReason::HoldNotReconciled);
    }
    if budget.exposed_units == 0 {
        return Err(NotAuthoritativeReason::ExposureNotCommitted);
    }
    // (d) hold <-> nonce cross-binding: the receipt must name the nonce.
    let linked_nonce_id = budget
        .execution_nonce_id
        .as_deref()
        .ok_or(NotAuthoritativeReason::NonceLinkMissing)?;
    if linked_nonce_id != presented_nonce.nonce_id() {
        return Err(NotAuthoritativeReason::NonceLinkMismatch);
    }
    // (d cont.) reserved-hold cross-binding. When the presented nonce
    // cryptographically names a reserved hold (the reconcile-by-nonce path binds
    // the settled hold's id into the signed nonce body), it MUST equal the
    // receipt's committed hold. A nonce that reserved a different hold links this
    // receipt by id yet is authoritative for a hold this receipt did not settle,
    // so accepting it would break the advertised hold <-> nonce binding. A nonce
    // that names no reserved hold (single-shot mediated spend and strict-retry
    // completion mint a nonce with no reserved hold) is bound to the receipt
    // through the nonce-id link alone and is permitted here.
    if let Some(reserved_hold_id) = presented_nonce.bound_reserved_hold_id() {
        if reserved_hold_id != budget.hold_id {
            return Err(NotAuthoritativeReason::ReservedHoldMismatch);
        }
    }
    // (c) the nonce binding must match the exact call the receipt authorized.
    if presented_nonce.bound_capability_id() != receipt.capability_id {
        return Err(NotAuthoritativeReason::NonceBindingMismatch {
            field: "capability_id",
        });
    }
    if presented_nonce.bound_tool_server() != receipt.tool_server {
        return Err(NotAuthoritativeReason::NonceBindingMismatch {
            field: "tool_server",
        });
    }
    if presented_nonce.bound_tool_name() != receipt.tool_name {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "tool_name" });
    }
    if presented_nonce.bound_parameter_hash() != receipt.action.parameter_hash {
        return Err(NotAuthoritativeReason::NonceBindingMismatch {
            field: "parameter_hash",
        });
    }
    // (e) the nonce must be signed by the same admitted kernel key.
    if !presented_nonce.verify_signed_by(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::NonceSignatureInvalid);
    }
    Ok(())
}

/// R4 guarantee-level truthfulness: refuse a receipt claiming a guarantee level
/// stronger than the operator's configured floor. Levels are ordered
/// advisory_posthoc < single_node_atomic < partition_escrowed < ha_linearizable.
#[must_use]
pub fn guarantee_level_rank(level: &str) -> u8 {
    match level {
        "ha_linearizable" => 3,
        "partition_escrowed" => 2,
        "single_node_atomic" => 1,
        _ => 0,
    }
}

/// Whether `level` names a defined guarantee level. `advisory_posthoc` is the
/// weakest defined level and ranks 0, so a bare rank cannot distinguish it from
/// an unrecognized string; callers pinning an operator floor must use this to
/// fail closed on a misconfigured level.
#[must_use]
pub fn is_recognized_guarantee_level(level: &str) -> bool {
    matches!(
        level,
        "advisory_posthoc" | "single_node_atomic" | "partition_escrowed" | "ha_linearizable"
    )
}

/// Returns `Ok(())` only when the receipt's guarantee level is at least the
/// operator floor. Fail-closed on a missing budget-authority block or on an
/// unrecognized floor (a misconfigured floor must not silently admit every
/// receipt by ranking as the weakest level).
pub fn receipt_meets_guarantee_floor(
    receipt: &ChioReceipt,
    minimum_level: &str,
) -> Result<(), NotAuthoritativeReason> {
    if !is_recognized_guarantee_level(minimum_level) {
        return Err(NotAuthoritativeReason::UnknownGuaranteeFloor {
            minimum: minimum_level.to_string(),
        });
    }
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    // The receipt's own guarantee level must be a recognized level before it can
    // be ranked. An unrecognized level ranks 0 (weakest), so against the weakest
    // valid floor (`advisory_posthoc`, also rank 0) the rank comparison below is
    // `0 < 0 == false` and a typoed or forged claim would pass. Reject it here so
    // the verifier fails closed on a malformed truthfulness claim.
    if !is_recognized_guarantee_level(&budget.guarantee_level) {
        return Err(NotAuthoritativeReason::UnknownGuaranteeLevel {
            actual: budget.guarantee_level.clone(),
        });
    }
    if guarantee_level_rank(&budget.guarantee_level) < guarantee_level_rank(minimum_level) {
        return Err(NotAuthoritativeReason::GuaranteeLevelBelowFloor {
            minimum: minimum_level.to_string(),
            actual: budget.guarantee_level.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, PublicKey};
    use crate::receipt::body::{ChioReceipt, ChioReceiptBody};
    use crate::receipt::decision::{Decision, ToolCallAction};
    use crate::receipt::kinds::{
        BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };

    /// Minimal test double for a kernel-signed execution nonce.
    struct FakeNonce {
        nonce_id: String,
        capability_id: String,
        tool_server: String,
        tool_name: String,
        parameter_hash: String,
        reserved_hold_id: Option<String>,
        signer: Option<PublicKey>,
    }

    impl PresentedNonceView for FakeNonce {
        fn nonce_id(&self) -> &str {
            &self.nonce_id
        }
        fn bound_capability_id(&self) -> &str {
            &self.capability_id
        }
        fn bound_tool_server(&self) -> &str {
            &self.tool_server
        }
        fn bound_tool_name(&self) -> &str {
            &self.tool_name
        }
        fn bound_parameter_hash(&self) -> &str {
            &self.parameter_hash
        }
        fn bound_reserved_hold_id(&self) -> Option<&str> {
            self.reserved_hold_id.as_deref()
        }
        fn verify_signed_by(&self, key: &PublicKey) -> bool {
            self.signer.as_ref() == Some(key)
        }
    }

    fn authoritative_receipt(kp: &Keypair) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({"x": 1})).unwrap();
        let content_hash = crate::sha256_hex(b"content");
        let metadata = serde_json::json!({
            "financial": { "grant_index": 0, "cost_charged": 50, "currency": "USD",
                "budget_remaining": 50, "budget_total": 100, "delegation_depth": 0,
                "root_budget_holder": "root", "settlement_status": "settled" },
            "budget_authority": {
                "guarantee_level": "single_node_atomic",
                "authority_profile": "authoritative_hold_event",
                "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
                "hold_id": "budget-hold:req-1:cap-1:0",
                "execution_nonce_id": "nonce-1",
                "mediated_spend": { "profile": MEDIATED_SPEND_PROFILE },
                "authorize": { "event_id": "budget-hold:req-1:cap-1:0:authorize",
                    "exposure_units": 100, "committed_cost_units_after": 100 },
                "terminal": { "disposition": "reconciled",
                    "event_id": "budget-hold:req-1:cap-1:0:reconcile",
                    "exposure_units": 100, "realized_spend_units": 50,
                    "committed_cost_units_after": 50 }
            }
        });
        let body = ChioReceiptBody {
            id: "rcpt-1".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash,
            policy_hash: crate::sha256_hex(b"policy"),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn good_nonce(kp: &Keypair, receipt: &ChioReceipt) -> FakeNonce {
        // A reconcile-by-nonce nonce names the exact hold the receipt commits,
        // so the good baseline carries the receipt's committed hold id.
        let reserved_hold_id =
            BudgetAuthorityReceiptRef::from_receipt(receipt).map(|budget| budget.hold_id);
        FakeNonce {
            nonce_id: "nonce-1".to_string(),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
            reserved_hold_id,
            signer: Some(kp.public_key()),
        }
    }

    #[test]
    fn authoritative_receipt_with_bound_nonce_passes() {
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn nonce_reserving_a_different_hold_is_rejected() {
        // The presented nonce is signed, its id links the receipt, and its call
        // binding matches, but it cryptographically reserved a DIFFERENT hold
        // than the one this receipt committed. The receipt is authoritative for
        // the hold the nonce reserved, not for this one, so it must be rejected
        // even though every other conjunct holds.
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let mut nonce = good_nonce(&kp, &receipt);
        nonce.reserved_hold_id = Some("budget-hold:attacker:cap-1:0".to_string());
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::ReservedHoldMismatch)
        );
    }

    #[test]
    fn nonce_reserving_the_committed_hold_passes() {
        // A reconcile-by-nonce nonce names exactly the committed hold id.
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            nonce.reserved_hold_id.as_deref(),
            Some("budget-hold:req-1:cap-1:0")
        );
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn nonce_without_reserved_hold_is_permitted() {
        // Non-reserving allow paths (single-shot mediated spend, strict-retry
        // completion) mint a nonce that names no reserved hold and bind it to
        // the receipt through the nonce-id link alone. Such a nonce stays
        // authoritative: the reserved-hold cross-binding only constrains a nonce
        // that DOES claim a reserved hold.
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let mut nonce = good_nonce(&kp, &receipt);
        nonce.reserved_hold_id = None;
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn mediated_spend_profile_absent_is_rejected() {
        // A reconciled receipt carrying budget_authority + nonce link but no
        // pinned mediated_spend profile must not be accepted as authoritative.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        if let Some(obj) = receipt
            .metadata
            .as_mut()
            .and_then(|m| m.get_mut("budget_authority"))
            .and_then(|b| b.as_object_mut())
        {
            obj.remove("mediated_spend");
        }
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::MissingOrWrongMediatedSpendProfile)
        );
    }

    #[test]
    fn mediated_spend_profile_mismatch_is_rejected() {
        // A different (or unversioned) contract shape must not satisfy a
        // consumer pinned to the frozen profile.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        if let Some(obj) = receipt
            .metadata
            .as_mut()
            .and_then(|m| m.get_mut("budget_authority"))
            .and_then(|b| b.get_mut("mediated_spend"))
            .and_then(|b| b.as_object_mut())
        {
            obj.insert(
                "profile".to_string(),
                serde_json::json!("chio.mediated_spend.v9"),
            );
        }
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::MissingOrWrongMediatedSpendProfile)
        );
    }

    #[test]
    fn r1_forged_mediated_label_without_budget_authority_is_rejected() {
        // A trusted signer stamps advisory content as Mediated with zero budget movement.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        // Strip the budget_authority metadata but keep the Mediated label. The
        // trusted signer re-signs the stripped body, so the rejection is the
        // structural one and not the signature precondition.
        receipt.metadata = Some(serde_json::json!({}));
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::MissingBudgetAuthority)
        );
    }

    #[test]
    fn tampered_receipt_body_with_admitted_key_is_rejected() {
        // A client holding a legitimately signed execution nonce cannot forge a
        // spend receipt: inflating a signed budget field without re-signing must
        // be rejected even though the embedded kernel key is admitted and every
        // structural field still checks out.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        if let Some(metadata) = receipt.metadata.as_mut() {
            metadata["budget_authority"]["terminal"]["realized_spend_units"] =
                serde_json::json!(9_999);
        }
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::ReceiptSignatureInvalid)
        );

        // The untampered, correctly-signed receipt still passes.
        let receipt = authoritative_receipt(&kp);
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn guarantee_level_rank_ordering() {
        // Unknown strings rank 0 (fail-closed: treated as weakest).
        assert_eq!(guarantee_level_rank("advisory_posthoc"), 0);
        assert_eq!(guarantee_level_rank("unknown_level"), 0);
        assert_eq!(guarantee_level_rank("single_node_atomic"), 1);
        assert_eq!(guarantee_level_rank("partition_escrowed"), 2);
        assert_eq!(guarantee_level_rank("ha_linearizable"), 3);
        // Ordering is strictly monotone across all four levels.
        assert!(
            guarantee_level_rank("advisory_posthoc") < guarantee_level_rank("single_node_atomic")
        );
        assert!(
            guarantee_level_rank("single_node_atomic") < guarantee_level_rank("partition_escrowed")
        );
        assert!(
            guarantee_level_rank("partition_escrowed") < guarantee_level_rank("ha_linearizable")
        );
    }

    #[test]
    fn guarantee_floor_passes_when_at_or_above_minimum() {
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        // Base receipt carries "single_node_atomic". Same level must pass.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "single_node_atomic"),
            Ok(())
        );
        // Weaker floor also passes.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "advisory_posthoc"),
            Ok(())
        );
    }

    #[test]
    fn guarantee_floor_fails_when_below_minimum() {
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        // Base receipt carries "single_node_atomic"; a stronger floor rejects it.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "ha_linearizable"),
            Err(NotAuthoritativeReason::GuaranteeLevelBelowFloor {
                minimum: "ha_linearizable".to_string(),
                actual: "single_node_atomic".to_string(),
            })
        );
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "partition_escrowed"),
            Err(NotAuthoritativeReason::GuaranteeLevelBelowFloor {
                minimum: "partition_escrowed".to_string(),
                actual: "single_node_atomic".to_string(),
            })
        );
    }

    #[test]
    fn guarantee_floor_with_unrecognized_minimum_is_rejected() {
        // A misspelled or unversioned operator floor must fail closed rather
        // than silently ranking as the weakest level and admitting everything.
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "ha_lienarizable"),
            Err(NotAuthoritativeReason::UnknownGuaranteeFloor {
                minimum: "ha_lienarizable".to_string(),
            })
        );
        // An unrecognized floor fails closed even when the receipt would clear a
        // valid floor at the same intended strength.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "linearizable"),
            Err(NotAuthoritativeReason::UnknownGuaranteeFloor {
                minimum: "linearizable".to_string(),
            })
        );
    }

    #[test]
    fn receipt_with_unrecognized_guarantee_level_is_rejected() {
        // A receipt whose own guarantee level is an unrecognized string must
        // fail closed, even against the weakest valid floor. Without an explicit
        // recognized-level check the unrecognized level ranks 0 and the
        // `advisory_posthoc` floor also ranks 0, so `0 < 0 == false` would let
        // the malformed truthfulness claim pass as authoritative.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        if let Some(obj) = receipt
            .metadata
            .as_mut()
            .and_then(|m| m.get_mut("budget_authority"))
            .and_then(|b| b.as_object_mut())
        {
            obj.insert(
                "guarantee_level".to_string(),
                serde_json::json!("single_node_atmoic"),
            );
        }
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "advisory_posthoc"),
            Err(NotAuthoritativeReason::UnknownGuaranteeLevel {
                actual: "single_node_atmoic".to_string(),
            })
        );
        // A recognized level at or above the floor still passes.
        let recognized = authoritative_receipt(&kp);
        assert_eq!(
            receipt_meets_guarantee_floor(&recognized, "advisory_posthoc"),
            Ok(())
        );
        assert_eq!(
            receipt_meets_guarantee_floor(&recognized, "single_node_atomic"),
            Ok(())
        );
    }

    #[test]
    fn r4_receipt_claiming_ha_linearizable_fails_single_node_operator_floor() {
        // HaLinearizable is a labeled claim; a single-node store must not be
        // accepted where the operator requires linearizable, and a receipt must
        // not claim a level above the backing store.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        // Operator floor is ha_linearizable; the receipt is single_node_atomic.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "ha_linearizable"),
            Err(NotAuthoritativeReason::GuaranteeLevelBelowFloor {
                minimum: "ha_linearizable".to_string(),
                actual: "single_node_atomic".to_string(),
            })
        );
        // A single_node floor accepts the single_node receipt.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "single_node_atomic"),
            Ok(())
        );
        // A forged higher claim still ranks correctly once re-signed.
        if let Some(obj) = receipt
            .metadata
            .as_mut()
            .and_then(|m| m.get_mut("budget_authority"))
            .and_then(|b| b.as_object_mut())
        {
            obj.insert(
                "guarantee_level".to_string(),
                serde_json::json!("ha_linearizable"),
            );
        }
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "ha_linearizable"),
            Ok(())
        );
    }

    /// Table-driven negative tests for security-critical rejection reasons.
    /// Each case mutates one field at a time from a valid baseline receipt.
    /// The full a-f conformance matrix is a later task; this covers the
    /// rejection paths most likely to mask a bypass.
    #[test]
    fn security_critical_rejections() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let base = authoritative_receipt(&kp);

        struct Case {
            name: &'static str,
            patch_receipt: Box<dyn Fn(&mut ChioReceipt)>,
            patch_nonce: Box<dyn Fn(&mut FakeNonce)>,
            admitted: Vec<PublicKey>,
            expected: NotAuthoritativeReason,
        }

        let cases: Vec<Case> = vec![
            Case {
                name: "signer_not_admitted",
                patch_receipt: Box::new(|_| {}),
                patch_nonce: Box::new(|_| {}),
                admitted: vec![other_kp.public_key()],
                expected: NotAuthoritativeReason::SignerNotAdmitted,
            },
            Case {
                name: "hold_not_reconciled",
                patch_receipt: Box::new(|r| {
                    if let Some(m) = r.metadata.as_mut() {
                        m["budget_authority"]["terminal"]["disposition"] =
                            serde_json::json!("released");
                    }
                }),
                patch_nonce: Box::new(|_| {}),
                admitted: vec![kp.public_key()],
                expected: NotAuthoritativeReason::HoldNotReconciled,
            },
            Case {
                name: "exposure_not_committed",
                patch_receipt: Box::new(|r| {
                    if let Some(m) = r.metadata.as_mut() {
                        m["budget_authority"]["authorize"]["exposure_units"] =
                            serde_json::json!(0_u64);
                    }
                }),
                patch_nonce: Box::new(|_| {}),
                admitted: vec![kp.public_key()],
                expected: NotAuthoritativeReason::ExposureNotCommitted,
            },
            Case {
                name: "nonce_link_mismatch",
                patch_receipt: Box::new(|_| {}),
                patch_nonce: Box::new(|n| {
                    n.nonce_id = "wrong-nonce-id".to_string();
                }),
                admitted: vec![kp.public_key()],
                expected: NotAuthoritativeReason::NonceLinkMismatch,
            },
            Case {
                name: "nonce_binding_mismatch_capability",
                patch_receipt: Box::new(|_| {}),
                patch_nonce: Box::new(|n| {
                    n.capability_id = "wrong-cap".to_string();
                }),
                admitted: vec![kp.public_key()],
                expected: NotAuthoritativeReason::NonceBindingMismatch {
                    field: "capability_id",
                },
            },
            Case {
                name: "nonce_signature_invalid",
                patch_receipt: Box::new(|_| {}),
                patch_nonce: Box::new(|n| {
                    n.signer = None;
                }),
                admitted: vec![kp.public_key()],
                expected: NotAuthoritativeReason::NonceSignatureInvalid,
            },
        ];

        for case in &cases {
            let mut receipt = base.clone();
            let mut nonce = good_nonce(&kp, &base);
            (case.patch_receipt)(&mut receipt);
            (case.patch_nonce)(&mut nonce);
            // Re-sign after mutating the body so each structural rejection is
            // exercised with a valid signature rather than masked by the
            // signature precondition.
            let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
            assert_eq!(
                is_authoritative_spend_receipt(&receipt, &case.admitted, &nonce),
                Err(case.expected.clone()),
                "case: {}",
                case.name,
            );
        }
    }
}
