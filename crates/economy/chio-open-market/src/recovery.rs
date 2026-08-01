//! Delivery-recovery authorization for a paid-but-lost reveal.
//!
//! A one-shot purchase grant is consumed by its successful reveal, and a
//! signed receipt is evidence rather than invocation authority. A buyer
//! that crashed between the Allow and persisting the payload therefore
//! needs an explicit re-authorization: the seller's recovery service
//! verifies the checkpointed original Allow and the buyer's key binding,
//! then mints a no-charge grant to the original delivery-token subject,
//! bound to the original receipt, the original capability, and the
//! finding. The grant carries the same output-digest commitment, no
//! monetary ceilings, a mandatory proof-of-possession binding, a short
//! expiry, and a bounded retry count.

use base64::Engine as _;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::metadata::{
    DeliveryResult, FindingDelivery, FindingMediaTypeCheck, FindingTransformProfile,
    FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    derive_finding_recovery_id, parse_finding_recovery_context, verify_signed_purchase_record,
    FindingRecoveryContext, SignedFindingPurchaseRecord,
    FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES,
};

use crate::capability::{
    scope::{ChioScope, Constraint, FindingRecoveryMarkerV1, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use crate::crypto::{Keypair, PublicKey};

/// Typed rejection from full recovery-carrier verification.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryVerificationError {
    #[error("recovery carrier is not valid base64 canonical JSON")]
    Carrier,
    #[error("recovery carrier member {0} failed strict parsing")]
    Member(&'static str),
    #[error("original capability signature is invalid")]
    CapabilitySignature,
    #[error("original capability is not the purchase authority named by the marker")]
    CapabilityBinding,
    #[error("original capability does not carry the exact purchase delivery profile")]
    CapabilityProfile,
    #[error("original purchase context was rejected")]
    PurchaseContext,
    #[error("settled purchase record signature or body is invalid")]
    PurchaseRecord,
    #[error("settled purchase record does not bind the verified purchase")]
    PurchaseRecordBinding,
    #[error("original delivery receipt signature or authority is invalid")]
    DeliveryReceiptSignature,
    #[error("original delivery receipt is not the bound finding Allow")]
    DeliveryReceiptBinding,
    #[error("recovery id is not the deterministic identity of the original artifacts")]
    RecoveryIdentity,
    #[error("recovery capability subject is not the original buyer")]
    SubjectMismatch,
    #[error("recovery capability issuer is not the pinned recovery authority")]
    RecoveryIssuer,
}

/// Pinned authorities required for recovery verification.
#[derive(Clone)]
pub struct RecoveryVerificationAuthorities {
    pub purchase: crate::purchase_verification::PurchaseVerificationAuthorities,
    pub purchase_authority: PublicKey,
    pub kernel_receipt_authority: PublicKey,
    pub recovery_authority: PublicKey,
}

/// Pure inputs supplied by the kernel recovery seam.
pub struct RecoveryVerificationInputs<'a> {
    pub marker: &'a FindingRecoveryMarkerV1,
    pub context_b64: &'a str,
    pub recovery_subject: &'a PublicKey,
    pub recovery_issuer: &'a PublicKey,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub arguments: &'a serde_json::Value,
    pub expected_output_digest: &'a str,
}

/// Fully cross-bound recovery facts.
pub struct RecoveryVerificationOutcome {
    context: FindingRecoveryContext,
    recovery_id: String,
    finding_id: String,
    listing_id: String,
    payload_sha256: String,
    status_feed_id: String,
    original_capability_id: String,
    original_delivery_receipt_id: String,
    purchase_key: String,
    original_subject: PublicKey,
    server_id: String,
    tool_name: String,
}

impl RecoveryVerificationOutcome {
    #[must_use]
    pub fn context(&self) -> &FindingRecoveryContext {
        &self.context
    }

    #[must_use]
    pub fn recovery_id(&self) -> &str {
        &self.recovery_id
    }

    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    #[must_use]
    pub fn listing_id(&self) -> &str {
        &self.listing_id
    }

    #[must_use]
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    #[must_use]
    pub fn status_feed_id(&self) -> &str {
        &self.status_feed_id
    }

    #[must_use]
    pub fn original_capability_id(&self) -> &str {
        &self.original_capability_id
    }

    #[must_use]
    pub fn original_delivery_receipt_id(&self) -> &str {
        &self.original_delivery_receipt_id
    }

    #[must_use]
    pub fn purchase_key(&self) -> &str {
        &self.purchase_key
    }

    #[must_use]
    pub fn original_subject(&self) -> &PublicKey {
        &self.original_subject
    }

    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
}

fn strict_member<T: serde::de::DeserializeOwned + serde::Serialize>(
    text: &str,
    name: &'static str,
) -> Result<T, RecoveryVerificationError> {
    let canonical = chio_core_types::canonical_json_bytes_from_str(text)
        .map_err(|_| RecoveryVerificationError::Member(name))?;
    if canonical.as_slice() != text.as_bytes() {
        return Err(RecoveryVerificationError::Member(name));
    }
    let value: T =
        serde_json::from_str(text).map_err(|_| RecoveryVerificationError::Member(name))?;
    let reserialized = chio_core_types::canonical_json_bytes(&value)
        .map_err(|_| RecoveryVerificationError::Member(name))?;
    if reserialized.as_slice() != text.as_bytes() {
        return Err(RecoveryVerificationError::Member(name));
    }
    Ok(value)
}

/// Verify the complete recovery carrier without clocks or mutable state.
pub fn verify_finding_recovery_context(
    inputs: &RecoveryVerificationInputs<'_>,
    authorities: &RecoveryVerificationAuthorities,
) -> Result<RecoveryVerificationOutcome, RecoveryVerificationError> {
    if inputs.recovery_issuer != &authorities.recovery_authority {
        return Err(RecoveryVerificationError::RecoveryIssuer);
    }
    let max_encoded = FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(4);
    if inputs.context_b64.is_empty() || inputs.context_b64.len() > max_encoded {
        return Err(RecoveryVerificationError::Carrier);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(inputs.context_b64.as_bytes())
        .map_err(|_| RecoveryVerificationError::Carrier)?;
    let context =
        parse_finding_recovery_context(&raw).map_err(|_| RecoveryVerificationError::Carrier)?;
    let original_capability: CapabilityToken = strict_member(
        &context.original_capability_json,
        "original_capability_json",
    )?;
    if !matches!(original_capability.verify_signature(), Ok(true)) {
        return Err(RecoveryVerificationError::CapabilitySignature);
    }
    if original_capability.id != inputs.marker.original_capability_id {
        return Err(RecoveryVerificationError::CapabilityBinding);
    }
    let matching_grants: Vec<_> = original_capability
        .scope
        .grants
        .iter()
        .filter(|grant| {
            grant.server_id == inputs.server_id
                && grant.tool_name == inputs.tool_name
                && grant.constraints.iter().any(|constraint| {
                    matches!(constraint, Constraint::RequireFindingPurchase(marker)
                        if marker.finding_id == inputs.marker.finding_id
                            && marker.listing_id == inputs.marker.listing_id)
                })
                && grant.constraints.iter().any(|constraint| {
                    matches!(constraint, Constraint::OutputDigestSha256(digest)
                        if digest == inputs.expected_output_digest)
                })
        })
        .collect();
    if matching_grants.len() != 1 {
        return Err(RecoveryVerificationError::CapabilityProfile);
    }

    let purchase_context_b64 =
        base64::engine::general_purpose::STANDARD.encode(context.purchase_context_json.as_bytes());
    let purchase = crate::purchase_verification::verify_purchase_context_pure(
        &crate::purchase_verification::PurchaseVerificationInputs {
            marker_finding_id: &inputs.marker.finding_id,
            marker_listing_id: &inputs.marker.listing_id,
            expected_output_digest: inputs.expected_output_digest,
            context_b64: &purchase_context_b64,
            capability: &original_capability,
            server_id: inputs.server_id,
            tool_name: inputs.tool_name,
            arguments: inputs.arguments,
        },
        &authorities.purchase,
    )
    .map_err(|_| RecoveryVerificationError::PurchaseContext)?;

    let purchase_record: SignedFindingPurchaseRecord = strict_member(
        &context.purchase_record_envelope_json,
        "purchase_record_envelope_json",
    )?;
    verify_signed_purchase_record(&purchase_record, &authorities.purchase_authority)
        .map_err(|_| RecoveryVerificationError::PurchaseRecord)?;
    let record = &purchase_record.body;
    if record.purchase_key != inputs.marker.purchase_key
        || record.finding_id != purchase.finding.finding_id
        || record.listing_id != inputs.marker.listing_id
        || record.buyer != original_capability.subject
        || record.purchase_intent_id != purchase.purchase_intent_id
        || record.authoritative_payment_operation_id != purchase.authoritative_payment_operation_id
        || record.accepted_bid_envelope_sha256 != purchase.accepted_bid_envelope_sha256
        || record.venue_admission_envelope_sha256 != purchase.venue_admission_envelope_sha256
        || record.realized_spend.units == 0
    {
        return Err(RecoveryVerificationError::PurchaseRecordBinding);
    }

    let receipt: ChioReceipt = strict_member(
        &context.original_delivery_receipt_json,
        "original_delivery_receipt_json",
    )?;
    if receipt.kernel_key != authorities.kernel_receipt_authority
        || !matches!(receipt.verify_signature(), Ok(true))
    {
        return Err(RecoveryVerificationError::DeliveryReceiptSignature);
    }
    let delivery: FindingDelivery = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .cloned()
        .ok_or(RecoveryVerificationError::DeliveryReceiptBinding)
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|_| RecoveryVerificationError::DeliveryReceiptBinding)
        })?;
    delivery
        .validate()
        .map_err(|_| RecoveryVerificationError::DeliveryReceiptBinding)?;
    if !matches!(receipt.decision, Some(Decision::Allow))
        || !matches!(receipt.action.verify_hash(), Ok(true))
        || receipt
            .action
            .parameters
            .get("finding_id")
            .and_then(serde_json::Value::as_str)
            != Some(purchase.finding.finding_id.as_str())
        || receipt.id != inputs.marker.original_delivery_receipt_id
        || receipt.id != record.delivery_receipt_id
        || receipt.capability_id != original_capability.id
        || receipt.tool_server != inputs.server_id
        || receipt.tool_name != inputs.tool_name
        || receipt.content_hash != purchase.finding.payload_sha256
        || delivery.finding_id != purchase.finding.finding_id
        || delivery.listing_id != inputs.marker.listing_id
        || delivery.transform_profile != FindingTransformProfile::Identity
        || delivery.digest_check != DeliveryResult::Matched
        || delivery.media_type_check != FindingMediaTypeCheck::Matched
        || delivery.purchase_intent_id != record.purchase_intent_id
        || delivery.authoritative_payment_operation_id != record.authoritative_payment_operation_id
        || delivery.accepted_bid_envelope_sha256 != record.accepted_bid_envelope_sha256
        || delivery.venue_admission_envelope_sha256 != record.venue_admission_envelope_sha256
    {
        return Err(RecoveryVerificationError::DeliveryReceiptBinding);
    }
    let recovery_id =
        derive_finding_recovery_id(&original_capability.id, &record.purchase_key, &receipt.id);
    if recovery_id != context.recovery_id || recovery_id != inputs.marker.recovery_id {
        return Err(RecoveryVerificationError::RecoveryIdentity);
    }
    if inputs.recovery_subject != &original_capability.subject {
        return Err(RecoveryVerificationError::SubjectMismatch);
    }
    Ok(RecoveryVerificationOutcome {
        context,
        recovery_id,
        finding_id: purchase.finding.finding_id,
        listing_id: inputs.marker.listing_id.clone(),
        payload_sha256: purchase.finding.payload_sha256,
        status_feed_id: purchase.finding.status_feed_ref,
        original_capability_id: original_capability.id,
        original_delivery_receipt_id: receipt.id,
        purchase_key: record.purchase_key.clone(),
        original_subject: original_capability.subject,
        server_id: inputs.server_id.to_owned(),
        tool_name: inputs.tool_name.to_owned(),
    })
}

/// Mint a first-class no-charge recovery capability from already-verified
/// facts. `token_id` may change across re-mints; the marker's deterministic
/// `recovery_id` and the durable issuer store preserve one shared quota.
pub fn mint_verified_finding_recovery_grant(
    verified: &RecoveryVerificationOutcome,
    issuer_keypair: &Keypair,
    token_id: String,
    max_recoveries: u32,
    issued_at: u64,
    expires_at: u64,
) -> Result<CapabilityToken, RecoveryMintError> {
    if max_recoveries == 0 || max_recoveries > 8 {
        return Err(RecoveryMintError::RetryBudget);
    }
    if expires_at <= issued_at {
        return Err(RecoveryMintError::WindowOutOfBounds);
    }
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: token_id,
            issuer: issuer_keypair.public_key(),
            subject: verified.original_subject.clone(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: verified.server_id.clone(),
                    tool_name: verified.tool_name.clone(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![
                        Constraint::OutputDigestSha256(verified.payload_sha256.clone()),
                        Constraint::RequireFindingRecovery(Box::new(FindingRecoveryMarkerV1 {
                            recovery_id: verified.recovery_id.clone(),
                            finding_id: verified.finding_id.clone(),
                            listing_id: verified.listing_id.clone(),
                            original_capability_id: verified.original_capability_id.clone(),
                            original_delivery_receipt_id: verified
                                .original_delivery_receipt_id
                                .clone(),
                            purchase_key: verified.purchase_key.clone(),
                            max_recoveries,
                        })),
                    ],
                    max_invocations: Some(max_recoveries),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer_keypair,
    )
    .map_err(|_| RecoveryMintError::Signing)
}

/// Typed rejections from [`mint_verified_finding_recovery_grant`]. Every
/// variant refuses the recovery authorization.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryMintError {
    #[error("recovery retry budget must be between 1 and 8")]
    RetryBudget,
    #[error("recovery window must end after it begins")]
    WindowOutOfBounds,
    #[error("recovery grant signing failed")]
    Signing,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn outcome(subject: &Keypair) -> RecoveryVerificationOutcome {
        RecoveryVerificationOutcome {
            context: FindingRecoveryContext {
                schema: chio_finding::FINDING_RECOVERY_CONTEXT_SCHEMA_V1.to_owned(),
                recovery_id: "a".repeat(64),
                original_capability_json: "{}".to_owned(),
                purchase_context_json: "{}".to_owned(),
                purchase_record_envelope_json: "{}".to_owned(),
                original_delivery_receipt_json: "{}".to_owned(),
            },
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            payload_sha256: "c".repeat(64),
            status_feed_id: "status-feed/test".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "d".repeat(64),
            original_subject: subject.public_key(),
            server_id: "finding-server".to_owned(),
            tool_name: "read_finding".to_owned(),
        }
    }

    #[test]
    fn deterministic_remints_share_first_class_no_charge_authority() {
        let issuer = Keypair::from_seed(&[1; 32]);
        let subject = Keypair::from_seed(&[2; 32]);
        let verified = outcome(&subject);
        let first = mint_verified_finding_recovery_grant(
            &verified,
            &issuer,
            "recovery-token-1".to_owned(),
            2,
            100,
            200,
        )
        .expect("first mint");
        let second = mint_verified_finding_recovery_grant(
            &verified,
            &issuer,
            "recovery-token-2".to_owned(),
            2,
            110,
            200,
        )
        .expect("second mint");
        assert_ne!(first.id, second.id);
        assert_eq!(first.subject, subject.public_key());
        for token in [&first, &second] {
            let grant = &token.scope.grants[0];
            assert_eq!(grant.max_cost_per_invocation, None);
            assert_eq!(grant.max_total_cost, None);
            assert_eq!(grant.max_invocations, Some(2));
            assert!(grant
                .constraints
                .iter()
                .all(|constraint| !matches!(constraint, Constraint::RequireFindingPurchase(_))));
            let marker = grant.constraints.iter().find_map(|constraint| {
                if let Constraint::RequireFindingRecovery(marker) = constraint {
                    Some(marker.as_ref())
                } else {
                    None
                }
            });
            assert_eq!(
                marker.map(|marker| marker.recovery_id.as_str()),
                Some(verified.recovery_id())
            );
            assert_eq!(marker.map(|marker| marker.max_recoveries), Some(2));
        }
    }

    #[test]
    fn buyer_self_minted_recovery_authority_is_rejected_before_carrier_use() {
        let recovery_authority = Keypair::from_seed(&[3; 32]);
        let buyer = Keypair::from_seed(&[4; 32]);
        let marker = FindingRecoveryMarkerV1 {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            max_recoveries: 2,
        };
        let authorities = RecoveryVerificationAuthorities {
            purchase: crate::purchase_verification::PurchaseVerificationAuthorities {
                venue_authority: Keypair::from_seed(&[5; 32]).public_key(),
                venue_id: "venue".to_owned(),
                reservation_authority: Keypair::from_seed(&[6; 32]).public_key(),
            },
            purchase_authority: Keypair::from_seed(&[7; 32]).public_key(),
            kernel_receipt_authority: Keypair::from_seed(&[8; 32]).public_key(),
            recovery_authority: recovery_authority.public_key(),
        };
        let arguments = serde_json::json!({"finding_id": marker.finding_id});
        let error = verify_finding_recovery_context(
            &RecoveryVerificationInputs {
                marker: &marker,
                context_b64: "not-used-for-an-untrusted-issuer",
                recovery_subject: &buyer.public_key(),
                recovery_issuer: &buyer.public_key(),
                server_id: "finding-server",
                tool_name: "read_finding",
                arguments: &arguments,
                expected_output_digest: &"d".repeat(64),
            },
            &authorities,
        )
        .err()
        .expect("buyer must not self-authorize recovery");
        assert_eq!(error, RecoveryVerificationError::RecoveryIssuer);
    }
}
