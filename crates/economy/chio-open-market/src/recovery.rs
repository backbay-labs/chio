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
//!
//! Compiled only under the `cognition-market-experimental` feature.

use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::metadata::{FindingDelivery, FINDING_DELIVERY_METADATA_KEY};

use crate::capability::{
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use crate::crypto::{Keypair, PublicKey};

/// Argument key naming the original delivery receipt on every recovery
/// invocation.
pub const RECOVERY_RECEIPT_ARGUMENT: &str = "recovery_of_receipt_id";

/// Argument key naming the original delivery capability on every
/// recovery invocation.
pub const RECOVERY_CAPABILITY_ARGUMENT: &str = "recovery_of_capability_id";

/// Typed rejections from [`mint_finding_recovery_grant`]. Every variant
/// refuses the recovery authorization.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryMintError {
    #[error("recovery requires the original signed Allow receipt")]
    NotAnAllow,
    #[error("original receipt does not carry a finding delivery block")]
    MissingDeliveryBlock,
    #[error("original receipt delivery block is malformed")]
    MalformedDeliveryBlock,
    #[error("original receipt does not bind the requested finding")]
    FindingMismatch,
    #[error("original receipt does not bind the requested capability")]
    CapabilityMismatch,
    #[error("original receipt content hash is not the finding commitment")]
    CommitmentMismatch,
    #[error("recovery retry budget must be between 1 and 8")]
    RetryBudget,
    #[error("recovery window must end after it begins")]
    WindowOutOfBounds,
    #[error("recovery grant signing failed")]
    Signing,
}

/// Inputs the seller's recovery service supplies after verifying the
/// checkpointed original Allow and the buyer's proof-of-possession.
pub struct RecoveryMintRequest<'a> {
    /// The original delivery receipt, already verified against the
    /// trusted kernel key and its checkpoint by the caller.
    pub original_receipt: &'a ChioReceipt,
    /// Capability id the original reveal was admitted under.
    pub original_capability_id: &'a str,
    /// The sold finding.
    pub finding_id: &'a str,
    /// The finding's payload commitment; stays the recovery grant's
    /// output digest.
    pub payload_sha256: &'a str,
    /// The original delivery-token subject the recovery grant re-binds.
    pub subject: PublicKey,
    /// Bounded retry count for the recovery window.
    pub max_retries: u32,
    /// Unix seconds when the grant becomes valid.
    pub issued_at: u64,
    /// Unix seconds when the grant expires.
    pub expires_at: u64,
}

/// Mint the no-charge recovery grant for one lost delivery.
///
/// The caller has already proved the original Allow is checkpointed and
/// the requester holds the original subject key; this function re-checks
/// every receipt binding it can prove from the artifact alone, then
/// mints the grant. No monetary ceiling exists, so no capture path does
/// either.
///
/// The authoritative binding to the sold finding is the committed output
/// digest, enforced at the output-aware terminal: a redelivery of any
/// other payload is denied there and its bytes are withheld. The request
/// constraints naming the original receipt, capability, and finding are
/// an additional pre-dispatch filter, not that binding; they match by
/// argument containment, so they narrow rather than pin the request.
pub fn mint_finding_recovery_grant(
    request: &RecoveryMintRequest<'_>,
    issuer_keypair: &Keypair,
    token_id: String,
) -> Result<CapabilityToken, RecoveryMintError> {
    let receipt = request.original_receipt;
    if !matches!(receipt.decision, Some(Decision::Allow)) {
        return Err(RecoveryMintError::NotAnAllow);
    }
    if receipt.capability_id != request.original_capability_id {
        return Err(RecoveryMintError::CapabilityMismatch);
    }
    if receipt.content_hash != request.payload_sha256 {
        return Err(RecoveryMintError::CommitmentMismatch);
    }
    let delivery: FindingDelivery = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .cloned()
        .ok_or(RecoveryMintError::MissingDeliveryBlock)
        .and_then(|value| {
            serde_json::from_value(value).map_err(|_| RecoveryMintError::MalformedDeliveryBlock)
        })?;
    delivery
        .validate()
        .map_err(|_| RecoveryMintError::MalformedDeliveryBlock)?;
    if delivery.finding_id != request.finding_id {
        return Err(RecoveryMintError::FindingMismatch);
    }
    if request.max_retries == 0 || request.max_retries > 8 {
        return Err(RecoveryMintError::RetryBudget);
    }
    if request.expires_at <= request.issued_at {
        return Err(RecoveryMintError::WindowOutOfBounds);
    }
    let body = CapabilityTokenBody {
        id: token_id,
        issuer: issuer_keypair.public_key(),
        subject: request.subject.clone(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: receipt.tool_server.clone(),
                tool_name: receipt.tool_name.clone(),
                operations: vec![Operation::Invoke],
                constraints: vec![
                    Constraint::OutputDigestSha256(request.payload_sha256.to_owned()),
                    Constraint::Custom(RECOVERY_RECEIPT_ARGUMENT.to_owned(), receipt.id.clone()),
                    Constraint::Custom(
                        RECOVERY_CAPABILITY_ARGUMENT.to_owned(),
                        request.original_capability_id.to_owned(),
                    ),
                    Constraint::Custom("finding_id".to_owned(), request.finding_id.to_owned()),
                ],
                max_invocations: Some(request.max_retries),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: Some(true),
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer_keypair).map_err(|_| RecoveryMintError::Signing)
}
