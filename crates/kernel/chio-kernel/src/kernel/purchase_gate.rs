//! Purchase-marked admission checks shared by both evaluation lanes and
//! the durable finalizer.

use base64::Engine as _;
use chio_core::capability::scope::{
    Constraint, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, ToolGrant,
};
use chio_core::crypto::PublicKey;

use super::delivery_contract::{
    finding_status_delivery_denial, preserve_terminal_delivery_denial, DeliveryEvaluation,
};
use crate::finding_denial::FindingDenial;
use crate::finding_purchase::{
    FindingCurrentStatusContextView, FindingPurchaseContextView, FindingPurchaseReplaySnapshotV1,
    FindingStatusProofContextView, VerifiedFindingPurchase, VerifiedFindingStatusProof,
    FINDING_ESCROW_WITNESS_CONTEXT_KEY, FINDING_PURCHASE_CONTEXT_KEY,
    FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA, FINDING_STATUS_PROOF_CONTEXT_KEY,
    MAX_FINDING_STATUS_PROOF_B64_BYTES,
};
use crate::request_matching::resolve_required_matching_grants;
use crate::runtime::ToolCallRequest;

use super::{ChioKernel, KernelError};

/// The purchase marker and its paired output digest recovered from one
/// selected grant, before context verification.
pub(crate) struct PurchaseMarkedGrant<'a> {
    pub(crate) marker: &'a FindingPurchaseMarkerV1,
    pub(crate) expected_output_digest: &'a str,
}

fn validate_verified_purchase_binding(
    marked: &PurchaseMarkedGrant<'_>,
    grant: &ToolGrant,
    request: &ToolCallRequest,
    verified: &VerifiedFindingPurchase,
) -> Result<(), FindingDenial> {
    if verified.finding_id != marked.marker.finding_id
        || verified.listing_id != marked.marker.listing_id
    {
        return Err(FindingDenial::binding_mismatch(
            "purchase context does not bind the marked finding sale",
        ));
    }
    if verified.payload_sha256 != marked.expected_output_digest {
        return Err(FindingDenial::binding_mismatch(
            "purchase context commits a different payload digest",
        ));
    }
    if verified.payload_media_type.is_empty() {
        return Err(FindingDenial::binding_mismatch(
            "purchase context omits the advertised reveal media type",
        ));
    }
    if verified.payer_key_hex != request.capability.subject.to_hex() {
        return Err(FindingDenial::binding_mismatch(
            "purchase reservation binds a different payer",
        ));
    }
    let exact = |amount: &Option<MonetaryAmount>| {
        amount.as_ref().is_some_and(|amount| {
            amount.units == verified.accepted_price.units
                && amount.currency == verified.accepted_price.currency
        })
    };
    if !exact(&grant.max_cost_per_invocation) || !exact(&grant.max_total_cost) {
        return Err(FindingDenial::binding_mismatch(
            "purchase grant ceilings do not equal the accepted price",
        ));
    }
    Ok(())
}

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Recover the purchase marker from a selected grant, enforcing the
/// closed delivery profile: exactly one marker, exactly one paired output
/// digest, the local settlement rail, a mandatory proof-of-possession
/// binding, and a single authorized invocation.
pub(crate) fn purchase_marked_grant(
    grant: &ToolGrant,
) -> Result<Option<PurchaseMarkedGrant<'_>>, FindingDenial> {
    let mut markers = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::RequireFindingPurchase(marker) = constraint {
            Some(marker.as_ref())
        } else {
            None
        }
    });
    let Some(marker) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err(FindingDenial::carrier_invalid(
            "purchase-marked grant carries more than one purchase marker",
        ));
    }
    match &marker.settlement {
        FindingSettlementSelector::LocalReversibleHold => {}
        FindingSettlementSelector::CrossOrgEscrow { .. } => {
            return Err(FindingDenial::carrier_invalid(
                "purchase-marked delivery requires the local reversible-hold settlement rail",
            ));
        }
    }
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest.as_str())
        } else {
            None
        }
    });
    let (Some(expected_output_digest), None) = (digests.next(), digests.next()) else {
        return Err(FindingDenial::carrier_invalid(
            "purchase-marked grant requires exactly one committed output digest",
        ));
    };
    if grant.dpop_required != Some(true) {
        return Err(FindingDenial::carrier_invalid(
            "purchase-marked delivery requires a mandatory proof-of-possession grant",
        ));
    }
    if grant.max_invocations != Some(1) {
        return Err(FindingDenial::carrier_invalid(
            "purchase-marked grant must authorize exactly one invocation",
        ));
    }
    Ok(Some(PurchaseMarkedGrant {
        marker,
        expected_output_digest,
    }))
}

impl ChioKernel {
    /// Pin the long-lived signer for cognition-market pool mutation receipts.
    /// Reinstall this key unchanged when the ordinary kernel key rotates.
    pub fn set_finding_pool_receipt_authority(
        &mut self,
        authority: chio_core::crypto::Keypair,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        validate_finding_pool_receipt_authority(&authority.public_key())?;
        if self.finding_pool_receipt_authority.is_some() {
            return Err(
                crate::finding_pool::FindingPoolLedgerError::ReceiptAuthorityAlreadyConfigured,
            );
        }
        self.finding_pool_receipt_authority = Some(authority);
        Ok(())
    }

    /// Pin the single qualified pool ledger for this deployment kernel.
    /// Once installed it cannot be replaced, preventing callers from routing
    /// successive debits for one signed allocation through disjoint ledgers.
    pub fn set_finding_pool_ledger(
        &mut self,
        ledger: std::sync::Arc<dyn crate::finding_pool::QualifiedFindingPoolLedger>,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        if self.finding_pool_ledger.is_some() {
            return Err(crate::finding_pool::FindingPoolLedgerError::AlreadyConfigured);
        }
        let receipt_authority = self
            .finding_pool_receipt_authority
            .as_ref()
            .ok_or(crate::finding_pool::FindingPoolLedgerError::ReceiptAuthorityMissing)?
            .public_key();
        if self.receipt_store.is_none() {
            return Err(crate::finding_pool::FindingPoolLedgerError::DurableReceiptStoreMissing);
        }
        if self.config.retention_config.is_some() {
            return Err(crate::finding_pool::FindingPoolLedgerError::UnqualifiedRetentionArchive);
        }
        let receipt_sink_id = self
            .receipt_store
            .as_ref()
            .and_then(|store| store.durable_sink_id())
            .ok_or(crate::finding_pool::FindingPoolLedgerError::InvalidReceiptSink)?;
        self.ensure_finding_pool_configuration_precedes_startup_reconciliation()?;
        ledger.bind_receipt_configuration(&receipt_authority, receipt_sink_id)?;
        self.finding_pool_ledger = Some(ledger);
        Ok(())
    }

    pub(crate) fn finding_pool_allocation_authority(&self) -> Option<&PublicKey> {
        self.finding_pool_allocation_authority.as_ref()
    }

    pub(crate) fn finding_pool_ledger(
        &self,
    ) -> Option<&dyn crate::finding_pool::QualifiedFindingPoolLedger> {
        self.finding_pool_ledger.as_deref()
    }

    pub(crate) fn verify_finding_status_for_pool(
        &self,
        proof_b64: Option<&str>,
        expected_finding_id: &str,
        expected_feed_id: &str,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        self.verify_status_proof_carrier(
            proof_b64,
            expected_finding_id,
            expected_feed_id,
            Some(now_unix_secs),
            "finding pool debit requires a portable status proof",
            None,
        )
        .map(|_| ())
    }

    /// Deterministically verify an optional portable status-proof carrier
    /// against the kernel's injected status verifier, then run clocked
    /// admission when `admission_now_unix_secs` is supplied.
    ///
    /// Three of the four verifier/proof combinations are fixed policy: a
    /// verifier without a proof denies with `missing_proof_denial`, a proof
    /// without a verifier always denies, and a present pair must verify. The
    /// only call-site choice is the empty pair: `missing_pair_denial` denies
    /// a lane that requires a configured verifier, while `None` passes that
    /// lane through unverified.
    fn verify_status_proof_carrier(
        &self,
        proof_b64: Option<&str>,
        expected_finding_id: &str,
        expected_feed_id: &str,
        admission_now_unix_secs: Option<u64>,
        missing_proof_denial: &'static str,
        missing_pair_denial: Option<&'static str>,
    ) -> Result<Option<VerifiedFindingStatusProof>, FindingDenial> {
        match (self.finding_status_proof_verifier.as_ref(), proof_b64) {
            (Some(status_verifier), Some(proof_b64)) => {
                if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
                    return Err(FindingDenial::carrier_invalid(
                        "finding status proof carrier exceeds the kernel size bound",
                    ));
                }
                let view = FindingStatusProofContextView {
                    proof_b64,
                    expected_finding_id,
                    expected_feed_id,
                };
                let verified = status_verifier
                    .verify_status_proof(&view)
                    .map_err(|denial| denial.prefixed("finding status proof rejected"))?;
                if let Some(now_unix_secs) = admission_now_unix_secs {
                    status_verifier
                        .verify_status_admission(&view, &verified, now_unix_secs)
                        .map_err(|denial| denial.prefixed("finding status admission rejected"))?;
                }
                Ok(Some(verified))
            }
            (Some(_), None) => Err(FindingDenial::carrier_invalid(missing_proof_denial)),
            (None, Some(_)) => Err(FindingDenial::unavailable(
                "finding status proof requires a configured kernel verifier",
            )),
            (None, None) => match missing_pair_denial {
                Some(denial) => Err(FindingDenial::carrier_invalid(denial)),
                None => Ok(None),
            },
        }
    }

    pub(crate) fn verify_purchase_context_for_pool(
        &self,
        view: &FindingPurchaseContextView<'_>,
    ) -> Result<VerifiedFindingPurchase, FindingDenial> {
        let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
            FindingDenial::unavailable(
                "finding pool debit requires the kernel's configured purchase verifier",
            )
        })?;
        let verified = verifier
            .verify_purchase(view)
            .map_err(|denial| denial.prefixed("purchase context rejected"))?;
        if verified.finding_id != view.marker.finding_id
            || verified.listing_id != view.marker.listing_id
            || verified.payload_sha256 != view.expected_output_digest
            || verified.payer_key_hex != view.capability.subject.to_hex()
        {
            return Err(FindingDenial::binding_mismatch(
                "purchase context does not bind the pool debit request",
            ));
        }
        Ok(verified)
    }

    pub(crate) fn verify_purchase_admission_for_pool(
        &self,
        view: &FindingPurchaseContextView<'_>,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
            FindingDenial::unavailable(
                "finding pool debit requires the kernel's configured purchase verifier",
            )
        })?;
        verifier
            .verify_purchase_admission(view, verified, now_unix_secs)
            .map_err(|denial| denial.prefixed("purchase admission rejected"))
    }

    /// Deterministically verify the purchase context for a marked grant
    /// and cross-check the result against the grant, the request, and the
    /// paying capability. Returns `Ok(None)` for an unmarked grant; every
    /// error denies.
    ///
    /// This half is replayed by the durable finalizer from the frozen
    /// request, so it must not consult clocks or mutable state.
    pub(crate) fn verify_purchase_context(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
    ) -> Result<Option<VerifiedFindingPurchase>, FindingDenial> {
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Ok(None);
        };
        let context = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid(
                    "purchase-marked delivery requires a governed purchase context",
                )
            })?;
        if context.contains_key(FINDING_ESCROW_WITNESS_CONTEXT_KEY) {
            return Err(FindingDenial::carrier_invalid(
                "an escrow witness is not admissible on the local settlement rail",
            ));
        }
        let context_b64 = context
            .get(FINDING_PURCHASE_CONTEXT_KEY)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid(
                    "purchase-marked delivery requires a governed purchase context",
                )
            })?;
        let Some(verifier) = self.finding_purchase_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "purchase-marked delivery requires a configured purchase verifier",
            ));
        };
        let view = FindingPurchaseContextView {
            marker: marked.marker,
            context_b64,
            capability: &request.capability,
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            arguments: &request.arguments,
            expected_output_digest: marked.expected_output_digest,
        };
        let mut verified = verifier
            .verify_purchase(&view)
            .map_err(|denial| denial.prefixed("purchase context rejected"))?;
        validate_verified_purchase_binding(&marked, grant, request, &verified)?;
        let status_proof_b64 = context
            .get(FINDING_STATUS_PROOF_CONTEXT_KEY)
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    FindingDenial::carrier_invalid(
                        "finding status proof carrier must be a base64 string",
                    )
                })
            })
            .transpose()?;
        verified.status_proof = self.verify_status_proof_carrier(
            status_proof_b64,
            &verified.finding_id,
            &verified.expected_status_feed_id,
            None,
            "finding purchase requires a portable status proof",
            Some("purchase-marked delivery requires a configured finding status verifier"),
        )?;
        Ok(Some(verified))
    }

    /// Validate an admission-verified purchase snapshot recovered from the
    /// authenticated raw tool return. This path deliberately does not consult
    /// the current status verifier: authority rotation after dispatch cannot
    /// invalidate the historical authorization captured with that return.
    pub(crate) fn validate_purchase_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        snapshot: FindingPurchaseReplaySnapshotV1,
    ) -> Result<Option<VerifiedFindingPurchase>, FindingDenial> {
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Err(FindingDenial::binding_mismatch(
                "an unmarked durable return carries a purchase snapshot",
            ));
        };
        if snapshot.schema != FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA {
            return Err(FindingDenial::carrier_invalid(
                "durable purchase snapshot schema is invalid",
            ));
        }
        let verified = snapshot.purchase;
        validate_verified_purchase_binding(&marked, grant, request, &verified)?;
        let status = verified.status_proof.as_ref().ok_or_else(|| {
            FindingDenial::binding_mismatch(
                "durable purchase snapshot has no verified status binding",
            )
        })?;
        if status.feed_id != verified.expected_status_feed_id
            || status.key_domain_nonce == 0
            || status.map_epoch == 0
            || status.non_inclusion_checked_at == 0
            || !is_lower_hex64(&status.status_epoch_id)
            || !is_lower_hex64(&status.status_epoch_artifact_sha256)
            || !is_lower_hex64(&status.proof_sha256)
            || !is_lower_hex64(&status.root_hash)
            || !is_lower_hex64(&status.operator_authorization_sha256)
            || !is_lower_hex64(&status.service_bond_evidence_sha256)
        {
            return Err(FindingDenial::carrier_invalid(
                "durable purchase status snapshot is malformed",
            ));
        }
        let proof_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid("durable purchase request lost its status proof")
            })?;
        if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
            return Err(FindingDenial::carrier_invalid(
                "durable purchase status proof exceeds the kernel size bound",
            ));
        }
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(proof_b64)
            .map_err(|_| {
                FindingDenial::carrier_invalid("durable purchase status proof is not valid base64")
            })?;
        if chio_core::crypto::sha256_hex(&proof_bytes) != status.proof_sha256 {
            return Err(FindingDenial::binding_mismatch(
                "durable purchase snapshot binds a different status proof",
            ));
        }
        Ok(Some(verified))
    }

    pub(crate) fn capture_purchase_replay_metadata(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        verified_purchase: Option<&VerifiedFindingPurchase>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let matching_grants = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let selected_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .ok_or_else(|| {
                KernelError::FindingDenied(FindingDenial::unavailable(
                    "durable tool return lost its matched grant",
                ))
            })?;
        let is_purchase = purchase_marked_grant(selected_grant.grant)
            .map_err(KernelError::FindingDenied)?
            .is_some();
        match (is_purchase, verified_purchase) {
            (true, Some(purchase)) => {
                let snapshot = FindingPurchaseReplaySnapshotV1::new(purchase.clone());
                self.validate_purchase_replay_snapshot(
                    selected_grant.grant,
                    request,
                    snapshot.clone(),
                )
                .map_err(|reason| {
                    KernelError::DurableAdmission(format!(
                        "purchase replay snapshot could not be captured: {reason}"
                    ))
                })?;
                serde_json::to_value(snapshot)
                    .map(|snapshot| {
                        Some(serde_json::json!({
                            crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY:
                                snapshot
                        }))
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))
            }
            (true, None) => Err(KernelError::FindingDenied(FindingDenial::unavailable(
                "durable purchase return has no frozen dispatch snapshot",
            ))),
            (false, Some(_)) => Err(KernelError::FindingDenied(FindingDenial::binding_mismatch(
                "unmarked durable return carries a frozen purchase snapshot",
            ))),
            (false, None) => Ok(None),
        }
    }

    pub(crate) fn restore_purchase_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<VerifiedFindingPurchase>, KernelError> {
        let snapshot = metadata
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| {
                metadata.get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
            })
            .cloned();
        let is_purchase = purchase_marked_grant(grant)
            .map_err(KernelError::FindingDenied)?
            .is_some();
        match (is_purchase, snapshot) {
            (true, Some(snapshot)) => {
                let snapshot: FindingPurchaseReplaySnapshotV1 = serde_json::from_value(snapshot)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "durable purchase snapshot is malformed: {error}"
                        ))
                    })?;
                self.validate_purchase_replay_snapshot(grant, request, snapshot)
                    .map_err(|reason| {
                        KernelError::DurableAdmission(format!(
                            "durable purchase snapshot was rejected: {reason}"
                        ))
                    })
            }
            (true, None) => Err(KernelError::FindingDenied(FindingDenial::unavailable(
                "durable purchase return has no frozen authority snapshot",
            ))),
            (false, Some(_)) => Err(KernelError::DurableAdmission(
                "unmarked durable return carries a purchase snapshot".to_owned(),
            )),
            (false, None) => Ok(None),
        }
    }

    /// Full admission gate for a purchase-marked grant: the deterministic
    /// verification plus the admission-time checks (finding liveness and
    /// authoritative reservation state) and the identity-pipeline
    /// requirement. Returns `Ok(None)` for an unmarked grant.
    pub(crate) fn verify_purchase_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingPurchase>, FindingDenial> {
        let Some(verified) = self.verify_purchase_context(grant, request)? else {
            return Ok(None);
        };
        if !self.post_invocation_pipeline.is_empty() {
            return Err(FindingDenial::carrier_invalid(
                "purchase-marked delivery requires an empty post-invocation pipeline",
            ));
        }
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Err(FindingDenial::unavailable(
                "purchase marker disappeared during admission",
            ));
        };
        let Some(verifier) = self.finding_purchase_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "purchase-marked delivery requires a configured purchase verifier",
            ));
        };
        let context_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_PURCHASE_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid(
                    "purchase-marked delivery requires a governed purchase context",
                )
            })?;
        let view = FindingPurchaseContextView {
            marker: marked.marker,
            context_b64,
            capability: &request.capability,
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            arguments: &request.arguments,
            expected_output_digest: marked.expected_output_digest,
        };
        verifier
            .verify_purchase_admission(&view, &verified, now_unix_secs)
            .map_err(|denial| denial.prefixed("purchase admission rejected"))?;
        if let Some(status) = verified.status_proof.as_ref() {
            let proof_b64 = request
                .governed_intent
                .as_ref()
                .and_then(|intent| intent.context.as_ref())
                .and_then(serde_json::Value::as_object)
                .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    FindingDenial::unavailable("verified finding status proof carrier disappeared")
                })?;
            let Some(status_verifier) = self.finding_status_proof_verifier.as_ref() else {
                return Err(FindingDenial::unavailable(
                    "finding status verifier disappeared during admission",
                ));
            };
            status_verifier
                .verify_status_admission(
                    &FindingStatusProofContextView {
                        proof_b64,
                        expected_finding_id: &verified.finding_id,
                        expected_feed_id: &verified.expected_status_feed_id,
                    },
                    status,
                    now_unix_secs,
                )
                .map_err(|denial| denial.prefixed("finding status admission rejected"))?;
        }
        Ok(Some(verified))
    }

    /// Recheck the purchased Finding against the current authenticated feed
    /// floor before a durable terminal captures payment or releases output.
    pub(crate) fn revalidate_completed_purchase_status(
        &self,
        purchase: Option<&VerifiedFindingPurchase>,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        let Some(purchase) = purchase else {
            return Ok(());
        };
        let status = purchase.status_proof.as_ref().ok_or_else(|| {
            FindingDenial::binding_mismatch(
                "completed purchase has no admission-verified status binding",
            )
        })?;
        if status.feed_id != purchase.expected_status_feed_id {
            return Err(FindingDenial::stale_or_superseded(
                "completed purchase status feed changed after admission",
            ));
        }
        let verifier = self.finding_status_proof_verifier.as_ref().ok_or_else(|| {
            FindingDenial::unavailable("finding status verifier disappeared before terminalization")
        })?;
        verifier
            .verify_current_status_admission(
                &FindingCurrentStatusContextView {
                    expected_finding_id: &purchase.finding_id,
                    expected_feed_id: &purchase.expected_status_feed_id,
                    minimum_map_epoch: status.map_epoch,
                    minimum_non_inclusion_checked_at: status.non_inclusion_checked_at,
                },
                now_unix_secs,
            )
            .map_err(|denial| denial.prefixed("completed purchase status admission rejected"))
    }

    /// Preserve a retained terminal denial and apply the current status gate
    /// before replaying a purchased delivery.
    pub(crate) fn revalidate_replayed_purchase_delivery(
        &self,
        retained_decision: Option<&chio_core::receipt::decision::Decision>,
        evaluation: &mut DeliveryEvaluation,
        purchase: Option<&VerifiedFindingPurchase>,
        now_unix_secs: u64,
    ) -> Option<String> {
        preserve_terminal_delivery_denial(retained_decision, evaluation);
        if evaluation.denial.is_some() {
            return None;
        }
        self.revalidate_completed_purchase_status(purchase, now_unix_secs)
            .err()
            .map(|denial| denial.detail().to_owned())
            .inspect(|_| evaluation.denial = Some(finding_status_delivery_denial()))
    }
}

pub(crate) fn validate_finding_pool_receipt_authority(
    authority: &chio_core::crypto::PublicKey,
) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
    if authority.algorithm() != chio_core::crypto::SigningAlgorithm::Ed25519
        || authority.is_weak_ed25519()
    {
        return Err(crate::finding_pool::FindingPoolLedgerError::InvalidReceiptAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_denial::FindingDenialCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use chio_core::capability::governance::{
        GovernedTransactionIntent, GovernedTransactionIntentBody,
    };
    use chio_core::capability::scope::{ChioScope, Operation};
    use chio_core::crypto::Keypair;

    use crate::finding_purchase::{FindingStatusProofVerifier, VerifiedFindingStatusProof};
    use crate::{HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct RotatedStatusVerifier {
        calls: AtomicU64,
    }

    impl FindingStatusProofVerifier for RotatedStatusVerifier {
        fn verify_status_proof(
            &self,
            _view: &FindingStatusProofContextView<'_>,
        ) -> Result<VerifiedFindingStatusProof, crate::finding_denial::FindingDenial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::finding_denial::FindingDenial::authority_invalid(
                "the prior status operator is no longer current",
            ))
        }

        fn verify_status_admission(
            &self,
            _view: &FindingStatusProofContextView<'_>,
            _verified: &VerifiedFindingStatusProof,
            _now_unix_secs: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::finding_denial::FindingDenial::authority_invalid(
                "the prior status operator is no longer current",
            ))
        }

        fn verify_current_status_admission(
            &self,
            _view: &FindingCurrentStatusContextView<'_>,
            _now_unix_secs: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::finding_denial::FindingDenial::status_denied(
                "finding is pending retraction",
            ))
        }
    }

    /// Cross-organization escrow is registered on the wire and has no
    /// admission lane. The reservation is only honest while every gate
    /// refuses it, so a lane appearing without this test noticing is the
    /// failure this guards.
    #[test]
    fn cross_organization_escrow_is_registered_and_never_admitted() {
        let grant = ToolGrant {
            server_id: "finding-server".to_owned(),
            tool_name: "finding.reveal".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::RequireFindingPurchase(Box::new(FindingPurchaseMarkerV1 {
                    finding_id: "finding-1".to_owned(),
                    listing_id: "listing-1".to_owned(),
                    settlement: FindingSettlementSelector::CrossOrgEscrow {
                        settlement_profile_sha256: DIGEST.to_owned(),
                    },
                })),
                Constraint::OutputDigestSha256(DIGEST.to_owned()),
            ],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        };

        let Err(denial) = purchase_marked_grant(&grant) else {
            panic!("an escrow-marked grant must never reach admission");
        };
        assert_eq!(denial.code(), FindingDenialCode::CarrierInvalid);
        assert_eq!(
            denial.detail(),
            "purchase-marked delivery requires the local reversible-hold settlement rail"
        );
    }

    #[test]
    fn durable_purchase_snapshot_survives_status_operator_rotation() {
        let kernel_key = Keypair::from_seed(&[91; 32]);
        let buyer = Keypair::from_seed(&[92; 32]);
        let marker = FindingPurchaseMarkerV1 {
            finding_id: "finding-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            settlement: FindingSettlementSelector::LocalReversibleHold,
        };
        let price = MonetaryAmount {
            units: 7,
            currency: "USD".to_owned(),
        };
        let grant = ToolGrant {
            server_id: "finding-server".to_owned(),
            tool_name: "finding.reveal".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::RequireFindingPurchase(Box::new(marker)),
                Constraint::OutputDigestSha256(DIGEST.to_owned()),
            ],
            max_invocations: Some(1),
            max_cost_per_invocation: Some(price.clone()),
            max_total_cost: Some(price.clone()),
            dpop_required: Some(true),
        };
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: kernel_key,
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "purchase-snapshot-test".to_owned(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: crate::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: crate::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: 0,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        });
        let capability = kernel
            .issue_capability(
                &buyer.public_key(),
                ChioScope {
                    grants: vec![grant.clone()],
                    ..ChioScope::default()
                },
                300,
            )
            .expect("issue purchase capability");
        let proof_bytes = b"frozen-prior-operator-status-proof";
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof_bytes);
        let request = ToolCallRequest {
            request_id: "purchase-snapshot-rotation".to_owned(),
            capability: capability.clone(),
            tool_name: "finding.reveal".to_owned(),
            server_id: "finding-server".to_owned(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({"finding_id": "finding-1"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-purchase-snapshot-rotation".to_owned(),
                server_id: "finding-server".to_owned(),
                tool_name: "finding.reveal".to_owned(),
                purpose: "complete an admitted purchase after key rotation".to_owned(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    FINDING_STATUS_PROOF_CONTEXT_KEY: proof_b64,
                })),
                body: GovernedTransactionIntentBody::ToolInvocation,
            }),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let frozen_purchase = VerifiedFindingPurchase {
            finding_id: "finding-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            payload_sha256: DIGEST.to_owned(),
            payload_media_type: "application/json".to_owned(),
            expected_status_feed_id: "status-feed/market".to_owned(),
            accepted_price: price,
            payer_key_hex: buyer.public_key().to_hex(),
            reservation_id: "reservation-1".to_owned(),
            purchase_intent_id: "purchase-intent-1".to_owned(),
            authoritative_payment_operation_id: "payment-operation-1".to_owned(),
            accepted_bid_envelope_sha256: "1".repeat(64),
            venue_admission_envelope_sha256: "2".repeat(64),
            status_proof: Some(VerifiedFindingStatusProof {
                feed_id: "status-feed/market".to_owned(),
                key_domain_nonce: 3_318_287_169_837_494,
                map_epoch: 7,
                status_epoch_id: "3".repeat(64),
                status_epoch_artifact_sha256: "4".repeat(64),
                proof_sha256: chio_core::crypto::sha256_hex(proof_bytes),
                root_hash: "5".repeat(64),
                non_inclusion_checked_at: 1_750_000_000,
                operator_authorization_sha256: "6".repeat(64),
                service_bond_evidence_sha256: "7".repeat(64),
            }),
        };
        let rotated = Arc::new(RotatedStatusVerifier {
            calls: AtomicU64::new(0),
        });
        kernel.set_finding_status_proof_verifier(rotated.clone());

        let recovered = kernel
            .validate_purchase_replay_snapshot(
                &grant,
                &request,
                FindingPurchaseReplaySnapshotV1::new(frozen_purchase.clone()),
            )
            .expect("frozen historical authority remains replayable")
            .expect("purchase snapshot remains present");
        assert_eq!(recovered, frozen_purchase);
        let captured = kernel
            .capture_purchase_replay_metadata(&request, 0, Some(&frozen_purchase))
            .expect("the dispatch-frozen purchase remains recordable")
            .expect("the durable return carries a purchase snapshot");
        assert!(captured
            .get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
            .is_some());
        assert_eq!(rotated.calls.load(Ordering::SeqCst), 0);
        let error = kernel
            .revalidate_completed_purchase_status(Some(&frozen_purchase), 1_800_000_000)
            .expect_err("terminal release must consult the current status floor");
        assert!(error.detail().contains("pending retraction"));
        assert_eq!(error.code(), FindingDenialCode::StatusDenied);
        assert_eq!(rotated.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_committed_digest_admits_only_a_matching_value_delivery() {
        let unconstrained_stream =
            crate::kernel::delivery_contract::evaluate_delivery(None, DIGEST, false, b"{}", None);
        assert!(unconstrained_stream.denial.is_none());
        assert!(!unconstrained_stream.digest_mismatched);

        let matching_value = crate::kernel::delivery_contract::evaluate_delivery(
            Some(DIGEST),
            DIGEST,
            true,
            b"{}",
            None,
        );
        assert!(matching_value.denial.is_none());
        assert!(!matching_value.digest_mismatched);

        // A stream whose derived content hash collides with the committed
        // digest still denies: the commitment is over canonical value
        // bytes, and a stream hash is provider-authored chunk metadata.
        let colliding_stream = crate::kernel::delivery_contract::evaluate_delivery(
            Some(DIGEST),
            DIGEST,
            false,
            b"{}",
            None,
        );
        assert!(colliding_stream.digest_mismatched);
        let denial = colliding_stream
            .denial
            .as_ref()
            .filter(|denial| denial.guard == "delivery_contract");
        assert!(
            denial.is_some_and(|denial| denial.message.contains("single value delivery")),
            "a stream delivery must deny under a committed digest"
        );
    }

    #[test]
    fn retained_terminal_deny_never_replays_as_allow() {
        let mut evaluation =
            crate::kernel::delivery_contract::evaluate_delivery(None, DIGEST, true, b"{}", None);
        assert!(evaluation.denial.is_none());
        preserve_terminal_delivery_denial(
            Some(&chio_core::receipt::decision::Decision::Deny {
                reason: "finding status changed before durable output release".to_owned(),
                guard: "finding_status".to_owned(),
            }),
            &mut evaluation,
        );
        let denial = evaluation.denial.expect("retained denial");
        assert_eq!(
            denial.message,
            "finding status changed before durable output release"
        );
        assert_eq!(denial.guard, "finding_status");
    }
}
