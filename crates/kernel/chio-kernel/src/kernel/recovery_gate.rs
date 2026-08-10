//! First-class no-charge finding-recovery admission and receipt metadata.

use chio_core::capability::scope::{Constraint, FindingRecoveryMarkerV1, ToolGrant};

use crate::finding_purchase::{
    FindingStatusProofContextView, FINDING_STATUS_PROOF_CONTEXT_KEY,
    MAX_FINDING_STATUS_PROOF_B64_BYTES,
};
use crate::finding_recovery::{
    FindingRecoveryContextView, VerifiedFindingRecovery, FINDING_RECOVERY_CONTEXT_ARGUMENT,
};
use crate::runtime::ToolCallRequest;

use super::ChioKernel;

pub(crate) struct RecoveryMarkedGrant<'a> {
    marker: &'a FindingRecoveryMarkerV1,
    expected_output_digest: &'a str,
}

/// Recover and validate the closed recovery grant profile.
pub(crate) fn recovery_marked_grant(
    grant: &ToolGrant,
) -> Result<Option<RecoveryMarkedGrant<'_>>, String> {
    if grant.constraints.iter().any(|constraint| {
        matches!(constraint, Constraint::Custom(key, _)
            if matches!(key.as_str(), "recovery_of_receipt_id" | "recovery_of_capability_id"))
    }) {
        return Err(
            "legacy Custom-only recovery authority is forbidden; use RequireFindingRecovery"
                .to_owned(),
        );
    }
    let mut markers = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::RequireFindingRecovery(marker) = constraint {
            Some(marker.as_ref())
        } else {
            None
        }
    });
    let Some(marker) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err("recovery grant carries more than one recovery marker".to_owned());
    }
    if grant.operations.as_slice() != [chio_core::capability::scope::Operation::Invoke] {
        return Err("recovery grant permits only the Invoke operation".to_owned());
    }
    if grant.constraints.len() != 2 {
        return Err(
            "recovery grant requires exactly its recovery marker and output digest".to_owned(),
        );
    }
    if grant
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, Constraint::RequireFindingPurchase(_)))
    {
        return Err("recovery grant must not carry a purchase marker".to_owned());
    }
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest.as_str())
        } else {
            None
        }
    });
    let (Some(expected_output_digest), None) = (digests.next(), digests.next()) else {
        return Err("recovery grant requires exactly one committed output digest".to_owned());
    };
    if marker.max_recoveries == 0 || marker.max_recoveries > 8 {
        return Err("recovery grant retry budget must be between 1 and 8".to_owned());
    }
    if grant.max_invocations != Some(marker.max_recoveries) {
        return Err(
            "recovery grant invocation budget must equal its durable retry budget".to_owned(),
        );
    }
    if grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some() {
        return Err("recovery grant must not carry monetary ceilings".to_owned());
    }
    if grant.dpop_required != Some(true) {
        return Err("recovery grant requires mandatory proof of possession".to_owned());
    }
    Ok(Some(RecoveryMarkedGrant {
        marker,
        expected_output_digest,
    }))
}

fn validate_recovery_capability_profile(
    capability: &chio_core::capability::token::CapabilityToken,
) -> Result<(), String> {
    let carries_recovery_authority = capability.scope.grants.iter().any(|grant| {
        grant.constraints.iter().any(|constraint| {
            matches!(constraint, Constraint::RequireFindingRecovery(_))
                || matches!(constraint, Constraint::Custom(key, _)
                    if matches!(key.as_str(), "recovery_of_receipt_id" | "recovery_of_capability_id" | "require_finding_recovery"))
        })
    });
    if !carries_recovery_authority {
        return Ok(());
    }
    if capability.scope.grants.len() != 1
        || !capability.scope.resource_grants.is_empty()
        || !capability.scope.prompt_grants.is_empty()
        || capability.aggregate_invocation_budget.is_some()
        || !capability.delegation_chain.is_empty()
    {
        return Err("finding recovery requires an undelegated, single-grant capability".to_owned());
    }
    Ok(())
}

impl ChioKernel {
    /// Deterministically re-derive a recovery binding from the frozen request.
    pub(crate) fn verify_recovery_context(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
    ) -> Result<Option<VerifiedFindingRecovery>, String> {
        validate_recovery_capability_profile(&request.capability)?;
        let Some(marked) = recovery_marked_grant(grant)? else {
            return Ok(None);
        };
        if !self.post_invocation_pipeline.is_empty() {
            return Err("finding recovery requires an empty post-invocation pipeline".to_owned());
        }
        let arguments = request
            .arguments
            .as_object()
            .ok_or_else(|| "finding recovery requires a top-level argument object".to_owned())?;
        let finding_id = arguments
            .get("finding_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "finding recovery requires a top-level finding_id".to_owned())?;
        if finding_id != marked.marker.finding_id {
            return Err("finding recovery targets a different finding".to_owned());
        }
        let context_b64 = arguments
            .get(FINDING_RECOVERY_CONTEXT_ARGUMENT)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "finding recovery requires its evidence carrier".to_owned())?;
        let Some(verifier) = self.finding_recovery_verifier.as_ref() else {
            return Err("finding recovery requires a configured recovery verifier".to_owned());
        };
        let verified = verifier
            .verify_recovery(&FindingRecoveryContextView {
                marker: marked.marker,
                context_b64,
                recovery_capability: &request.capability,
                server_id: &request.server_id,
                tool_name: &request.tool_name,
                arguments: &request.arguments,
                expected_output_digest: marked.expected_output_digest,
            })
            .map_err(|error| format!("finding recovery context rejected: {error}"))?;
        if verified.recovery_id != marked.marker.recovery_id
            || verified.finding_id != marked.marker.finding_id
            || verified.listing_id != marked.marker.listing_id
            || verified.original_capability_id != marked.marker.original_capability_id
            || verified.original_delivery_receipt_id != marked.marker.original_delivery_receipt_id
            || verified.purchase_key != marked.marker.purchase_key
        {
            return Err("finding recovery carrier does not match its signed marker".to_owned());
        }
        if verified.payload_sha256 != marked.expected_output_digest {
            return Err("finding recovery commits a different payload digest".to_owned());
        }
        if verified.original_subject_key_hex != request.capability.subject.to_hex() {
            return Err("finding recovery binds a different original subject".to_owned());
        }
        Ok(Some(verified))
    }

    /// Verify the carrier and atomically reserve one durable attempt before
    /// dispatch. Re-evaluating the same request id is idempotent.
    pub(crate) fn verify_recovery_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecovery>, String> {
        let Some(verified) =
            self.verify_recovery_status_admission(grant, request, now_unix_secs)?
        else {
            return Ok(None);
        };
        let Some(marked) = recovery_marked_grant(grant)? else {
            return Err("finding recovery marker disappeared during admission".to_owned());
        };
        let Some(verifier) = self.finding_recovery_verifier.as_ref() else {
            return Err("finding recovery requires a configured recovery verifier".to_owned());
        };
        verifier
            .reserve_recovery_attempt(
                &verified,
                &request.request_id,
                marked.marker.max_recoveries,
                now_unix_secs,
            )
            .map_err(|error| format!("finding recovery quota rejected: {error}"))?;
        Ok(Some(verified))
    }

    /// Recheck mutable finding status without consuming recovery quota.
    ///
    /// Initial admission calls this before reserving an attempt. The dispatch
    /// boundary calls it again so a concurrent pending or retracted transition
    /// cannot redeliver quarantined bytes using an earlier live proof.
    pub(crate) fn verify_recovery_status_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecovery>, String> {
        let Some(verified) = self.verify_recovery_context(grant, request)? else {
            return Ok(None);
        };
        // Recovery is another delivery of the purchased bytes, so it must
        // cross the same current status floor before consuming retry quota.
        let proof_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "finding recovery requires a portable status proof".to_owned())?;
        if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
            return Err("finding status proof carrier exceeds the kernel size bound".to_owned());
        }
        let Some(status_verifier) = self.finding_status_proof_verifier.as_ref() else {
            return Err(
                "finding recovery requires a configured finding status verifier".to_owned(),
            );
        };
        let status_view = FindingStatusProofContextView {
            proof_b64,
            expected_finding_id: &verified.finding_id,
            expected_feed_id: &verified.expected_status_feed_id,
        };
        let status = status_verifier
            .verify_status_proof(&status_view)
            .map_err(|error| format!("finding recovery status proof rejected: {error}"))?;
        status_verifier
            .verify_status_admission(&status_view, &status, now_unix_secs)
            .map_err(|error| format!("finding recovery status admission rejected: {error}"))?;
        Ok(Some(verified))
    }
}

pub(crate) fn finding_recovery_block(
    binding: &VerifiedFindingRecovery,
) -> chio_core::receipt::metadata::FindingRecovery {
    chio_core::receipt::metadata::FindingRecovery {
        schema: chio_core::receipt::metadata::FINDING_RECOVERY_SCHEMA.to_owned(),
        recovery_id: binding.recovery_id.clone(),
        finding_id: binding.finding_id.clone(),
        original_capability_id: binding.original_capability_id.clone(),
        original_delivery_receipt_id: binding.original_delivery_receipt_id.clone(),
        purchase_key: binding.purchase_key.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_purchase::{FindingStatusProofVerifier, VerifiedFindingStatusProof};
    use crate::finding_recovery::{FindingRecoveryVerifier, VerifiedFindingRecovery};
    use crate::{HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};
    use chio_core::capability::governance::GovernedTransactionIntent;
    use chio_core::capability::scope::{
        ChioScope, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, Operation,
        PromptGrant, ResourceGrant,
    };
    use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core::crypto::Keypair;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    struct TestRecoveryVerifier {
        reservations: Arc<AtomicU64>,
    }

    impl FindingRecoveryVerifier for TestRecoveryVerifier {
        fn verify_recovery(
            &self,
            view: &FindingRecoveryContextView<'_>,
        ) -> Result<VerifiedFindingRecovery, String> {
            Ok(VerifiedFindingRecovery {
                recovery_id: view.marker.recovery_id.clone(),
                finding_id: view.marker.finding_id.clone(),
                listing_id: view.marker.listing_id.clone(),
                payload_sha256: view.expected_output_digest.to_owned(),
                expected_status_feed_id: "feed-1".to_owned(),
                original_capability_id: view.marker.original_capability_id.clone(),
                original_delivery_receipt_id: view.marker.original_delivery_receipt_id.clone(),
                purchase_key: view.marker.purchase_key.clone(),
                original_subject_key_hex: view.recovery_capability.subject.to_hex(),
            })
        }

        fn reserve_recovery_attempt(
            &self,
            _verified: &VerifiedFindingRecovery,
            _request_id: &str,
            _max_recoveries: u32,
            _now_unix_secs: u64,
        ) -> Result<(), String> {
            self.reservations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn record_recovery_receipt(
            &self,
            _verified: &VerifiedFindingRecovery,
            _recovery_receipt_id: &str,
            _recorded_at: u64,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    struct MutableStatusVerifier {
        deny: Arc<AtomicBool>,
    }

    impl FindingStatusProofVerifier for MutableStatusVerifier {
        fn verify_status_proof(
            &self,
            _view: &FindingStatusProofContextView<'_>,
        ) -> Result<VerifiedFindingStatusProof, String> {
            Ok(VerifiedFindingStatusProof {
                feed_id: "feed-1".to_owned(),
                key_domain_nonce: 1,
                map_epoch: 1,
                status_epoch_id: "epoch-1".to_owned(),
                status_epoch_artifact_sha256: "1".repeat(64),
                proof_sha256: "2".repeat(64),
                root_hash: "3".repeat(64),
                non_inclusion_checked_at: 1,
            })
        }

        fn verify_status_admission(
            &self,
            _view: &FindingStatusProofContextView<'_>,
            _verified: &VerifiedFindingStatusProof,
            _now_unix_secs: u64,
        ) -> Result<(), String> {
            if self.deny.load(Ordering::SeqCst) {
                Err("finding is pending retraction".to_owned())
            } else {
                Ok(())
            }
        }
    }

    fn marker() -> FindingRecoveryMarkerV1 {
        FindingRecoveryMarkerV1 {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            max_recoveries: 2,
        }
    }

    fn grant(extra: Vec<Constraint>) -> ToolGrant {
        let mut constraints = vec![
            Constraint::OutputDigestSha256("d".repeat(64)),
            Constraint::RequireFindingRecovery(Box::new(marker())),
        ];
        constraints.extend(extra);
        ToolGrant {
            server_id: "srv".to_owned(),
            tool_name: "read_finding".to_owned(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: Some(2),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }
    }

    fn capability() -> CapabilityToken {
        let key = Keypair::from_seed(&[9; 32]);
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "recovery-capability".to_owned(),
                issuer: key.public_key(),
                subject: key.public_key(),
                scope: ChioScope {
                    grants: vec![grant(Vec::new())],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: 1,
                expires_at: 2,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &key,
        )
        .expect("sign recovery capability")
    }

    fn kernel() -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair: Keypair::from_seed(&[8; 32]),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_owned(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: 60,
            max_stream_total_bytes: 1_048_576,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: 100,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        })
    }

    fn recovery_request() -> ToolCallRequest {
        let capability = capability();
        ToolCallRequest {
            request_id: "recovery-request".to_owned(),
            capability: capability.clone(),
            tool_name: "read_finding".to_owned(),
            server_id: "srv".to_owned(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({
                "finding_id": marker().finding_id,
                FINDING_RECOVERY_CONTEXT_ARGUMENT: "recovery-carrier"
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "recovery-intent".to_owned(),
                server_id: "srv".to_owned(),
                tool_name: "read_finding".to_owned(),
                purpose: "recover purchased finding".to_owned(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    FINDING_STATUS_PROOF_CONTEXT_KEY: "status-proof"
                })),
                body: Default::default(),
            }),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn dispatch_status_recheck_denies_without_reserving_again() {
        let deny = Arc::new(AtomicBool::new(false));
        let reservations = Arc::new(AtomicU64::new(0));
        let mut kernel = kernel();
        kernel.set_finding_recovery_verifier(Arc::new(TestRecoveryVerifier {
            reservations: Arc::clone(&reservations),
        }));
        kernel.set_finding_status_proof_verifier(Arc::new(MutableStatusVerifier {
            deny: Arc::clone(&deny),
        }));
        let request = recovery_request();
        let grant = &request.capability.scope.grants[0];

        assert!(kernel
            .verify_recovery_admission(grant, &request, 1)
            .expect("initial live admission")
            .is_some());
        assert_eq!(reservations.load(Ordering::SeqCst), 1);

        deny.store(true, Ordering::SeqCst);
        let error = kernel
            .verify_recovery_status_admission(grant, &request, 1)
            .expect_err("dispatch boundary must observe pending retraction");
        assert!(error.contains("pending retraction"));
        assert_eq!(reservations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recovery_profile_is_first_class_no_charge() {
        assert!(recovery_marked_grant(&grant(Vec::new()))
            .expect("valid recovery")
            .is_some());
        let mut priced = grant(Vec::new());
        priced.max_total_cost = Some(MonetaryAmount {
            units: 1,
            currency: "USD".to_owned(),
        });
        assert!(recovery_marked_grant(&priced).is_err());
        assert!(
            recovery_marked_grant(&grant(vec![Constraint::RequireFindingPurchase(Box::new(
                FindingPurchaseMarkerV1 {
                    finding_id: "b".repeat(64),
                    listing_id: "listing-1".to_owned(),
                    settlement: FindingSettlementSelector::LocalReversibleHold,
                }
            ),)]))
            .is_err()
        );
        assert!(recovery_marked_grant(&grant(vec![Constraint::Custom(
            "recovery_of_receipt_id".to_owned(),
            "receipt-original".to_owned(),
        )]))
        .is_err());

        let mut legacy = grant(Vec::new());
        legacy.constraints = vec![
            Constraint::Custom(
                "recovery_of_receipt_id".to_owned(),
                "receipt-original".to_owned(),
            ),
            Constraint::Custom(
                "recovery_of_capability_id".to_owned(),
                "capability-original".to_owned(),
            ),
        ];
        assert!(recovery_marked_grant(&legacy).is_err());

        let mut widened = grant(Vec::new());
        widened.operations.push(Operation::Read);
        assert!(recovery_marked_grant(&widened).is_err());
    }

    #[test]
    fn recovery_receipt_block_keeps_original_lineage() {
        let verified = VerifiedFindingRecovery {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            payload_sha256: "d".repeat(64),
            expected_status_feed_id: "feed-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            original_subject_key_hex: "e".repeat(64),
        };
        let block = finding_recovery_block(&verified);
        block.validate().expect("valid recovery block");
        assert_eq!(block.recovery_id, verified.recovery_id);
        assert_eq!(
            block.original_delivery_receipt_id,
            verified.original_delivery_receipt_id
        );
        assert_eq!(block.purchase_key, verified.purchase_key);
    }

    #[test]
    fn recovery_capability_rejects_additional_authority_surfaces() {
        assert!(validate_recovery_capability_profile(&capability()).is_ok());

        let mut additional_grant = capability();
        additional_grant.scope.grants.push(grant(Vec::new()));
        assert!(validate_recovery_capability_profile(&additional_grant).is_err());

        let mut ordinary = capability();
        ordinary.scope.grants.iter_mut().for_each(|grant| {
            grant.constraints = vec![Constraint::OutputDigestSha256("d".repeat(64))]
        });
        ordinary.scope.grants.push(ordinary.scope.grants[0].clone());
        assert!(validate_recovery_capability_profile(&ordinary).is_ok());

        let mut resource = capability();
        resource.scope.resource_grants.push(ResourceGrant {
            uri_pattern: "*".to_owned(),
            operations: vec![Operation::Read],
        });
        assert!(validate_recovery_capability_profile(&resource).is_err());

        let mut prompt = capability();
        prompt.scope.prompt_grants.push(PromptGrant {
            prompt_name: "*".to_owned(),
            operations: vec![Operation::Get],
        });
        assert!(validate_recovery_capability_profile(&prompt).is_err());
    }
}
