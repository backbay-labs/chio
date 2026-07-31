//! First-class no-charge finding-recovery admission and receipt metadata.

use chio_core::capability::scope::{Constraint, FindingRecoveryMarkerV1, ToolGrant};

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

impl ChioKernel {
    /// Deterministically re-derive a recovery binding from the frozen request.
    pub(crate) fn verify_recovery_context(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
    ) -> Result<Option<VerifiedFindingRecovery>, String> {
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
        let Some(verified) = self.verify_recovery_context(grant, request)? else {
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
    use chio_core::capability::scope::{
        FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, Operation,
    };

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
    }

    #[test]
    fn recovery_receipt_block_keeps_original_lineage() {
        let verified = VerifiedFindingRecovery {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            payload_sha256: "d".repeat(64),
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
}
