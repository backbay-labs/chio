//! SQLite-backed composition for the opt-in Finding memory quarantine guard.
//!
//! The guard itself stays storage-agnostic. This module supplies the hosted
//! profile that joins durable memory provenance, a signed typed receipt edge,
//! and the cryptographically re-verified local status cache.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::governance::ProvenanceEvidenceClass;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::ReceiptLineageRelationKind;
use chio_core::receipt::metadata::{FindingDelivery, FINDING_DELIVERY_METADATA_KEY};
use chio_core::session::SessionAnchorReference;
use chio_guards::finding_retraction::{
    AuthenticatedFindingStatus, FindingDeliveryLineageResolver, FindingRetractionClock,
    FindingRetractionResolveError, FindingRetractionResolver, FindingStatusCache,
    FindingStatusValue, VerifiedFindingDeliveryLineage, VerifiedFindingRetractionResolver,
};
use chio_kernel::{MemoryProvenanceStore, ReceiptStore, RetainedReceiptCommitment};
use chio_store_sqlite::{FindingStatusDecision, FindingStatusProofKind, SqliteFindingStatusStore};

use super::finding_status_verifier::verify_proof_record;
use super::{FindingMarketConfig, FindingStatusOperatorPin, FindingStatusServiceBond};

/// Wall clock used by the hosted synchronous guard profile, fenced by the
/// authenticated durable status-feed high-water.
#[derive(Clone)]
pub struct SystemFindingRetractionClock {
    feed_id: String,
    store: SqliteFindingStatusStore,
}

impl SystemFindingRetractionClock {
    fn new(feed_id: String, store: SqliteFindingStatusStore) -> Self {
        Self { feed_id, store }
    }
}

impl FindingRetractionClock for SystemFindingRetractionClock {
    fn now_unix_secs(&self) -> Result<u64, FindingRetractionResolveError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|error| FindingRetractionResolveError::ClockUnavailable(error.to_string()))?;
        self.store
            .observe_trusted_time(&self.feed_id, now)
            .map_err(|error| FindingRetractionResolveError::ClockUnavailable(error.to_string()))?;
        Ok(now)
    }
}

/// Resolve only the signed child-memory-write -> parent-delivery lineage edge.
pub struct ReceiptStoreFindingDeliveryLineageResolver {
    receipts: Arc<dyn ReceiptStore>,
}

impl ReceiptStoreFindingDeliveryLineageResolver {
    #[must_use]
    pub fn new(receipts: Arc<dyn ReceiptStore>) -> Self {
        Self { receipts }
    }
}

fn verify_retained_parent_receipt(
    parent: &ChioReceipt,
    expected_receipt_id: &str,
    expected_anchor: &SessionAnchorReference,
) -> Result<(), FindingRetractionResolveError> {
    if parent.id != expected_receipt_id
        || !parent
            .verify_signature()
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
    {
        return Err(FindingRetractionResolveError::InvalidLineage(
            "Finding delivery parent is not an authentic retained receipt".to_owned(),
        ));
    }
    let parent_bytes = chio_core::canonical::canonical_json_bytes(parent)
        .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
    if expected_anchor.session_anchor_id != format!("receipt:{}", parent.id)
        || expected_anchor.session_anchor_hash != chio_core::crypto::sha256_hex(&parent_bytes)
    {
        return Err(FindingRetractionResolveError::InvalidLineage(
            "Finding delivery parent differs from the signed lineage anchor".to_owned(),
        ));
    }
    Ok(())
}

fn verify_retained_child_receipt(
    child: &ChioReceipt,
    commitment: &RetainedReceiptCommitment,
    expected_receipt_id: &str,
    expected_capability_id: &str,
    expected_anchor: &SessionAnchorReference,
) -> Result<(), FindingRetractionResolveError> {
    if child.id != expected_receipt_id
        || child.capability_id != expected_capability_id
        || !matches!(child.action.verify_hash(), Ok(true))
        || !child
            .verify_signature()
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
    {
        return Err(FindingRetractionResolveError::InvalidLineage(
            "memory write child is not an authentic retained receipt".to_owned(),
        ));
    }
    let child_bytes = chio_core::canonical::canonical_json_bytes(child)
        .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
    let child_sha256 = chio_core::crypto::sha256_hex(&child_bytes);
    if commitment.receipt_id != child.id
        || commitment.receipt_sha256 != child_sha256
        || commitment.kernel_key != child.kernel_key
    {
        return Err(FindingRetractionResolveError::InvalidLineage(
            "memory write child differs from the append-only receipt commitment".to_owned(),
        ));
    }
    if expected_anchor.session_anchor_id != format!("receipt:{}", child.id)
        || expected_anchor.session_anchor_hash != child_sha256
    {
        return Err(FindingRetractionResolveError::InvalidLineage(
            "memory write child differs from the signed lineage anchor".to_owned(),
        ));
    }
    Ok(())
}

impl FindingDeliveryLineageResolver for ReceiptStoreFindingDeliveryLineageResolver {
    fn verified_finding_parent(
        &self,
        memory_write_receipt_id: &str,
        memory_write_capability_id: &str,
    ) -> Result<Option<VerifiedFindingDeliveryLineage>, FindingRetractionResolveError> {
        let child = self
            .receipts
            .load_retained_chio_receipt(memory_write_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        let Some(child) = child else {
            return Ok(None);
        };
        let statement = self
            .receipts
            .load_retained_receipt_lineage_statement(memory_write_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        let Some(statement) = statement else {
            return Ok(None);
        };
        let commitment = self
            .receipts
            .load_retained_chio_receipt_commitment(memory_write_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
            .ok_or_else(|| {
                FindingRetractionResolveError::InvalidLineage(
                    "memory write child has no append-only receipt commitment".to_owned(),
                )
            })?;
        verify_retained_child_receipt(
            &child,
            &commitment,
            memory_write_receipt_id,
            memory_write_capability_id,
            &statement.child_session_anchor,
        )?;
        if statement.child_receipt_id != memory_write_receipt_id
            || statement.relation_kind != ReceiptLineageRelationKind::FindingMemoryWriteToDelivery
            || statement.evidence_class != ProvenanceEvidenceClass::Verified
            || statement.kernel_key != child.kernel_key
            || !statement
                .verify_signature()
                .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
        {
            return Err(FindingRetractionResolveError::InvalidLineage(
                "typed Finding delivery lineage statement is invalid".to_owned(),
            ));
        }
        let verification = self
            .receipts
            .get_retained_receipt_lineage_verification(memory_write_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
            .ok_or_else(|| {
                FindingRetractionResolveError::InvalidLineage(
                    "receipt lineage verification is unavailable".to_owned(),
                )
            })?;
        if verification.receipt_id != memory_write_receipt_id
            || !verification.parent_receipt_verified
        {
            return Err(FindingRetractionResolveError::InvalidLineage(
                "typed Finding lineage parent is not a verified durable receipt".to_owned(),
            ));
        }
        let parent = self
            .receipts
            .load_retained_chio_receipt(&statement.parent_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?
            .ok_or_else(|| {
                FindingRetractionResolveError::InvalidLineage(
                    "Finding delivery receipt is unavailable".to_owned(),
                )
            })?;
        verify_retained_parent_receipt(
            &parent,
            &statement.parent_receipt_id,
            &statement.parent_session_anchor,
        )?;
        let delivery_value = parent
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
            .cloned()
            .ok_or_else(|| {
                FindingRetractionResolveError::InvalidLineage(
                    "lineage parent is not a Finding delivery receipt".to_owned(),
                )
            })?;
        let delivery: FindingDelivery = serde_json::from_value(delivery_value)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        delivery
            .validate()
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        let status_feed_id = delivery
            .status_proof
            .as_ref()
            .map(|proof| proof.feed_id.clone())
            .ok_or_else(|| {
                FindingRetractionResolveError::InvalidLineage(
                    "Finding delivery lineage has no authenticated status feed".to_owned(),
                )
            })?;
        let memory_content = child.action.parameters.get("content").ok_or_else(|| {
            FindingRetractionResolveError::InvalidLineage(
                "memory write child omits the committed content".to_owned(),
            )
        })?;
        let memory_content_bytes = chio_core::canonical::canonical_json_bytes(memory_content)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        Ok(Some(VerifiedFindingDeliveryLineage {
            memory_write_receipt_id: child.id,
            memory_write_capability_id: child.capability_id,
            delivery_receipt_id: parent.id,
            finding_id: delivery.finding_id,
            status_feed_id,
            memory_content_sha256: chio_core::crypto::sha256_hex(&memory_content_bytes),
        }))
    }
}

/// Authenticated status cache backed by the durable status rollback floor.
pub struct SqliteFindingStatusCache {
    feed_id: String,
    operator: FindingStatusOperatorPin,
    service_bond: FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    store: SqliteFindingStatusStore,
    clock: Arc<dyn FindingRetractionClock>,
}

impl SqliteFindingStatusCache {
    pub fn new(
        config: &FindingMarketConfig,
        store: SqliteFindingStatusStore,
        clock: Arc<dyn FindingRetractionClock>,
    ) -> Result<Self, FindingRetractionResolveError> {
        config
            .validate()
            .map_err(|error| FindingRetractionResolveError::InvalidStatus(error.to_string()))?;
        Ok(Self {
            feed_id: config.status_feed_operator_ref.clone(),
            operator: config.status_feed_operator.clone(),
            service_bond: config.status_feed_service_bond.clone(),
            max_epoch_age_secs: config.status_max_epoch_age_secs,
            store,
            clock,
        })
    }
}

impl FindingStatusCache for SqliteFindingStatusCache {
    fn authenticated_status(
        &self,
        finding_id: &str,
    ) -> Result<Option<AuthenticatedFindingStatus>, FindingRetractionResolveError> {
        let now = self.clock.now_unix_secs()?;
        let (proof, expected_kind) = match self
            .store
            .status_for_purchase(&self.feed_id, finding_id, now, self.max_epoch_age_secs)
            .map_err(|error| FindingRetractionResolveError::StatusUnavailable(error.to_string()))?
        {
            FindingStatusDecision::VerifiedLive(proof) => {
                (proof, FindingStatusProofKind::NonInclusion)
            }
            FindingStatusDecision::Pending(_) => {
                return Err(FindingRetractionResolveError::StatusUnavailable(
                    "finding retraction publication is pending".to_owned(),
                ));
            }
            FindingStatusDecision::Retracted(_) => (
                self.store
                    .get_latest_proof(&self.feed_id, finding_id)
                    .map_err(|error| {
                        FindingRetractionResolveError::StatusUnavailable(error.to_string())
                    })?
                    .ok_or_else(|| {
                        FindingRetractionResolveError::StatusUnavailable(
                            "retracted finding has no durable inclusion proof".to_owned(),
                        )
                    })?,
                FindingStatusProofKind::Inclusion,
            ),
        };
        let verified_at = self.clock.now_unix_secs()?;
        verify_proof_record(
            &self.operator,
            &self.service_bond,
            self.max_epoch_age_secs,
            &proof,
            verified_at,
        )
        .map_err(|denial| FindingRetractionResolveError::InvalidStatus(denial.to_string()))?;
        if proof.kind != expected_kind {
            return Err(FindingRetractionResolveError::InvalidStatus(
                "durable status decision and portable proof kind differ".to_owned(),
            ));
        }
        let final_now = self.clock.now_unix_secs()?;
        verify_proof_record(
            &self.operator,
            &self.service_bond,
            self.max_epoch_age_secs,
            &proof,
            final_now,
        )
        .map_err(|denial| FindingRetractionResolveError::InvalidStatus(denial.to_string()))?;
        let final_decision = self
            .store
            .status_for_purchase(
                &self.feed_id,
                finding_id,
                final_now,
                self.max_epoch_age_secs,
            )
            .map_err(|error| FindingRetractionResolveError::StatusUnavailable(error.to_string()))?;
        let decision_unchanged = match final_decision {
            FindingStatusDecision::VerifiedLive(final_proof) => {
                expected_kind == FindingStatusProofKind::NonInclusion && final_proof == proof
            }
            FindingStatusDecision::Retracted(_) => {
                expected_kind == FindingStatusProofKind::Inclusion
                    && self
                        .store
                        .get_latest_proof(&self.feed_id, finding_id)
                        .map_err(|error| {
                            FindingRetractionResolveError::StatusUnavailable(error.to_string())
                        })?
                        .is_some_and(|final_proof| final_proof == proof)
            }
            FindingStatusDecision::Pending(_) => false,
        };
        if !decision_unchanged {
            return Err(FindingRetractionResolveError::StatusUnavailable(
                "finding status changed after proof verification".to_owned(),
            ));
        }
        let value = match proof.kind {
            FindingStatusProofKind::NonInclusion => FindingStatusValue::Live,
            FindingStatusProofKind::Inclusion => FindingStatusValue::Retracted,
        };
        Ok(Some(AuthenticatedFindingStatus {
            finding_id: proof.finding_id,
            feed_id: proof.feed_id,
            map_epoch: proof.map_epoch,
            epoch_id: proof.epoch_id,
            root_hash: proof.root_hash,
            checked_at: proof.checked_at,
            valid_until: proof.valid_until,
            value,
        }))
    }
}

/// Compose the production resolver used by `MemoryGovernanceGuard`.
pub fn sqlite_finding_retraction_resolver(
    resolver_id: impl Into<String>,
    config: &FindingMarketConfig,
    provenance: Arc<dyn MemoryProvenanceStore>,
    receipts: Arc<dyn ReceiptStore>,
    status_store: SqliteFindingStatusStore,
) -> Result<Arc<dyn FindingRetractionResolver>, FindingRetractionResolveError> {
    let clock: Arc<dyn FindingRetractionClock> = Arc::new(SystemFindingRetractionClock::new(
        config.status_feed_operator_ref.clone(),
        status_store.clone(),
    ));
    let lineage: Arc<dyn FindingDeliveryLineageResolver> =
        Arc::new(ReceiptStoreFindingDeliveryLineageResolver::new(receipts));
    let status: Arc<dyn FindingStatusCache> = Arc::new(SqliteFindingStatusCache::new(
        config,
        status_store,
        Arc::clone(&clock),
    )?);
    Ok(Arc::new(VerifiedFindingRetractionResolver::new(
        resolver_id,
        config.status_feed_operator_ref.clone(),
        provenance,
        lineage,
        status,
        clock,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::body::ChioReceiptBody;
    use chio_core::receipt::decision::{Decision, ToolCallAction};
    use chio_core::receipt::kinds::TrustLevel;
    use chio_test_support::prelude::*;

    fn signed_parent_receipt() -> ChioReceipt {
        let kernel = Keypair::from_seed(&[81; 32]);
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "parent-fixture".to_owned(),
                timestamp: 1_750_000_000,
                capability_id: "capability-fixture".to_owned(),
                tool_server: "finding-market".to_owned(),
                tool_name: "finding.purchase".to_owned(),
                action: ToolCallAction::from_parameters(serde_json::json!({"finding": "f-1"}))
                    .test_expect("fixture action is canonical"),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: chio_core::crypto::sha256_hex(b"finding-content"),
                policy_hash: chio_core::crypto::sha256_hex(b"finding-policy"),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({"finding_delivery": {"finding_id": "f-1"}})),
                trust_level: TrustLevel::Mediated,
                tenant_id: None,
                kernel_key: kernel.public_key(),
                bbs_projection_version: None,
            },
            &kernel,
        )
        .test_expect("fixture receipt signs")
    }

    fn signed_child_receipt() -> ChioReceipt {
        let kernel = Keypair::from_seed(&[82; 32]);
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "child-fixture".to_owned(),
                timestamp: 1_750_000_001,
                capability_id: "memory-capability-fixture".to_owned(),
                tool_server: "memory".to_owned(),
                tool_name: "memory_write".to_owned(),
                action: ToolCallAction::from_parameters(serde_json::json!({
                    "collection": "purchased-findings",
                    "id": "f-1",
                    "content": {"payload": "verified"}
                }))
                .test_expect("fixture action is canonical"),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: chio_core::crypto::sha256_hex(b"memory-write-result"),
                policy_hash: chio_core::crypto::sha256_hex(b"memory-policy"),
                evidence: Vec::new(),
                metadata: None,
                trust_level: TrustLevel::Mediated,
                tenant_id: None,
                kernel_key: kernel.public_key(),
                bbs_projection_version: None,
            },
            &kernel,
        )
        .test_expect("fixture receipt signs")
    }

    fn exact_anchor(parent: &ChioReceipt) -> SessionAnchorReference {
        let canonical = chio_core::canonical::canonical_json_bytes(parent)
            .test_expect("fixture receipt canonicalizes");
        SessionAnchorReference::new(
            format!("receipt:{}", parent.id),
            chio_core::crypto::sha256_hex(&canonical),
        )
    }

    fn exact_commitment(receipt: &ChioReceipt) -> RetainedReceiptCommitment {
        let canonical = chio_core::canonical::canonical_json_bytes(receipt)
            .test_expect("fixture receipt canonicalizes");
        RetainedReceiptCommitment {
            entry_seq: 1,
            receipt_id: receipt.id.clone(),
            receipt_sha256: chio_core::crypto::sha256_hex(&canonical),
            kernel_key: receipt.kernel_key.clone(),
        }
    }

    #[test]
    fn retained_parent_reverifies_receipt_and_exact_lineage_anchor() {
        let parent = signed_parent_receipt();
        let anchor = exact_anchor(&parent);
        assert!(verify_retained_parent_receipt(&parent, &parent.id, &anchor).is_ok());

        let mut tampered = parent.clone();
        tampered.metadata = Some(serde_json::json!({"finding_delivery": {"finding_id": "f-2"}}));
        let tampered_anchor = exact_anchor(&tampered);
        assert!(verify_retained_parent_receipt(&tampered, &parent.id, &tampered_anchor).is_err());

        let substituted_anchor = SessionAnchorReference::new(
            format!("receipt:{}", parent.id),
            chio_core::crypto::sha256_hex(b"substituted-parent"),
        );
        assert!(verify_retained_parent_receipt(&parent, &parent.id, &substituted_anchor).is_err());
    }

    #[test]
    fn retained_child_reverifies_receipt_and_exact_lineage_anchor() {
        let child = signed_child_receipt();
        let anchor = exact_anchor(&child);
        let commitment = exact_commitment(&child);
        assert!(verify_retained_child_receipt(
            &child,
            &commitment,
            &child.id,
            &child.capability_id,
            &anchor,
        )
        .is_ok());

        let mut substituted = child.clone();
        substituted.action = ToolCallAction::from_parameters(serde_json::json!({
            "collection": "purchased-findings",
            "id": "f-1",
            "content": {"payload": "substituted"}
        }))
        .test_expect("substituted action is canonical");
        assert!(verify_retained_child_receipt(
            &substituted,
            &commitment,
            &child.id,
            &child.capability_id,
            &anchor,
        )
        .is_err());

        let wrong_anchor = SessionAnchorReference::new(
            format!("receipt:{}", child.id),
            chio_core::crypto::sha256_hex(b"substituted-child"),
        );
        assert!(verify_retained_child_receipt(
            &child,
            &commitment,
            &child.id,
            &child.capability_id,
            &wrong_anchor,
        )
        .is_err());

        let substituted_commitment = RetainedReceiptCommitment {
            receipt_sha256: chio_core::crypto::sha256_hex(b"substituted-child"),
            kernel_key: Keypair::from_seed(&[83; 32]).public_key(),
            ..commitment
        };
        assert!(verify_retained_child_receipt(
            &child,
            &substituted_commitment,
            &child.id,
            &child.capability_id,
            &anchor,
        )
        .is_err());
    }
}
