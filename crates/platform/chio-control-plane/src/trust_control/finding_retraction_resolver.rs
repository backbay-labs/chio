//! SQLite-backed composition for the opt-in Finding memory quarantine guard.
//!
//! The guard itself stays storage-agnostic. This module supplies the hosted
//! profile that joins durable memory provenance, a signed typed receipt edge,
//! and the cryptographically re-verified local status cache.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::governance::ProvenanceEvidenceClass;
use chio_core::receipt::lineage::ReceiptLineageRelationKind;
use chio_core::receipt::metadata::{FindingDelivery, FINDING_DELIVERY_METADATA_KEY};
use chio_guards::finding_retraction::{
    AuthenticatedFindingStatus, FindingDeliveryLineageResolver, FindingRetractionClock,
    FindingRetractionResolveError, FindingRetractionResolver, FindingStatusCache,
    FindingStatusValue, VerifiedFindingDeliveryLineage, VerifiedFindingRetractionResolver,
};
use chio_kernel::{MemoryProvenanceStore, ReceiptStore};
use chio_store_sqlite::{FindingStatusDecision, FindingStatusProofKind, SqliteFindingStatusStore};

use super::finding_status_verifier::verify_proof_record;
use super::{FindingMarketConfig, FindingStatusOperatorPin, FindingStatusServiceBond};

/// Wall clock used by the hosted synchronous guard profile.
#[derive(Debug, Default)]
pub struct SystemFindingRetractionClock;

impl FindingRetractionClock for SystemFindingRetractionClock {
    fn now_unix_secs(&self) -> Result<u64, FindingRetractionResolveError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|error| FindingRetractionResolveError::ClockUnavailable(error.to_string()))
    }
}

/// Resolve only the signed M6-specific child-write -> parent-delivery edge.
pub struct ReceiptStoreFindingDeliveryLineageResolver {
    receipts: Arc<dyn ReceiptStore>,
}

impl ReceiptStoreFindingDeliveryLineageResolver {
    #[must_use]
    pub fn new(receipts: Arc<dyn ReceiptStore>) -> Self {
        Self { receipts }
    }
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
        if child.id != memory_write_receipt_id || child.capability_id != memory_write_capability_id
        {
            return Err(FindingRetractionResolveError::InvalidLineage(
                "memory write receipt or capability binding differs".to_owned(),
            ));
        }
        let statement = self
            .receipts
            .load_retained_receipt_lineage_statement(memory_write_receipt_id)
            .map_err(|error| FindingRetractionResolveError::InvalidLineage(error.to_string()))?;
        let Some(statement) = statement else {
            return Ok(None);
        };
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
        Ok(Some(VerifiedFindingDeliveryLineage {
            memory_write_receipt_id: child.id,
            memory_write_capability_id: child.capability_id,
            delivery_receipt_id: parent.id,
            finding_id: delivery.finding_id,
        }))
    }
}

/// Authenticated status cache backed by the durable M6 rollback floor.
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
            .status_for_purchase(&self.feed_id, finding_id, now)
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
        verify_proof_record(
            &self.operator,
            &self.service_bond,
            self.max_epoch_age_secs,
            &proof,
            now,
        )
        .map_err(FindingRetractionResolveError::InvalidStatus)?;
        if proof.kind != expected_kind {
            return Err(FindingRetractionResolveError::InvalidStatus(
                "durable status decision and portable proof kind differ".to_owned(),
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
    let clock: Arc<dyn FindingRetractionClock> = Arc::new(SystemFindingRetractionClock);
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
