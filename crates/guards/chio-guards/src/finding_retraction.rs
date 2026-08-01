//! Verified Finding retraction resolution for governed memory reads.
//!
//! The resolver composes three independently durable boundaries:
//!
//! 1. the kernel's verified memory provenance chain resolves `(store, key)`
//!    to the governed write receipt and capability;
//! 2. a verified typed lineage edge resolves that write to its parent Finding
//!    delivery receipt and Finding id; and
//! 3. an authenticated local status cache resolves the Finding against the
//!    admission-pinned feed and a fresh signed sparse-map epoch.
//!
//! Each missing, unavailable, stale, or cross-bound value fails closed. The
//! trait boundary is synchronous because guard evaluation cannot defer a
//! memory read while a network lookup completes.

use std::sync::Arc;

use chio_kernel::{MemoryProvenanceStore, ProvenanceVerification, UnverifiedReason};

/// Stable resolver profile implemented by this composition.
pub const FINDING_RETRACTION_RESOLVER_PROFILE: &str = "chio.finding.retraction-resolver.v1";

/// Query issued by [`crate::MemoryGovernanceGuard`] for one exact memory key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingRetractionQuery<'a> {
    pub store: &'a str,
    pub key: &'a str,
}

/// Verified typed lineage from one governed memory write to one delivered
/// Finding. Implementations return this value only after verifying the signed
/// lineage statement, both receipt identities, and capability binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFindingDeliveryLineage {
    pub memory_write_receipt_id: String,
    pub memory_write_capability_id: String,
    pub delivery_receipt_id: String,
    pub finding_id: String,
}

/// Durable verified-lineage lookup used by the resolver.
pub trait FindingDeliveryLineageResolver: Send + Sync {
    fn verified_finding_parent(
        &self,
        memory_write_receipt_id: &str,
        memory_write_capability_id: &str,
    ) -> Result<Option<VerifiedFindingDeliveryLineage>, FindingRetractionResolveError>;
}

/// Status represented by an authenticated local cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusValue {
    Live,
    Pending,
    Retracted,
}

/// Cache record created only from an authorized signed status epoch and a
/// verified portable proof. The cache implementation is responsible for its
/// durable rollback and equivocation floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedFindingStatus {
    pub finding_id: String,
    pub feed_id: String,
    pub map_epoch: u64,
    pub epoch_id: String,
    pub root_hash: String,
    pub checked_at: u64,
    pub valid_until: u64,
    pub value: FindingStatusValue,
}

/// Authenticated local status cache. Implementations must not perform a
/// caller-directed online lookup or return an unsigned root.
pub trait FindingStatusCache: Send + Sync {
    fn authenticated_status(
        &self,
        finding_id: &str,
    ) -> Result<Option<AuthenticatedFindingStatus>, FindingRetractionResolveError>;
}

/// Trusted clock used to enforce the signed epoch freshness window.
pub trait FindingRetractionClock: Send + Sync {
    fn now_unix_secs(&self) -> Result<u64, FindingRetractionResolveError>;
}

/// Successful resolution returned to the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRetractionResolution {
    pub delivery_receipt_id: String,
    pub finding_id: String,
    pub feed_id: String,
    pub map_epoch: u64,
    pub epoch_id: String,
    pub root_hash: String,
    pub value: FindingStatusValue,
}

/// Synchronous resolver injected into the opt-in memory guard profile.
pub trait FindingRetractionResolver: Send + Sync {
    fn resolver_id(&self) -> &str;
    fn feed_id(&self) -> &str;
    fn resolve(
        &self,
        query: FindingRetractionQuery<'_>,
    ) -> Result<FindingRetractionResolution, FindingRetractionResolveError>;
}

/// Fail-closed resolver errors. The guard deliberately maps every variant to
/// Deny while callers may retain the detail for operator diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingRetractionResolveError {
    #[error("memory provenance is missing")]
    MissingProvenance,
    #[error("memory provenance failed verification: {0}")]
    InvalidProvenance(String),
    #[error("memory provenance store is unavailable: {0}")]
    ProvenanceUnavailable(String),
    #[error("finding delivery lineage is missing")]
    MissingLineage,
    #[error("finding delivery lineage binding is invalid: {0}")]
    InvalidLineage(String),
    #[error("finding status cache is unavailable: {0}")]
    StatusUnavailable(String),
    #[error("finding status cache has no entry")]
    MissingStatus,
    #[error("finding status binding is invalid: {0}")]
    InvalidStatus(String),
    #[error("finding status root is stale")]
    StaleStatus,
    #[error("trusted status time is unavailable: {0}")]
    ClockUnavailable(String),
}

/// Production composition over injected durable stores. The component traits
/// make platform persistence replaceable without moving verification into
/// caller-controlled request fields.
pub struct VerifiedFindingRetractionResolver {
    resolver_id: String,
    feed_id: String,
    provenance: Arc<dyn MemoryProvenanceStore>,
    lineage: Arc<dyn FindingDeliveryLineageResolver>,
    status: Arc<dyn FindingStatusCache>,
    clock: Arc<dyn FindingRetractionClock>,
}

impl VerifiedFindingRetractionResolver {
    pub fn new(
        resolver_id: impl Into<String>,
        feed_id: impl Into<String>,
        provenance: Arc<dyn MemoryProvenanceStore>,
        lineage: Arc<dyn FindingDeliveryLineageResolver>,
        status: Arc<dyn FindingStatusCache>,
        clock: Arc<dyn FindingRetractionClock>,
    ) -> Result<Self, FindingRetractionResolveError> {
        let resolver_id = resolver_id.into();
        let feed_id = feed_id.into();
        if resolver_id.trim().is_empty() || resolver_id.trim() != resolver_id {
            return Err(FindingRetractionResolveError::InvalidStatus(
                "resolver id must be non-empty and unpadded".to_owned(),
            ));
        }
        if feed_id.trim().is_empty() || feed_id.trim() != feed_id {
            return Err(FindingRetractionResolveError::InvalidStatus(
                "feed id must be non-empty and unpadded".to_owned(),
            ));
        }
        Ok(Self {
            resolver_id,
            feed_id,
            provenance,
            lineage,
            status,
            clock,
        })
    }

    fn verified_provenance(
        &self,
        query: FindingRetractionQuery<'_>,
    ) -> Result<chio_kernel::MemoryProvenanceEntry, FindingRetractionResolveError> {
        let latest = self
            .provenance
            .latest_for_key(query.store, query.key)
            .map_err(|error| {
                FindingRetractionResolveError::ProvenanceUnavailable(error.to_string())
            })?
            .ok_or(FindingRetractionResolveError::MissingProvenance)?;
        match self
            .provenance
            .verify_entry(&latest.entry_id)
            .map_err(|error| {
                FindingRetractionResolveError::ProvenanceUnavailable(error.to_string())
            })? {
            ProvenanceVerification::Verified {
                entry,
                chain_digest,
            } if entry == latest && is_hex64(&chain_digest) => Ok(entry),
            ProvenanceVerification::Verified { .. } => {
                Err(FindingRetractionResolveError::InvalidProvenance(
                    "verified entry or chain digest does not match the latest key".to_owned(),
                ))
            }
            ProvenanceVerification::Unverified { reason } => {
                let detail = match reason {
                    UnverifiedReason::NoProvenance => "no provenance",
                    UnverifiedReason::ChainTampered => "chain tampered",
                    UnverifiedReason::ChainLinkBroken => "chain link broken",
                    UnverifiedReason::StoreUnavailable => "store unavailable",
                };
                Err(FindingRetractionResolveError::InvalidProvenance(
                    detail.to_owned(),
                ))
            }
        }
    }
}

impl FindingRetractionResolver for VerifiedFindingRetractionResolver {
    fn resolver_id(&self) -> &str {
        &self.resolver_id
    }

    fn feed_id(&self) -> &str {
        &self.feed_id
    }

    fn resolve(
        &self,
        query: FindingRetractionQuery<'_>,
    ) -> Result<FindingRetractionResolution, FindingRetractionResolveError> {
        if query.store.trim().is_empty()
            || query.store.trim() != query.store
            || query.key.trim().is_empty()
            || query.key.trim() != query.key
        {
            return Err(FindingRetractionResolveError::InvalidProvenance(
                "memory store and key must be non-empty and unpadded".to_owned(),
            ));
        }
        let provenance = self.verified_provenance(query)?;
        let lineage = self
            .lineage
            .verified_finding_parent(&provenance.receipt_id, &provenance.capability_id)?
            .ok_or(FindingRetractionResolveError::MissingLineage)?;
        if lineage.memory_write_receipt_id != provenance.receipt_id
            || lineage.memory_write_capability_id != provenance.capability_id
            || lineage.delivery_receipt_id.trim().is_empty()
            || lineage.finding_id.trim().is_empty()
        {
            return Err(FindingRetractionResolveError::InvalidLineage(
                "write receipt, capability, delivery receipt, or finding binding differs"
                    .to_owned(),
            ));
        }
        let status = self
            .status
            .authenticated_status(&lineage.finding_id)?
            .ok_or(FindingRetractionResolveError::MissingStatus)?;
        if status.finding_id != lineage.finding_id
            || status.feed_id != self.feed_id
            || !is_hex64(&status.epoch_id)
            || !is_hex64(&status.root_hash)
            || status.checked_at > status.valid_until
        {
            return Err(FindingRetractionResolveError::InvalidStatus(
                "finding, feed, epoch, root, or validity binding differs".to_owned(),
            ));
        }
        let now = self
            .clock
            .now_unix_secs()
            .map_err(|error| FindingRetractionResolveError::ClockUnavailable(error.to_string()))?;
        if status.checked_at > now || now > status.valid_until {
            return Err(FindingRetractionResolveError::StaleStatus);
        }
        Ok(FindingRetractionResolution {
            delivery_receipt_id: lineage.delivery_receipt_id,
            finding_id: lineage.finding_id,
            feed_id: status.feed_id,
            map_epoch: status.map_epoch,
            epoch_id: status.epoch_id,
            root_hash: status.root_hash,
            value: status.value,
        })
    }
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::{InMemoryMemoryProvenanceStore, MemoryProvenanceAppend};

    struct StaticLineage {
        value: Option<VerifiedFindingDeliveryLineage>,
    }

    impl FindingDeliveryLineageResolver for StaticLineage {
        fn verified_finding_parent(
            &self,
            _memory_write_receipt_id: &str,
            _memory_write_capability_id: &str,
        ) -> Result<Option<VerifiedFindingDeliveryLineage>, FindingRetractionResolveError> {
            Ok(self.value.clone())
        }
    }

    struct StaticStatus {
        value: Option<AuthenticatedFindingStatus>,
    }

    impl FindingStatusCache for StaticStatus {
        fn authenticated_status(
            &self,
            _finding_id: &str,
        ) -> Result<Option<AuthenticatedFindingStatus>, FindingRetractionResolveError> {
            Ok(self.value.clone())
        }
    }

    struct StaticClock(u64);

    impl FindingRetractionClock for StaticClock {
        fn now_unix_secs(&self) -> Result<u64, FindingRetractionResolveError> {
            Ok(self.0)
        }
    }

    fn resolver(
        status_value: FindingStatusValue,
        valid_until: u64,
        now: u64,
    ) -> VerifiedFindingRetractionResolver {
        let provenance = Arc::new(InMemoryMemoryProvenanceStore::new());
        provenance
            .append(MemoryProvenanceAppend {
                store: "memory".to_owned(),
                key: "key-1".to_owned(),
                capability_id: "cap-1".to_owned(),
                receipt_id: "write-receipt-1".to_owned(),
                written_at: 5,
            })
            .expect("append test provenance");
        let lineage = Arc::new(StaticLineage {
            value: Some(VerifiedFindingDeliveryLineage {
                memory_write_receipt_id: "write-receipt-1".to_owned(),
                memory_write_capability_id: "cap-1".to_owned(),
                delivery_receipt_id: "delivery-receipt-1".to_owned(),
                finding_id: "finding-1".to_owned(),
            }),
        });
        let status = Arc::new(StaticStatus {
            value: Some(AuthenticatedFindingStatus {
                finding_id: "finding-1".to_owned(),
                feed_id: "feed-1".to_owned(),
                map_epoch: 7,
                epoch_id: "a".repeat(64),
                root_hash: "b".repeat(64),
                checked_at: 9,
                valid_until,
                value: status_value,
            }),
        });
        VerifiedFindingRetractionResolver::new(
            "resolver-1",
            "feed-1",
            provenance,
            lineage,
            status,
            Arc::new(StaticClock(now)),
        )
        .expect("build test resolver")
    }

    #[test]
    fn verified_resolution_cross_binds_provenance_lineage_and_status() {
        let resolved = resolver(FindingStatusValue::Live, 20, 10)
            .resolve(FindingRetractionQuery {
                store: "memory",
                key: "key-1",
            })
            .expect("resolve verified memory lineage");
        assert_eq!(resolved.finding_id, "finding-1");
        assert_eq!(resolved.delivery_receipt_id, "delivery-receipt-1");
        assert_eq!(resolved.value, FindingStatusValue::Live);
        assert_eq!(resolved.map_epoch, 7);
    }

    #[test]
    fn stale_status_and_missing_provenance_fail_closed() {
        let stale = resolver(FindingStatusValue::Live, 10, 11).resolve(FindingRetractionQuery {
            store: "memory",
            key: "key-1",
        });
        assert_eq!(stale, Err(FindingRetractionResolveError::StaleStatus));

        let missing = resolver(FindingStatusValue::Live, 20, 10).resolve(FindingRetractionQuery {
            store: "memory",
            key: "missing",
        });
        assert_eq!(
            missing,
            Err(FindingRetractionResolveError::MissingProvenance)
        );
    }

    #[test]
    fn pending_and_retracted_status_are_preserved_for_the_guard() {
        for value in [FindingStatusValue::Pending, FindingStatusValue::Retracted] {
            let resolved = resolver(value, 20, 10)
                .resolve(FindingRetractionQuery {
                    store: "memory",
                    key: "key-1",
                })
                .expect("resolve sticky status");
            assert_eq!(resolved.value, value);
        }
    }
}
