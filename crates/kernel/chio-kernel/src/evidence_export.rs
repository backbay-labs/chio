use std::collections::BTreeMap;

use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use serde::{Deserialize, Serialize};

use crate::capability_lineage::{CapabilityLineageError, CapabilitySnapshot};
use crate::checkpoint::{
    CheckpointError, CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};
use crate::receipt_query::{ReceiptQuery, ReceiptReadBoundary, ReceiptReadContext};
use crate::receipt_store::ReceiptStoreError;

pub const EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA: &str = "chio.evidence_transparency_claims.v1";

/// Full-export query used for offline evidence packaging.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// Multi-tenant receipt isolation: restrict the export to a single tenant
    /// so exported evidence bundles carry the tenant tag end-to-end. MUST be
    /// derived from the operator's authenticated tenant claim; callers MUST
    /// NOT let the agent choose this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Explicit read boundary for receipt export. Local exports must not infer
    /// admin scope from an omitted tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_boundary: Option<ReceiptReadBoundary>,
}

/// Coverage mode for child receipts in an export bundle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChildReceiptScope {
    /// All child receipts matching the query window are included.
    FullQueryWindow,
    /// Child receipts are included only as time-window context because there is
    /// no capability/agent join path for them yet.
    TimeWindowContextOnly,
    /// Child receipts are omitted because the export was capability/agent scoped
    /// without a capability/agent join path or time-window fallback.
    OmittedNoJoinPath,
}

/// Forward-compatible lineage reference slots that outward report and export
/// surfaces can populate once provenance artifacts become first-class records.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceLineageReferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_lineage_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_lineage_statement_id: Option<String>,
}

impl EvidenceLineageReferences {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.session_anchor_id.is_none()
            && self.request_lineage_id.is_none()
            && self.receipt_lineage_statement_id.is_none()
    }
}

/// Tool receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceToolReceiptRecord {
    pub seq: u64,
    pub receipt: ChioReceipt,
}

/// Child receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceChildReceiptRecord {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

/// Receipt that was exported but does not currently have checkpoint coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceUncheckpointedReceipt {
    pub seq: u64,
    pub receipt_id: String,
}

/// Live-database retention state captured at export time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRetentionMetadata {
    #[serde(default)]
    pub live_db_size_bytes: Option<u64>,
    #[serde(default)]
    pub oldest_live_receipt_timestamp: Option<u64>,
}

/// Audit-only claims that can be made from a local evidence export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceAuditClaims {
    pub checkpoint_logs: Vec<String>,
    pub signed_checkpoints: u64,
    pub checkpoint_publications: u64,
    pub checkpoint_witnesses: u64,
    pub checkpoint_consistency_proofs: u64,
    pub inclusion_proofs: u64,
    pub capability_lineage_records: u64,
}

/// Transparency materials that remain preview-only without a trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceTransparencyPreviewClaim {
    pub log_id: String,
    pub claim: String,
    pub reason: String,
    pub checkpoint_count: u64,
    pub witness_count: u64,
    pub consistency_proof_count: u64,
    pub log_tree_size: u64,
}

/// Explicit publication state for bundled checkpoint claims.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePublicationState {
    #[default]
    TransparencyPreview,
    TrustAnchored,
}

impl EvidencePublicationState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransparencyPreview => "transparency_preview",
            Self::TrustAnchored => "trust_anchored",
        }
    }
}

/// Stable outward separation between audit claims and transparency-preview claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceTransparencyClaims {
    pub schema: String,
    #[serde(default)]
    pub publication_state: EvidencePublicationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor: Option<String>,
    pub audit: EvidenceAuditClaims,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transparency_preview: Vec<EvidenceTransparencyPreviewClaim>,
}

impl EvidenceTransparencyClaims {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA {
            return Err(format!(
                "unsupported transparency claims schema: expected {}, got {}",
                EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA, self.schema
            ));
        }
        let trust_anchor = self
            .trust_anchor
            .as_deref()
            .map(str::trim)
            .filter(|anchor| !anchor.is_empty());
        match self.publication_state {
            EvidencePublicationState::TransparencyPreview => {
                if trust_anchor.is_some() {
                    return Err(
                        "transparency_preview claims must not declare a trust_anchor".to_string(),
                    );
                }
            }
            EvidencePublicationState::TrustAnchored => {
                if trust_anchor.is_none() {
                    return Err(
                        "trust_anchored claims require a non-empty trust_anchor".to_string()
                    );
                }
                if !self.transparency_preview.is_empty() {
                    return Err(
                        "trust_anchored claims must not retain transparency_preview entries"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_trust_anchored(&self) -> bool {
        self.publication_state == EvidencePublicationState::TrustAnchored
    }
}

/// Complete evidence bundle assembled from a local SQLite store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportBundle {
    pub query: EvidenceExportQuery,
    pub tool_receipts: Vec<EvidenceToolReceiptRecord>,
    pub child_receipts: Vec<EvidenceChildReceiptRecord>,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub checkpoints: Vec<KernelCheckpoint>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
    pub inclusion_proofs: Vec<ReceiptInclusionProof>,
    pub uncheckpointed_receipts: Vec<EvidenceUncheckpointedReceipt>,
    pub retention: EvidenceRetentionMetadata,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceExportError {
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("capability lineage error: {0}")]
    CapabilityLineage(#[from] CapabilityLineageError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error("core error: {0}")]
    Core(#[from] chio_core::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("receipt read boundary error: {0}")]
    ReadBoundary(String),
}

impl EvidenceExportQuery {
    pub fn as_receipt_query(&self, cursor: Option<u64>) -> ReceiptQuery {
        let tenant_filter = self.effective_tenant_filter();
        let read_context = match &self.read_boundary {
            Some(ReceiptReadBoundary::AdminAll) => Some(ReceiptReadContext::admin_service()),
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
                Some(ReceiptReadContext::authenticated_tenant(tenant.clone()))
            }
            None => None,
        };
        ReceiptQuery {
            capability_id: self.capability_id.clone(),
            tool_server: None,
            tool_name: None,
            outcome: None,
            since: self.since,
            until: self.until,
            min_cost: None,
            max_cost: None,
            cost_currency: None,
            cursor,
            limit: crate::MAX_QUERY_LIMIT,
            agent_subject: self.agent_subject.clone(),
            tenant_filter,
            read_context,
        }
    }

    #[must_use]
    pub fn admin_all() -> Self {
        Self {
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn tenant_scoped(tenant: impl Into<String>) -> Self {
        let tenant = tenant.into();
        Self {
            tenant: Some(tenant.clone()),
            read_boundary: Some(ReceiptReadBoundary::TenantScoped { tenant }),
            ..Self::default()
        }
    }

    pub fn validate_read_boundary(&self) -> Result<(), EvidenceExportError> {
        match &self.read_boundary {
            Some(ReceiptReadBoundary::AdminAll) => {
                if self
                    .tenant
                    .as_deref()
                    .is_some_and(|tenant| tenant.trim().is_empty())
                {
                    return Err(EvidenceExportError::ReadBoundary(
                        "admin-all evidence export tenant filter requires a non-empty tenant"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
                let tenant = tenant.trim();
                if tenant.is_empty() {
                    return Err(EvidenceExportError::ReadBoundary(
                        "tenant-scoped evidence export requires a non-empty tenant".to_string(),
                    ));
                }
                if self
                    .tenant
                    .as_deref()
                    .is_some_and(|query_tenant| query_tenant != tenant)
                {
                    return Err(EvidenceExportError::ReadBoundary(
                        "tenant-scoped evidence export tenant does not match query tenant"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            None => Err(EvidenceExportError::ReadBoundary(
                "evidence export requires an explicit receipt read boundary".to_string(),
            )),
        }
    }

    #[must_use]
    pub fn normalized_for_read_boundary(&self) -> Self {
        let mut normalized = self.clone();
        if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &self.read_boundary {
            normalized.tenant = Some(tenant.clone());
        }
        normalized
    }

    fn effective_tenant_filter(&self) -> Option<String> {
        match &self.read_boundary {
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => Some(tenant.clone()),
            _ => self.tenant.clone(),
        }
    }

    fn has_subject_or_capability_scope(&self) -> bool {
        self.capability_id.is_some() || self.agent_subject.is_some()
    }

    fn has_time_window(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    #[must_use]
    pub fn child_receipt_scope(&self) -> EvidenceChildReceiptScope {
        if self
            .effective_tenant_filter()
            .as_deref()
            .is_some_and(|tenant| !tenant.trim().is_empty())
        {
            return EvidenceChildReceiptScope::OmittedNoJoinPath;
        }
        if matches!(
            self.read_boundary,
            Some(ReceiptReadBoundary::TenantScoped { .. })
        ) {
            return EvidenceChildReceiptScope::OmittedNoJoinPath;
        }
        if self.has_subject_or_capability_scope() {
            if self.has_time_window() {
                EvidenceChildReceiptScope::TimeWindowContextOnly
            } else {
                EvidenceChildReceiptScope::OmittedNoJoinPath
            }
        } else {
            EvidenceChildReceiptScope::FullQueryWindow
        }
    }
}

#[derive(Default)]
struct EvidenceTransparencyLogStats {
    checkpoint_count: u64,
    witness_count: u64,
    consistency_proof_count: u64,
    log_tree_size: u64,
}

fn trusted_publication_anchor(
    publications: &[crate::checkpoint::CheckpointPublication],
    requested_trust_anchor: Option<&str>,
) -> Option<String> {
    let requested_trust_anchor = requested_trust_anchor
        .map(str::trim)
        .filter(|trust_anchor| !trust_anchor.is_empty());
    if publications.is_empty() {
        return None;
    }

    let mut shared_trust_anchor = None::<String>;
    for publication in publications {
        let binding = publication.trust_anchor_binding.as_ref()?;
        if binding.validate().is_err() {
            return None;
        }
        if binding.publication_identity.kind
            == chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog
            && binding.publication_identity.identity != publication.log_id
        {
            return None;
        }
        match shared_trust_anchor.as_deref() {
            Some(existing) if existing != binding.trust_anchor_ref => return None,
            None => shared_trust_anchor = Some(binding.trust_anchor_ref.clone()),
            Some(_) => {}
        }
    }

    match (shared_trust_anchor, requested_trust_anchor) {
        (Some(shared), Some(requested)) if shared == requested => Some(shared),
        (Some(_), Some(_)) => None,
        (Some(shared), None) => Some(shared),
        (None, _) => None,
    }
}

#[must_use]
pub fn build_evidence_transparency_claims(
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
    trust_anchor: Option<&str>,
) -> EvidenceTransparencyClaims {
    let trust_anchor = trusted_publication_anchor(&transparency.publications, trust_anchor);
    let mut by_log = BTreeMap::<String, EvidenceTransparencyLogStats>::new();

    for publication in &transparency.publications {
        let stats = by_log.entry(publication.log_id.clone()).or_default();
        stats.checkpoint_count += 1;
        stats.log_tree_size = stats.log_tree_size.max(publication.log_tree_size);
    }
    for witness in &transparency.witnesses {
        by_log
            .entry(witness.log_id.clone())
            .or_default()
            .witness_count += 1;
    }
    for proof in &transparency.consistency_proofs {
        let stats = by_log.entry(proof.log_id.clone()).or_default();
        stats.consistency_proof_count += 1;
        stats.log_tree_size = stats.log_tree_size.max(proof.to_log_tree_size);
    }

    let checkpoint_logs = by_log.keys().cloned().collect::<Vec<_>>();
    let transparency_preview = if trust_anchor.is_some() {
        Vec::new()
    } else {
        by_log
            .into_iter()
            .map(|(log_id, stats)| EvidenceTransparencyPreviewClaim {
                log_id,
                claim: "append_only_local_checkpoint_log".to_string(),
                reason: "no trust anchor is attached, so log identity and prefix growth remain transparency-preview claims".to_string(),
                checkpoint_count: stats.checkpoint_count,
                witness_count: stats.witness_count,
                consistency_proof_count: stats.consistency_proof_count,
                log_tree_size: stats.log_tree_size,
            })
            .collect()
    };

    EvidenceTransparencyClaims {
        schema: EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
        publication_state: if trust_anchor.is_some() {
            EvidencePublicationState::TrustAnchored
        } else {
            EvidencePublicationState::TransparencyPreview
        },
        trust_anchor,
        audit: EvidenceAuditClaims {
            checkpoint_logs,
            signed_checkpoints: bundle.checkpoints.len() as u64,
            checkpoint_publications: transparency.publications.len() as u64,
            checkpoint_witnesses: transparency.witnesses.len() as u64,
            checkpoint_consistency_proofs: transparency.consistency_proofs.len() as u64,
            inclusion_proofs: bundle.inclusion_proofs.len() as u64,
            capability_lineage_records: bundle.capability_lineage.len() as u64,
        },
        transparency_preview,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::checkpoint::{
        build_checkpoint, build_checkpoint_transparency, build_checkpoint_with_previous,
    };
    use chio_core::crypto::Keypair;

    #[test]
    fn evidence_lineage_references_detect_when_empty() {
        let references = EvidenceLineageReferences::default();
        assert!(references.is_empty());
        assert_eq!(
            serde_json::to_value(references).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn evidence_export_query_child_scope_reserves_time_window_context_until_lineage_joins_exist() {
        assert_eq!(
            EvidenceExportQuery {
                capability_id: Some("cap-1".to_string()),
                since: Some(10),
                ..EvidenceExportQuery::default()
            }
            .child_receipt_scope(),
            EvidenceChildReceiptScope::TimeWindowContextOnly
        );
    }

    #[test]
    fn tenant_scoped_evidence_export_omits_child_receipts_without_join_path() {
        assert_eq!(
            EvidenceExportQuery::tenant_scoped("tenant-a").child_receipt_scope(),
            EvidenceChildReceiptScope::OmittedNoJoinPath
        );
    }

    #[test]
    fn evidence_export_query_allows_admin_all_with_tenant_filter() {
        EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        }
        .validate_read_boundary()
        .expect("admin-all evidence export may narrow to a tenant filter");
    }

    #[test]
    fn evidence_export_query_requires_explicit_read_boundary() {
        let err = EvidenceExportQuery::default()
            .validate_read_boundary()
            .expect_err("missing read boundary must fail closed");

        assert!(
            matches!(err, EvidenceExportError::ReadBoundary(message) if message
            == "evidence export requires an explicit receipt read boundary")
        );
    }

    #[test]
    fn evidence_export_query_rejects_empty_admin_tenant_filter() {
        let err = EvidenceExportQuery {
            tenant: Some("   ".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        }
        .validate_read_boundary()
        .expect_err("blank admin tenant filter must fail closed");

        assert!(
            matches!(err, EvidenceExportError::ReadBoundary(message) if message
            == "admin-all evidence export tenant filter requires a non-empty tenant")
        );
    }

    #[test]
    fn evidence_export_query_rejects_empty_tenant_scoped_boundary() {
        let err = EvidenceExportQuery::tenant_scoped("   ")
            .validate_read_boundary()
            .expect_err("blank tenant-scoped boundary must fail closed");

        assert!(
            matches!(err, EvidenceExportError::ReadBoundary(message) if message
            == "tenant-scoped evidence export requires a non-empty tenant")
        );
    }

    #[test]
    fn evidence_export_query_rejects_tenant_scoped_boundary_mismatch() {
        let err = EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::TenantScoped {
                tenant: "tenant-b".to_string(),
            }),
            ..EvidenceExportQuery::default()
        }
        .validate_read_boundary()
        .expect_err("tenant-scoped boundary must match query tenant");

        assert!(
            matches!(err, EvidenceExportError::ReadBoundary(message) if message
            == "tenant-scoped evidence export tenant does not match query tenant")
        );
    }

    #[test]
    fn evidence_export_query_normalizes_tenant_from_scoped_boundary() {
        let normalized = EvidenceExportQuery {
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::TenantScoped {
                tenant: "tenant-a".to_string(),
            }),
            ..EvidenceExportQuery::default()
        }
        .normalized_for_read_boundary();

        assert_eq!(normalized.tenant.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn admin_all_evidence_export_uses_remote_safe_read_context() {
        let receipt_query = EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        }
        .as_receipt_query(None);

        assert_eq!(receipt_query.tenant_filter.as_deref(), Some("tenant-a"));
        assert_eq!(
            receipt_query.read_context,
            Some(ReceiptReadContext::admin_service())
        );
    }

    #[test]
    fn admin_all_tenant_filtered_export_omits_child_receipts_without_join_path() {
        assert_eq!(
            EvidenceExportQuery {
                tenant: Some("tenant-a".to_string()),
                read_boundary: Some(ReceiptReadBoundary::AdminAll),
                ..EvidenceExportQuery::default()
            }
            .child_receipt_scope(),
            EvidenceChildReceiptScope::OmittedNoJoinPath
        );
    }

    #[test]
    fn evidence_export_marks_unanchored_publication_as_transparency_preview() {
        let keypair = Keypair::generate();
        let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &keypair)
            .expect("first checkpoint");
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"three".to_vec(), b"four".to_vec()],
            &keypair,
            Some(&first),
            &[crate::checkpoint::checkpoint_chain_leaf_hash(&first.body)
                .expect("first chain leaf")],
        )
        .expect("second checkpoint");
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            checkpoints: vec![first.clone(), second.clone()],
            capability_lineage: Vec::new(),
            inclusion_proofs: Vec::new(),
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(0),
                oldest_live_receipt_timestamp: None,
            },
        };
        let transparency =
            build_checkpoint_transparency(&[first, second]).expect("transparency summary");

        let claims = build_evidence_transparency_claims(&bundle, &transparency, None);
        assert_eq!(
            claims.publication_state,
            EvidencePublicationState::TransparencyPreview
        );
        assert!(claims.trust_anchor.is_none());
        assert_eq!(claims.audit.signed_checkpoints, 2);
        assert_eq!(claims.audit.checkpoint_consistency_proofs, 1);
        assert_eq!(claims.transparency_preview.len(), 1);
        assert_eq!(
            claims.transparency_preview[0].claim,
            "append_only_local_checkpoint_log"
        );
        assert_eq!(claims.transparency_preview[0].log_tree_size, 4);

        let anchored_claims =
            build_evidence_transparency_claims(&bundle, &transparency, Some("witness-root"));
        assert_eq!(
            anchored_claims.publication_state,
            EvidencePublicationState::TransparencyPreview
        );
        assert!(anchored_claims.trust_anchor.is_none());
        assert_eq!(anchored_claims.transparency_preview.len(), 1);
    }

    #[test]
    fn evidence_export_marks_bound_publication_as_trust_anchored() {
        let keypair = Keypair::generate();
        let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &keypair)
            .expect("first checkpoint");
        let second = build_checkpoint_with_previous(
            2,
            3,
            4,
            &[b"three".to_vec(), b"four".to_vec()],
            &keypair,
            Some(&first),
            &[crate::checkpoint::checkpoint_chain_leaf_hash(&first.body)
                .expect("first chain leaf")],
        )
        .expect("second checkpoint");
        let bundle = EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: Vec::new(),
            child_receipts: Vec::new(),
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            checkpoints: vec![first.clone(), second.clone()],
            capability_lineage: Vec::new(),
            inclusion_proofs: Vec::new(),
            uncheckpointed_receipts: Vec::new(),
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: Some(0),
                oldest_live_receipt_timestamp: None,
            },
        };
        let mut transparency =
            build_checkpoint_transparency(&[first.clone(), second.clone()]).expect("summary");
        let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
            publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
                transparency.publications[0].log_id.clone(),
            ),
            trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
                "root-set-1",
            ),
            trust_anchor_ref: "witness-root".to_string(),
            signer_cert_ref: "cert-chain-1".to_string(),
            publication_profile_version: "phase4-pilot".to_string(),
        };
        transparency.publications = vec![
            crate::checkpoint::build_trust_anchored_checkpoint_publication(&first, binding.clone())
                .expect("first anchored publication"),
            crate::checkpoint::build_trust_anchored_checkpoint_publication(&second, binding)
                .expect("second anchored publication"),
        ];

        let anchored_claims =
            build_evidence_transparency_claims(&bundle, &transparency, Some("witness-root"));
        assert_eq!(
            anchored_claims.publication_state,
            EvidencePublicationState::TrustAnchored
        );
        assert_eq!(
            anchored_claims.trust_anchor.as_deref(),
            Some("witness-root")
        );
        assert!(anchored_claims.transparency_preview.is_empty());
    }

    #[test]
    fn evidence_transparency_claims_reject_invalid_publication_state_combinations() {
        let anchored_without_anchor = EvidenceTransparencyClaims {
            schema: EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
            publication_state: EvidencePublicationState::TrustAnchored,
            trust_anchor: None,
            audit: EvidenceAuditClaims {
                checkpoint_logs: Vec::new(),
                signed_checkpoints: 0,
                checkpoint_publications: 0,
                checkpoint_witnesses: 0,
                checkpoint_consistency_proofs: 0,
                inclusion_proofs: 0,
                capability_lineage_records: 0,
            },
            transparency_preview: Vec::new(),
        };
        assert!(anchored_without_anchor
            .validate()
            .unwrap_err()
            .contains("trust_anchor"));
    }
}
