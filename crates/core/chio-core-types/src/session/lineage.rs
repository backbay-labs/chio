use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::capability::governance::ProvenanceEvidenceClass;
use crate::error::Result;
use crate::schema_binding::ensure_schema_matches;

use super::anchor::SessionAnchorReference;
use super::identifiers::RequestId;
use super::operation::OperationKind;

/// Versioned schema identifier for persisted request-lineage records.
pub const CHIO_REQUEST_LINEAGE_RECORD_SCHEMA: &str = "chio.request_lineage_record.v1";
/// Runtime lineage mode for a request node inside Chio's provenance graph.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestLineageMode {
    Root,
    LocalChild,
    Continued,
}

/// Persisted kernel record for one request node in the provenance DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestLineageRecord {
    pub schema: String,
    pub request_id: RequestId,
    pub session_anchor: SessionAnchorReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    pub lineage_mode: RequestLineageMode,
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub started_at: u64,
}

impl RequestLineageRecord {
    #[must_use]
    pub fn new(
        request_id: RequestId,
        session_anchor: SessionAnchorReference,
        operation_kind: OperationKind,
        lineage_mode: RequestLineageMode,
        started_at: u64,
    ) -> Self {
        let evidence_class = match lineage_mode {
            RequestLineageMode::Root | RequestLineageMode::LocalChild => {
                ProvenanceEvidenceClass::Observed
            }
            RequestLineageMode::Continued => ProvenanceEvidenceClass::Verified,
        };

        Self {
            schema: CHIO_REQUEST_LINEAGE_RECORD_SCHEMA.to_string(),
            request_id,
            session_anchor,
            parent_request_id: None,
            operation_kind,
            capability_id: None,
            subject_key: None,
            issuer_key: None,
            intent_hash: None,
            lineage_mode,
            evidence_class,
            continuation_token_id: None,
            started_at,
        }
    }

    pub fn validate_schema(&self) -> Result<()> {
        ensure_schema_matches(
            &self.schema,
            CHIO_REQUEST_LINEAGE_RECORD_SCHEMA,
            "request lineage record",
        )
    }

    #[must_use]
    pub fn with_parent_request_id(mut self, parent_request_id: RequestId) -> Self {
        self.parent_request_id = Some(parent_request_id);
        self
    }

    #[must_use]
    pub fn with_capability_attribution(
        mut self,
        capability_id: impl Into<String>,
        subject_key: impl Into<String>,
        issuer_key: impl Into<String>,
    ) -> Self {
        self.capability_id = Some(capability_id.into());
        self.subject_key = Some(subject_key.into());
        self.issuer_key = Some(issuer_key.into());
        self
    }

    #[must_use]
    pub fn with_intent_hash(mut self, intent_hash: impl Into<String>) -> Self {
        self.intent_hash = Some(intent_hash.into());
        self
    }

    #[must_use]
    pub fn with_evidence_class(mut self, evidence_class: ProvenanceEvidenceClass) -> Self {
        self.evidence_class = evidence_class;
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::Root)
    }

    #[must_use]
    pub fn is_local_child(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::LocalChild)
    }

    #[must_use]
    pub fn is_continued(&self) -> bool {
        matches!(self.lineage_mode, RequestLineageMode::Continued)
    }
}
