//! HTTP handler for `POST /compliance/score`.
//!
//! The handler is substrate-agnostic: adapters feed in raw request
//! bytes, the handler parses them into a [`ComplianceScoreRequest`],
//! hands the filtered query to a pluggable [`ComplianceSource`], and
//! returns a [`ComplianceScoreResponse`] carrying the score and the
//! per-factor breakdown.
//!
//! The kernel never signs the response itself -- `chio-kernel` already
//! guarantees receipts are authenticated. Operators who need a signed
//! report compose this handler with the regulatory API.

use std::sync::Arc;

use chio_kernel::compliance_score::{
    compliance_score, ComplianceScore, ComplianceScoreConfig, ComplianceScoreInputs,
};
use chio_kernel::operator_report::ComplianceReport;
use chio_kernel::{ChioKernel, UnderwritingComplianceEvidence};
use serde::{Deserialize, Serialize};

/// Time window over which to compute the score.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScoreWindow {
    /// Inclusive lower bound (unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Inclusive upper bound (unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Request body for `POST /compliance/score`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScoreRequest {
    /// Agent subject to score.
    pub agent_id: String,
    /// Time window bounds. All fields optional.
    #[serde(default)]
    pub window: ComplianceScoreWindow,
    /// Optional overrides for the scoring config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ComplianceScoreConfig>,
}

/// Response body for `POST /compliance/score`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScoreResponse {
    #[serde(flatten)]
    pub score: ComplianceScore,
}

impl ComplianceScoreResponse {
    #[must_use]
    pub fn underwriting_evidence(&self) -> UnderwritingComplianceEvidence {
        self.score.as_underwriting_evidence()
    }
}

/// Inputs the handler requires from the backing store.
#[derive(Debug, Clone)]
pub struct ComplianceSourceResult {
    /// Compliance report for the window (lineage + checkpoint
    /// coverage).
    pub report: ComplianceReport,
    /// Ambient inputs the report doesn't carry.
    pub inputs: ComplianceScoreInputs,
}

/// Error shape for [`handle_compliance_score`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceScoreError {
    /// Malformed request body.
    BadRequest(String),
    /// The backing store was unavailable.
    StoreUnavailable(String),
}

impl ComplianceScoreError {
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::StoreUnavailable(_) => 503,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::StoreUnavailable(_) => "store_unavailable",
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(m) => m.clone(),
            Self::StoreUnavailable(m) => m.clone(),
        }
    }

    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

/// Pluggable compliance source. Substrate adapters plug in an
/// chio-store-sqlite-backed implementation; the handler itself stays
/// decoupled from storage.
pub trait ComplianceSource: Send + Sync {
    fn fetch(
        &self,
        agent_id: &str,
        window: &ComplianceScoreWindow,
    ) -> Result<ComplianceSourceResult, ComplianceScoreError>;
}

/// Handler for `POST /compliance/score`.
pub fn handle_compliance_score(
    _kernel: &Arc<ChioKernel>,
    source: &dyn ComplianceSource,
    body: &[u8],
    now: u64,
) -> Result<ComplianceScoreResponse, ComplianceScoreError> {
    let parsed: ComplianceScoreRequest = serde_json::from_slice(body).map_err(|e| {
        ComplianceScoreError::BadRequest(format!("invalid compliance/score body: {e}"))
    })?;
    if parsed.agent_id.trim().is_empty() {
        return Err(ComplianceScoreError::BadRequest(
            "agent_id must not be empty".to_string(),
        ));
    }
    let data = source.fetch(&parsed.agent_id, &parsed.window)?;
    let config = parsed.config.unwrap_or_default();
    let score = compliance_score(&data.report, &data.inputs, &config, &parsed.agent_id, now);
    Ok(ComplianceScoreResponse { score })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};

    fn clean_report() -> ComplianceReport {
        ComplianceReport {
            matching_receipts: 1000,
            evidence_ready_receipts: 1000,
            uncheckpointed_receipts: 0,
            checkpoint_coverage_rate: Some(1.0),
            lineage_covered_receipts: 1000,
            lineage_gap_receipts: 0,
            lineage_coverage_rate: Some(1.0),
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            direct_evidence_export_supported: true,
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            proofs_complete: true,
            export_query: EvidenceExportQuery::default(),
            export_scope_note: None,
        }
    }

    struct FixedSource(ComplianceSourceResult);
    impl ComplianceSource for FixedSource {
        fn fetch(
            &self,
            _agent_id: &str,
            _window: &ComplianceScoreWindow,
        ) -> Result<ComplianceSourceResult, ComplianceScoreError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn empty_agent_id_is_rejected() {
        let source = FixedSource(ComplianceSourceResult {
            report: clean_report(),
            inputs: ComplianceScoreInputs::default(),
        });
        let body = serde_json::to_vec(&ComplianceScoreRequest {
            agent_id: "".to_string(),
            window: ComplianceScoreWindow::default(),
            config: None,
        })
        .unwrap();
        let keypair = chio_core_types::crypto::Keypair::generate();
        let kernel = Arc::new(ChioKernel::new(chio_kernel::KernelConfig {
            keypair,
            ca_public_keys: vec![],
            max_delegation_depth: 1,
            policy_hash: "ph".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        }));
        let err = handle_compliance_score(&kernel, &source, &body, 0).unwrap_err();
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn returns_clean_score_for_clean_inputs() {
        let result = ComplianceSourceResult {
            report: clean_report(),
            inputs: ComplianceScoreInputs::new(1000, 0, 1, 0, 1000, 0, Some(0)),
        };
        let source = FixedSource(result);
        let body = serde_json::to_vec(&ComplianceScoreRequest {
            agent_id: "a1".to_string(),
            window: ComplianceScoreWindow::default(),
            config: None,
        })
        .unwrap();
        let keypair = chio_core_types::crypto::Keypair::generate();
        let kernel = Arc::new(ChioKernel::new(chio_kernel::KernelConfig {
            keypair,
            ca_public_keys: vec![],
            max_delegation_depth: 1,
            policy_hash: "ph".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        }));
        let resp = handle_compliance_score(&kernel, &source, &body, 0).unwrap();
        assert!(resp.score.score > 900);
    }
}
