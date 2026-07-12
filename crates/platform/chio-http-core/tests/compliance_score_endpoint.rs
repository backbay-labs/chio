//! HTTP integration tests for `POST /compliance/score`.
//!
//! These tests wire a stubbed `ComplianceSource` into the handler to
//! verify the wire contract: the response carries a 0..=1000 score and
//! a per-factor breakdown.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core_types::crypto::Keypair;
use chio_http_core::{
    handle_compliance_score, ComplianceScoreError, ComplianceScoreRequest, ComplianceScoreWindow,
    ComplianceSource, ComplianceSourceResult,
};
use chio_kernel::compliance_score::ComplianceScoreInputs;
use chio_kernel::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};
use chio_kernel::operator_report::ComplianceReport;
use chio_kernel::{ChioKernel, KernelConfig};

fn build_kernel() -> Arc<ChioKernel> {
    let keypair = Keypair::generate();
    Arc::new(ChioKernel::new(KernelConfig {
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
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }))
}

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
fn clean_agent_scores_above_900_over_http() {
    let kernel = build_kernel();
    let source = FixedSource(ComplianceSourceResult {
        report: clean_report(),
        inputs: ComplianceScoreInputs::new(1000, 0, 1, 0, 1000, 0, Some(0)),
    });
    let body = serde_json::to_vec(&ComplianceScoreRequest {
        agent_id: "agent-http-clean".to_string(),
        window: ComplianceScoreWindow::default(),
        config: None,
    })
    .unwrap();

    let resp = handle_compliance_score(&kernel, &source, &body, 10).unwrap();
    assert!(resp.score.score > 900);
    assert_eq!(resp.score.agent_id, "agent-http-clean");
}

#[test]
fn revoked_agent_scores_below_500_over_http() {
    let kernel = build_kernel();
    let mut inputs = ComplianceScoreInputs::new(1000, 0, 1, 1, 1000, 0, Some(0));
    inputs.any_revoked = true;
    let source = FixedSource(ComplianceSourceResult {
        report: clean_report(),
        inputs,
    });
    let body = serde_json::to_vec(&ComplianceScoreRequest {
        agent_id: "agent-http-revoked".to_string(),
        window: ComplianceScoreWindow::default(),
        config: None,
    })
    .unwrap();

    let resp = handle_compliance_score(&kernel, &source, &body, 10).unwrap();
    assert!(resp.score.score < 500);
}

#[test]
fn malformed_body_rejected_with_400() {
    let kernel = build_kernel();
    let source = FixedSource(ComplianceSourceResult {
        report: clean_report(),
        inputs: ComplianceScoreInputs::default(),
    });
    let err = handle_compliance_score(&kernel, &source, b"not-json", 0).unwrap_err();
    assert_eq!(err.status(), 400);
}
