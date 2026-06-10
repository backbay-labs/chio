use crate::bundle::{
    MercuryArtifactReference, MercuryBundleManifest, MERCURY_BUNDLE_MANIFEST_SCHEMA,
};
use crate::receipt_metadata::{
    MercuryApprovalState, MercuryApprovalStatus, MercuryChronology, MercuryChronologyStage,
    MercuryDecisionContext, MercuryDecisionType, MercuryDisclosurePolicy, MercuryProvenance,
    MercuryReceiptMetadata, MercurySensitivity, MercurySensitivityClass,
    MercuryWorkflowIdentifiers, MERCURY_RECEIPT_METADATA_SCHEMA,
};

pub fn sample_mercury_receipt_metadata() -> MercuryReceiptMetadata {
    MercuryReceiptMetadata {
        schema: MERCURY_RECEIPT_METADATA_SCHEMA.to_string(),
        business_ids: MercuryWorkflowIdentifiers {
            workflow_id: "workflow-release-control".to_string(),
            account_id: Some("acct-alpha".to_string()),
            desk_id: Some("desk-delta".to_string()),
            strategy_id: Some("strat-shadow-01".to_string()),
            release_id: Some("release-2026-04-02".to_string()),
            rollback_id: None,
            exception_id: None,
            inquiry_id: Some("inquiry-2026-04-02".to_string()),
        },
        decision_context: MercuryDecisionContext {
            decision_type: MercuryDecisionType::Release,
            workflow_version: Some("mercury-workflow-v1".to_string()),
            policy_reference: Some("policy-hash-123".to_string()),
            model_id: Some("model-ops-reviewer".to_string()),
        },
        chronology: MercuryChronology {
            event_id: "evt-release-1".to_string(),
            stage: MercuryChronologyStage::Release,
            ingested_at: 1_775_137_626,
            source_timestamp: Some(1_775_137_620),
            idempotency_key: Some("idempotency-release-1".to_string()),
            causal_parent_event_ids: vec!["evt-approval-1".to_string()],
        },
        provenance: MercuryProvenance {
            source_system: "shadow-release-review".to_string(),
            source_record_id: Some("source-release-1".to_string()),
            model_provider: Some("openai".to_string()),
            model_name: Some("gpt-5.4".to_string()),
            model_version: Some("2026-04-02".to_string()),
            hosting_mode: Some("supervised-shadow".to_string()),
            dependency_digest: Some("deps-sha256-123".to_string()),
        },
        sensitivity: MercurySensitivity {
            classification: MercurySensitivityClass::Confidential,
            contains_customer_data: false,
            contains_market_data: true,
            retention_class: Some("pilot-90d".to_string()),
        },
        disclosure: MercuryDisclosurePolicy {
            policy: "internal-review-only".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            audience: Some("compliance".to_string()),
            verifier_equivalent: true,
            reviewed_export_approved: true,
        },
        approval_state: MercuryApprovalState {
            state: MercuryApprovalStatus::Approved,
            approver_subjects: vec!["approver-risk-1".to_string()],
            approval_ticket_id: Some("chg-1042".to_string()),
        },
        bundle_refs: Vec::new(),
    }
}

pub fn sample_mercury_bundle_manifest() -> MercuryBundleManifest {
    MercuryBundleManifest {
        schema: MERCURY_BUNDLE_MANIFEST_SCHEMA.to_string(),
        bundle_id: "bundle-release-2026-04-02".to_string(),
        created_at: 1_775_137_626,
        business_ids: sample_mercury_receipt_metadata().business_ids,
        artifacts: vec![
            MercuryArtifactReference {
                artifact_id: "approval-note-1".to_string(),
                artifact_type: "approval_note".to_string(),
                sha256: "artifact-sha256-approval".to_string(),
                media_type: "application/json".to_string(),
                retention_class: Some("pilot-90d".to_string()),
                legal_hold: false,
                redaction_policy: Some("mask-counterparty".to_string()),
            },
            MercuryArtifactReference {
                artifact_id: "release-diff-1".to_string(),
                artifact_type: "release_diff".to_string(),
                sha256: "artifact-sha256-diff".to_string(),
                media_type: "application/json".to_string(),
                retention_class: Some("pilot-90d".to_string()),
                legal_hold: false,
                redaction_policy: Some("none".to_string()),
            },
        ],
    }
}
