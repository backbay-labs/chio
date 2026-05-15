//! Live Chiodos runtime admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::ChioReceipt;
use chio_core_types::{PublicKey, SignedExportEnvelope};
use chio_kernel::{
    KernelError, RuntimeAdmissionContext as KernelRuntimeAdmissionContext,
    RuntimeAdmissionDecision as KernelRuntimeAdmissionDecision, RuntimeAdmissionHook,
    ToolCallRequest,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA: &str =
    "chio.chiodos.runtime-admission-profile.v1";
pub const CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA: &str =
    "chio.chiodos.runtime-admission-bundle.v1";
pub const CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4: &str =
    "chio.chiodos.verifier-trust-bundle.v4";
pub const CHIODOS_RUNTIME_ADMISSION_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-admission-report.v1";
pub const CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-workflow-run-report.v1";
pub const CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA: &str = "chio.chiodos.runtime-step-evidence.v1";
pub const CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA: &str =
    "chio.chiodos.runtime-evidence-manifest.v1";
pub const CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA: &str =
    "chio.chiodos.runtime-proof-regeneration-input.v1";
pub const CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-proof-regeneration-report.v1";
pub const CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-proof-parity-report.v1";
pub const CHIODOS_RUNTIME_ADMISSION_STORE_SCHEMA: &str = "chio.chiodos.runtime-admission-store.v1";
pub const CHIODOS_RUNTIME_TRUSTED_VERIFIERS_SCHEMA: &str =
    "chio.chiodos.runtime-trusted-verifiers.v1";
pub const CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA: &str =
    "chio.chiodos.runtime-pheromone-policy.v1";
pub const CHIODOS_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA: &str =
    "chio.chiodos.runtime-pheromone-policy-decision.v1";
pub const CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA: &str = "chio.chiodos.runtime-peer-weights.v1";
pub const CHIODOS_RUNTIME_TRUST_FLOOR_STATE_SCHEMA: &str =
    "chio.chiodos.runtime-trust-floor-state.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-profile.v1";
pub const CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA: &str = "chio.chiodos.runtime-run-contract.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-plan.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-run-report.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-resume-plan.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-status-report.v1";
pub const CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-proof-drift-report.v1";
pub const CHIODOS_RUNTIME_ORCHESTRATION_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.chiodos.runtime-orchestration-negative-fixture-corpus.v1";
pub const CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA: &str =
    "chio.chiodos.runtime-supervisor-profile.v1";
pub const CHIODOS_RUNTIME_RUN_LEASE_SCHEMA: &str = "chio.chiodos.runtime-run-lease.v1";
pub const CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-scheduler-tick-report.v1";
pub const CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-evidence-sink-health-report.v1";
pub const CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-recovery-drill-report.v1";
pub const CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA: &str =
    "chio.chiodos.runtime-artifact-retention-profile.v1";
pub const CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA: &str =
    "chio.chiodos.runtime-artifact-retention-plan.v1";
pub const CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA: &str =
    "chio.chiodos.runtime-provider-bindings.v1";
pub const CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-provider-health-report.v1";
pub const CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA: &str =
    "chio.chiodos.runtime-ops-status-report.v1";
pub const CHIODOS_RUNTIME_OPS_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.chiodos.runtime-ops-negative-fixture-corpus.v1";
pub const CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA: &str =
    "chio.chiodos.governance-ladder-manifest.v1";
pub const CHIODOS_TREATY_SCOPE_SCHEMA: &str = "chio.chiodos.treaty-scope.v1";
pub const CHIODOS_LADDER_INTERSECTION_SCHEMA: &str = "chio.chiodos.ladder-intersection.v1";
pub const CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA: &str =
    "chio.chiodos.cross-kernel-continuation.v1";
pub const CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA: &str =
    "chio.chiodos.receipt-lineage-statement.v1";
pub const CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA: &str =
    "chio.chiodos.cross-boundary-admission-report.v1";
pub const CHIODOS_BILATERAL_INVOCATION_SCHEMA: &str = "chio.chiodos.bilateral-invocation.v1";
pub const CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA: &str =
    "chio.chiodos.buyer-attestation-packet.v1";
pub const CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA: &str =
    "chio.chiodos.buyer-attestation-verification-report.v1";
pub const CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA: &str = "chio.chiodos.receipt-lineage-bundle.v1";
pub const CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA: &str =
    "chio.chiodos.buyer-attestation-review-package.v1";
pub const CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA: &str =
    "chio.chiodos.buyer-attestation-review-report.v1";
pub const CHIODOS_TREATY_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.chiodos.treaty-negative-fixture-corpus.v1";

pub const CHIODOS_RUNTIME_FAILURE_CODES: &[&str] = &[
    "admission_bundle_hash_mismatch",
    "bilateral_invocation_duplicate_signer",
    "bilateral_invocation_empty_action_class",
    "bilateral_invocation_empty_capability",
    "bilateral_invocation_empty_id",
    "bilateral_invocation_empty_signer",
    "bilateral_invocation_empty_treaty",
    "bilateral_invocation_invalid_continuation_hash",
    "bilateral_invocation_invalid_intersection_hash",
    "bilateral_invocation_invalid_lineage_hash",
    "bilateral_invocation_invalid_local_receipt_hash",
    "bilateral_invocation_invalid_outcome_hash",
    "bilateral_invocation_invalid_remote_receipt_hash",
    "bilateral_invocation_invalid_request_hash",
    "bilateral_invocation_signer_count_mismatch",
    "buyer_packet_empty_buyer",
    "buyer_packet_empty_capability",
    "buyer_packet_empty_id",
    "buyer_packet_invalid_admission_hash",
    "buyer_packet_invalid_bilateral_dsse_hash",
    "buyer_packet_invalid_bilateral_hash",
    "buyer_packet_invalid_continuation_hash",
    "buyer_packet_invalid_intersection_hash",
    "buyer_packet_invalid_lineage_hash",
    "buyer_packet_invalid_package_hash",
    "buyer_packet_invalid_treaty_hash",
    "buyer_packet_invalid_verifier_hash",
    "buyer_packet_invalid_workflow_hash",
    "buyer_review_artifact_empty_bytes",
    "buyer_review_artifact_empty_relative_path",
    "buyer_review_artifact_empty_role",
    "buyer_review_artifact_invalid_hash",
    "buyer_review_package_empty_buyer",
    "buyer_review_package_empty_id",
    "buyer_review_package_empty_packet",
    "buyer_review_report_empty_package",
    "buyer_review_report_empty_packet",
    "buyer_review_report_missing_failure_code",
    "buyer_verification_empty_packet",
    "buyer_verification_invalid_state",
    "buyer_verification_missing_failure_code",
    "chiodos_buyer_packet_hash_mismatch",
    "chiodos_buyer_packet_lineage_not_verified",
    "chiodos_buyer_packet_settlement_claimed",
    "chiodos_buyer_packet_source_missing",
    "chiodos_buyer_review_artifact_hash_mismatch",
    "chiodos_buyer_review_artifact_path_mismatch",
    "chiodos_buyer_review_duplicate_artifact_path",
    "chiodos_buyer_review_duplicate_artifact_role",
    "chiodos_buyer_review_lineage_hash_mismatch",
    "chiodos_buyer_review_missing_artifact_role",
    "chiodos_buyer_review_missing_treaty_dsse_binding",
    "chiodos_buyer_review_non_strict_dsse",
    "chiodos_buyer_review_package_manifest_timestamp_mismatch",
    "chiodos_buyer_review_package_stale",
    "chiodos_buyer_review_packet_hash_mismatch",
    "chiodos_buyer_review_proof_package_incomplete",
    "chiodos_buyer_review_proof_package_mismatch",
    "chiodos_buyer_review_runtime_report_mismatch",
    "chiodos_buyer_review_runtime_timestamp_mismatch",
    "chiodos_buyer_review_strict_dsse_binding_mismatch",
    "chiodos_buyer_review_strict_dsse_signature_invalid",
    "chiodos_buyer_review_strict_dsse_signer_mismatch",
    "chiodos_buyer_review_verifier_report_rejected",
    "chiodos_ladder_alias_conflict",
    "chiodos_ladder_consistency_mismatch",
    "chiodos_ladder_destructive_below_floor",
    "chiodos_ladder_destructive_crdt_not_allowed",
    "chiodos_ladder_duplicate_action_class",
    "chiodos_ladder_invalid_consistency_model",
    "chiodos_ladder_invalid_cosign_mode",
    "chiodos_ladder_invalid_mode",
    "chiodos_ladder_manifest_hash_mismatch",
    "chiodos_ladder_manifest_stale",
    "chiodos_lineage_bundle_cycle",
    "chiodos_lineage_bundle_incomplete",
    "chiodos_lineage_bundle_unverified_edge",
    "chiodos_treaty_action_class_not_allowed",
    "chiodos_treaty_bilateral_hash_mismatch",
    "chiodos_treaty_bilateral_mismatch",
    "chiodos_treaty_continuation_hash_mismatch",
    "chiodos_treaty_continuation_mismatch",
    "chiodos_treaty_continuation_replay",
    "chiodos_treaty_continuation_stale",
    "chiodos_treaty_dsse_binding_mismatch",
    "chiodos_treaty_intersection_mismatch",
    "chiodos_treaty_lineage_hash_mismatch",
    "chiodos_treaty_lineage_mismatch",
    "chiodos_treaty_missing_bilateral_evidence",
    "chiodos_treaty_missing_continuation",
    "chiodos_treaty_missing_intersection",
    "chiodos_treaty_missing_intersection_binding",
    "chiodos_treaty_missing_participant",
    "chiodos_treaty_missing_required_evidence",
    "chiodos_treaty_missing_scope",
    "chiodos_treaty_scope_hash_mismatch",
    "chiodos_treaty_stale",
    "chiodos_treaty_unverified_required_evidence",
    "continuation_empty_action_class",
    "continuation_empty_audience",
    "continuation_empty_capability",
    "continuation_empty_id",
    "continuation_empty_nonce",
    "continuation_empty_source_kernel",
    "continuation_empty_target_kernel",
    "continuation_invalid_parent_hash",
    "continuation_invalid_session_anchor_hash",
    "continuation_invalid_window",
    "cross_boundary_admission_empty_action_class",
    "cross_boundary_admission_empty_treaty",
    "cross_boundary_admission_invalid_evidence_class",
    "cross_boundary_admission_invalid_evidence_hash",
    "cross_boundary_admission_invalid_intersection_hash",
    "cross_boundary_admission_invalid_treaty_hash",
    "cross_boundary_admission_missing_failure_code",
    "destructive_lease_replay",
    "duplicate_admission_bundle_mismatch",
    "duplicate_consumed_lease",
    "duplicate_consumed_treaty_continuation",
    "duplicate_runtime_trust_floor",
    "duplicate_treaty_runtime_artifact_mismatch",
    "duplicate_trusted_verifier_key",
    "governance_ladder_action_empty_id",
    "governance_ladder_destructive_missing_evidence",
    "governance_ladder_duplicate_evidence",
    "governance_ladder_empty_alias",
    "governance_ladder_invalid_evidence_label",
    "governance_ladder_manifest_empty_id",
    "governance_ladder_manifest_empty_issuer",
    "governance_ladder_manifest_empty_kernel",
    "governance_ladder_manifest_empty_key",
    "governance_ladder_manifest_invalid_window",
    "governance_ladder_manifest_missing_action_classes",
    "governance_ladder_manifest_unknown_default_not_deny",
    "host_kernel_mismatch",
    "invalid_chiodos_admission_context",
    "invalid_chiodos_treaty_context",
    "invalid_chiodos_treaty_evidence_ref",
    "invalid_chiodos_treaty_hash",
    "invalid_pheromone_query_report",
    "ladder_intersection_empty_action_class",
    "ladder_intersection_empty_id",
    "ladder_intersection_empty_treaty",
    "missing_action_class_id",
    "missing_admission_bundle",
    "missing_admission_id",
    "missing_chiodos_admission_context",
    "missing_chiodos_treaty_context",
    "missing_chiodos_treaty_evidence_ref",
    "missing_destructive_lease",
    "missing_governance_receipt",
    "missing_governed_intent",
    "missing_ladder_intersection_hash",
    "missing_ladder_intersection_id",
    "missing_pheromone_concentration",
    "missing_runtime_peer_weights",
    "missing_runtime_pheromone_advisory",
    "missing_runtime_pheromone_policy",
    "missing_runtime_trust_input",
    "missing_treaty_scope_hash",
    "missing_treaty_scope_id",
    "receipt_lineage_bundle_empty_id",
    "receipt_lineage_bundle_invalid_leaf_hash",
    "receipt_lineage_bundle_invalid_root_hash",
    "receipt_lineage_empty_id",
    "receipt_lineage_empty_source_kernel",
    "receipt_lineage_empty_target_kernel",
    "receipt_lineage_invalid_bilateral_hash",
    "receipt_lineage_invalid_child_hash",
    "receipt_lineage_invalid_continuation_hash",
    "receipt_lineage_invalid_evidence_class",
    "receipt_lineage_invalid_parent_hash",
    "request_binding_mismatch",
    "request_smuggled_dynamic_trust",
    "request_smuggled_trust_root",
    "runtime_admission_canonical",
    "runtime_evidence_artifact_byte_count_mismatch",
    "runtime_evidence_artifact_hash_mismatch",
    "runtime_evidence_health_empty_run_id",
    "runtime_evidence_health_invalid_required_role",
    "runtime_evidence_health_invalid_root_hash",
    "runtime_evidence_manifest_duplicate_path",
    "runtime_evidence_manifest_empty_role",
    "runtime_evidence_manifest_invalid_artifact_hash",
    "runtime_evidence_manifest_invalid_proof_report_hash",
    "runtime_evidence_manifest_invalid_workflow_report_hash",
    "runtime_evidence_manifest_missing_entries",
    "runtime_evidence_manifest_run_mismatch",
    "runtime_evidence_missing_required_role",
    "runtime_evidence_sink_unavailable",
    "runtime_ops_status_accepted_degraded",
    "runtime_ops_status_degraded",
    "runtime_ops_status_invalid_profile_hash",
    "runtime_ops_status_invalid_run_state",
    "runtime_orchestration_plan_duplicate_step",
    "runtime_orchestration_plan_empty_admission_id",
    "runtime_orchestration_plan_empty_run_id",
    "runtime_orchestration_plan_invalid_contract_hash",
    "runtime_orchestration_plan_invalid_profile_hash",
    "runtime_orchestration_plan_invalid_step_state",
    "runtime_orchestration_plan_missing_failure_code",
    "runtime_orchestration_plan_missing_steps",
    "runtime_orchestration_plan_unexpected_failure_code",
    "runtime_orchestration_profile_duplicate_fail_closed_code",
    "runtime_orchestration_profile_empty_id",
    "runtime_orchestration_profile_empty_kernel",
    "runtime_orchestration_profile_empty_verifier",
    "runtime_orchestration_profile_invalid_fail_closed_code",
    "runtime_orchestration_profile_invalid_mode",
    "runtime_orchestration_profile_invalid_window",
    "runtime_orchestration_profile_stale",
    "runtime_orchestration_profile_zero_concurrency",
    "runtime_orchestration_resume_accepted_blocked",
    "runtime_orchestration_resume_empty_run_id",
    "runtime_orchestration_resume_missing_failure_code",
    "runtime_orchestration_resume_unexpected_failure_code",
    "runtime_orchestration_run_accepted_without_proof",
    "runtime_orchestration_run_duplicate_step",
    "runtime_orchestration_run_empty_id",
    "runtime_orchestration_run_invalid_contract_hash",
    "runtime_orchestration_run_invalid_manifest_hash",
    "runtime_orchestration_run_invalid_profile_hash",
    "runtime_orchestration_run_invalid_proof_hash",
    "runtime_orchestration_run_invalid_status",
    "runtime_orchestration_run_invalid_verifier_hash",
    "runtime_orchestration_run_invalid_workflow_hash",
    "runtime_orchestration_run_missing_accepted_hash",
    "runtime_orchestration_run_missing_steps",
    "runtime_orchestration_status_accepted_degraded",
    "runtime_orchestration_status_invalid_profile_hash",
    "runtime_orchestration_status_invalid_run_state",
    "runtime_orchestration_status_invalid_store_backend",
    "runtime_orchestration_status_invalid_store_hash",
    "runtime_orchestration_step_empty_admission_id",
    "runtime_orchestration_step_invalid_admission_hash",
    "runtime_orchestration_step_invalid_receipt_hash",
    "runtime_orchestration_step_invalid_state",
    "runtime_orchestration_step_missing_destructive_lease",
    "runtime_peer_weights_duplicate_peer",
    "runtime_peer_weights_hash_failed",
    "runtime_peer_weights_hash_mismatch",
    "runtime_peer_weights_invalid",
    "runtime_peer_weights_stale",
    "runtime_peer_weights_untrusted",
    "runtime_pheromone_advisory_future_dated",
    "runtime_pheromone_advisory_not_observe_only",
    "runtime_pheromone_advisory_rejected",
    "runtime_pheromone_advisory_stale",
    "runtime_pheromone_distinct_origin_floor",
    "runtime_pheromone_policy_allow",
    "runtime_pheromone_policy_deny",
    "runtime_pheromone_policy_direction_unsupported",
    "runtime_pheromone_policy_effect_unsupported",
    "runtime_pheromone_policy_escalate",
    "runtime_pheromone_policy_mode_unsupported",
    "runtime_pheromone_policy_query_report_signer_mismatch",
    "runtime_pheromone_policy_stale",
    "runtime_pheromone_policy_trust_mismatch",
    "runtime_pheromone_policy_untrusted",
    "runtime_pheromone_policy_verifier_mismatch",
    "runtime_pheromone_query_report_signature_invalid",
    "runtime_pheromone_required_for_destructive",
    "runtime_policy_hash_failed",
    "runtime_proof_drift_accepted_with_drifts",
    "runtime_proof_drift_detected",
    "runtime_proof_drift_empty_artifact_role",
    "runtime_proof_drift_empty_baseline",
    "runtime_proof_drift_empty_candidate",
    "runtime_proof_drift_empty_field",
    "runtime_proof_drift_invalid_baseline_artifact_hash",
    "runtime_proof_drift_invalid_baseline_manifest_hash",
    "runtime_proof_drift_invalid_baseline_proof_hash",
    "runtime_proof_drift_invalid_baseline_value_hash",
    "runtime_proof_drift_invalid_candidate_artifact_hash",
    "runtime_proof_drift_invalid_candidate_manifest_hash",
    "runtime_proof_drift_invalid_candidate_proof_hash",
    "runtime_proof_drift_invalid_candidate_value_hash",
    "runtime_proof_drift_invalid_severity",
    "runtime_proof_parity_accepted_with_mismatches",
    "runtime_proof_parity_empty_mismatch_field",
    "runtime_proof_parity_invalid_runtime_package_hash",
    "runtime_proof_parity_invalid_runtime_report_hash",
    "runtime_proof_parity_invalid_runtime_value_hash",
    "runtime_proof_parity_invalid_static_package_hash",
    "runtime_proof_parity_invalid_static_report_hash",
    "runtime_proof_parity_invalid_static_value_hash",
    "runtime_proof_parity_missing_compared_fields",
    "runtime_proof_regeneration_duplicate_source_record",
    "runtime_proof_regeneration_input_invalid_admission_hash",
    "runtime_proof_regeneration_input_invalid_context_hash",
    "runtime_proof_regeneration_input_invalid_manifest_hash",
    "runtime_proof_regeneration_input_invalid_trust_bundle_hash",
    "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    "runtime_proof_regeneration_input_missing_source_records",
    "runtime_proof_regeneration_invalid_admission_hash",
    "runtime_proof_regeneration_invalid_dsse_hash",
    "runtime_proof_regeneration_invalid_package_hash",
    "runtime_proof_regeneration_invalid_tool_receipt_hash",
    "runtime_proof_regeneration_invalid_verifier_report_hash",
    "runtime_proof_regeneration_invalid_workflow_receipt_hash",
    "runtime_proof_regeneration_invalid_workflow_step_hash",
    "runtime_proof_regeneration_missing_package_hash",
    "runtime_proof_regeneration_missing_source_records",
    "runtime_proof_regeneration_missing_verifier_report_hash",
    "runtime_proof_regeneration_missing_workflow_receipt_hash",
    "runtime_provider_discovery_not_allowed",
    "runtime_provider_duplicate_id",
    "runtime_provider_empty_id",
    "runtime_provider_empty_kernel",
    "runtime_provider_empty_server",
    "runtime_provider_empty_tool",
    "runtime_provider_health_degraded",
    "runtime_provider_health_empty_degraded_id",
    "runtime_provider_health_invalid_bindings_hash",
    "runtime_recovery_accepted_blocked",
    "runtime_recovery_empty_run_id",
    "runtime_recovery_run_not_found",
    "runtime_reputation_epoch_mismatch",
    "runtime_resume_destructive_repair_required",
    "runtime_retention_dry_run_only",
    "runtime_retention_empty_kernel",
    "runtime_retention_empty_profile_id",
    "runtime_retention_empty_run_id",
    "runtime_retention_invalid_action",
    "runtime_retention_invalid_profile_hash",
    "runtime_retention_invalid_reason",
    "runtime_retention_invalid_window",
    "runtime_retention_legal_hold",
    "runtime_retention_mutation_not_allowed",
    "runtime_retention_plan_missing_failure_code",
    "runtime_retention_plan_unexpected_failure_code",
    "runtime_run_contract_duplicate_admission_id",
    "runtime_run_contract_empty_admission_id",
    "runtime_run_contract_empty_evidence_sink",
    "runtime_run_contract_empty_run_id",
    "runtime_run_contract_empty_store",
    "runtime_run_contract_empty_workflow",
    "runtime_run_contract_invalid_profile_hash",
    "runtime_run_contract_step_count_mismatch",
    "runtime_run_contract_zero_steps",
    "runtime_run_empty_id",
    "runtime_run_invalid_status",
    "runtime_run_lease_conflict",
    "runtime_run_lease_empty_lease_id",
    "runtime_run_lease_empty_owner",
    "runtime_run_lease_empty_run_id",
    "runtime_run_lease_expired",
    "runtime_run_lease_invalid_state",
    "runtime_run_lease_invalid_time_order",
    "runtime_run_lease_invalid_ttl",
    "runtime_run_lease_missing",
    "runtime_run_stale_fencing_token",
    "runtime_scheduler_empty_owner",
    "runtime_scheduler_empty_tick_id",
    "runtime_scheduler_profile_stale",
    "runtime_sqlite_integer_negative",
    "runtime_sqlite_integer_out_of_range",
    "runtime_step_evidence_invalid_admission_hash",
    "runtime_step_evidence_invalid_dsse_hash",
    "runtime_step_evidence_invalid_output_hash",
    "runtime_step_evidence_invalid_parent_hash",
    "runtime_step_evidence_invalid_tool_receipt_hash",
    "runtime_step_evidence_invalid_workflow_step_hash",
    "runtime_step_evidence_missing_admission_id",
    "runtime_step_evidence_missing_consistency_anchor",
    "runtime_step_evidence_missing_governance",
    "runtime_supervisor_empty_kernel",
    "runtime_supervisor_empty_profile_id",
    "runtime_supervisor_invalid_fail_closed_code",
    "runtime_supervisor_invalid_limits",
    "runtime_supervisor_invalid_required_role",
    "runtime_supervisor_invalid_window",
    "runtime_treaty_artifact_empty_id",
    "runtime_treaty_artifact_invalid_kind",
    "runtime_trust_bundle_hash_mismatch",
    "runtime_trust_context_hash_mismatch",
    "runtime_trust_floor_version_zero",
    "runtime_trust_hash_failed",
    "runtime_trust_previous_hash_mismatch",
    "runtime_trust_previous_hash_missing",
    "runtime_trust_revocation_roots_missing",
    "runtime_trust_rollback",
    "runtime_trust_same_version_mismatch",
    "runtime_trust_signature_invalid",
    "runtime_trust_signer_inactive",
    "runtime_trust_signer_stale",
    "runtime_trust_signer_untrusted",
    "runtime_trust_stale",
    "runtime_trust_version_zero",
    "runtime_workflow_duplicate_step_evidence",
    "runtime_workflow_invalid_admission_report_hash",
    "runtime_workflow_invalid_proof_regeneration_hash",
    "runtime_workflow_missing_proof_regeneration_report",
    "runtime_workflow_missing_step_evidence",
    "signature_invalid",
    "signer_inactive",
    "signer_stale",
    "signer_untrusted",
    "stale_profile",
    "treaty_scope_duplicate_participant",
    "treaty_scope_duplicate_participant_key",
    "treaty_scope_empty_action_class",
    "treaty_scope_empty_id",
    "treaty_scope_empty_participant",
    "treaty_scope_invalid_revocation_epoch_hash",
    "treaty_scope_invalid_trust_bundle_hash",
    "unsupported_bilateral_invocation_schema",
    "unsupported_bundle_schema",
    "unsupported_buyer_attestation_packet_schema",
    "unsupported_buyer_attestation_review_package_schema",
    "unsupported_buyer_attestation_review_report_schema",
    "unsupported_buyer_attestation_verification_report_schema",
    "unsupported_cross_boundary_admission_report_schema",
    "unsupported_cross_kernel_continuation_schema",
    "unsupported_governance_ladder_manifest_schema",
    "unsupported_ladder_intersection_schema",
    "unsupported_pheromone_query_report_schema",
    "unsupported_profile_schema",
    "unsupported_receipt_lineage_bundle_schema",
    "unsupported_receipt_lineage_statement_schema",
    "unsupported_runtime_evidence_manifest_schema",
    "unsupported_runtime_evidence_sink_health_report_schema",
    "unsupported_runtime_ops_status_report_schema",
    "unsupported_runtime_orchestration_plan_schema",
    "unsupported_runtime_orchestration_profile_schema",
    "unsupported_runtime_orchestration_resume_plan_schema",
    "unsupported_runtime_orchestration_run_report_schema",
    "unsupported_runtime_orchestration_status_report_schema",
    "unsupported_runtime_peer_weights_schema",
    "unsupported_runtime_pheromone_policy_schema",
    "unsupported_runtime_proof_drift_report_schema",
    "unsupported_runtime_proof_parity_report_schema",
    "unsupported_runtime_proof_regeneration_input_schema",
    "unsupported_runtime_proof_regeneration_report_schema",
    "unsupported_runtime_provider_bindings_schema",
    "unsupported_runtime_provider_health_report_schema",
    "unsupported_runtime_recovery_drill_report_schema",
    "unsupported_runtime_retention_plan_schema",
    "unsupported_runtime_retention_profile_schema",
    "unsupported_runtime_run_contract_schema",
    "unsupported_runtime_run_lease_schema",
    "unsupported_runtime_scheduler_tick_report_schema",
    "unsupported_runtime_step_evidence_schema",
    "unsupported_runtime_store_schema",
    "unsupported_runtime_supervisor_profile_schema",
    "unsupported_runtime_trust_floor_state_schema",
    "unsupported_runtime_trust_schema",
    "unsupported_runtime_workflow_report_schema",
    "unsupported_treaty_scope_schema",
    "unsupported_trusted_verifiers_schema",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub verifier_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustedVerifierKey {
    pub verifier_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustedVerifierKeysDocument {
    pub schema: String,
    pub verifier_keys: Vec<RuntimeTrustedVerifierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeVerifierTrustBundleV4 {
    pub schema: String,
    pub verifier_id: String,
    pub key_id: String,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash_sha256: Option<String>,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
    pub revocation_checkpoint_sha256: String,
    pub revocation_authority_roots: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedRuntimeVerifierTrustBundle = SignedExportEnvelope<RuntimeVerifierTrustBundleV4>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePeerWeight {
    pub peer_kernel_id: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePeerWeights {
    pub schema: String,
    pub verifier_id: String,
    pub key_id: String,
    pub reputation_epoch: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub weights: Vec<RuntimePeerWeight>,
}

pub type SignedRuntimePeerWeights = SignedExportEnvelope<RuntimePeerWeights>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicyRule {
    pub rule_id: String,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub action_class_id: String,
    pub direction: String,
    pub threshold_total_strength: f64,
    pub effect: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicy {
    pub schema: String,
    pub policy_id: String,
    pub verifier_id: String,
    pub key_id: String,
    pub policy_version: u64,
    pub mode: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub allowed_reputation_epochs: Vec<u64>,
    pub max_query_report_age_ms: u64,
    pub min_distinct_origin_pairs: u64,
    pub runtime_trust_bundle_sha256: String,
    pub peer_weights_sha256: String,
    pub rules: Vec<RuntimePheromonePolicyRule>,
}

pub type SignedRuntimePheromonePolicy = SignedExportEnvelope<RuntimePheromonePolicy>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicyDecision {
    pub schema: String,
    pub enforced: bool,
    pub decision: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub query_report_sha256: String,
    pub peer_weights_sha256: String,
    pub reputation_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustFloorEntry {
    pub verifier_id: String,
    pub key_id: String,
    pub highest_version: u64,
    pub latest_bundle_sha256: String,
    pub latest_revocation_checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustFloorState {
    pub schema: String,
    pub entries: Vec<RuntimeTrustFloorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRequestBinding {
    pub request_id: String,
    pub capability_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub tool_args_sha256: String,
    pub origin_kernel_id: Option<String>,
    pub host_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionBundle {
    pub schema: String,
    pub admission_id: String,
    pub binding: RuntimeRequestBinding,
    pub workflow_id: String,
    pub workflow_grant_id: String,
    pub step_index: u64,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    pub evidence_required: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderManifest {
    pub schema: String,
    pub manifest_id: String,
    pub kernel_id: String,
    pub issuer: String,
    pub key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub destructive_floor: String,
    pub default_unknown_mode: String,
    pub action_classes: Vec<GovernanceLadderActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreatyScope {
    pub schema: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub participant_public_keys: Vec<PublicKey>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub allowed_action_classes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revocation_epoch_sha256: String,
    pub trust_bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersectionActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    pub evidence_required: Vec<String>,
    pub participant_modes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersection {
    pub schema: String,
    pub intersection_id: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub action_classes: Vec<LadderIntersectionActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossKernelContinuation {
    pub schema: String,
    pub continuation_id: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
    pub parent_receipt_sha256: String,
    pub parent_session_anchor_sha256: String,
    pub capability_id: String,
    pub action_class_id: String,
    pub audience_tool: String,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageStatement {
    pub schema: String,
    pub statement_id: String,
    pub parent_receipt_sha256: String,
    pub child_receipt_sha256: String,
    pub continuation_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub evidence_class: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryAdmissionReport {
    pub schema: String,
    pub treaty_id: String,
    pub action_class_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub mode: String,
    pub consistency_model: String,
    pub co_sign: String,
    pub required_evidence: Vec<String>,
    pub present_evidence: Vec<String>,
    #[serde(default)]
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ladder_intersection_sha256: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryEvidenceRef {
    pub evidence_class: String,
    pub artifact_sha256: String,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BilateralInvocation {
    pub schema: String,
    pub invocation_id: String,
    pub treaty_id: String,
    pub ladder_intersection_sha256: String,
    pub continuation_sha256: String,
    pub lineage_statement_sha256: String,
    pub action_class_id: String,
    pub consistency_model: String,
    pub capability_id: String,
    pub request_sha256: String,
    pub outcome_sha256: String,
    pub local_receipt_sha256: String,
    pub remote_receipt_sha256: String,
    pub signer_kernel_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationPacket {
    pub schema: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub capability_id: String,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    pub cross_boundary_admission_report_sha256: String,
    pub continuation_sha256: String,
    pub receipt_lineage_statement_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_receipt_sha256: String,
    pub proof_package_sha256: String,
    pub verifier_report_sha256: String,
    pub budget_refs: Vec<String>,
    pub settlement_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationVerificationReport {
    pub schema: String,
    pub packet_id: String,
    pub verification_state: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageBundle {
    pub schema: String,
    pub bundle_id: String,
    pub root_receipt_sha256: String,
    pub leaf_receipt_sha256: String,
    pub statements: Vec<ReceiptLineageStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewArtifactRef {
    pub role: String,
    pub relative_path: String,
    pub artifact_sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyerAttestationReviewSource {
    pub role: String,
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

pub struct BuyerAttestationReviewTrustContext<'a> {
    pub verifier_trust_bundle: &'a serde_json::Value,
    pub verification_context: &'a serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub generated_at_unix_ms: u64,
    pub artifacts: Vec<BuyerAttestationReviewArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewCheck {
    pub code: String,
    pub passed: bool,
    pub severity: String,
    pub artifact_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_sha256: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewReport {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<BuyerAttestationReviewCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreatyRuntimeArtifactRecord {
    pub evidence_kind: String,
    pub evidence_id: String,
    pub artifact_sha256: String,
    pub raw_json: serde_json::Value,
}

pub struct CrossBoundaryAdmissionInput<'a> {
    pub treaty_scope: &'a TreatyScope,
    pub ladder_intersection: &'a LadderIntersection,
    pub expected_ladder_intersection_sha256: Option<String>,
    pub action_class_id: &'a str,
    pub present_evidence: Vec<String>,
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionCheck {
    pub code: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionReport {
    pub schema: String,
    pub admission_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<RuntimeAdmissionCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pheromone_advisory: Option<RuntimePheromoneAdvisory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pheromone_policy_decision: Option<RuntimePheromonePolicyDecision>,
    pub receipt_metadata: serde_json::Value,
}

pub type SignedRuntimeAdmissionReport = SignedExportEnvelope<RuntimeAdmissionReport>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromoneAdvisory {
    pub source_report_sha256: String,
    pub accepted: bool,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub total_strength: f64,
    #[serde(default)]
    pub distinct_origin_pairs: u64,
    pub reputation_epoch: u64,
    pub evaluated_at_unix_ms: u64,
    pub observe_only: bool,
}

pub type SignedRuntimePheromoneQueryReport = SignedExportEnvelope<serde_json::Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeWorkflowRunReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub admission_report_sha256: String,
    pub evidence_paths: Vec<String>,
    pub step_evidence: Vec<RuntimeStepEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_regeneration_report_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeStepEvidence {
    pub schema: String,
    pub step_index: u64,
    pub admission_id: String,
    pub admission_report_sha256: String,
    pub tool_receipt_id: String,
    pub tool_receipt_sha256: String,
    pub output_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_step_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_sha256: Option<String>,
    pub consistency_anchor: String,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofSourceRecord {
    pub step_index: u64,
    pub admission_report_sha256: String,
    pub tool_receipt_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_step_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifestEntry {
    pub role: String,
    pub path: String,
    pub sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifest {
    pub schema: String,
    pub run_id: String,
    pub generated_at_unix_ms: u64,
    pub workflow_run_report_sha256: String,
    pub proof_regeneration_report_sha256: String,
    pub entries: Vec<RuntimeEvidenceManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofRegenerationInput {
    pub schema: String,
    pub run_id: String,
    pub evidence_manifest_sha256: String,
    pub workflow_run_report_sha256: String,
    pub admission_report_sha256: String,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
    pub source_records: Vec<RuntimeProofSourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofRegenerationReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_package_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_receipt_sha256: Option<String>,
    pub source_records: Vec<RuntimeProofSourceRecord>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofParityMismatch {
    pub field: String,
    pub static_value_sha256: String,
    pub runtime_value_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofParityReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub static_proof_package_sha256: String,
    pub runtime_proof_package_sha256: String,
    pub static_verifier_report_sha256: String,
    pub runtime_verifier_report_sha256: String,
    pub compared_fields: Vec<String>,
    pub mismatches: Vec<RuntimeProofParityMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub verifier_id: String,
    pub mode: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_concurrent_runs: u64,
    pub fail_closed_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRunContract {
    pub schema: String,
    pub run_id: String,
    pub profile_sha256: String,
    pub workflow_id: String,
    pub expected_step_count: u64,
    pub admission_ids: Vec<String>,
    pub store_id: String,
    pub evidence_sink_id: String,
    pub proof_regeneration_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationPlannedStep {
    pub step_index: u64,
    pub admission_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationPlan {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub run_contract_sha256: String,
    pub planned_steps: Vec<RuntimeOrchestrationPlannedStep>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationStepState {
    pub step_index: u64,
    pub admission_id: String,
    pub state: String,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationRunReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub status: String,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub run_contract_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_run_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_regeneration_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_report_sha256: Option<String>,
    pub step_states: Vec<RuntimeOrchestrationStepState>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationResumePlan {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step_index: Option<u64>,
    pub reusable_step_indices: Vec<u64>,
    pub blocked: bool,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationStatusReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub store_backend: String,
    pub store_path_sha256: String,
    pub run_counts: BTreeMap<String, u64>,
    pub consumed_lease_count: u64,
    pub trust_floor_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_failure_code: Option<String>,
    pub evidence_sink_healthy: bool,
    pub ready: bool,
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofDrift {
    pub field: String,
    pub baseline_value_sha256: String,
    pub candidate_value_sha256: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofArtifactDrift {
    pub role: String,
    pub path: String,
    pub baseline_sha256: String,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofDriftReport {
    pub schema: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub baseline_manifest_sha256: String,
    pub candidate_manifest_sha256: String,
    pub baseline_proof_regeneration_report_sha256: String,
    pub candidate_proof_regeneration_report_sha256: String,
    pub comparison_profile: String,
    pub normalized_fields: Vec<String>,
    pub semantic_drifts: Vec<RuntimeProofDrift>,
    pub artifact_drifts: Vec<RuntimeProofArtifactDrift>,
    pub verifier_drifts: Vec<RuntimeProofDrift>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSupervisorProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_concurrent_runs: u64,
    pub run_lease_ttl_ms: u64,
    pub stale_run_after_ms: u64,
    pub evidence_required_roles: Vec<String>,
    pub fail_closed_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRunLease {
    pub schema: String,
    pub run_id: String,
    pub lease_id: String,
    pub owner_id: String,
    pub acquired_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub heartbeat_at_unix_ms: u64,
    pub fencing_token: u64,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSchedulerTickReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub tick_id: String,
    pub owner_id: String,
    pub generated_at_unix_ms: u64,
    pub max_runs: u64,
    pub claimed_run_ids: Vec<String>,
    pub expired_run_ids: Vec<String>,
    pub blocked_run_ids: Vec<String>,
    pub skipped_run_count: u64,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceSinkHealthReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub evidence_root_sha256: String,
    pub required_roles: Vec<String>,
    pub missing_roles: Vec<String>,
    pub missing_artifacts: Vec<String>,
    pub artifact_hash_mismatches: Vec<String>,
    pub artifact_byte_count_mismatches: Vec<String>,
    pub unexpected_paths: Vec<String>,
    pub temp_write_ok: bool,
    pub atomic_rename_ok: bool,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRecoveryDrillReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub resumable: bool,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step_index: Option<u64>,
    pub reusable_step_indices: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_required_reason: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub min_retain_ms: u64,
    pub destructive_hold_ms: u64,
    pub legal_hold: bool,
    pub dry_run_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionAction {
    pub run_id: String,
    pub action: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionPlan {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub retention_profile_sha256: String,
    pub retain_count: u64,
    pub blocked_count: u64,
    pub quarantine_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_operator_review_count: u64,
    pub candidate_actions: Vec<RuntimeArtifactRetentionAction>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderBinding {
    pub provider_id: String,
    pub local_kernel_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub discovery_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderBindingsDocument {
    pub schema: String,
    pub bindings: Vec<RuntimeProviderBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderHealthReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub provider_bindings_sha256: String,
    pub checked_provider_count: u64,
    pub healthy_provider_count: u64,
    pub degraded_provider_ids: Vec<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOpsStatusReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub supervisor_profile_sha256: String,
    pub run_counts: BTreeMap<String, u64>,
    pub active_lease_count: u64,
    pub stale_lease_count: u64,
    pub consumed_lease_count: u64,
    pub evidence_sink_healthy: bool,
    pub provider_healthy: bool,
    pub ready: bool,
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_failure_code: Option<String>,
    pub checks: Vec<String>,
}

pub struct RuntimeAdmissionInput<'a> {
    pub profile: &'a RuntimeAdmissionProfile,
    pub store: &'a dyn RuntimeAdmissionStore,
    pub admission_id: &'a str,
    pub request: &'a RuntimeRequestBinding,
    pub runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    pub trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    pub pheromone_query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    pub runtime_pheromone_policy: Option<&'a SignedRuntimePheromonePolicy>,
    pub runtime_peer_weights: Option<&'a SignedRuntimePeerWeights>,
    pub now_unix_ms: u64,
}

pub trait RuntimeAdmissionStore: Send + Sync {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError>;

    fn treaty_runtime_artifact(
        &self,
        _evidence_kind: &str,
        _evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        Ok(None)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError>;

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError>;

    fn consume_treaty_continuation(
        &self,
        _continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        _continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_runtime_trust_floor_transition(
            self.runtime_trust_floor(&entry.verifier_id, &entry.key_id)?,
            &entry,
            previous_hash_sha256,
        )?;
        self.record_runtime_trust_floor(entry)
    }
}

pub trait RuntimeTrustFloorStore: Send + Sync {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_runtime_trust_floor_transition(
            self.runtime_trust_floor(&entry.verifier_id, &entry.key_id)?,
            &entry,
            previous_hash_sha256,
        )?;
        self.record_runtime_trust_floor(entry)
    }
}

impl<T> RuntimeTrustFloorStore for T
where
    T: RuntimeAdmissionStore + ?Sized,
{
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(self, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(self, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
            self,
            entry,
            previous_hash_sha256,
        )
    }
}

pub struct LayeredRuntimeAdmissionStore<'a> {
    admission_store: &'a dyn RuntimeAdmissionStore,
    trust_floor_store: &'a dyn RuntimeTrustFloorStore,
}

impl<'a> LayeredRuntimeAdmissionStore<'a> {
    #[must_use]
    pub fn new(
        admission_store: &'a dyn RuntimeAdmissionStore,
        trust_floor_store: &'a dyn RuntimeTrustFloorStore,
    ) -> Self {
        Self {
            admission_store,
            trust_floor_store,
        }
    }
}

impl RuntimeAdmissionStore for LayeredRuntimeAdmissionStore<'_> {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        self.admission_store.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        self.admission_store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        self.trust_floor_store
            .runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        self.trust_floor_store.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        self.trust_floor_store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryRuntimeAdmissionStore {
    bundles: Arc<Mutex<BTreeMap<String, RuntimeAdmissionBundle>>>,
    treaty_artifacts: Arc<Mutex<BTreeMap<(String, String), TreatyRuntimeArtifactRecord>>>,
    consumed_leases: Arc<Mutex<BTreeSet<String>>>,
    consumed_treaty_continuations: Arc<Mutex<BTreeSet<String>>>,
    trust_floors: Arc<Mutex<BTreeMap<String, RuntimeTrustFloorEntry>>>,
}

impl InMemoryRuntimeAdmissionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChiodosRuntimeError> {
        let mut bundles = self.bundles.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        if bundles
            .insert(bundle.admission_id.clone(), bundle)
            .is_some()
        {
            return Err(ChiodosRuntimeError::DuplicateAdmissionBundle);
        }
        Ok(())
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_value(artifact)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        let mut treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        let key = (evidence_kind.to_string(), evidence_id.to_string());
        if let Some(existing) = treaty_artifacts.get(&key) {
            if existing.artifact_sha256 == artifact_sha256 {
                return Ok(());
            }
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        treaty_artifacts.insert(
            key,
            TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            },
        );
        Ok(())
    }
}

impl RuntimeAdmissionStore for InMemoryRuntimeAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        let bundles = self.bundles.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        Ok(bundles.get(admission_id).cloned())
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        let treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        Ok(treaty_artifacts
            .get(&(evidence_kind.to_string(), evidence_id.to_string()))
            .cloned())
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut consumed = self.consumed_leases.lock().map_err(|_| {
            ChiodosRuntimeError::Store(
                "runtime admission consumption store is poisoned".to_string(),
            )
        })?;
        if !consumed.insert(lease_id.to_string()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut consumed = self.consumed_leases.lock().map_err(|_| {
            ChiodosRuntimeError::Store(
                "runtime admission consumption store is poisoned".to_string(),
            )
        })?;
        consumed.remove(lease_id);
        Ok(())
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut consumed = self.consumed_treaty_continuations.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime treaty continuation store is poisoned".to_string())
        })?;
        if !consumed.insert(continuation_id.to_string()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "chiodos_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut consumed = self.consumed_treaty_continuations.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime treaty continuation store is poisoned".to_string())
        })?;
        consumed.remove(continuation_id);
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let floors = self.trust_floors.lock().map_err(|_| {
            ChiodosRuntimeError::Store(
                "runtime admission trust floor store is poisoned".to_string(),
            )
        })?;
        Ok(floors
            .get(&trust_floor_identity(verifier_id, key_id))
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut floors = self.trust_floors.lock().map_err(|_| {
            ChiodosRuntimeError::Store(
                "runtime admission trust floor store is poisoned".to_string(),
            )
        })?;
        floors.insert(
            trust_floor_identity(&entry.verifier_id, &entry.key_id),
            entry,
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct JsonRuntimeAdmissionStore {
    path: PathBuf,
    state: Arc<Mutex<JsonRuntimeAdmissionStoreState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsonRuntimeAdmissionStoreState {
    schema: String,
    bundles: Vec<RuntimeAdmissionBundle>,
    consumed_lease_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    consumed_treaty_continuation_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    trust_floors: Vec<RuntimeTrustFloorEntry>,
}

impl Default for JsonRuntimeAdmissionStoreState {
    fn default() -> Self {
        Self {
            schema: CHIODOS_RUNTIME_ADMISSION_STORE_SCHEMA.to_string(),
            bundles: Vec::new(),
            consumed_lease_ids: Vec::new(),
            consumed_treaty_continuation_ids: Vec::new(),
            trust_floors: Vec::new(),
        }
    }
}

impl JsonRuntimeAdmissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChiodosRuntimeError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let json = fs::read_to_string(&path).map_err(|error| {
                ChiodosRuntimeError::Io(format!(
                    "failed to read runtime admission store {}: {error}",
                    path.display()
                ))
            })?;
            let state: JsonRuntimeAdmissionStoreState =
                serde_json::from_str(&json).map_err(|error| {
                    ChiodosRuntimeError::Json(format!(
                        "failed to parse runtime admission store {}: {error}",
                        path.display()
                    ))
                })?;
            if state.schema != CHIODOS_RUNTIME_ADMISSION_STORE_SCHEMA {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "unsupported_runtime_store_schema",
                    detail: format!(
                        "runtime admission store {} declared unsupported schema {}",
                        path.display(),
                        state.schema
                    ),
                });
            }
            state
        } else {
            JsonRuntimeAdmissionStoreState::default()
        };
        let store = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };
        store.validate_locked_state()?;
        Ok(store)
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state
            .bundles
            .iter()
            .find(|existing| existing.admission_id == bundle.admission_id)
        {
            if existing == &bundle {
                return Ok(());
            }
            return Err(ChiodosRuntimeError::DuplicateAdmissionBundle);
        }
        state.bundles.push(bundle);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn validate_locked_state(&self) -> Result<(), ChiodosRuntimeError> {
        let state = self.lock_state()?;
        Self::validate_state(&state)
    }

    fn validate_state(state: &JsonRuntimeAdmissionStoreState) -> Result<(), ChiodosRuntimeError> {
        let mut admission_ids = BTreeSet::new();
        for bundle in &state.bundles {
            if !admission_ids.insert(bundle.admission_id.as_str()) {
                return Err(ChiodosRuntimeError::DuplicateAdmissionBundle);
            }
        }
        let mut lease_ids = BTreeSet::new();
        for lease_id in &state.consumed_lease_ids {
            if !lease_ids.insert(lease_id.as_str()) {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "duplicate_consumed_lease",
                    detail: format!("runtime admission store repeats consumed lease {lease_id}"),
                });
            }
        }
        let mut continuation_ids = BTreeSet::new();
        for continuation_id in &state.consumed_treaty_continuation_ids {
            if !continuation_ids.insert(continuation_id.as_str()) {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "duplicate_consumed_treaty_continuation",
                    detail: format!(
                        "runtime admission store repeats treaty continuation {continuation_id}"
                    ),
                });
            }
        }
        let mut trust_floor_ids = BTreeSet::new();
        for entry in &state.trust_floors {
            let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
            if !trust_floor_ids.insert(identity.clone()) {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "duplicate_runtime_trust_floor",
                    detail: format!("runtime admission store repeats trust floor {identity}"),
                });
            }
            if entry.highest_version == 0 {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "runtime_trust_floor_version_zero",
                    detail: format!("runtime trust floor {identity} has version zero"),
                });
            }
        }
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, JsonRuntimeAdmissionStoreState>, ChiodosRuntimeError>
    {
        self.state.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime admission JSON store is poisoned".to_string())
        })
    }

    fn persist_state(
        &self,
        state: &JsonRuntimeAdmissionStoreState,
    ) -> Result<(), ChiodosRuntimeError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChiodosRuntimeError::Io(format!(
                        "failed to create runtime admission store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let json = serde_json::to_string_pretty(state)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        fs::write(&self.path, format!("{json}\n")).map_err(|error| {
            ChiodosRuntimeError::Io(format!(
                "failed to write runtime admission store {}: {error}",
                self.path.display()
            ))
        })
    }
}

impl RuntimeAdmissionStore for JsonRuntimeAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .bundles
            .iter()
            .find(|bundle| bundle.admission_id == admission_id)
            .cloned())
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        if state
            .consumed_lease_ids
            .iter()
            .any(|consumed| consumed == lease_id)
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        state.consumed_lease_ids.push(lease_id.to_string());
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        state
            .consumed_lease_ids
            .retain(|consumed| consumed != lease_id);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        if state
            .consumed_treaty_continuation_ids
            .iter()
            .any(|consumed| consumed == continuation_id)
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "chiodos_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        state
            .consumed_treaty_continuation_ids
            .push(continuation_id.to_string());
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        state
            .consumed_treaty_continuation_ids
            .retain(|consumed| consumed != continuation_id);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .trust_floors
            .iter()
            .find(|entry| entry.verifier_id == verifier_id && entry.key_id == key_id)
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.trust_floors.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.trust_floors.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }
}

#[derive(Debug, Clone)]
pub struct JsonRuntimeTrustFloorStateStore {
    path: PathBuf,
    state: Arc<Mutex<RuntimeTrustFloorState>>,
}

impl JsonRuntimeTrustFloorStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChiodosRuntimeError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let json = fs::read_to_string(&path).map_err(|error| {
                ChiodosRuntimeError::Io(format!(
                    "failed to read runtime trust-floor state {}: {error}",
                    path.display()
                ))
            })?;
            let state: RuntimeTrustFloorState = serde_json::from_str(&json).map_err(|error| {
                ChiodosRuntimeError::Json(format!(
                    "failed to parse runtime trust-floor state {}: {error}",
                    path.display()
                ))
            })?;
            if state.schema != CHIODOS_RUNTIME_TRUST_FLOOR_STATE_SCHEMA {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "unsupported_runtime_trust_floor_state_schema",
                    detail: format!(
                        "runtime trust-floor state {} declared unsupported schema {}",
                        path.display(),
                        state.schema
                    ),
                });
            }
            state
        } else {
            RuntimeTrustFloorState {
                schema: CHIODOS_RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string(),
                entries: Vec::new(),
            }
        };
        let store = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };
        store.validate_locked_state()?;
        Ok(store)
    }

    fn validate_locked_state(&self) -> Result<(), ChiodosRuntimeError> {
        let state = self.lock_state()?;
        Self::validate_state(&state)
    }

    fn validate_state(state: &RuntimeTrustFloorState) -> Result<(), ChiodosRuntimeError> {
        if state.schema != CHIODOS_RUNTIME_TRUST_FLOOR_STATE_SCHEMA {
            return Err(ChiodosRuntimeError::Rejected {
                code: "unsupported_runtime_trust_floor_state_schema",
                detail: format!(
                    "runtime trust-floor state declared unsupported schema {}",
                    state.schema
                ),
            });
        }
        let mut trust_floor_ids = BTreeSet::new();
        for entry in &state.entries {
            let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
            if !trust_floor_ids.insert(identity.clone()) {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "duplicate_runtime_trust_floor",
                    detail: format!("runtime trust-floor state repeats trust floor {identity}"),
                });
            }
            if entry.highest_version == 0 {
                return Err(ChiodosRuntimeError::Rejected {
                    code: "runtime_trust_floor_version_zero",
                    detail: format!("runtime trust floor {identity} has version zero"),
                });
            }
        }
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RuntimeTrustFloorState>, ChiodosRuntimeError> {
        self.state.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime trust-floor JSON state is poisoned".to_string())
        })
    }

    fn persist_state(&self, state: &RuntimeTrustFloorState) -> Result<(), ChiodosRuntimeError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChiodosRuntimeError::Io(format!(
                        "failed to create runtime trust-floor state directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let json = serde_json::to_string_pretty(state)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        fs::write(&self.path, format!("{json}\n")).map_err(|error| {
            ChiodosRuntimeError::Io(format!(
                "failed to write runtime trust-floor state {}: {error}",
                self.path.display()
            ))
        })
    }
}

impl RuntimeTrustFloorStore for JsonRuntimeTrustFloorStateStore {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .entries
            .iter()
            .find(|entry| entry.verifier_id == verifier_id && entry.key_id == key_id)
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.entries.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.entries.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut state = self.lock_state()?;
        let existing = state
            .entries
            .iter()
            .find(|existing| {
                existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
            })
            .cloned();
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        if let Some(existing) = state.entries.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.entries.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }
}

#[derive(Debug)]
pub struct SqliteRuntimeOrchestrationStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl SqliteRuntimeOrchestrationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChiodosRuntimeError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChiodosRuntimeError::Io(format!(
                        "failed to create runtime orchestration store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sqlite_error)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .map_err(sqlite_error)?;
        let store = Self {
            path,
            connection: Mutex::new(connection),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS runtime_admission_bundles (
                    admission_id TEXT PRIMARY KEY NOT NULL,
                    bundle_sha256 TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_consumed_leases (
                    lease_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_consumed_treaty_continuations (
                    continuation_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_trust_floors (
                    verifier_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    highest_version INTEGER NOT NULL,
                    latest_bundle_sha256 TEXT NOT NULL,
                    latest_revocation_checkpoint_sha256 TEXT NOT NULL,
                    PRIMARY KEY (verifier_id, key_id)
                );
                CREATE TABLE IF NOT EXISTS runtime_runs (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    status TEXT NOT NULL,
                    started_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    failure_code TEXT,
                    workflow_report_sha256 TEXT,
                    proof_regeneration_report_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_step_states (
                    run_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    admission_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    destructive INTEGER NOT NULL,
                    admission_report_sha256 TEXT,
                    tool_receipt_sha256 TEXT,
                    lease_id TEXT,
                    PRIMARY KEY (run_id, step_index)
                );
                CREATE TABLE IF NOT EXISTS runtime_evidence_artifacts (
                    run_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    role TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    recorded_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (run_id, artifact_sha256)
                );
                CREATE TABLE IF NOT EXISTS runtime_treaty_artifacts (
                    evidence_kind TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (evidence_kind, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS runtime_run_leases (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    lease_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    acquired_at_unix_ms INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL,
                    heartbeat_at_unix_ms INTEGER NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    reason_code TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_scheduler_ticks (
                    tick_id TEXT PRIMARY KEY NOT NULL,
                    owner_id TEXT NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    claimed_count INTEGER NOT NULL,
                    blocked_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_recovery_drills (
                    run_id TEXT NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    accepted INTEGER NOT NULL,
                    failure_code TEXT,
                    PRIMARY KEY (run_id, generated_at_unix_ms)
                );
                CREATE TABLE IF NOT EXISTS runtime_provider_health (
                    provider_id TEXT PRIMARY KEY NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    healthy INTEGER NOT NULL,
                    failure_code TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_evidence_sink_health (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    healthy INTEGER NOT NULL,
                    failure_code TEXT
                );
                "#,
            )
            .map_err(sqlite_error)?;
        Self::migrate_evidence_artifacts_schema(&connection)
    }

    fn migrate_evidence_artifacts_schema(
        connection: &Connection,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut statement = connection
            .prepare("PRAGMA table_info(runtime_evidence_artifacts)")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
            })
            .map_err(sqlite_error)?;
        let mut primary_key_columns = BTreeSet::new();
        for row in rows {
            let (name, primary_key_index) = row.map_err(sqlite_error)?;
            if primary_key_index > 0 {
                primary_key_columns.insert(name);
            }
        }
        if primary_key_columns.contains("run_id") && primary_key_columns.contains("artifact_sha256")
        {
            return Ok(());
        }
        connection
            .execute_batch(
                r#"
                CREATE TABLE runtime_evidence_artifacts_v2 (
                    run_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    role TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    recorded_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (run_id, artifact_sha256)
                );
                INSERT OR REPLACE INTO runtime_evidence_artifacts_v2 (
                    run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                )
                SELECT run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                FROM runtime_evidence_artifacts;
                DROP TABLE runtime_evidence_artifacts;
                ALTER TABLE runtime_evidence_artifacts_v2 RENAME TO runtime_evidence_artifacts;
                "#,
            )
            .map_err(sqlite_error)
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChiodosRuntimeError> {
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        let raw_json = serde_json::to_string(&bundle)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT bundle_sha256 FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![bundle.admission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == bundle_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_admission_bundle_mismatch",
                detail: "runtime admission bundle id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            "INSERT INTO runtime_admission_bundles (admission_id, bundle_sha256, raw_json, created_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            params![bundle.admission_id, bundle_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn record_run_state(
        &self,
        run_id: &str,
        status: &str,
        failure_code: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_state_label(status, "runtime_run_invalid_status")?;
        let now = sqlite_i64(now_unix_ms, "runtime run timestamp")?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_runs (run_id, status, started_at_unix_ms, updated_at_unix_ms, failure_code)
                VALUES (?1, ?2, ?3, ?3, ?4)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    updated_at_unix_ms = excluded.updated_at_unix_ms,
                    failure_code = excluded.failure_code
                "#,
                params![run_id, status, now, failure_code],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn record_step_state(
        &self,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChiodosRuntimeError> {
        self.record_run_step_state("default", state)
    }

    pub fn record_run_step_state(
        &self,
        run_id: &str,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_runtime_orchestration_step_state(&state)?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_step_states (
                    run_id, step_index, admission_id, state, destructive,
                    admission_report_sha256, tool_receipt_sha256, lease_id
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(run_id, step_index) DO UPDATE SET
                    admission_id = excluded.admission_id,
                    state = excluded.state,
                    destructive = excluded.destructive,
                    admission_report_sha256 = excluded.admission_report_sha256,
                    tool_receipt_sha256 = excluded.tool_receipt_sha256,
                    lease_id = excluded.lease_id
                "#,
                params![
                    run_id,
                    sqlite_i64(state.step_index, "runtime step index")?,
                    state.admission_id,
                    state.state,
                    if state.destructive { 1_i64 } else { 0_i64 },
                    state.admission_report_sha256,
                    state.tool_receipt_sha256,
                    state.lease_id
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn record_evidence_artifact(
        &self,
        run_id: &str,
        entry: &RuntimeEvidenceManifestEntry,
        recorded_at_unix_ms: u64,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_evidence_artifacts (
                    run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(run_id, artifact_sha256) DO UPDATE SET
                    role = excluded.role,
                    relative_path = excluded.relative_path,
                    byte_count = excluded.byte_count,
                    recorded_at_unix_ms = excluded.recorded_at_unix_ms
                "#,
                params![
                    run_id,
                    entry.sha256,
                    entry.role,
                    entry.path,
                    sqlite_i64(entry.byte_count, "runtime evidence byte count")?,
                    sqlite_i64(recorded_at_unix_ms, "runtime evidence timestamp")?
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_string(artifact)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT artifact_sha256 FROM runtime_treaty_artifacts WHERE evidence_kind = ?1 AND evidence_id = ?2",
                params![evidence_kind, evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == artifact_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            r#"
            INSERT INTO runtime_treaty_artifacts (
                evidence_kind, evidence_id, artifact_sha256, raw_json, created_at_unix_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![evidence_kind, evidence_id, artifact_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                r#"
                SELECT artifact_sha256, raw_json
                FROM runtime_treaty_artifacts
                WHERE evidence_kind = ?1 AND evidence_id = ?2
                "#,
                params![evidence_kind, evidence_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(artifact_sha256, raw_json)| {
            let raw_json = serde_json::from_str(&raw_json)
                .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
            Ok(TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            })
        })
        .transpose()
    }

    pub fn acquire_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
        if ttl_ms == 0 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_invalid_ttl",
                detail: "runtime run lease ttl must be positive".to_string(),
            });
        }
        let now = sqlite_i64(now_unix_ms, "runtime run lease timestamp")?;
        let expires_at = sqlite_i64(
            now_unix_ms.saturating_add(ttl_ms),
            "runtime run lease expiry",
        )?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, i64, i64, String)> = tx
            .query_row(
                "SELECT owner_id, expires_at_unix_ms, fencing_token, state FROM runtime_run_leases WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let fencing_token =
            if let Some((_existing_owner, existing_expires, existing_token, state)) = existing {
                if state == "active" && existing_expires > now {
                    return Err(ChiodosRuntimeError::Rejected {
                        code: "runtime_run_lease_conflict",
                        detail: format!("runtime run {run_id} already has an active lease"),
                    });
                }
                sqlite_u64(existing_token, "runtime run lease fencing token")?.saturating_add(1)
            } else {
                1
            };
        let lease = RuntimeRunLease {
            schema: CHIODOS_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            lease_id: format!("{run_id}:{owner_id}:{fencing_token}"),
            owner_id: owner_id.to_string(),
            acquired_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            heartbeat_at_unix_ms: now_unix_ms,
            fencing_token,
            state: "active".to_string(),
            reason_code: None,
        };
        validate_runtime_run_lease(&lease)?;
        tx.execute(
            r#"
            INSERT INTO runtime_run_leases (
                run_id, lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                heartbeat_at_unix_ms, fencing_token, state, reason_code
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(run_id) DO UPDATE SET
                lease_id = excluded.lease_id,
                owner_id = excluded.owner_id,
                acquired_at_unix_ms = excluded.acquired_at_unix_ms,
                expires_at_unix_ms = excluded.expires_at_unix_ms,
                heartbeat_at_unix_ms = excluded.heartbeat_at_unix_ms,
                fencing_token = excluded.fencing_token,
                state = excluded.state,
                reason_code = excluded.reason_code
            "#,
            params![
                lease.run_id,
                lease.lease_id,
                lease.owner_id,
                now,
                expires_at,
                now,
                sqlite_i64(lease.fencing_token, "runtime run lease fencing token")?,
                lease.state,
                lease.reason_code
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(lease)
    }

    pub fn heartbeat_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
        let now = sqlite_i64(now_unix_ms, "runtime run lease heartbeat timestamp")?;
        let expires_at = sqlite_i64(
            now_unix_ms.saturating_add(ttl_ms),
            "runtime run lease heartbeat expiry",
        )?;
        let connection = self.lock_connection()?;
        let row: Option<(String, String, i64, i64, i64, String)> = connection
            .query_row(
                r#"
                SELECT lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                       fencing_token, state
                FROM runtime_run_leases
                WHERE run_id = ?1
                "#,
                params![run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((lease_id, existing_owner, acquired_at, existing_expires, existing_token, state)) =
            row
        else {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_missing",
                detail: format!("runtime run {run_id} has no lease"),
            });
        };
        if existing_owner != owner_id
            || sqlite_u64(existing_token, "runtime run lease fencing token")? != fencing_token
            || state != "active"
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_stale_fencing_token",
                detail: format!("runtime run {run_id} heartbeat used stale fencing token"),
            });
        }
        if existing_expires <= now {
            connection
                .execute(
                    "UPDATE runtime_run_leases SET state = 'expired', reason_code = 'runtime_run_lease_expired' WHERE run_id = ?1 AND state = 'active'",
                    params![run_id],
                )
                .map_err(sqlite_error)?;
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_expired",
                detail: format!("runtime run {run_id} lease expired before heartbeat"),
            });
        }
        connection
            .execute(
                "UPDATE runtime_run_leases SET heartbeat_at_unix_ms = ?1, expires_at_unix_ms = ?2 WHERE run_id = ?3",
                params![now, expires_at, run_id],
            )
            .map_err(sqlite_error)?;
        let lease = RuntimeRunLease {
            schema: CHIODOS_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            lease_id,
            owner_id: owner_id.to_string(),
            acquired_at_unix_ms: sqlite_u64(acquired_at, "runtime run lease acquired timestamp")?,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            heartbeat_at_unix_ms: now_unix_ms,
            fencing_token,
            state,
            reason_code: None,
        };
        validate_runtime_run_lease(&lease)?;
        Ok(lease)
    }

    pub fn scheduler_tick_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        owner_id: &str,
        now_unix_ms: u64,
        max_runs: u64,
    ) -> Result<RuntimeSchedulerTickReport, ChiodosRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        validate_non_empty(owner_id, "runtime_scheduler_empty_owner")?;
        let mut claimed_run_ids = Vec::new();
        let mut expired_run_ids = Vec::new();
        let blocked_run_ids = Vec::new();
        let mut skipped_run_count = 0_u64;
        let mut accepted = true;
        let mut failure_code = None;
        if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
            accepted = false;
            failure_code = Some("runtime_scheduler_profile_stale".to_string());
        } else {
            let now = sqlite_i64(now_unix_ms, "runtime scheduler tick timestamp")?;
            let stale_before = sqlite_i64(
                now_unix_ms.saturating_sub(profile.stale_run_after_ms),
                "runtime scheduler stale heartbeat timestamp",
            )?;
            {
                let connection = self.lock_connection()?;
                let mut statement = connection
                    .prepare(
                        "SELECT run_id FROM runtime_run_leases WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
                    )
                    .map_err(sqlite_error)?;
                let rows = statement
                    .query_map(params![now, stale_before], |row| row.get::<_, String>(0))
                    .map_err(sqlite_error)?;
                for row in rows {
                    expired_run_ids.push(row.map_err(sqlite_error)?);
                }
                connection
                    .execute(
                        "UPDATE runtime_run_leases SET state = 'expired', reason_code = 'runtime_run_lease_expired' WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
                        params![now, stale_before],
                    )
                    .map_err(sqlite_error)?;
            }
            let claim_limit = max_runs.min(profile.max_concurrent_runs);
            let pending_runs = self.pending_run_ids()?;
            skipped_run_count = pending_runs
                .len()
                .saturating_sub(usize::try_from(claim_limit).unwrap_or(usize::MAX))
                .try_into()
                .unwrap_or(u64::MAX);
            for run_id in pending_runs
                .into_iter()
                .take(usize::try_from(claim_limit).unwrap_or(usize::MAX))
            {
                match self.acquire_run_lease(
                    &run_id,
                    owner_id,
                    now_unix_ms,
                    profile.run_lease_ttl_ms,
                ) {
                    Ok(_) => claimed_run_ids.push(run_id),
                    Err(_) => skipped_run_count = skipped_run_count.saturating_add(1),
                }
            }
        }
        let tick_id = format!("{owner_id}:{now_unix_ms}");
        {
            let connection = self.lock_connection()?;
            connection
                .execute(
                    "INSERT OR REPLACE INTO runtime_scheduler_ticks (tick_id, owner_id, generated_at_unix_ms, claimed_count, blocked_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        tick_id,
                        owner_id,
                        sqlite_i64(now_unix_ms, "runtime scheduler tick timestamp")?,
                        sqlite_i64(u64::try_from(claimed_run_ids.len()).unwrap_or(u64::MAX), "runtime scheduler claimed count")?,
                        sqlite_i64(u64::try_from(blocked_run_ids.len()).unwrap_or(u64::MAX), "runtime scheduler blocked count")?
                    ],
                )
                .map_err(sqlite_error)?;
        }
        let report = RuntimeSchedulerTickReport {
            schema: CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA.to_string(),
            accepted,
            failure_code,
            tick_id,
            owner_id: owner_id.to_string(),
            generated_at_unix_ms: now_unix_ms,
            max_runs,
            claimed_run_ids,
            expired_run_ids,
            blocked_run_ids,
            skipped_run_count,
            checks: vec!["runtime_ops.scheduler_tick".to_string()],
        };
        validate_runtime_scheduler_tick_report(&report)?;
        Ok(report)
    }

    pub fn status_report(
        &self,
        profile_id: &str,
        profile_sha256: String,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
    ) -> Result<RuntimeOrchestrationStatusReport, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let mut run_counts = BTreeMap::new();
        {
            let mut statement = connection
                .prepare("SELECT status, COUNT(*) FROM runtime_runs GROUP BY status")
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(sqlite_error)?;
            for row in rows {
                let (status, count) = row.map_err(sqlite_error)?;
                run_counts.insert(status, sqlite_u64(count, "runtime run count")?);
            }
        }
        let consumed_lease_count = query_count(&connection, "runtime_consumed_leases")?;
        let trust_floor_count = query_count(&connection, "runtime_trust_floors")?;
        let latest_failure_code: Option<String> = connection
            .query_row(
                "SELECT failure_code FROM runtime_runs WHERE failure_code IS NOT NULL ORDER BY updated_at_unix_ms DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let degraded = !evidence_sink_healthy || latest_failure_code.is_some();
        let failure_code = degraded.then(|| {
            latest_failure_code
                .clone()
                .unwrap_or_else(|| "runtime_ops_status_degraded".to_string())
        });
        let report = RuntimeOrchestrationStatusReport {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA.to_string(),
            accepted: !degraded,
            failure_code,
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            store_backend: "sqlite".to_string(),
            store_path_sha256: sha256_hex(self.path.to_string_lossy().as_bytes()),
            run_counts,
            consumed_lease_count,
            trust_floor_count,
            latest_failure_code,
            evidence_sink_healthy,
            ready: !profile_id.trim().is_empty() && evidence_sink_healthy,
            degraded,
        };
        validate_runtime_orchestration_status_report(&report)?;
        Ok(report)
    }

    pub fn recovery_drill_report(
        &self,
        run_id: &str,
        now_unix_ms: u64,
    ) -> Result<RuntimeRecoveryDrillReport, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_recovery_empty_run_id")?;
        let connection = self.lock_connection()?;
        let run_exists = connection
            .query_row(
                "SELECT 1 FROM runtime_runs WHERE run_id = ?1 LIMIT 1",
                params![run_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(sqlite_error)?
            .is_some();
        if !run_exists {
            let report = RuntimeRecoveryDrillReport {
                schema: CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
                run_id: run_id.to_string(),
                accepted: false,
                failure_code: Some("runtime_recovery_run_not_found".to_string()),
                generated_at_unix_ms: now_unix_ms,
                resumable: false,
                blocked: true,
                next_step_index: None,
                reusable_step_indices: Vec::new(),
                recovery_required_reason: Some("runtime_recovery_run_not_found".to_string()),
                checks: vec!["runtime_ops.recovery_run_lookup".to_string()],
            };
            validate_runtime_recovery_drill_report(&report)?;
            return Ok(report);
        }
        let mut reusable_step_indices = Vec::new();
        let mut destructive_terminal_without_evidence = false;
        {
            let mut statement = connection
                .prepare(
                    "SELECT step_index, destructive, tool_receipt_sha256 FROM runtime_step_states WHERE run_id = ?1 ORDER BY step_index",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map(params![run_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(sqlite_error)?;
            for row in rows {
                let (index, destructive, receipt) = row.map_err(sqlite_error)?;
                let index = sqlite_u64(index, "runtime recovery step index")?;
                reusable_step_indices.push(index);
                if destructive != 0 && receipt.is_some() {
                    let artifact_count: i64 = connection
                        .query_row(
                            "SELECT COUNT(*) FROM runtime_evidence_artifacts WHERE run_id = ?1",
                            params![run_id],
                            |row| row.get(0),
                        )
                        .map_err(sqlite_error)?;
                    destructive_terminal_without_evidence = artifact_count == 0;
                }
            }
        }
        let blocked = destructive_terminal_without_evidence;
        let failure_code = if blocked {
            Some("runtime_resume_destructive_repair_required".to_string())
        } else {
            None
        };
        let next_step_index = reusable_step_indices
            .last()
            .map(|last| last.saturating_add(1))
            .or(Some(0));
        let report = RuntimeRecoveryDrillReport {
            schema: CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: !blocked,
            failure_code: failure_code.clone(),
            generated_at_unix_ms: now_unix_ms,
            resumable: !blocked,
            blocked,
            next_step_index,
            reusable_step_indices,
            recovery_required_reason: failure_code,
            checks: vec!["runtime_ops.recovery_drill".to_string()],
        };
        validate_runtime_recovery_drill_report(&report)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO runtime_recovery_drills (run_id, generated_at_unix_ms, accepted, failure_code) VALUES (?1, ?2, ?3, ?4)",
                params![
                    run_id,
                    sqlite_i64(now_unix_ms, "runtime recovery timestamp")?,
                    if report.accepted { 1_i64 } else { 0_i64 },
                    report.failure_code
                ],
            )
            .map_err(sqlite_error)?;
        Ok(report)
    }

    pub fn ops_status_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
        provider_healthy: bool,
    ) -> Result<RuntimeOpsStatusReport, ChiodosRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        let connection = self.lock_connection()?;
        let run_counts = runtime_run_counts(&connection)?;
        let consumed_lease_count = query_count(&connection, "runtime_consumed_leases")?;
        let active_lease_count = lease_count_by_state(&connection, "active")?;
        let stale_lease_count =
            stale_lease_count(&connection, now_unix_ms, profile.stale_run_after_ms)?;
        let latest_failure_code: Option<String> = connection
            .query_row(
                "SELECT failure_code FROM runtime_runs WHERE failure_code IS NOT NULL ORDER BY updated_at_unix_ms DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let degraded = !evidence_sink_healthy
            || !provider_healthy
            || stale_lease_count > 0
            || latest_failure_code.is_some();
        let report = RuntimeOpsStatusReport {
            schema: CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA.to_string(),
            accepted: !degraded,
            failure_code: if degraded {
                Some("runtime_ops_status_degraded".to_string())
            } else {
                None
            },
            generated_at_unix_ms: now_unix_ms,
            supervisor_profile_sha256: canonical_sha256(profile)?,
            run_counts,
            active_lease_count,
            stale_lease_count,
            consumed_lease_count,
            evidence_sink_healthy,
            provider_healthy,
            ready: !degraded,
            degraded,
            latest_failure_code,
            checks: vec!["runtime_ops.status_aggregated".to_string()],
        };
        validate_runtime_ops_status_report(&report)?;
        Ok(report)
    }

    fn pending_run_ids(&self) -> Result<Vec<String>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT run_id
                FROM runtime_runs
                WHERE status IN ('pending', 'planned', 'proof_pending')
                ORDER BY updated_at_unix_ms, run_id
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?;
        let mut run_ids = Vec::new();
        for row in rows {
            run_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(run_ids)
    }

    fn lock_connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, ChiodosRuntimeError> {
        self.connection.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime orchestration sqlite store is poisoned".to_string())
        })
    }
}

impl RuntimeAdmissionStore for SqliteRuntimeOrchestrationStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let raw_json: Option<String> = connection
            .query_row(
                "SELECT raw_json FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![admission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        raw_json
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
            })
            .transpose()
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        SqliteRuntimeOrchestrationStore::treaty_runtime_artifact(self, evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_leases (lease_id, admission_id) VALUES (?1, ?2)",
                params![lease_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_leases WHERE lease_id = ?1 AND admission_id = ?2",
                params![lease_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_treaty_continuations (continuation_id, admission_id) VALUES (?1, ?2)",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "chiodos_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_treaty_continuations WHERE continuation_id = ?1 AND admission_id = ?2",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let row: Option<(String, String, i64, String, String)> = connection
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![verifier_id, key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(
            |(
                verifier_id,
                key_id,
                highest_version,
                latest_bundle_sha256,
                latest_revocation_checkpoint_sha256,
            )| {
                Ok(RuntimeTrustFloorEntry {
                    verifier_id,
                    key_id,
                    highest_version: sqlite_u64(highest_version, "runtime trust floor version")?,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                })
            },
        )
        .transpose()
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_trust_floors (
                    verifier_id, key_id, highest_version, latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256
                )
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                    highest_version = excluded.highest_version,
                    latest_bundle_sha256 = excluded.latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
                "#,
                params![
                    entry.verifier_id,
                    entry.key_id,
                    sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                    entry.latest_bundle_sha256,
                    entry.latest_revocation_checkpoint_sha256
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, String, i64, String, String)> = tx
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![entry.verifier_id, entry.key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let existing = existing
            .map(
                |(
                    verifier_id,
                    key_id,
                    highest_version,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                )| {
                    Ok(RuntimeTrustFloorEntry {
                        verifier_id,
                        key_id,
                        highest_version: sqlite_u64(
                            highest_version,
                            "runtime trust floor version",
                        )?,
                        latest_bundle_sha256,
                        latest_revocation_checkpoint_sha256,
                    })
                },
            )
            .transpose()?;
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        tx.execute(
            r#"
            INSERT INTO runtime_trust_floors (
                verifier_id, key_id, highest_version, latest_bundle_sha256,
                latest_revocation_checkpoint_sha256
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                highest_version = excluded.highest_version,
                latest_bundle_sha256 = excluded.latest_bundle_sha256,
                latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
            "#,
            params![
                entry.verifier_id,
                entry.key_id,
                sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                entry.latest_bundle_sha256,
                entry.latest_revocation_checkpoint_sha256
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChiodosRuntimeError {
    #[error("runtime admission rejected: {code}: {detail}")]
    Rejected { code: &'static str, detail: String },
    #[error("duplicate runtime admission bundle")]
    DuplicateAdmissionBundle,
    #[error("runtime admission store failed: {0}")]
    Store(String),
    #[error("runtime admission IO failed: {0}")]
    Io(String),
    #[error("runtime admission JSON failed: {0}")]
    Json(String),
    #[error("runtime admission canonical JSON failed: {0}")]
    Canonical(String),
}

impl ChiodosRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ChiodosRuntimeError::Rejected { code, .. } => code,
            ChiodosRuntimeError::DuplicateAdmissionBundle => "duplicate_admission_bundle",
            ChiodosRuntimeError::Store(_) => "runtime_admission_store",
            ChiodosRuntimeError::Io(_) => "runtime_admission_io",
            ChiodosRuntimeError::Json(_) => "runtime_admission_json",
            ChiodosRuntimeError::Canonical(_) => "runtime_admission_canonical",
        }
    }
}

pub fn runtime_admission_profile_from_json(
    json: &str,
) -> Result<RuntimeAdmissionProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_bundle_from_json(
    json: &str,
) -> Result<RuntimeAdmissionBundle, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_request_binding_from_json(
    json: &str,
) -> Result<RuntimeRequestBinding, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn governance_ladder_manifest_from_json(
    json: &str,
) -> Result<GovernanceLadderManifest, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn treaty_scope_from_json(json: &str) -> Result<TreatyScope, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn ladder_intersection_from_json(
    json: &str,
) -> Result<LadderIntersection, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn receipt_lineage_statement_from_json(
    json: &str,
) -> Result<ReceiptLineageStatement, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_packet_from_json(
    json: &str,
) -> Result<BuyerAttestationPacket, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn receipt_lineage_bundle_from_json(
    json: &str,
) -> Result<ReceiptLineageBundle, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_package_from_json(
    json: &str,
) -> Result<BuyerAttestationReviewPackage, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_verifier_trust_bundle_from_json(
    json: &str,
) -> Result<SignedRuntimeVerifierTrustBundle, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_trusted_verifier_keys_from_json(
    json: &str,
) -> Result<RuntimeTrustedVerifierKeysDocument, ChiodosRuntimeError> {
    let document: RuntimeTrustedVerifierKeysDocument =
        serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    if document.schema != CHIODOS_RUNTIME_TRUSTED_VERIFIERS_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_trusted_verifiers_schema",
            detail: format!(
                "runtime trusted verifiers document declared unsupported schema {}",
                document.schema
            ),
        });
    }
    let mut keys = BTreeSet::new();
    for key in &document.verifier_keys {
        let identity = format!("{}:{}", key.verifier_id, key.key_id);
        if !keys.insert(identity.clone()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_trusted_verifier_key",
                detail: format!("runtime trusted verifier key {identity} is duplicated"),
            });
        }
    }
    Ok(document)
}

pub fn signed_runtime_pheromone_policy_from_json(
    json: &str,
) -> Result<SignedRuntimePheromonePolicy, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_peer_weights_from_json(
    json: &str,
) -> Result<SignedRuntimePeerWeights, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_admission_report_json(
    report: &RuntimeAdmissionReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn sign_runtime_admission_report(
    report: RuntimeAdmissionReport,
    keypair: &Keypair,
) -> Result<SignedRuntimeAdmissionReport, ChiodosRuntimeError> {
    SignedExportEnvelope::sign(report, keypair)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))
}

pub fn signed_runtime_admission_report_from_json(
    json: &str,
) -> Result<SignedRuntimeAdmissionReport, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_admission_report_json(
    report: &SignedRuntimeAdmissionReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn verify_signed_runtime_admission_report(
    report: &SignedRuntimeAdmissionReport,
) -> Result<bool, ChiodosRuntimeError> {
    report
        .verify_signature()
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))
}

pub fn runtime_pheromone_advisory_from_query_report_json(
    json: &str,
) -> Result<RuntimePheromoneAdvisory, ChiodosRuntimeError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    runtime_pheromone_advisory_from_query_report_value(&value)
}

pub fn signed_runtime_pheromone_query_report_from_json(
    json: &str,
) -> Result<SignedRuntimePheromoneQueryReport, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn signed_runtime_pheromone_query_report_json(
    report: &SignedRuntimePheromoneQueryReport,
) -> Result<String, ChiodosRuntimeError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

fn runtime_pheromone_advisory_from_query_report_value(
    value: &serde_json::Value,
) -> Result<RuntimePheromoneAdvisory, ChiodosRuntimeError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    let schema = value.get("schema").and_then(|item| item.as_str());
    if schema != Some("chio.pheromone.query-report.v1") {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_pheromone_query_report_schema",
            detail: "runtime pheromone advisory requires chio.pheromone.query-report.v1"
                .to_string(),
        });
    }
    let concentration =
        value
            .get("concentration")
            .ok_or_else(|| ChiodosRuntimeError::Rejected {
                code: "missing_pheromone_concentration",
                detail: "runtime pheromone advisory query report is missing concentration"
                    .to_string(),
            })?;
    Ok(RuntimePheromoneAdvisory {
        source_report_sha256: sha256_hex(&canonical),
        accepted: value
            .get("accepted")
            .and_then(|item| item.as_bool())
            .unwrap_or(false),
        subject_class: required_string_any(concentration, &["subject_class", "subjectClass"])?,
        subject_class_namespace: required_string_any(
            concentration,
            &["subject_class_namespace", "subjectClassNamespace"],
        )?,
        total_strength: required_f64_any(concentration, &["total_strength", "totalStrength"])?,
        distinct_origin_pairs: required_u64_any(
            concentration,
            &["distinct_origin_pairs", "distinctOriginPairs"],
        )?,
        reputation_epoch: required_u64_any(
            concentration,
            &["reputation_epoch", "reputationEpoch"],
        )?,
        evaluated_at_unix_ms: required_u64_any(
            concentration,
            &["evaluated_at_unix_ms", "evaluatedAtUnixMs"],
        )?,
        observe_only: true,
    })
}

pub fn runtime_workflow_run_report_json(
    report: &RuntimeWorkflowRunReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_workflow_run_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn ladder_intersection_json(
    intersection: &LadderIntersection,
) -> Result<String, ChiodosRuntimeError> {
    validate_ladder_intersection(intersection)?;
    serde_json::to_string_pretty(intersection)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn cross_boundary_admission_report_json(
    report: &CrossBoundaryAdmissionReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_cross_boundary_admission_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_verification_report_json(
    report: &BuyerAttestationVerificationReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_buyer_attestation_verification_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn buyer_attestation_review_report_json(
    report: &BuyerAttestationReviewReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_buyer_attestation_review_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_report_json(
    report: &RuntimeProofRegenerationReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_regeneration_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_manifest_json(
    manifest: &RuntimeEvidenceManifest,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_evidence_manifest(manifest)?;
    serde_json::to_string_pretty(manifest)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_regeneration_input_json(
    input: &RuntimeProofRegenerationInput,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_regeneration_input(input)?;
    serde_json::to_string_pretty(input)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_parity_report_json(
    report: &RuntimeProofParityReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_parity_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_profile_from_json(
    json: &str,
) -> Result<RuntimeOrchestrationProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_run_contract_from_json(
    json: &str,
) -> Result<RuntimeRunContract, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_supervisor_profile_from_json(
    json: &str,
) -> Result<RuntimeSupervisorProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_profile_from_json(
    json: &str,
) -> Result<RuntimeArtifactRetentionProfile, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_bindings_from_json(
    json: &str,
) -> Result<RuntimeProviderBindingsDocument, ChiodosRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_profile_sha256(
    profile: &RuntimeOrchestrationProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_run_contract_sha256(
    contract: &RuntimeRunContract,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(contract)
}

pub fn runtime_supervisor_profile_sha256(
    profile: &RuntimeSupervisorProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_artifact_retention_profile_sha256(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(profile)
}

pub fn runtime_orchestration_plan_json(
    plan: &RuntimeOrchestrationPlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_run_report_json(
    report: &RuntimeOrchestrationRunReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_run_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_resume_plan_json(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_resume_plan(plan)?;
    serde_json::to_string_pretty(plan).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_orchestration_status_report_json(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_orchestration_status_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_proof_drift_report_json(
    report: &RuntimeProofDriftReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_proof_drift_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_scheduler_tick_report_json(
    report: &RuntimeSchedulerTickReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_scheduler_tick_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_evidence_sink_health_report_json(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_evidence_sink_health_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_recovery_drill_report_json(
    report: &RuntimeRecoveryDrillReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_recovery_drill_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_artifact_retention_plan_json(
    report: &RuntimeArtifactRetentionPlan,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_artifact_retention_plan(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_provider_health_report_json(
    report: &RuntimeProviderHealthReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_provider_health_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn runtime_ops_status_report_json(
    report: &RuntimeOpsStatusReport,
) -> Result<String, ChiodosRuntimeError> {
    validate_runtime_ops_status_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

pub fn governance_ladder_manifest_sha256(
    manifest: &GovernanceLadderManifest,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(manifest)
}

pub fn treaty_scope_sha256(scope: &TreatyScope) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(scope)
}

pub fn treaty_scope_semantic_intersection_sha256(
    scope: &TreatyScope,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "treatyId": scope.treaty_id,
        "participantKernelIds": scope.participant_kernel_ids,
        "participantPublicKeys": scope.participant_public_keys,
        "ladderManifestSha256s": scope.ladder_manifest_sha256s,
        "allowedActionClasses": scope.allowed_action_classes,
        "revocationEpochSha256": scope.revocation_epoch_sha256,
        "trustBundleSha256": scope.trust_bundle_sha256
    }))
}

pub fn ladder_intersection_sha256(
    intersection: &LadderIntersection,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(intersection)
}

pub fn ladder_intersection_semantic_sha256(
    intersection: &LadderIntersection,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "treatyId": intersection.treaty_id,
        "participantKernelIds": intersection.participant_kernel_ids,
        "ladderManifestSha256s": intersection.ladder_manifest_sha256s,
        "actionClasses": intersection.action_classes
    }))
}

pub fn receipt_lineage_statement_sha256(
    statement: &ReceiptLineageStatement,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(statement)
}

pub fn bilateral_invocation_binding_sha256(
    invocation: &BilateralInvocation,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "schema": &invocation.schema,
        "invocationId": &invocation.invocation_id,
        "treatyId": &invocation.treaty_id,
        "ladderIntersectionSha256": &invocation.ladder_intersection_sha256,
        "continuationSha256": &invocation.continuation_sha256,
        "actionClassId": &invocation.action_class_id,
        "consistencyModel": &invocation.consistency_model,
        "capabilityId": &invocation.capability_id,
        "requestSha256": &invocation.request_sha256,
        "outcomeSha256": &invocation.outcome_sha256,
        "localReceiptSha256": &invocation.local_receipt_sha256,
        "remoteReceiptSha256": &invocation.remote_receipt_sha256,
        "signerKernelIds": &invocation.signer_kernel_ids
    }))
}

pub fn buyer_attestation_packet_sha256(
    packet: &BuyerAttestationPacket,
) -> Result<String, ChiodosRuntimeError> {
    canonical_sha256(packet)
}

pub fn validate_governance_ladder_manifest(
    manifest: &GovernanceLadderManifest,
) -> Result<(), ChiodosRuntimeError> {
    if manifest.schema != CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA {
        return rejected(
            "unsupported_governance_ladder_manifest_schema",
            "governance ladder manifest declared an unsupported schema",
        );
    }
    validate_non_empty(&manifest.manifest_id, "governance_ladder_manifest_empty_id")?;
    validate_non_empty(
        &manifest.kernel_id,
        "governance_ladder_manifest_empty_kernel",
    )?;
    validate_non_empty(&manifest.issuer, "governance_ladder_manifest_empty_issuer")?;
    validate_non_empty(&manifest.key_id, "governance_ladder_manifest_empty_key")?;
    if manifest.issued_at_unix_ms >= manifest.expires_at_unix_ms {
        return rejected(
            "governance_ladder_manifest_invalid_window",
            "governance ladder manifest validity window is empty",
        );
    }
    if manifest.default_unknown_mode != "deny" {
        return rejected(
            "governance_ladder_manifest_unknown_default_not_deny",
            "governance ladder manifest must deny unknown action classes",
        );
    }
    let destructive_floor_rank = ladder_mode_rank(&manifest.destructive_floor)?;
    let mut action_ids = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    if manifest.action_classes.is_empty() {
        return rejected(
            "governance_ladder_manifest_missing_action_classes",
            "governance ladder manifest must define at least one action class",
        );
    }
    for action in &manifest.action_classes {
        validate_non_empty(&action.action_class_id, "governance_ladder_action_empty_id")?;
        if !action_ids.insert(action.action_class_id.as_str()) {
            return rejected(
                "chiodos_ladder_duplicate_action_class",
                "governance ladder manifest contains a duplicate action class",
            );
        }
        let action_rank = ladder_mode_rank(&action.mode)?;
        validate_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        if action.destructive && action_rank < destructive_floor_rank {
            return rejected(
                "chiodos_ladder_destructive_below_floor",
                "destructive action class resolves below the destructive floor",
            );
        }
        if action.destructive && action.consistency_model == "crdt_commutative" {
            return rejected(
                "chiodos_ladder_destructive_crdt_not_allowed",
                "destructive action class cannot use crdt_commutative consistency",
            );
        }
        if action.destructive && action.evidence_required.is_empty() {
            return rejected(
                "governance_ladder_destructive_missing_evidence",
                "destructive action class must require evidence",
            );
        }
        let mut evidence = BTreeSet::new();
        for item in &action.evidence_required {
            validate_state_label(item, "governance_ladder_invalid_evidence_label")?;
            if !evidence.insert(item.as_str()) {
                return rejected(
                    "governance_ladder_duplicate_evidence",
                    "governance ladder action contains duplicate required evidence",
                );
            }
        }
        for alias in &action.aliases {
            validate_non_empty(alias, "governance_ladder_empty_alias")?;
            if !aliases.insert(alias.as_str()) || action_ids.contains(alias.as_str()) {
                return rejected(
                    "chiodos_ladder_alias_conflict",
                    "governance ladder alias conflicts with another action class",
                );
            }
        }
    }
    Ok(())
}

pub fn validate_treaty_scope(scope: &TreatyScope) -> Result<(), ChiodosRuntimeError> {
    if scope.schema != CHIODOS_TREATY_SCOPE_SCHEMA {
        return rejected(
            "unsupported_treaty_scope_schema",
            "treaty scope declared an unsupported schema",
        );
    }
    validate_non_empty(&scope.treaty_id, "treaty_scope_empty_id")?;
    if scope.issued_at_unix_ms >= scope.expires_at_unix_ms {
        return rejected(
            "chiodos_treaty_stale",
            "treaty scope validity window is empty",
        );
    }
    if scope.participant_kernel_ids.len() < 2 {
        return rejected(
            "chiodos_treaty_missing_participant",
            "treaty scope must bind at least two participant kernels",
        );
    }
    if scope.participant_kernel_ids.len() != scope.ladder_manifest_sha256s.len() {
        return rejected(
            "chiodos_ladder_manifest_hash_mismatch",
            "treaty scope must bind one ladder manifest hash per participant",
        );
    }
    if scope.participant_kernel_ids.len() != scope.participant_public_keys.len() {
        return rejected(
            "chiodos_treaty_missing_participant",
            "treaty scope must bind one public key per participant",
        );
    }
    let mut participants = BTreeSet::new();
    for participant in &scope.participant_kernel_ids {
        validate_non_empty(participant, "treaty_scope_empty_participant")?;
        if !participants.insert(participant.as_str()) {
            return rejected(
                "treaty_scope_duplicate_participant",
                "treaty scope contains duplicate participant kernel",
            );
        }
    }
    let mut public_keys = BTreeSet::new();
    for public_key in &scope.participant_public_keys {
        if !public_keys.insert(public_key.to_hex()) {
            return rejected(
                "treaty_scope_duplicate_participant_key",
                "treaty scope contains duplicate participant public key",
            );
        }
    }
    let mut hashes = BTreeSet::new();
    for hash in &scope.ladder_manifest_sha256s {
        ensure_sha256_hash(hash, "chiodos_ladder_manifest_hash_mismatch")?;
        if !hashes.insert(hash.as_str()) {
            return rejected(
                "chiodos_ladder_manifest_hash_mismatch",
                "treaty scope contains duplicate ladder manifest hash",
            );
        }
    }
    for action_class in &scope.allowed_action_classes {
        validate_non_empty(action_class, "treaty_scope_empty_action_class")?;
    }
    ensure_sha256_hash(
        &scope.revocation_epoch_sha256,
        "treaty_scope_invalid_revocation_epoch_hash",
    )?;
    ensure_sha256_hash(
        &scope.trust_bundle_sha256,
        "treaty_scope_invalid_trust_bundle_hash",
    )
}

pub fn compute_ladder_intersection(
    treaty_scope: &TreatyScope,
    manifests: &[GovernanceLadderManifest],
    now_unix_ms: u64,
) -> Result<LadderIntersection, ChiodosRuntimeError> {
    validate_treaty_scope(treaty_scope)?;
    if now_unix_ms < treaty_scope.issued_at_unix_ms
        || now_unix_ms >= treaty_scope.expires_at_unix_ms
    {
        return rejected("chiodos_treaty_stale", "treaty scope is not fresh");
    }
    if manifests.len() != treaty_scope.participant_kernel_ids.len() {
        return rejected(
            "chiodos_treaty_missing_participant",
            "manifest set does not cover every treaty participant",
        );
    }
    let mut manifest_hashes = Vec::new();
    let mut by_kernel = BTreeMap::new();
    for manifest in manifests {
        validate_governance_ladder_manifest(manifest)?;
        if now_unix_ms < manifest.issued_at_unix_ms || now_unix_ms >= manifest.expires_at_unix_ms {
            return rejected(
                "chiodos_ladder_manifest_stale",
                "governance ladder manifest is not fresh",
            );
        }
        if !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|kernel| kernel == &manifest.kernel_id)
        {
            return rejected(
                "chiodos_treaty_missing_participant",
                "governance ladder manifest kernel is outside treaty scope",
            );
        }
        let hash = governance_ladder_manifest_sha256(manifest)?;
        manifest_hashes.push(hash);
        if by_kernel
            .insert(manifest.kernel_id.as_str(), manifest)
            .is_some()
        {
            return rejected(
                "chiodos_treaty_missing_participant",
                "duplicate governance ladder manifest for participant",
            );
        }
    }
    let expected: BTreeSet<_> = treaty_scope.ladder_manifest_sha256s.iter().collect();
    let actual: BTreeSet<_> = manifest_hashes.iter().collect();
    if expected != actual {
        return rejected(
            "chiodos_ladder_manifest_hash_mismatch",
            "computed ladder manifest hashes do not match treaty scope",
        );
    }

    let mut action_classes = Vec::new();
    for action_class_id in &treaty_scope.allowed_action_classes {
        let mut participant_modes = BTreeMap::new();
        let mut mode_rank = 0;
        let mut mode = "observation".to_string();
        let mut destructive = false;
        let mut consistency_model: Option<String> = None;
        let mut co_sign = "none".to_string();
        let mut evidence_required = BTreeSet::new();
        for participant in &treaty_scope.participant_kernel_ids {
            let Some(manifest) = by_kernel.get(participant.as_str()) else {
                return rejected(
                    "chiodos_treaty_missing_participant",
                    "treaty participant is missing a governance ladder manifest",
                );
            };
            let Some(action) = find_ladder_action(manifest, action_class_id) else {
                return rejected(
                    "chiodos_treaty_action_class_not_allowed",
                    "governance ladder manifest does not allow action class",
                );
            };
            let rank = ladder_mode_rank(&action.mode)?;
            if rank > mode_rank {
                mode_rank = rank;
                mode = action.mode.clone();
            }
            destructive |= action.destructive;
            if let Some(existing) = consistency_model.as_ref() {
                if existing != &action.consistency_model {
                    return rejected(
                        "chiodos_ladder_consistency_mismatch",
                        "governance ladder consistency models do not intersect",
                    );
                }
            } else {
                consistency_model = Some(action.consistency_model.clone());
            }
            if action.co_sign == "bilateral_required" {
                co_sign = action.co_sign.clone();
            }
            for item in &action.evidence_required {
                evidence_required.insert(item.clone());
            }
            participant_modes.insert(participant.clone(), action.mode.clone());
        }
        if destructive && mode_rank < ladder_mode_rank("receipt_backed")? {
            return rejected(
                "chiodos_ladder_destructive_below_floor",
                "intersected destructive action resolves below receipt backed mode",
            );
        }
        action_classes.push(LadderIntersectionActionClass {
            action_class_id: action_class_id.clone(),
            mode,
            destructive,
            consistency_model: consistency_model.unwrap_or_else(|| "totally_ordered".to_string()),
            co_sign,
            evidence_required: evidence_required.into_iter().collect(),
            participant_modes,
        });
    }
    if action_classes.is_empty() {
        return rejected(
            "chiodos_treaty_action_class_not_allowed",
            "treaty scope does not allow any action classes",
        );
    }
    let expires_at_unix_ms = manifests
        .iter()
        .map(|manifest| manifest.expires_at_unix_ms)
        .chain(std::iter::once(treaty_scope.expires_at_unix_ms))
        .min()
        .unwrap_or(treaty_scope.expires_at_unix_ms);
    Ok(LadderIntersection {
        schema: CHIODOS_LADDER_INTERSECTION_SCHEMA.to_string(),
        intersection_id: format!("{}:{}", treaty_scope.treaty_id, now_unix_ms),
        treaty_id: treaty_scope.treaty_id.clone(),
        participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
        ladder_manifest_sha256s: treaty_scope.ladder_manifest_sha256s.clone(),
        generated_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
        action_classes,
    })
}

pub fn validate_ladder_intersection(
    intersection: &LadderIntersection,
) -> Result<(), ChiodosRuntimeError> {
    if intersection.schema != CHIODOS_LADDER_INTERSECTION_SCHEMA {
        return rejected(
            "unsupported_ladder_intersection_schema",
            "ladder intersection declared an unsupported schema",
        );
    }
    validate_non_empty(
        &intersection.intersection_id,
        "ladder_intersection_empty_id",
    )?;
    validate_non_empty(&intersection.treaty_id, "ladder_intersection_empty_treaty")?;
    if intersection.generated_at_unix_ms >= intersection.expires_at_unix_ms {
        return rejected(
            "chiodos_treaty_stale",
            "ladder intersection validity window is empty",
        );
    }
    if intersection.action_classes.is_empty() {
        return rejected(
            "chiodos_treaty_action_class_not_allowed",
            "ladder intersection contains no action classes",
        );
    }
    for hash in &intersection.ladder_manifest_sha256s {
        ensure_sha256_hash(hash, "chiodos_ladder_manifest_hash_mismatch")?;
    }
    for action in &intersection.action_classes {
        validate_non_empty(
            &action.action_class_id,
            "ladder_intersection_empty_action_class",
        )?;
        ladder_mode_rank(&action.mode)?;
        validate_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        if action.destructive
            && ladder_mode_rank(&action.mode)? < ladder_mode_rank("receipt_backed")?
        {
            return rejected(
                "chiodos_ladder_destructive_below_floor",
                "ladder intersection destructive action resolves below receipt backed mode",
            );
        }
    }
    Ok(())
}

pub fn evaluate_cross_boundary_admission(
    input: CrossBoundaryAdmissionInput<'_>,
) -> Result<CrossBoundaryAdmissionReport, ChiodosRuntimeError> {
    validate_treaty_scope(input.treaty_scope)?;
    validate_ladder_intersection(input.ladder_intersection)?;
    let treaty_scope_sha256 = treaty_scope_sha256(input.treaty_scope)?;
    let ladder_intersection_sha256 = ladder_intersection_sha256(input.ladder_intersection)?;
    let mut checks = vec![
        "chiodos_treaty.scope_valid".to_string(),
        "chiodos_treaty.intersection_valid".to_string(),
    ];
    if input.now_unix_ms < input.treaty_scope.issued_at_unix_ms
        || input.now_unix_ms >= input.treaty_scope.expires_at_unix_ms
        || input.now_unix_ms >= input.ladder_intersection.expires_at_unix_ms
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_stale",
            checks,
        ));
    }
    if input.treaty_scope.treaty_id != input.ladder_intersection.treaty_id
        || input.treaty_scope.ladder_manifest_sha256s
            != input.ladder_intersection.ladder_manifest_sha256s
        || input.treaty_scope.participant_kernel_ids
            != input.ladder_intersection.participant_kernel_ids
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_intersection_mismatch",
            checks,
        ));
    }
    let Some(expected_ladder_intersection_sha256) =
        input.expected_ladder_intersection_sha256.clone()
    else {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_missing_intersection_binding",
            checks,
        ));
    };
    if expected_ladder_intersection_sha256 != ladder_intersection_sha256 {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_intersection_mismatch",
            checks,
        ));
    }
    if !input
        .treaty_scope
        .allowed_action_classes
        .iter()
        .any(|action| action == input.action_class_id)
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_action_class_not_allowed",
            checks,
        ));
    }
    let Some(action) = input
        .ladder_intersection
        .action_classes
        .iter()
        .find(|action| action.action_class_id == input.action_class_id)
    else {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chiodos_treaty_action_class_not_allowed",
            checks,
        ));
    };
    let present: BTreeSet<_> = input.present_evidence.iter().map(String::as_str).collect();
    let verified: BTreeMap<_, _> = input
        .verified_evidence
        .iter()
        .map(|evidence| (evidence.evidence_class.as_str(), evidence))
        .collect();
    let required_evidence = required_evidence_for_action(action);
    let missing_required = required_evidence
        .iter()
        .any(|required| !present.contains(required.as_str()));
    if missing_required {
        return Ok(CrossBoundaryAdmissionReport {
            schema: CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
            treaty_id: input.treaty_scope.treaty_id.clone(),
            action_class_id: input.action_class_id.to_string(),
            accepted: false,
            failure_code: Some("chiodos_treaty_missing_required_evidence".to_string()),
            mode: action.mode.clone(),
            consistency_model: action.consistency_model.clone(),
            co_sign: action.co_sign.clone(),
            required_evidence,
            present_evidence: input.present_evidence,
            verified_evidence: input.verified_evidence,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
            checks,
        });
    }
    let missing_verified = required_evidence.iter().any(|required| {
        verified
            .get(required.as_str())
            .is_none_or(|evidence| !evidence.verified)
    });
    if missing_verified {
        return Ok(CrossBoundaryAdmissionReport {
            schema: CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
            treaty_id: input.treaty_scope.treaty_id.clone(),
            action_class_id: input.action_class_id.to_string(),
            accepted: false,
            failure_code: Some("chiodos_treaty_unverified_required_evidence".to_string()),
            mode: action.mode.clone(),
            consistency_model: action.consistency_model.clone(),
            co_sign: action.co_sign.clone(),
            required_evidence,
            present_evidence: input.present_evidence,
            verified_evidence: input.verified_evidence,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
            checks,
        });
    }
    checks.push("chiodos_treaty.required_evidence_present".to_string());
    checks.push("chiodos_treaty.required_evidence_verified".to_string());
    Ok(CrossBoundaryAdmissionReport {
        schema: CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: input.treaty_scope.treaty_id.clone(),
        action_class_id: input.action_class_id.to_string(),
        accepted: true,
        failure_code: None,
        mode: action.mode.clone(),
        consistency_model: action.consistency_model.clone(),
        co_sign: action.co_sign.clone(),
        required_evidence,
        present_evidence: input.present_evidence,
        verified_evidence: input.verified_evidence,
        treaty_scope_sha256,
        ladder_intersection_sha256,
        expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
        checks,
    })
}

fn required_evidence_for_action(action: &LadderIntersectionActionClass) -> Vec<String> {
    let mut required = action.evidence_required.clone();
    if action.co_sign == "bilateral_required"
        && !required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    {
        required.push("bilateral_invocation".to_string());
    }
    required
}

pub fn validate_cross_boundary_admission_report(
    report: &CrossBoundaryAdmissionReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA {
        return rejected(
            "unsupported_cross_boundary_admission_report_schema",
            "cross-boundary admission report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.treaty_id, "cross_boundary_admission_empty_treaty")?;
    validate_non_empty(
        &report.action_class_id,
        "cross_boundary_admission_empty_action_class",
    )?;
    ladder_mode_rank(&report.mode)?;
    validate_consistency_model(&report.consistency_model)?;
    validate_co_sign_mode(&report.co_sign)?;
    ensure_sha256_hash(
        &report.treaty_scope_sha256,
        "cross_boundary_admission_invalid_treaty_hash",
    )?;
    ensure_sha256_hash(
        &report.ladder_intersection_sha256,
        "cross_boundary_admission_invalid_intersection_hash",
    )?;
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "cross_boundary_admission_missing_failure_code",
            "rejected cross-boundary admission report must include failure code",
        );
    }
    for evidence in &report.verified_evidence {
        validate_state_label(
            &evidence.evidence_class,
            "cross_boundary_admission_invalid_evidence_class",
        )?;
        ensure_sha256_hash(
            &evidence.artifact_sha256,
            "cross_boundary_admission_invalid_evidence_hash",
        )?;
    }
    Ok(())
}

pub fn verify_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<BuyerAttestationVerificationReport, ChiodosRuntimeError> {
    validate_buyer_attestation_packet(packet)?;
    validate_receipt_lineage_statement(lineage)?;
    validate_cross_kernel_continuation(continuation)?;
    validate_cross_boundary_admission_report(admission)?;
    validate_bilateral_invocation(bilateral)?;
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)?;
    let mut checks = vec!["chiodos_buyer.packet_valid".to_string()];
    if packet.settlement_claimed {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_settlement_claimed",
            checks,
        ));
    }
    if lineage.evidence_class != "verified" {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_lineage_not_verified",
            checks,
        ));
    }
    if packet.buyer_id != continuation.source_kernel_id
        || lineage.source_kernel_id != continuation.source_kernel_id
        || lineage.target_kernel_id != continuation.target_kernel_id
        || bilateral.signer_kernel_ids.len() != 2
        || bilateral.signer_kernel_ids.first() != Some(&continuation.source_kernel_id)
        || bilateral.signer_kernel_ids.get(1) != Some(&continuation.target_kernel_id)
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_identity_mismatch",
            checks,
        ));
    }
    if packet.capability_id != continuation.capability_id
        || bilateral.capability_id != continuation.capability_id
        || continuation.action_class_id != admission.action_class_id
        || bilateral.action_class_id != continuation.action_class_id
        || bilateral.treaty_id != admission.treaty_id
        || bilateral.consistency_model != admission.consistency_model
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    if receipt_lineage_statement_sha256(lineage)? != packet.receipt_lineage_statement_sha256
        || canonical_sha256(continuation)? != packet.continuation_sha256
        || canonical_sha256(admission)? != packet.cross_boundary_admission_report_sha256
        || bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.continuation_sha256 != packet.continuation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || bilateral.continuation_sha256 != packet.continuation_sha256
        || bilateral.lineage_statement_sha256 != packet.receipt_lineage_statement_sha256
        || bilateral.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || bilateral.local_receipt_sha256 != lineage.parent_receipt_sha256
        || bilateral.remote_receipt_sha256 != lineage.child_receipt_sha256
        || admission.treaty_scope_sha256 != packet.treaty_scope_sha256
        || admission.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || verified_evidence_missing_or_mismatch(
            admission,
            "receipt_lineage",
            &packet.receipt_lineage_statement_sha256,
        )
        || verified_evidence_missing_or_mismatch(
            admission,
            "bilateral_invocation",
            &packet.bilateral_invocation_sha256,
        )
        || !admission.accepted
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    checks.push("chiodos_buyer.lineage_verified".to_string());
    checks.push("chiodos_buyer.verification_state_hash_only".to_string());
    Ok(BuyerAttestationVerificationReport {
        schema: CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "hash_only".to_string(),
        accepted: true,
        failure_code: None,
        checks,
    })
}

fn verified_evidence_missing_or_mismatch(
    admission: &CrossBoundaryAdmissionReport,
    evidence_class: &str,
    artifact_sha256: &str,
) -> bool {
    let mut refs = admission
        .verified_evidence
        .iter()
        .filter(|evidence| evidence.evidence_class == evidence_class);
    let Some(evidence) = refs.next() else {
        return true;
    };
    refs.next().is_some() || evidence.artifact_sha256 != artifact_sha256 || !evidence.verified
}

pub fn verify_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    verify_buyer_attestation_review_package_internal(package, sources, None)
}

pub fn verify_buyer_attestation_review_package_with_trust(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: &BuyerAttestationReviewTrustContext<'_>,
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    verify_buyer_attestation_review_package_internal(package, sources, Some(trust_context))
}

fn verify_buyer_attestation_review_package_internal(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: Option<&BuyerAttestationReviewTrustContext<'_>>,
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    validate_buyer_attestation_review_package(package)?;
    let mut checks = vec![buyer_review_check(
        "chiodos_buyer_review.package_valid",
        true,
        "info",
        "buyer_attestation_review_package",
        None,
        None,
        "buyer review package structure is valid",
    )];
    let refs_by_role = review_refs_by_role(package)?;
    let mut source_bytes_by_role = BTreeMap::new();
    let mut source_paths = BTreeSet::new();
    for source in sources {
        validate_non_empty(&source.role, "buyer_review_artifact_empty_role")?;
        validate_relative_evidence_path(
            &source.relative_path,
            "buyer_review_artifact_unsafe_path",
        )?;
        if !source_paths.insert(source.relative_path.clone()) {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_duplicate_artifact_path",
                checks,
            ));
        }
        let Some(artifact_ref) = refs_by_role.get(&source.role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        if artifact_ref.relative_path != source.relative_path {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_path_bound",
                false,
                "error",
                &source.role,
                Some(artifact_ref.relative_path.clone()),
                Some(source.relative_path.clone()),
                "artifact bytes were supplied from a path outside the package manifest binding",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_path_mismatch",
                checks,
            ));
        }
        let observed = sha256_hex(&source.bytes);
        if observed != artifact_ref.artifact_sha256
            || source.bytes.len() as u64 != artifact_ref.byte_count
        {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_hash_bound",
                false,
                "error",
                &source.role,
                Some(artifact_ref.artifact_sha256.clone()),
                Some(observed),
                "artifact bytes did not match the package manifest",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_hash_mismatch",
                checks,
            ));
        }
        if source_bytes_by_role
            .insert(source.role.clone(), source.bytes.clone())
            .is_some()
        {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_duplicate_artifact_role",
                checks,
            ));
        }
    }
    for role in BUYER_REVIEW_REQUIRED_ROLES {
        let Some(artifact_ref) = refs_by_role.get(*role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        let Some(bytes) = source_bytes_by_role.get(*role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        if bytes.len() as u64 != artifact_ref.byte_count {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_hash_bound",
                false,
                "error",
                role,
                Some(artifact_ref.artifact_sha256.clone()),
                Some(sha256_hex(bytes)),
                "artifact bytes did not match the package manifest",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_hash_mismatch",
                checks,
            ));
        }
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.artifacts_hydrated",
        true,
        "info",
        "artifact_manifest",
        None,
        None,
        "all required artifact roles resolved by hash and byte count",
    ));

    let packet: BuyerAttestationPacket =
        parse_review_json(&source_bytes_by_role, "buyer_attestation_packet")?;
    let lineage: ReceiptLineageStatement =
        parse_review_json(&source_bytes_by_role, "receipt_lineage_statement")?;
    let lineage_bundle: ReceiptLineageBundle =
        parse_review_json(&source_bytes_by_role, "receipt_lineage_bundle")?;
    let continuation: CrossKernelContinuation =
        parse_review_json(&source_bytes_by_role, "cross_kernel_continuation")?;
    let admission: CrossBoundaryAdmissionReport =
        parse_review_json(&source_bytes_by_role, "cross_boundary_admission_report")?;
    let bilateral: BilateralInvocation =
        parse_review_json(&source_bytes_by_role, "bilateral_invocation")?;
    let bilateral_dsse: chio_federation::DsseEnvelope =
        parse_review_json(&source_bytes_by_role, "bilateral_dsse_envelope")?;
    let proof_package: serde_json::Value =
        parse_review_json(&source_bytes_by_role, "proof_package")?;
    if packet.packet_id != package.packet_id || packet.buyer_id != package.buyer_id {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    if !verify_receipt_lineage_bundle(&lineage_bundle)? {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_lineage_bundle_incomplete",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.lineage_bundle_closed",
        true,
        "info",
        "receipt_lineage_bundle",
        None,
        None,
        "receipt lineage bundle closed over verified edges",
    ));
    if let Err(code) =
        verify_buyer_review_lineage_binding(&packet, &lineage, &lineage_bundle, &bilateral)
    {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.lineage_bundle_bound",
        true,
        "info",
        "receipt_lineage_bundle",
        None,
        None,
        "receipt lineage bundle root, leaf, and statement hash matched the buyer packet",
    ));
    let packet_report =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    if !packet_report.accepted {
        return Ok(buyer_review_rejection_report(
            package,
            packet_report
                .failure_code
                .as_deref()
                .unwrap_or("chiodos_buyer_packet_hash_mismatch"),
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.packet_semantics_verified",
        true,
        "info",
        "buyer_attestation_packet",
        None,
        None,
        "buyer packet bindings matched hydrated treaty evidence",
    ));
    let workflow_receipt: serde_json::Value =
        parse_review_json(&source_bytes_by_role, "workflow_receipt")?;
    let verifier_report: serde_json::Value =
        parse_review_json(&source_bytes_by_role, "verifier_report")?;
    let proof_regeneration_report: RuntimeProofRegenerationReport =
        parse_review_json(&source_bytes_by_role, "proof_regeneration_report")?;
    let runtime_run_report: RuntimeWorkflowRunReport =
        parse_review_json(&source_bytes_by_role, "runtime_run_report")?;
    let runtime_evidence_manifest: RuntimeEvidenceManifest =
        parse_review_json(&source_bytes_by_role, "runtime_evidence_manifest")?;
    let proof_regeneration_input: RuntimeProofRegenerationInput =
        parse_review_json(&source_bytes_by_role, "proof_regeneration_input")?;
    let workflow_sha256 = canonical_sha256(&workflow_receipt)?;
    let proof_sha256 = canonical_sha256(&proof_package)?;
    let verifier_sha256 = canonical_sha256(&verifier_report)?;
    if workflow_sha256 != packet.workflow_receipt_sha256
        || proof_sha256 != packet.proof_package_sha256
        || verifier_sha256 != packet.verifier_report_sha256
    {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    let bilateral_dsse_sha256 = canonical_sha256(&bilateral_dsse)?;
    if bilateral_dsse_sha256 != packet.bilateral_dsse_sha256 {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    if let Err(code) = verify_buyer_review_proof_package(
        &proof_package,
        &workflow_receipt,
        &workflow_sha256,
        &bilateral_dsse_sha256,
    ) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.proof_package_hydrated",
        true,
        "info",
        "proof_package",
        None,
        None,
        "proof package carried the hydrated workflow receipt and bilateral DSSE envelope",
    ));
    let Some(trust_context) = trust_context else {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_strict_dsse_signer_mismatch",
            checks,
        ));
    };
    if package.generated_at_unix_ms != runtime_evidence_manifest.generated_at_unix_ms {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_manifest_timestamp_mismatch",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.package_manifest_timestamp_bound",
        true,
        "info",
        "runtime_evidence_manifest",
        None,
        None,
        "buyer review package timestamp matched the runtime evidence manifest",
    ));
    let Some((context_issued_at, context_expires_at)) =
        buyer_review_verification_context_window(trust_context.verification_context)
    else {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_stale",
            checks,
        ));
    };
    if package.generated_at_unix_ms < context_issued_at
        || package.generated_at_unix_ms >= context_expires_at
    {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_stale",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.package_fresh",
        true,
        "info",
        "buyer_attestation_review_package",
        None,
        None,
        &format!(
            "buyer review package generated at {} inside verification context window {}..{}",
            package.generated_at_unix_ms, context_issued_at, context_expires_at
        ),
    ));
    let trust_bundle_sha256 = canonical_sha256(trust_context.verifier_trust_bundle)
        .map_err(|_| ChiodosRuntimeError::Canonical("verifier trust bundle".to_string()))?;
    let verification_context_sha256 = canonical_sha256(trust_context.verification_context)
        .map_err(|_| ChiodosRuntimeError::Canonical("verification context".to_string()))?;
    let runtime_step = match verify_buyer_review_runtime_reports(BuyerReviewRuntimeReportContext {
        runtime_run_report: &runtime_run_report,
        proof_regeneration_report: &proof_regeneration_report,
        packet: &packet,
        bilateral: &bilateral,
        proof_package: &proof_package,
        workflow_receipt: &workflow_receipt,
        runtime_evidence_manifest: &runtime_evidence_manifest,
        proof_regeneration_input: &proof_regeneration_input,
        proof_sha256: &proof_sha256,
        verifier_sha256: &verifier_sha256,
        workflow_sha256: &workflow_sha256,
        bilateral_dsse_sha256: &bilateral_dsse_sha256,
        trust_bundle_sha256: &trust_bundle_sha256,
        verification_context_sha256: &verification_context_sha256,
        artifact_refs: &package.artifacts,
    }) {
        Ok(step) => step,
        Err(code) => return Ok(buyer_review_rejection_report(package, code, checks)),
    };
    checks.push(buyer_review_check(
        "chiodos_buyer_review.runtime_reports_bound",
        true,
        "info",
        "runtime_run_report",
        None,
        None,
        "runtime run and proof regeneration reports bound the hydrated proof artifacts",
    ));
    let signer_public_keys = match buyer_review_signer_public_keys_from_trust_bundle(
        trust_context.verifier_trust_bundle,
        &verifier_report,
        &proof_package,
        &bilateral.signer_kernel_ids,
    ) {
        Ok(Some(keys)) => keys,
        Ok(None) => {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_strict_dsse_signer_mismatch",
                checks,
            ))
        }
        Err(code) => return Ok(buyer_review_rejection_report(package, code, checks)),
    };
    let strict_dsse_context = BuyerReviewStrictDsseContext {
        packet: &packet,
        lineage_bundle: &lineage_bundle,
        admission: &admission,
        bilateral: &bilateral,
        proof_package: &proof_package,
        runtime_step: &runtime_step,
        signer_public_keys: &signer_public_keys,
        generated_at_unix_ms: package.generated_at_unix_ms,
    };
    if let Err(code) = verify_buyer_review_strict_dsse(&bilateral_dsse, &strict_dsse_context) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.strict_dsse_treaty_bound",
        true,
        "info",
        "bilateral_dsse_envelope",
        None,
        None,
        "strict Chiodos DSSE predicate carried treaty runtime bindings",
    ));
    if let Err(code) = verify_buyer_review_existing_verifier(
        &verifier_report,
        &BuyerReviewExistingVerifierContext {
            proof_package: &proof_package,
            verifier_trust_bundle: trust_context.verifier_trust_bundle,
            verification_context: trust_context.verification_context,
            proof_sha256: &proof_sha256,
            trust_bundle_sha256: &trust_bundle_sha256,
            verification_context_sha256: &verification_context_sha256,
            verifier_sha256: &verifier_sha256,
        },
    ) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.proof_verifier_accepted",
        true,
        "info",
        "verifier_report",
        None,
        None,
        "verifier report accepted the regenerated proof package",
    ));
    Ok(BuyerAttestationReviewReport {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: true,
        failure_code: None,
        checks,
    })
}

fn buyer_review_verification_context_window(context: &serde_json::Value) -> Option<(u64, u64)> {
    let issued_at = context.get("issuedAtUnixMs")?.as_u64()?;
    let expires_at = context.get("expiresAtUnixMs")?.as_u64()?;
    (expires_at > issued_at).then_some((issued_at, expires_at))
}

fn verify_buyer_review_lineage_binding(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    lineage_bundle: &ReceiptLineageBundle,
    bilateral: &BilateralInvocation,
) -> Result<(), &'static str> {
    let lineage_sha256 =
        canonical_sha256(lineage).map_err(|_| "chiodos_buyer_review_packet_hash_mismatch")?;
    if lineage_sha256 != packet.receipt_lineage_statement_sha256 {
        return Err("chiodos_buyer_review_packet_hash_mismatch");
    }
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)
        .map_err(|_| "chiodos_treaty_bilateral_mismatch")?;
    if bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
    {
        return Err("chiodos_treaty_bilateral_mismatch");
    }
    let mut bundle_contains_packet_statement = false;
    for statement in &lineage_bundle.statements {
        let statement_sha256 =
            canonical_sha256(statement).map_err(|_| "chiodos_lineage_bundle_incomplete")?;
        if statement_sha256 == packet.receipt_lineage_statement_sha256 {
            bundle_contains_packet_statement = true;
            break;
        }
    }
    if !bundle_contains_packet_statement {
        return Err("chiodos_lineage_bundle_incomplete");
    }
    if lineage_bundle.root_receipt_sha256 != bilateral.local_receipt_sha256
        || lineage_bundle.leaf_receipt_sha256 != bilateral.remote_receipt_sha256
    {
        return Err("chiodos_treaty_bilateral_mismatch");
    }
    Ok(())
}

fn verify_buyer_review_proof_package(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    workflow_sha256: &str,
    bilateral_dsse_sha256: &str,
) -> Result<(), &'static str> {
    if proof_package
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some("chio.chiodos.proof-package.v1")
    {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    }
    for field in [
        "toolReceipts",
        "bilateralEnvelopes",
        "capabilityLeases",
        "leaseScopeBindings",
        "peerLadderBindings",
        "vendorKeys",
    ] {
        let Some(values) = proof_package
            .get(field)
            .and_then(serde_json::Value::as_array)
        else {
            return Err("chiodos_buyer_review_proof_package_incomplete");
        };
        if values.is_empty() {
            return Err("chiodos_buyer_review_proof_package_incomplete");
        }
    }
    if !proof_package
        .get("selectiveDisclosureProof")
        .is_some_and(serde_json::Value::is_object)
        || !proof_package
            .get("workflowIntersection")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    }
    let Some(embedded_workflow_receipt) = proof_package.get("workflowReceipt") else {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    };
    if embedded_workflow_receipt != workflow_receipt {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let embedded_workflow_sha256 = canonical_sha256(embedded_workflow_receipt)
        .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
    if embedded_workflow_sha256 != workflow_sha256 {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    if proof_package.get("treatyBilateralEnvelopes").is_some() {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let bilateral_envelopes = proof_package
        .get("bilateralEnvelopes")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    let mut contains_hydrated_envelope = false;
    for envelope in bilateral_envelopes {
        let envelope_sha256 = canonical_sha256(envelope)
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if envelope_sha256 == bilateral_dsse_sha256 {
            contains_hydrated_envelope = true;
            break;
        }
    }
    if !contains_hydrated_envelope {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    Ok(())
}

fn verify_buyer_review_existing_verifier(
    verifier_report: &serde_json::Value,
    context: &BuyerReviewExistingVerifierContext<'_>,
) -> Result<(), &'static str> {
    if verifier_report
        .get("packageSha256")
        .and_then(serde_json::Value::as_str)
        != Some(context.proof_sha256)
        || verifier_report
            .get("trustBundleSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.trust_bundle_sha256)
        || verifier_report
            .get("contextSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.verification_context_sha256)
        || verifier_report
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    let proof_package_json = serde_json::to_string(context.proof_package)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let verifier_trust_bundle_json = serde_json::to_string(context.verifier_trust_bundle)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let verification_context_json = serde_json::to_string(context.verification_context)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_package = chio_chiodos::proof_package_from_json(&proof_package_json)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_trust_bundle =
        chio_chiodos::verifier_trust_bundle_from_json(&verifier_trust_bundle_json)
            .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_context = chio_chiodos::verification_context_from_json(&verification_context_json)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let expected_report =
        chio_chiodos::verify_package_report(&typed_package, &typed_trust_bundle, &typed_context);
    if !expected_report.accepted {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    if expected_report.package_sha256 != context.proof_sha256
        || expected_report.trust_bundle_sha256.as_deref() != Some(context.trust_bundle_sha256)
        || expected_report.context_sha256.as_deref() != Some(context.verification_context_sha256)
    {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    let expected_sha256 = canonical_sha256(&expected_report)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    if expected_sha256 != context.verifier_sha256 {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    Ok(())
}

struct BuyerReviewExistingVerifierContext<'a> {
    proof_package: &'a serde_json::Value,
    verifier_trust_bundle: &'a serde_json::Value,
    verification_context: &'a serde_json::Value,
    proof_sha256: &'a str,
    trust_bundle_sha256: &'a str,
    verification_context_sha256: &'a str,
    verifier_sha256: &'a str,
}

struct BuyerReviewRuntimeReportContext<'a> {
    runtime_run_report: &'a RuntimeWorkflowRunReport,
    proof_regeneration_report: &'a RuntimeProofRegenerationReport,
    packet: &'a BuyerAttestationPacket,
    bilateral: &'a BilateralInvocation,
    proof_package: &'a serde_json::Value,
    workflow_receipt: &'a serde_json::Value,
    runtime_evidence_manifest: &'a RuntimeEvidenceManifest,
    proof_regeneration_input: &'a RuntimeProofRegenerationInput,
    proof_sha256: &'a str,
    verifier_sha256: &'a str,
    workflow_sha256: &'a str,
    bilateral_dsse_sha256: &'a str,
    trust_bundle_sha256: &'a str,
    verification_context_sha256: &'a str,
    artifact_refs: &'a [BuyerAttestationReviewArtifactRef],
}

fn verify_buyer_review_runtime_reports(
    context: BuyerReviewRuntimeReportContext<'_>,
) -> Result<RuntimeStepEvidence, &'static str> {
    let BuyerReviewRuntimeReportContext {
        runtime_run_report,
        proof_regeneration_report,
        packet,
        bilateral,
        proof_package,
        workflow_receipt,
        runtime_evidence_manifest,
        proof_regeneration_input,
        proof_sha256,
        verifier_sha256,
        workflow_sha256,
        bilateral_dsse_sha256,
        trust_bundle_sha256,
        verification_context_sha256,
        artifact_refs,
    } = context;
    if validate_runtime_workflow_run_report(runtime_run_report).is_err()
        || validate_runtime_proof_regeneration_report(proof_regeneration_report).is_err()
        || validate_runtime_evidence_manifest(runtime_evidence_manifest).is_err()
        || validate_runtime_proof_regeneration_input(proof_regeneration_input).is_err()
        || !runtime_run_report.accepted
        || !proof_regeneration_report.accepted
        || runtime_run_report.generated_at_unix_ms != runtime_evidence_manifest.generated_at_unix_ms
        || proof_regeneration_report.generated_at_unix_ms
            != runtime_evidence_manifest.generated_at_unix_ms
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    let proof_regeneration_sha256 = canonical_sha256(proof_regeneration_report)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    let runtime_run_sha256 = canonical_sha256(runtime_run_report)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    let manifest_sha256 = canonical_sha256(runtime_evidence_manifest)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    if runtime_run_report
        .proof_regeneration_report_sha256
        .as_deref()
        != Some(proof_regeneration_sha256.as_str())
        || runtime_run_report.run_id != proof_regeneration_report.run_id
        || runtime_evidence_manifest.run_id != runtime_run_report.run_id
        || runtime_evidence_manifest.workflow_run_report_sha256 != runtime_run_sha256
        || runtime_evidence_manifest.proof_regeneration_report_sha256 != proof_regeneration_sha256
        || proof_regeneration_input.run_id != runtime_run_report.run_id
        || proof_regeneration_input.evidence_manifest_sha256 != manifest_sha256
        || proof_regeneration_input.workflow_run_report_sha256 != runtime_run_sha256
        || proof_regeneration_input.source_records != proof_regeneration_report.source_records
        || runtime_run_report.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.trust_bundle_sha256 != trust_bundle_sha256
        || proof_regeneration_input.verification_context_sha256 != verification_context_sha256
        || proof_regeneration_report.proof_package_sha256.as_deref() != Some(proof_sha256)
        || proof_regeneration_report.verifier_report_sha256.as_deref() != Some(verifier_sha256)
        || proof_regeneration_report.workflow_receipt_sha256.as_deref() != Some(workflow_sha256)
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    verify_runtime_evidence_manifest_artifacts(runtime_evidence_manifest, artifact_refs)?;
    let Some(step) = runtime_run_report
        .step_evidence
        .iter()
        .find(|step| step.bilateral_dsse_sha256 == bilateral_dsse_sha256)
    else {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    };
    if step.lease_id.is_none() || step.governance_receipt_id.is_none() {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if step.admission_report_sha256 != packet.cross_boundary_admission_report_sha256
        || step.tool_receipt_sha256 != bilateral.remote_receipt_sha256
        || step.parent_receipt_sha256.as_deref() != Some(bilateral.local_receipt_sha256.as_str())
        || step.output_sha256 != bilateral.outcome_sha256
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if !workflow_receipt_contains_step_hash(workflow_receipt, &step.workflow_step_sha256)? {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if !proof_package_contains_signed_receipt(proof_package, &step.tool_receipt_sha256)? {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    if let Some(parent_receipt_sha256) = step.parent_receipt_sha256.as_deref() {
        if !proof_package_contains_parent_lineage_anchor(
            proof_package,
            workflow_receipt,
            &step.workflow_step_sha256,
            parent_receipt_sha256,
        )? {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
    }
    if !proof_package_array_contains_field(
        proof_package,
        "capabilityLeases",
        "leaseId",
        step.lease_id
            .as_deref()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?,
    ) || !proof_package_array_contains_field(
        proof_package,
        "governanceReceipts",
        "receiptId",
        step.governance_receipt_id
            .as_deref()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?,
    ) {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let source_record_matches = proof_regeneration_report
        .source_records
        .iter()
        .any(|record| {
            record.step_index == step.step_index
                && record.admission_report_sha256 == step.admission_report_sha256
                && record.tool_receipt_sha256 == step.tool_receipt_sha256
                && record.bilateral_dsse_sha256 == step.bilateral_dsse_sha256
                && record.workflow_step_sha256 == step.workflow_step_sha256
        });
    if !source_record_matches {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    Ok(step.clone())
}

fn verify_runtime_evidence_manifest_artifacts(
    manifest: &RuntimeEvidenceManifest,
    artifact_refs: &[BuyerAttestationReviewArtifactRef],
) -> Result<(), &'static str> {
    for role in [
        "bilateral_dsse_envelope",
        "workflow_receipt",
        "proof_package",
        "verifier_report",
        "proof_regeneration_report",
        "runtime_run_report",
    ] {
        let Some(artifact) = artifact_refs.iter().find(|artifact| artifact.role == role) else {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        };
        let Some(entry) = manifest.entries.iter().find(|entry| entry.role == role) else {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        };
        if entry.path != artifact.relative_path
            || entry.sha256 != artifact.artifact_sha256
            || entry.byte_count != artifact.byte_count
        {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        }
    }
    Ok(())
}

fn receipt_wire_value_matches_parsed_receipt(
    wire_value: &serde_json::Value,
    receipt: &ChioReceipt,
) -> Result<bool, &'static str> {
    let typed_value =
        serde_json::to_value(receipt).map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
    let mut normalized_wire_value = wire_value.clone();
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "trust_level",
        |value| value.as_str() == Some("mediated"),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "algorithm",
        |value| value.as_str() == Some("ed25519") || value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "evidence",
        |value| value.as_array().is_some_and(Vec::is_empty),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "metadata",
        |value| value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "tenant_id",
        |value| value.is_null(),
    );
    Ok(normalized_wire_value == typed_value)
}

fn remove_default_receipt_wire_field<F>(
    wire_value: &mut serde_json::Value,
    typed_value: &serde_json::Value,
    field: &str,
    is_default: F,
) where
    F: Fn(&serde_json::Value) -> bool,
{
    if typed_value.get(field).is_some() {
        return;
    }
    let Some(wire_object) = wire_value.as_object_mut() else {
        return;
    };
    if wire_object.get(field).is_some_and(is_default) {
        wire_object.remove(field);
    }
}

fn proof_package_contains_signed_receipt(
    proof_package: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?
        .iter()
        .map(|value| {
            let actual_sha256 = canonical_sha256(value)
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if actual_sha256 != expected_sha256 {
                return Ok(false);
            }
            let receipt: ChioReceipt = serde_json::from_value(value.clone())
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if !receipt_wire_value_matches_parsed_receipt(value, &receipt)? {
                return Err("chiodos_buyer_review_proof_package_mismatch");
            }
            let signature_valid = receipt
                .verify_signature()
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if !signature_valid {
                return Err("chiodos_buyer_review_proof_package_mismatch");
            }
            Ok(true)
        })
        .try_fold(false, |found, current| {
            current.map(|current| found || current)
        })
}

fn proof_package_array_contains_field(
    proof_package: &serde_json::Value,
    array_field: &str,
    field: &str,
    expected: &str,
) -> bool {
    proof_package
        .get(array_field)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .get(field)
                    .or_else(|| value.get("body").and_then(|body| body.get(field)))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actual| actual == expected)
            })
        })
}

fn workflow_receipt_contains_step_hash(
    workflow_receipt: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    Ok(workflow_step_by_hash(workflow_receipt, expected_sha256)?.is_some())
}

fn workflow_step_by_hash<'a>(
    workflow_receipt: &'a serde_json::Value,
    expected_sha256: &str,
) -> Result<Option<&'a serde_json::Value>, &'static str> {
    let Some(steps) = workflow_receipt
        .get("steps")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(workflow_receipt
            .get("workflowStepSha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|hash| hash == expected_sha256)
            .then_some(workflow_receipt));
    };
    for step in steps {
        let hash =
            canonical_sha256(step).map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
        if hash == expected_sha256 {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn proof_package_contains_parent_lineage_anchor(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    child_workflow_step_sha256: &str,
    parent_sha256: &str,
) -> Result<bool, &'static str> {
    if proof_package_contains_signed_receipt(proof_package, parent_sha256)? {
        return Ok(true);
    }
    let Some(child_step) = workflow_step_by_hash(workflow_receipt, child_workflow_step_sha256)?
    else {
        return Ok(false);
    };
    if child_step
        .get("parent_receipt_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(parent_sha256)
    {
        return Ok(false);
    }
    workflow_receipt_contains_step_hash(workflow_receipt, parent_sha256)
}

fn proof_package_receipt_subject(
    proof_package: &serde_json::Value,
    receipt_sha256: &str,
) -> Result<(String, String), &'static str> {
    let receipts = proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for receipt_value in receipts {
        let Ok(actual_sha256) = canonical_sha256(receipt_value) else {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        };
        if actual_sha256 != receipt_sha256 {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_value(receipt_value.clone())
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if !receipt_wire_value_matches_parsed_receipt(receipt_value, &receipt)? {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        let signature_valid = receipt
            .verify_signature()
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if !signature_valid {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        let subject_sha256 = canonical_sha256(&receipt.body())
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        return Ok((
            chio_federation::receipt_subject_name(&receipt.id),
            subject_sha256,
        ));
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

fn proof_package_capability_lease_ref(
    proof_package: &serde_json::Value,
    lease_id: &str,
) -> Result<chio_federation::CapabilityLeaseRef, &'static str> {
    let leases = proof_package
        .get("capabilityLeases")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for lease in leases {
        let body = lease.get("body").unwrap_or(lease);
        if body.get("leaseId").and_then(serde_json::Value::as_str) != Some(lease_id) {
            continue;
        }
        let issuer = body
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let expires_at_unix_ms = body
            .get("expiresAtUnixMs")
            .and_then(serde_json::Value::as_u64)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let scope_digest = body
            .get("scopeDigest")
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        return Ok(chio_federation::CapabilityLeaseRef {
            lease_id: lease_id.to_string(),
            issuer: issuer.to_string(),
            expires_at_unix_ms,
            scope_digest: Some(chio_federation::HashRecord {
                alg: "sha256".to_string(),
                value: scope_digest.to_string(),
            }),
        });
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

fn proof_package_governance_receipt_ref(
    proof_package: &serde_json::Value,
    receipt_id: &str,
) -> Result<chio_federation::GovernanceReceiptRef, &'static str> {
    let receipts = proof_package
        .get("governanceReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for receipt in receipts {
        let body = receipt.get("body").unwrap_or(receipt);
        if body.get("receiptId").and_then(serde_json::Value::as_str) != Some(receipt_id) {
            continue;
        }
        let kernel_id = body
            .get("authorizingKernel")
            .or_else(|| body.get("kernelId"))
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let digest =
            canonical_sha256(receipt).map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if receipt
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|claimed| claimed != digest)
        {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        return Ok(chio_federation::GovernanceReceiptRef {
            receipt_id: receipt_id.to_string(),
            kernel_id: kernel_id.to_string(),
            digest: chio_federation::HashRecord {
                alg: "sha256".to_string(),
                value: digest,
            },
        });
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

pub fn verify_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<bool, ChiodosRuntimeError> {
    validate_receipt_lineage_bundle(bundle)?;
    if bundle.statements.is_empty() {
        return rejected(
            "chiodos_lineage_bundle_incomplete",
            "receipt lineage bundle must contain at least one statement",
        );
    }
    let mut seen_statement_ids = BTreeSet::new();
    let mut seen_receipts = BTreeSet::new();
    let mut current = bundle.root_receipt_sha256.clone();
    seen_receipts.insert(current.clone());
    for statement in &bundle.statements {
        validate_receipt_lineage_statement(statement)?;
        if statement.evidence_class != "verified" {
            return rejected(
                "chiodos_lineage_bundle_unverified_edge",
                "receipt lineage bundle requires verified lineage edges",
            );
        }
        if !seen_statement_ids.insert(statement.statement_id.clone()) {
            return rejected(
                "chiodos_lineage_bundle_cycle",
                "receipt lineage bundle contains duplicate statement id",
            );
        }
        if statement.parent_receipt_sha256 != current {
            return rejected(
                "chiodos_lineage_bundle_incomplete",
                "receipt lineage bundle has a parent-child gap",
            );
        }
        if !seen_receipts.insert(statement.child_receipt_sha256.clone()) {
            return rejected(
                "chiodos_lineage_bundle_cycle",
                "receipt lineage bundle reuses a child receipt",
            );
        }
        current = statement.child_receipt_sha256.clone();
    }
    if current != bundle.leaf_receipt_sha256 {
        return rejected(
            "chiodos_lineage_bundle_incomplete",
            "receipt lineage bundle does not reach the declared leaf receipt",
        );
    }
    Ok(true)
}

struct BuyerReviewStrictDsseContext<'a> {
    packet: &'a BuyerAttestationPacket,
    lineage_bundle: &'a ReceiptLineageBundle,
    admission: &'a CrossBoundaryAdmissionReport,
    bilateral: &'a BilateralInvocation,
    proof_package: &'a serde_json::Value,
    runtime_step: &'a RuntimeStepEvidence,
    signer_public_keys: &'a BTreeMap<String, PublicKey>,
    generated_at_unix_ms: u64,
}

fn verify_buyer_review_strict_dsse(
    envelope: &chio_federation::DsseEnvelope,
    context: &BuyerReviewStrictDsseContext<'_>,
) -> Result<(), &'static str> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return Err("chiodos_buyer_review_non_strict_dsse");
    };
    if statement.predicate_type != chio_federation::PREDICATE_TYPE_CHIODOS_BILATERAL {
        return Err("chiodos_buyer_review_non_strict_dsse");
    }
    if statement.predicate.timestamp_unix_ms != context.generated_at_unix_ms {
        return Err("chiodos_buyer_review_runtime_timestamp_mismatch");
    }
    let lineage_bundle_sha256 = match canonical_sha256(context.lineage_bundle) {
        Ok(hash) => hash,
        Err(_) => return Err("chiodos_buyer_review_lineage_hash_mismatch"),
    };
    let expected_treaty_binding = chio_federation::TreatyBindingRef {
        treaty_id: context.admission.treaty_id.clone(),
        treaty_scope_sha256: context.packet.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: context.packet.ladder_intersection_sha256.clone(),
        admission_report_sha256: context
            .packet
            .cross_boundary_admission_report_sha256
            .clone(),
        continuation_sha256: context.packet.continuation_sha256.clone(),
        lineage_bundle_sha256,
        action_class_id: context.admission.action_class_id.clone(),
        consistency_model: context.admission.consistency_model.clone(),
        request_sha256: context.bilateral.request_sha256.clone(),
        outcome_sha256: context.bilateral.outcome_sha256.clone(),
        local_receipt_sha256: context.bilateral.local_receipt_sha256.clone(),
        remote_receipt_sha256: context.bilateral.remote_receipt_sha256.clone(),
        lease_refs: vec![context
            .runtime_step
            .lease_id
            .clone()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?],
        governance_refs: vec![context
            .runtime_step
            .governance_receipt_id
            .clone()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?],
        signer_kernel_ids: context.bilateral.signer_kernel_ids.clone(),
    };
    let (expected_subject_name, expected_subject_sha256) = proof_package_receipt_subject(
        context.proof_package,
        &context.runtime_step.tool_receipt_sha256,
    )?;
    let lease_id = context
        .runtime_step
        .lease_id
        .as_deref()
        .ok_or("chiodos_buyer_review_runtime_report_mismatch")?;
    let expected_capability_lease_ref =
        proof_package_capability_lease_ref(context.proof_package, lease_id)?;
    let governance_receipt_id = context
        .runtime_step
        .governance_receipt_id
        .as_deref()
        .ok_or("chiodos_buyer_review_runtime_report_mismatch")?;
    let expected_governance_receipt_ref =
        proof_package_governance_receipt_ref(context.proof_package, governance_receipt_id)?;
    let review = chio_federation::TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: &context.runtime_step.consistency_anchor,
        signer_public_keys: context.signer_public_keys,
    };
    chio_federation::verify_treaty_bound_chiodos_bilateral_invocation(envelope, &review)
        .map(|_| ())
        .map_err(|error| buyer_review_strict_dsse_error_code(&error))
}

fn buyer_review_signer_public_keys_from_trust_bundle(
    verifier_trust_bundle: &serde_json::Value,
    verifier_report: &serde_json::Value,
    proof_package: &serde_json::Value,
    signer_kernel_ids: &[String],
) -> Result<Option<BTreeMap<String, PublicKey>>, &'static str> {
    let trust_bundle_sha256 = canonical_sha256(verifier_trust_bundle)
        .map_err(|_| "chiodos_buyer_review_strict_dsse_signer_mismatch")?;
    if verifier_report
        .get("trustBundleSha256")
        .and_then(serde_json::Value::as_str)
        != Some(trust_bundle_sha256.as_str())
    {
        return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
    }
    let Some(trusted_peers) = verifier_trust_bundle
        .get("peers")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let Some(proof_bindings) = proof_package
        .get("peerLadderBindings")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let expected_signers: BTreeSet<&str> = signer_kernel_ids.iter().map(String::as_str).collect();
    let mut signer_public_keys = BTreeMap::new();
    for binding in trusted_peers {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        let public_key = PublicKey::from_hex(public_key_hex)
            .map_err(|_| "chiodos_buyer_review_strict_dsse_signature_invalid")?;
        if signer_public_keys
            .insert(kernel_id.to_string(), public_key)
            .is_some()
        {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    for binding in proof_bindings {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        let Some(trusted_key) = signer_public_keys.get(kernel_id) else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        if trusted_key.to_hex() != public_key_hex {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    if signer_public_keys.is_empty() {
        return Ok(None);
    }
    if signer_kernel_ids
        .iter()
        .any(|kernel_id| !signer_public_keys.contains_key(kernel_id))
    {
        return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
    }
    Ok(Some(signer_public_keys))
}

fn buyer_review_strict_dsse_error_code(error: &chio_federation::VerifierError) -> &'static str {
    match error {
        chio_federation::VerifierError::PredicateTypeUnrecognised(_)
        | chio_federation::VerifierError::StatementMalformed(_)
        | chio_federation::VerifierError::StatementSchemaInvalid(_) => {
            "chiodos_buyer_review_non_strict_dsse"
        }
        chio_federation::VerifierError::PredicateSchemaInvalid(message) => {
            if message.contains("missing treaty_binding_ref") {
                "chiodos_buyer_review_missing_treaty_dsse_binding"
            } else if message.contains("signer_kernel_ids") || message.contains("signer kernels") {
                "chiodos_buyer_review_strict_dsse_signer_mismatch"
            } else {
                "chiodos_buyer_review_strict_dsse_binding_mismatch"
            }
        }
        chio_federation::VerifierError::PeerUnpinnedOrKeyidMismatch(_) => {
            "chiodos_buyer_review_strict_dsse_signer_mismatch"
        }
        chio_federation::VerifierError::SignatureServerAInvalid(_)
        | chio_federation::VerifierError::SignatureServerBInvalid(_) => {
            "chiodos_buyer_review_strict_dsse_signature_invalid"
        }
        chio_federation::VerifierError::DsseMalformed(message) => {
            if message.contains("duplicate signature")
                || message.contains("signature keyid")
                || message.contains("signer keys")
                || message.contains("independent Org")
                || message.contains("expected exactly 2 signatures")
            {
                "chiodos_buyer_review_strict_dsse_signature_invalid"
            } else {
                "chiodos_buyer_review_non_strict_dsse"
            }
        }
        _ => "chiodos_buyer_review_strict_dsse_binding_mismatch",
    }
}

pub fn build_runtime_orchestration_plan(
    profile: &RuntimeOrchestrationProfile,
    contract: &RuntimeRunContract,
    now_unix_ms: u64,
) -> Result<RuntimeOrchestrationPlan, ChiodosRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    validate_runtime_run_contract(contract)?;
    let profile_sha256 = runtime_orchestration_profile_sha256(profile)?;
    if contract.profile_sha256 != profile_sha256 {
        return Ok(RuntimeOrchestrationPlan {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
            run_id: contract.run_id.clone(),
            accepted: false,
            failure_code: Some("runtime_orchestration_profile_hash_mismatch".to_string()),
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            run_contract_sha256: runtime_run_contract_sha256(contract)?,
            planned_steps: Vec::new(),
            checks: vec!["runtime_orchestration.profile_hash".to_string()],
        });
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Ok(RuntimeOrchestrationPlan {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
            run_id: contract.run_id.clone(),
            accepted: false,
            failure_code: Some("runtime_orchestration_profile_stale".to_string()),
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            run_contract_sha256: runtime_run_contract_sha256(contract)?,
            planned_steps: Vec::new(),
            checks: vec![
                "runtime_orchestration.profile_hash".to_string(),
                "runtime_orchestration.profile_freshness".to_string(),
            ],
        });
    }
    let planned_steps = contract
        .admission_ids
        .iter()
        .enumerate()
        .map(|(index, admission_id)| RuntimeOrchestrationPlannedStep {
            step_index: u64::try_from(index).unwrap_or(u64::MAX),
            admission_id: admission_id.clone(),
            state: "pending".to_string(),
        })
        .collect();
    Ok(RuntimeOrchestrationPlan {
        schema: CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA.to_string(),
        run_id: contract.run_id.clone(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: now_unix_ms,
        profile_sha256,
        run_contract_sha256: runtime_run_contract_sha256(contract)?,
        planned_steps,
        checks: vec![
            "runtime_orchestration.profile_valid".to_string(),
            "runtime_orchestration.run_contract_valid".to_string(),
        ],
    })
}

pub fn generate_runtime_proof_drift_report(
    baseline_manifest: &RuntimeEvidenceManifest,
    candidate_manifest: &RuntimeEvidenceManifest,
    baseline_proof: &RuntimeProofRegenerationReport,
    candidate_proof: &RuntimeProofRegenerationReport,
    now_unix_ms: u64,
) -> Result<RuntimeProofDriftReport, ChiodosRuntimeError> {
    validate_runtime_evidence_manifest(baseline_manifest)?;
    validate_runtime_evidence_manifest(candidate_manifest)?;
    validate_runtime_proof_regeneration_report(baseline_proof)?;
    validate_runtime_proof_regeneration_report(candidate_proof)?;
    let mut semantic_drifts = Vec::new();
    let mut artifact_drifts = Vec::new();
    let mut verifier_drifts = Vec::new();

    compare_semantic_field(
        "proof_package_sha256",
        &baseline_proof.proof_package_sha256,
        &candidate_proof.proof_package_sha256,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "workflow_receipt_sha256",
        &baseline_proof.workflow_receipt_sha256,
        &candidate_proof.workflow_receipt_sha256,
        &mut semantic_drifts,
    )?;
    compare_semantic_field(
        "source_records",
        &baseline_proof.source_records,
        &candidate_proof.source_records,
        &mut semantic_drifts,
    )?;
    compare_verifier_field(
        "verifier_report_sha256",
        &baseline_proof.verifier_report_sha256,
        &candidate_proof.verifier_report_sha256,
        &mut verifier_drifts,
    )?;
    let baseline_entries: BTreeMap<(&str, &str), &RuntimeEvidenceManifestEntry> = baseline_manifest
        .entries
        .iter()
        .map(|entry| ((entry.role.as_str(), entry.path.as_str()), entry))
        .collect();
    let candidate_entries: BTreeMap<(&str, &str), &RuntimeEvidenceManifestEntry> =
        candidate_manifest
            .entries
            .iter()
            .map(|entry| ((entry.role.as_str(), entry.path.as_str()), entry))
            .collect();
    for (key, baseline_entry) in &baseline_entries {
        if let Some(candidate_entry) = candidate_entries.get(key) {
            if baseline_entry.sha256 != candidate_entry.sha256 {
                artifact_drifts.push(RuntimeProofArtifactDrift {
                    role: baseline_entry.role.clone(),
                    path: baseline_entry.path.clone(),
                    baseline_sha256: baseline_entry.sha256.clone(),
                    candidate_sha256: candidate_entry.sha256.clone(),
                });
            }
        } else {
            artifact_drifts.push(RuntimeProofArtifactDrift {
                role: baseline_entry.role.clone(),
                path: baseline_entry.path.clone(),
                baseline_sha256: baseline_entry.sha256.clone(),
                candidate_sha256: "0".repeat(64),
            });
        }
    }
    for (key, candidate_entry) in &candidate_entries {
        if !baseline_entries.contains_key(key) {
            artifact_drifts.push(RuntimeProofArtifactDrift {
                role: candidate_entry.role.clone(),
                path: candidate_entry.path.clone(),
                baseline_sha256: "0".repeat(64),
                candidate_sha256: candidate_entry.sha256.clone(),
            });
        }
    }
    let accepted =
        semantic_drifts.is_empty() && artifact_drifts.is_empty() && verifier_drifts.is_empty();
    let report = RuntimeProofDriftReport {
        schema: CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA.to_string(),
        baseline_run_id: baseline_manifest.run_id.clone(),
        candidate_run_id: candidate_manifest.run_id.clone(),
        accepted,
        failure_code: if accepted {
            None
        } else {
            Some("runtime_proof_drift_detected".to_string())
        },
        generated_at_unix_ms: now_unix_ms,
        baseline_manifest_sha256: canonical_sha256(baseline_manifest)?,
        candidate_manifest_sha256: canonical_sha256(candidate_manifest)?,
        baseline_proof_regeneration_report_sha256: canonical_sha256(baseline_proof)?,
        candidate_proof_regeneration_report_sha256: canonical_sha256(candidate_proof)?,
        comparison_profile: "local-repeat-deterministic-v1".to_string(),
        normalized_fields: vec!["generatedAtUnixMs".to_string()],
        semantic_drifts,
        artifact_drifts,
        verifier_drifts,
    };
    validate_runtime_proof_drift_report(&report)?;
    Ok(report)
}

pub fn generate_runtime_evidence_sink_health_report(
    run_id: &str,
    evidence_root: &Path,
    manifest: &RuntimeEvidenceManifest,
    required_roles: &[String],
    now_unix_ms: u64,
    perform_write_probe: bool,
) -> Result<RuntimeEvidenceSinkHealthReport, ChiodosRuntimeError> {
    validate_non_empty(run_id, "runtime_evidence_health_empty_run_id")?;
    validate_runtime_evidence_manifest(manifest)?;
    let manifest_run_mismatch = manifest.run_id != run_id;
    let mut missing_roles = Vec::new();
    for role in required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
        if !manifest.entries.iter().any(|entry| entry.role == *role) {
            missing_roles.push(role.clone());
        }
    }
    let mut missing_artifacts = Vec::new();
    let mut artifact_hash_mismatches = Vec::new();
    let mut artifact_byte_count_mismatches = Vec::new();
    for entry in &manifest.entries {
        let path = evidence_root.join(&entry.path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                missing_artifacts.push(entry.path.clone());
                continue;
            }
        };
        if sha256_hex(&bytes) != entry.sha256 {
            artifact_hash_mismatches.push(entry.path.clone());
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.byte_count {
            artifact_byte_count_mismatches.push(entry.path.clone());
        }
    }
    let (temp_write_ok, atomic_rename_ok) = if perform_write_probe {
        evidence_sink_write_probe(evidence_root)
    } else {
        (true, true)
    };
    let failure_code = if manifest_run_mismatch {
        Some("runtime_evidence_manifest_run_mismatch".to_string())
    } else if !missing_roles.is_empty() {
        Some("runtime_evidence_missing_required_role".to_string())
    } else if !missing_artifacts.is_empty() || !temp_write_ok || !atomic_rename_ok {
        Some("runtime_evidence_sink_unavailable".to_string())
    } else if !artifact_hash_mismatches.is_empty() {
        Some("runtime_evidence_artifact_hash_mismatch".to_string())
    } else if !artifact_byte_count_mismatches.is_empty() {
        Some("runtime_evidence_artifact_byte_count_mismatch".to_string())
    } else {
        None
    };
    let report = RuntimeEvidenceSinkHealthReport {
        schema: CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        accepted: failure_code.is_none(),
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        evidence_root_sha256: sha256_hex(evidence_root.to_string_lossy().as_bytes()),
        required_roles: required_roles.to_vec(),
        missing_roles,
        missing_artifacts,
        artifact_hash_mismatches,
        artifact_byte_count_mismatches,
        unexpected_paths: Vec::new(),
        temp_write_ok,
        atomic_rename_ok,
        checks: vec!["runtime_ops.evidence_sink_health".to_string()],
    };
    validate_runtime_evidence_sink_health_report(&report)?;
    Ok(report)
}

pub fn generate_runtime_provider_health_report(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChiodosRuntimeError> {
    validate_runtime_supervisor_profile(profile)?;
    validate_runtime_provider_bindings(bindings)?;
    let mut degraded_provider_ids = Vec::new();
    for binding in &bindings.bindings {
        if binding.discovery_allowed {
            degraded_provider_ids.push(binding.provider_id.clone());
        }
        if binding.local_kernel_id != profile.local_kernel_id {
            degraded_provider_ids.push(binding.provider_id.clone());
        }
    }
    degraded_provider_ids.sort();
    degraded_provider_ids.dedup();
    let failure_code = if bindings
        .bindings
        .iter()
        .any(|binding| binding.discovery_allowed)
    {
        Some("runtime_provider_discovery_not_allowed".to_string())
    } else if !degraded_provider_ids.is_empty() {
        Some("runtime_provider_health_degraded".to_string())
    } else {
        None
    };
    let checked_provider_count = u64::try_from(bindings.bindings.len()).unwrap_or(u64::MAX);
    let degraded_count = u64::try_from(degraded_provider_ids.len()).unwrap_or(u64::MAX);
    let report = RuntimeProviderHealthReport {
        schema: CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: failure_code.is_none(),
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        provider_bindings_sha256: canonical_sha256(bindings)?,
        checked_provider_count,
        healthy_provider_count: checked_provider_count.saturating_sub(degraded_count),
        degraded_provider_ids,
        checks: vec!["runtime_ops.provider_bindings_static".to_string()],
    };
    validate_runtime_provider_health_report(&report)?;
    Ok(report)
}

pub fn generate_runtime_artifact_retention_plan(
    profile: &RuntimeArtifactRetentionProfile,
    run_ids: &[String],
    now_unix_ms: u64,
) -> Result<RuntimeArtifactRetentionPlan, ChiodosRuntimeError> {
    validate_runtime_artifact_retention_profile(profile)?;
    let mut candidate_actions = Vec::new();
    for run_id in run_ids {
        validate_non_empty(run_id, "runtime_retention_empty_run_id")?;
        let action = if profile.legal_hold {
            "blocked"
        } else {
            "retain"
        };
        let reason_code = if profile.legal_hold {
            "runtime_retention_legal_hold"
        } else {
            "runtime_retention_dry_run_only"
        };
        candidate_actions.push(RuntimeArtifactRetentionAction {
            run_id: run_id.clone(),
            action: action.to_string(),
            reason_code: reason_code.to_string(),
        });
    }
    let blocked_count = candidate_actions
        .iter()
        .filter(|action| action.action == "blocked")
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let retain_count = candidate_actions
        .iter()
        .filter(|action| action.action == "retain")
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let report = RuntimeArtifactRetentionPlan {
        schema: CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA.to_string(),
        accepted: profile.dry_run_only,
        failure_code: if profile.dry_run_only {
            None
        } else {
            Some("runtime_retention_mutation_not_allowed".to_string())
        },
        generated_at_unix_ms: now_unix_ms,
        retention_profile_sha256: canonical_sha256(profile)?,
        retain_count,
        blocked_count,
        quarantine_count: 0,
        expiring_soon_count: 0,
        eligible_for_operator_review_count: 0,
        candidate_actions,
        checks: vec!["runtime_ops.retention_dry_run".to_string()],
    };
    validate_runtime_artifact_retention_plan(&report)?;
    Ok(report)
}

pub fn validate_runtime_orchestration_profile(
    profile: &RuntimeOrchestrationProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_profile_schema",
            detail: format!(
                "runtime orchestration profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(
        &profile.profile_id,
        "runtime_orchestration_profile_empty_id",
    )?;
    validate_non_empty(
        &profile.local_kernel_id,
        "runtime_orchestration_profile_empty_kernel",
    )?;
    validate_non_empty(
        &profile.verifier_id,
        "runtime_orchestration_profile_empty_verifier",
    )?;
    validate_state_label(&profile.mode, "runtime_orchestration_profile_invalid_mode")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_invalid_window",
            detail: "runtime orchestration profile issued time must precede expiry".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_zero_concurrency",
            detail: "runtime orchestration profile must allow at least one local run".to_string(),
        });
    }
    let mut codes = BTreeSet::new();
    for code in &profile.fail_closed_on {
        validate_state_label(
            code,
            "runtime_orchestration_profile_invalid_fail_closed_code",
        )?;
        if !codes.insert(code.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_profile_duplicate_fail_closed_code",
                detail: format!("runtime orchestration fail-closed code {code} is duplicated"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_run_contract(
    contract: &RuntimeRunContract,
) -> Result<(), ChiodosRuntimeError> {
    if contract.schema != CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_contract_schema",
            detail: format!(
                "runtime run contract declared unsupported schema {}",
                contract.schema
            ),
        });
    }
    validate_non_empty(&contract.run_id, "runtime_run_contract_empty_run_id")?;
    ensure_sha256_hash(
        &contract.profile_sha256,
        "runtime_run_contract_invalid_profile_hash",
    )?;
    validate_non_empty(&contract.workflow_id, "runtime_run_contract_empty_workflow")?;
    validate_non_empty(&contract.store_id, "runtime_run_contract_empty_store")?;
    validate_non_empty(
        &contract.evidence_sink_id,
        "runtime_run_contract_empty_evidence_sink",
    )?;
    if contract.expected_step_count == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_zero_steps",
            detail: "runtime run contract must expect at least one step".to_string(),
        });
    }
    if contract.admission_ids.len() != usize::try_from(contract.expected_step_count).unwrap_or(0) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_step_count_mismatch",
            detail: "runtime run contract admission ids must match expected step count".to_string(),
        });
    }
    let mut ids = BTreeSet::new();
    for id in &contract.admission_ids {
        validate_non_empty(id, "runtime_run_contract_empty_admission_id")?;
        if !ids.insert(id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_contract_duplicate_admission_id",
                detail: format!("runtime run contract repeats admission id {id}"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_plan(
    plan: &RuntimeOrchestrationPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_plan_schema",
            detail: format!(
                "runtime orchestration plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_plan_missing_failure_code",
        "runtime_orchestration_plan_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_plan_empty_run_id")?;
    ensure_sha256_hash(
        &plan.profile_sha256,
        "runtime_orchestration_plan_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &plan.run_contract_sha256,
        "runtime_orchestration_plan_invalid_contract_hash",
    )?;
    if plan.accepted && plan.planned_steps.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_plan_missing_steps",
            detail: "accepted runtime orchestration plan must carry planned steps".to_string(),
        });
    }
    validate_planned_steps(&plan.planned_steps)
}

pub fn validate_runtime_orchestration_run_report(
    report: &RuntimeOrchestrationRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_run_report_schema",
            detail: format!(
                "runtime orchestration run report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_orchestration_run_empty_id")?;
    validate_state_label(&report.status, "runtime_orchestration_run_invalid_status")?;
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_run_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.run_contract_sha256,
        "runtime_orchestration_run_invalid_contract_hash",
    )?;
    ensure_optional_sha256(
        report.workflow_run_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_workflow_hash",
    )?;
    ensure_optional_sha256(
        report.evidence_manifest_sha256.as_deref(),
        "runtime_orchestration_run_invalid_manifest_hash",
    )?;
    ensure_optional_sha256(
        report.proof_regeneration_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_proof_hash",
    )?;
    ensure_optional_sha256(
        report.verifier_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_verifier_hash",
    )?;
    if report.accepted && report.status != "proof_accepted" {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_accepted_without_proof",
            detail: "accepted runtime orchestration run must be proof_accepted".to_string(),
        });
    }
    if report.accepted
        && (report.workflow_run_report_sha256.is_none()
            || report.evidence_manifest_sha256.is_none()
            || report.proof_regeneration_report_sha256.is_none()
            || report.verifier_report_sha256.is_none())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_accepted_hash",
            detail: "accepted runtime orchestration run must bind proof artifacts".to_string(),
        });
    }
    if report.accepted && report.step_states.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_steps",
            detail: "accepted runtime orchestration run must carry step states".to_string(),
        });
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_states {
        validate_runtime_orchestration_step_state(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_run_duplicate_step",
                detail: format!("runtime orchestration run repeats step {}", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_resume_plan(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_resume_plan_schema",
            detail: format!(
                "runtime orchestration resume plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_resume_missing_failure_code",
        "runtime_orchestration_resume_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_resume_empty_run_id")?;
    if plan.accepted && plan.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_resume_accepted_blocked",
            detail: "accepted runtime orchestration resume plan cannot be blocked".to_string(),
        });
    }
    Ok(())
}

fn validate_acceptance_failure_code(
    accepted: bool,
    failure_code: Option<&str>,
    missing_code: &'static str,
    unexpected_code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if accepted && failure_code.is_some() {
        return Err(ChiodosRuntimeError::Rejected {
            code: unexpected_code,
            detail: "accepted runtime report cannot carry a failure code".to_string(),
        });
    }
    if !accepted && failure_code.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: missing_code,
            detail: "rejected runtime report must carry a failure code".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_orchestration_status_report(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_status_report_schema",
            detail: format!(
                "runtime orchestration status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_status_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.store_path_sha256,
        "runtime_orchestration_status_invalid_store_hash",
    )?;
    validate_state_label(
        &report.store_backend,
        "runtime_orchestration_status_invalid_store_backend",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_orchestration_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_orchestration_status_missing_failure_code",
        "runtime_orchestration_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_status_accepted_degraded",
            detail: "accepted runtime orchestration status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_drift_report_schema",
            detail: format!(
                "runtime proof drift report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(
        &report.baseline_run_id,
        "runtime_proof_drift_empty_baseline",
    )?;
    validate_non_empty(
        &report.candidate_run_id,
        "runtime_proof_drift_empty_candidate",
    )?;
    ensure_sha256_hash(
        &report.baseline_manifest_sha256,
        "runtime_proof_drift_invalid_baseline_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_manifest_sha256,
        "runtime_proof_drift_invalid_candidate_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.baseline_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_baseline_proof_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_candidate_proof_hash",
    )?;
    for drift in &report.semantic_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.verifier_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.artifact_drifts {
        validate_non_empty(&drift.role, "runtime_proof_drift_empty_artifact_role")?;
        validate_relative_evidence_path(&drift.path, "runtime_proof_drift_invalid_artifact_path")?;
        ensure_sha256_hash(
            &drift.baseline_sha256,
            "runtime_proof_drift_invalid_baseline_artifact_hash",
        )?;
        ensure_sha256_hash(
            &drift.candidate_sha256,
            "runtime_proof_drift_invalid_candidate_artifact_hash",
        )?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_drift_missing_failure_code",
        "runtime_proof_drift_unexpected_failure_code",
    )?;
    if report.accepted
        && (!report.semantic_drifts.is_empty()
            || !report.artifact_drifts.is_empty()
            || !report.verifier_drifts.is_empty())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_drift_accepted_with_drifts",
            detail: "accepted runtime proof drift report cannot carry drift rows".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_supervisor_profile(
    profile: &RuntimeSupervisorProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_supervisor_profile_schema",
            detail: format!(
                "runtime supervisor profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_supervisor_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_supervisor_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_window",
            detail: "runtime supervisor profile validity window is invalid".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0
        || profile.run_lease_ttl_ms == 0
        || profile.stale_run_after_ms == 0
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_limits",
            detail: "runtime supervisor profile limits must be positive".to_string(),
        });
    }
    for role in &profile.evidence_required_roles {
        validate_state_label(role, "runtime_supervisor_invalid_required_role")?;
    }
    for code in &profile.fail_closed_on {
        validate_state_label(code, "runtime_supervisor_invalid_fail_closed_code")?;
    }
    Ok(())
}

pub fn validate_runtime_run_lease(lease: &RuntimeRunLease) -> Result<(), ChiodosRuntimeError> {
    if lease.schema != CHIODOS_RUNTIME_RUN_LEASE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_lease_schema",
            detail: format!(
                "runtime run lease declared unsupported schema {}",
                lease.schema
            ),
        });
    }
    validate_non_empty(&lease.run_id, "runtime_run_lease_empty_run_id")?;
    validate_non_empty(&lease.lease_id, "runtime_run_lease_empty_lease_id")?;
    validate_non_empty(&lease.owner_id, "runtime_run_lease_empty_owner")?;
    validate_state_label(&lease.state, "runtime_run_lease_invalid_state")?;
    if lease.acquired_at_unix_ms > lease.heartbeat_at_unix_ms
        || lease.heartbeat_at_unix_ms > lease.expires_at_unix_ms
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_lease_invalid_time_order",
            detail: "runtime run lease timestamps are not ordered".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_scheduler_tick_report(
    report: &RuntimeSchedulerTickReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_scheduler_tick_report_schema",
            detail: format!(
                "runtime scheduler tick report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.tick_id, "runtime_scheduler_empty_tick_id")?;
    validate_non_empty(&report.owner_id, "runtime_scheduler_empty_owner")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_scheduler_missing_failure_code",
        "runtime_scheduler_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_evidence_sink_health_report(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_sink_health_report_schema",
            detail: format!(
                "runtime evidence sink health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_evidence_health_empty_run_id")?;
    ensure_sha256_hash(
        &report.evidence_root_sha256,
        "runtime_evidence_health_invalid_root_hash",
    )?;
    for role in &report.required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
    }
    for path in report
        .missing_artifacts
        .iter()
        .chain(report.artifact_hash_mismatches.iter())
        .chain(report.artifact_byte_count_mismatches.iter())
        .chain(report.unexpected_paths.iter())
    {
        validate_relative_evidence_path(path, "runtime_evidence_health_invalid_path")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_evidence_health_missing_failure_code",
        "runtime_evidence_health_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_recovery_drill_report(
    report: &RuntimeRecoveryDrillReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_recovery_drill_report_schema",
            detail: format!(
                "runtime recovery drill report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_recovery_empty_run_id")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_recovery_missing_failure_code",
        "runtime_recovery_unexpected_failure_code",
    )?;
    if report.accepted && report.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_recovery_accepted_blocked",
            detail: "accepted runtime recovery drill cannot be blocked".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_profile(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_profile_schema",
            detail: format!(
                "runtime retention profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_retention_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_retention_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_invalid_window",
            detail: "runtime retention profile validity window is invalid".to_string(),
        });
    }
    if !profile.dry_run_only {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_mutation_not_allowed",
            detail: "runtime retention planning must be dry-run only".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_plan(
    plan: &RuntimeArtifactRetentionPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_plan_schema",
            detail: format!(
                "runtime retention plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_retention_plan_missing_failure_code",
        "runtime_retention_plan_unexpected_failure_code",
    )?;
    ensure_sha256_hash(
        &plan.retention_profile_sha256,
        "runtime_retention_invalid_profile_hash",
    )?;
    for action in &plan.candidate_actions {
        validate_non_empty(&action.run_id, "runtime_retention_empty_run_id")?;
        validate_state_label(&action.action, "runtime_retention_invalid_action")?;
        validate_state_label(&action.reason_code, "runtime_retention_invalid_reason")?;
    }
    Ok(())
}

pub fn validate_runtime_provider_bindings(
    document: &RuntimeProviderBindingsDocument,
) -> Result<(), ChiodosRuntimeError> {
    if document.schema != CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_bindings_schema",
            detail: format!(
                "runtime provider bindings declared unsupported schema {}",
                document.schema
            ),
        });
    }
    let mut provider_ids = BTreeSet::new();
    for binding in &document.bindings {
        validate_non_empty(&binding.provider_id, "runtime_provider_empty_id")?;
        validate_non_empty(&binding.local_kernel_id, "runtime_provider_empty_kernel")?;
        validate_non_empty(&binding.server_id, "runtime_provider_empty_server")?;
        validate_non_empty(&binding.tool_name, "runtime_provider_empty_tool")?;
        if !provider_ids.insert(binding.provider_id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_provider_duplicate_id",
                detail: format!("runtime provider binding repeats {}", binding.provider_id),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_provider_health_report(
    report: &RuntimeProviderHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_health_report_schema",
            detail: format!(
                "runtime provider health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.provider_bindings_sha256,
        "runtime_provider_health_invalid_bindings_hash",
    )?;
    for provider_id in &report.degraded_provider_ids {
        validate_non_empty(provider_id, "runtime_provider_health_empty_degraded_id")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_provider_health_missing_failure_code",
        "runtime_provider_health_unexpected_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_ops_status_report(
    report: &RuntimeOpsStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_ops_status_report_schema",
            detail: format!(
                "runtime ops status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.supervisor_profile_sha256,
        "runtime_ops_status_invalid_profile_hash",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_ops_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_ops_status_missing_failure_code",
        "runtime_ops_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_ops_status_accepted_degraded",
            detail: "accepted runtime ops status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_workflow_run_report(
    report: &RuntimeWorkflowRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_workflow_report_schema",
            detail: format!(
                "runtime workflow report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    if !is_sha256_hex(&report.admission_report_sha256) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_invalid_admission_report_hash",
            detail: "runtime workflow report admission report hash is not sha256 hex".to_string(),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_workflow_missing_failure_code",
        "runtime_workflow_unexpected_failure_code",
    )?;
    if report.accepted && report.step_evidence.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_step_evidence",
            detail: "accepted runtime workflow report must carry step evidence".to_string(),
        });
    }
    if report.accepted && report.proof_regeneration_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_proof_regeneration_report",
            detail: "accepted runtime workflow report must bind proof regeneration report"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_regeneration_report_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_workflow_invalid_proof_regeneration_hash")?;
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_evidence {
        validate_runtime_step_evidence(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_workflow_duplicate_step_evidence",
                detail: format!("runtime workflow step {} is duplicated", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_evidence_manifest(
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChiodosRuntimeError> {
    if manifest.schema != CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_manifest_schema",
            detail: format!(
                "runtime evidence manifest declared unsupported schema {}",
                manifest.schema
            ),
        });
    }
    ensure_sha256_hash(
        &manifest.workflow_run_report_sha256,
        "runtime_evidence_manifest_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &manifest.proof_regeneration_report_sha256,
        "runtime_evidence_manifest_invalid_proof_report_hash",
    )?;
    if manifest.entries.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_evidence_manifest_missing_entries",
            detail: "runtime evidence manifest must bind at least one artifact".to_string(),
        });
    }
    let mut paths = BTreeSet::new();
    for entry in &manifest.entries {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        if entry.role.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_empty_role",
                detail: "runtime evidence manifest entry role is empty".to_string(),
            });
        }
        if !paths.insert(entry.path.clone()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_duplicate_path",
                detail: format!(
                    "runtime evidence manifest carries duplicate path {}",
                    entry.path
                ),
            });
        }
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
    }
    Ok(())
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChiodosRuntimeError> {
    if input.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_input_schema",
            detail: format!(
                "runtime proof regeneration input declared unsupported schema {}",
                input.schema
            ),
        });
    }
    ensure_sha256_hash(
        &input.evidence_manifest_sha256,
        "runtime_proof_regeneration_input_invalid_manifest_hash",
    )?;
    ensure_sha256_hash(
        &input.workflow_run_report_sha256,
        "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &input.admission_report_sha256,
        "runtime_proof_regeneration_input_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &input.trust_bundle_sha256,
        "runtime_proof_regeneration_input_invalid_trust_bundle_hash",
    )?;
    ensure_sha256_hash(
        &input.verification_context_sha256,
        "runtime_proof_regeneration_input_invalid_context_hash",
    )?;
    if input.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_input_missing_source_records",
            detail: "runtime proof regeneration input must carry source records".to_string(),
        });
    }
    validate_runtime_proof_source_records(&input.source_records)
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_report_schema",
            detail: format!(
                "runtime proof regeneration report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_regeneration_missing_failure_code",
        "runtime_proof_regeneration_unexpected_failure_code",
    )?;
    if report.accepted && report.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_source_records",
            detail: "accepted runtime proof regeneration report must carry source records"
                .to_string(),
        });
    }
    if report.accepted && report.proof_package_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_package_hash",
            detail: "accepted runtime proof regeneration report must bind proof package hash"
                .to_string(),
        });
    }
    if report.accepted && report.verifier_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_verifier_report_hash",
            detail: "accepted runtime proof regeneration report must bind verifier report hash"
                .to_string(),
        });
    }
    if report.accepted && report.workflow_receipt_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_workflow_receipt_hash",
            detail: "accepted runtime proof regeneration report must bind workflow receipt hash"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_package_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_proof_regeneration_invalid_package_hash")?;
    }
    if let Some(hash) = report.verifier_report_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_verifier_report_hash",
        )?;
    }
    if let Some(hash) = report.workflow_receipt_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_workflow_receipt_hash",
        )?;
    }
    validate_runtime_proof_source_records(&report.source_records)?;
    Ok(())
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_parity_report_schema",
            detail: format!(
                "runtime proof parity report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.static_proof_package_sha256,
        "runtime_proof_parity_invalid_static_package_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_proof_package_sha256,
        "runtime_proof_parity_invalid_runtime_package_hash",
    )?;
    ensure_sha256_hash(
        &report.static_verifier_report_sha256,
        "runtime_proof_parity_invalid_static_report_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_verifier_report_sha256,
        "runtime_proof_parity_invalid_runtime_report_hash",
    )?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_parity_missing_failure_code",
        "runtime_proof_parity_unexpected_failure_code",
    )?;
    if report.compared_fields.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_missing_compared_fields",
            detail: "runtime proof parity report must name compared fields".to_string(),
        });
    }
    if report.accepted && !report.mismatches.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_accepted_with_mismatches",
            detail: "accepted runtime proof parity report cannot carry mismatches".to_string(),
        });
    }
    for mismatch in &report.mismatches {
        if mismatch.field.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_parity_empty_mismatch_field",
                detail: "runtime proof parity mismatch field is empty".to_string(),
            });
        }
        ensure_sha256_hash(
            &mismatch.static_value_sha256,
            "runtime_proof_parity_invalid_static_value_hash",
        )?;
        ensure_sha256_hash(
            &mismatch.runtime_value_sha256,
            "runtime_proof_parity_invalid_runtime_value_hash",
        )?;
    }
    Ok(())
}

fn validate_runtime_proof_source_records(
    source_records: &[RuntimeProofSourceRecord],
) -> Result<(), ChiodosRuntimeError> {
    let mut step_indices = BTreeSet::new();
    for record in source_records {
        if !step_indices.insert(record.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_regeneration_duplicate_source_record",
                detail: format!(
                    "runtime proof source record step {} is duplicated",
                    record.step_index
                ),
            });
        }
        ensure_sha256_hash(
            &record.admission_report_sha256,
            "runtime_proof_regeneration_invalid_admission_hash",
        )?;
        ensure_sha256_hash(
            &record.tool_receipt_sha256,
            "runtime_proof_regeneration_invalid_tool_receipt_hash",
        )?;
        ensure_sha256_hash(
            &record.bilateral_dsse_sha256,
            "runtime_proof_regeneration_invalid_dsse_hash",
        )?;
        ensure_sha256_hash(
            &record.workflow_step_sha256,
            "runtime_proof_regeneration_invalid_workflow_step_hash",
        )?;
    }
    Ok(())
}

fn validate_relative_evidence_path(
    path: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains("//")
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime evidence path {path:?} is not a safe relative path"),
        });
    }
    Ok(())
}

pub fn evaluate_runtime_admission(
    input: RuntimeAdmissionInput<'_>,
) -> Result<RuntimeAdmissionReport, ChiodosRuntimeError> {
    let mut checks = Vec::new();
    if input.profile.schema != CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA {
        return Ok(rejected_report(
            input.admission_id,
            "unsupported_profile_schema",
            checks,
        ));
    }
    checks.push(passed("profile.schema"));
    if input.now_unix_ms < input.profile.issued_at_unix_ms
        || input.now_unix_ms >= input.profile.expires_at_unix_ms
    {
        return Ok(rejected_report(input.admission_id, "stale_profile", checks));
    }
    checks.push(passed("profile.freshness"));

    let Some(bundle) = input.store.bundle(input.admission_id)? else {
        return Ok(rejected_report(
            input.admission_id,
            "missing_admission_bundle",
            checks,
        ));
    };
    if bundle.schema != CHIODOS_RUNTIME_ADMISSION_BUNDLE_SCHEMA {
        return Ok(rejected_report(
            input.admission_id,
            "unsupported_bundle_schema",
            checks,
        ));
    }
    checks.push(passed("bundle.schema"));

    let mut trust_floor_update = None;
    if let Some(runtime_trust_input) = input.runtime_trust_input {
        match validate_runtime_trust_input(
            runtime_trust_input,
            input.trusted_verifier_keys,
            &bundle,
            input.now_unix_ms,
            &mut checks,
        ) {
            Ok(entry) => {
                trust_floor_update = Some((
                    entry,
                    runtime_trust_input.body.previous_hash_sha256.as_deref(),
                ));
            }
            Err(code) => return Ok(rejected_report(input.admission_id, code, checks)),
        }
    } else if !input.trusted_verifier_keys.is_empty() {
        return Ok(rejected_report(
            input.admission_id,
            "missing_runtime_trust_input",
            checks,
        ));
    }

    if bundle.binding.host_kernel_id != input.profile.local_kernel_id {
        return Ok(rejected_report(
            input.admission_id,
            "host_kernel_mismatch",
            checks,
        ));
    }
    checks.push(passed("bundle.host_kernel"));

    if &bundle.binding != input.request {
        return Ok(rejected_report(
            input.admission_id,
            "request_binding_mismatch",
            checks,
        ));
    }
    checks.push(passed("request.binding"));

    if input.pheromone_query_report.is_some() {
        checks.push(passed("pheromone.query_report_signed"));
    }
    let (policy_decision, pheromone_advisory) =
        match evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
            policy: input.runtime_pheromone_policy,
            peer_weights: input.runtime_peer_weights,
            query_report: input.pheromone_query_report,
            runtime_trust_input: input.runtime_trust_input,
            trusted_verifier_keys: input.trusted_verifier_keys,
            bundle: &bundle,
            now_unix_ms: input.now_unix_ms,
            checks: &mut checks,
        }) {
            Ok(result) => result,
            Err(code) => {
                return Ok(rejected_report_with_policy(
                    input.admission_id,
                    code,
                    checks,
                    None,
                ));
            }
        };
    if pheromone_advisory.is_some() {
        checks.push(passed("pheromone.observe_only"));
    }
    if let Some(decision) = policy_decision.as_ref() {
        if decision.decision == "deny" {
            return Ok(rejected_report_with_policy(
                input.admission_id,
                "runtime_pheromone_policy_deny",
                checks,
                Some(decision.clone()),
            ));
        }
        if decision.decision == "escalate" {
            return Ok(rejected_report_with_policy(
                input.admission_id,
                "runtime_pheromone_policy_escalate",
                checks,
                Some(decision.clone()),
            ));
        }
    }

    let mut consumed_destructive_lease_id = None;
    if bundle.destructive {
        let Some(lease_id) = bundle.lease_id.as_deref() else {
            return Ok(rejected_report(
                input.admission_id,
                "missing_destructive_lease",
                checks,
            ));
        };
        if bundle.governance_receipt_id.is_none() {
            return Ok(rejected_report(
                input.admission_id,
                "missing_governance_receipt",
                checks,
            ));
        }
        match input
            .store
            .consume_destructive_lease(lease_id, input.admission_id)
        {
            Ok(()) => {
                consumed_destructive_lease_id = Some(lease_id.to_string());
                checks.push(passed("destructive.lease_reserved"));
            }
            Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                return Ok(rejected_report(input.admission_id, code, checks));
            }
            Err(error) => return Err(error),
        }
    }
    if let Some((entry, previous_hash_sha256)) = trust_floor_update {
        match input
            .store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
        {
            Ok(()) => checks.push(passed("runtime_trust.floor")),
            Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    input
                        .store
                        .release_destructive_lease(lease_id, input.admission_id)?;
                }
                return Ok(rejected_report(input.admission_id, code, checks));
            }
            Err(error) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    input
                        .store
                        .release_destructive_lease(lease_id, input.admission_id)?;
                }
                return Err(error);
            }
        }
    }

    Ok(RuntimeAdmissionReport {
        schema: CHIODOS_RUNTIME_ADMISSION_REPORT_SCHEMA.to_string(),
        admission_id: input.admission_id.to_string(),
        accepted: true,
        failure_code: None,
        checks,
        pheromone_advisory: pheromone_advisory.clone(),
        pheromone_policy_decision: policy_decision.clone(),
        receipt_metadata: receipt_metadata(
            &bundle,
            true,
            None,
            consumed_destructive_lease_id.as_deref(),
            pheromone_advisory.as_ref(),
            policy_decision.as_ref(),
        ),
    })
}

pub fn runtime_admission_bundle_sha256(
    bundle: &RuntimeAdmissionBundle,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_verifier_trust_bundle_sha256(
    bundle: &RuntimeVerifierTrustBundleV4,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(bundle)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_pheromone_policy_sha256(
    policy: &RuntimePheromonePolicy,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(policy)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn runtime_peer_weights_sha256(
    weights: &RuntimePeerWeights,
) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(weights)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn tool_args_sha256(arguments: &serde_json::Value) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(arguments)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

#[derive(Debug, Clone)]
pub struct ChiodosRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
}

impl<S> ChiodosRuntimeAdmissionHook<S> {
    #[must_use]
    pub fn new(profile: RuntimeAdmissionProfile, store: S) -> Self {
        Self {
            profile,
            store,
            runtime_trust_input: None,
            trusted_verifier_keys: Vec::new(),
            pheromone_query_report: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
        }
    }

    #[must_use]
    pub fn with_runtime_trust_input(
        mut self,
        runtime_trust_input: SignedRuntimeVerifierTrustBundle,
        trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    ) -> Self {
        self.runtime_trust_input = Some(runtime_trust_input);
        self.trusted_verifier_keys = trusted_verifier_keys;
        self
    }

    #[must_use]
    pub fn with_pheromone_query_report(
        mut self,
        report: SignedRuntimePheromoneQueryReport,
    ) -> Self {
        self.pheromone_query_report = Some(report);
        self
    }

    #[must_use]
    pub fn with_runtime_pheromone_policy(
        mut self,
        policy: SignedRuntimePheromonePolicy,
        peer_weights: SignedRuntimePeerWeights,
    ) -> Self {
        self.runtime_pheromone_policy = Some(policy);
        self.runtime_peer_weights = Some(peer_weights);
        self
    }
}

impl<S> RuntimeAdmissionHook for ChiodosRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chiodos-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(code) => {
                let metadata = serde_json::json!({
                    "chiodos_runtime": {
                        "accepted": false,
                        "failure_code": code
                    }
                });
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chiodos runtime admission reference missing or invalid",
                    Some(metadata),
                ));
            }
        };
        let binding = match RuntimeRequestBinding::from_tool_call_request(
            context.request,
            &context.local_kernel_id,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chiodos runtime admission request binding failed",
                    Some(serde_json::json!({
                        "chiodos_runtime": {
                            "admission_id": admission_ref.admission_id,
                            "accepted": false,
                            "failure_code": error.code()
                        }
                    })),
                ));
            }
        };
        if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
            match self.store.bundle(&admission_ref.admission_id) {
                Ok(Some(bundle)) => match runtime_admission_bundle_sha256(&bundle) {
                    Ok(actual) if actual == expected_hash => {}
                    Ok(_) => {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chiodos runtime admission bundle hash mismatch",
                            Some(serde_json::json!({
                                "chiodos_runtime": {
                                    "admission_id": admission_ref.admission_id,
                                    "accepted": false,
                                    "failure_code": "admission_bundle_hash_mismatch"
                                }
                            })),
                        ));
                    }
                    Err(error) => {
                        return Err(KernelError::Internal(error.to_string()));
                    }
                },
                Ok(None) => {}
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        let mut treaty_continuation_id_to_consume = None;
        match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => match verify_treaty_reference_from_store(
                &self.store,
                &admission_ref.admission_id,
                &treaty_ref,
                context.now_unix_secs.saturating_mul(1000),
            ) {
                Ok(continuation_id) => {
                    treaty_continuation_id_to_consume = continuation_id;
                }
                Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chiodos treaty-bound runtime admission denied",
                        Some(serde_json::json!({
                            "chiodos_runtime": {
                                "admission_id": admission_ref.admission_id,
                                "accepted": false,
                                "failure_code": code
                            }
                        })),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            },
            Ok(None) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chiodos treaty-bound runtime admission context missing",
                        Some(serde_json::json!({
                            "chiodos_runtime": {
                                "admission_id": admission_ref.admission_id,
                                "accepted": false,
                                "failure_code": "missing_chiodos_treaty_context"
                            }
                        })),
                    ));
                }
            }
            Err(code) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chiodos treaty-bound runtime admission reference invalid",
                    Some(serde_json::json!({
                        "chiodos_runtime": {
                            "admission_id": admission_ref.admission_id,
                            "accepted": false,
                            "failure_code": code
                        }
                    })),
                ));
            }
        }
        if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
            match self
                .store
                .consume_treaty_continuation(continuation_id, &admission_ref.admission_id)
            {
                Ok(()) => {}
                Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chiodos treaty-bound runtime continuation replay denied",
                        Some(serde_json::json!({
                            "chiodos_runtime": {
                                "admission_id": admission_ref.admission_id,
                                "accepted": false,
                                "failure_code": code
                            }
                        })),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        let report = match evaluate_runtime_admission(RuntimeAdmissionInput {
            profile: &self.profile,
            store: &self.store,
            admission_id: &admission_ref.admission_id,
            request: &binding,
            runtime_trust_input: self.runtime_trust_input.as_ref(),
            trusted_verifier_keys: &self.trusted_verifier_keys,
            pheromone_query_report: self.pheromone_query_report.as_ref(),
            runtime_pheromone_policy: self.runtime_pheromone_policy.as_ref(),
            runtime_peer_weights: self.runtime_peer_weights.as_ref(),
            now_unix_ms: context.now_unix_secs.saturating_mul(1000),
        }) {
            Ok(report) => report,
            Err(error) => {
                if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                    self.store
                        .release_treaty_continuation(continuation_id, &admission_ref.admission_id)
                        .map_err(|release_error| {
                            KernelError::Internal(release_error.to_string())
                        })?;
                }
                return Err(KernelError::Internal(error.to_string()));
            }
        };
        if report.accepted {
            let mut metadata = report.receipt_metadata;
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                metadata["chiodos_runtime"]["reserved_treaty_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            Ok(KernelRuntimeAdmissionDecision::allow(Some(metadata)))
        } else {
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                self.store
                    .release_treaty_continuation(continuation_id, &admission_ref.admission_id)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            Ok(KernelRuntimeAdmissionDecision::deny(
                "chiodos runtime admission denied",
                Some(report.receipt_metadata),
            ))
        }
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        let Some(runtime) = metadata
            .get("chiodos_runtime")
            .and_then(serde_json::Value::as_object)
        else {
            return Ok(());
        };
        let Some(admission_id) = runtime
            .get("admission_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(());
        };
        if let Some(lease_id) = runtime
            .get("reserved_destructive_lease_id")
            .and_then(serde_json::Value::as_str)
        {
            self.store
                .release_destructive_lease(lease_id, admission_id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        if let Some(continuation_id) = runtime
            .get("reserved_treaty_continuation_id")
            .and_then(serde_json::Value::as_str)
        {
            self.store
                .release_treaty_continuation(continuation_id, admission_id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }
}

impl RuntimeRequestBinding {
    pub fn from_tool_call_request(
        request: &ToolCallRequest,
        host_kernel_id: &str,
    ) -> Result<Self, ChiodosRuntimeError> {
        Ok(Self {
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            tool_args_sha256: tool_args_sha256(&request.arguments)?,
            origin_kernel_id: request.federated_origin_kernel_id.clone(),
            host_kernel_id: host_kernel_id.to_string(),
        })
    }
}

struct AdmissionReference {
    admission_id: String,
    bundle_sha256: Option<String>,
}

struct TreatyReference {
    treaty_scope_id: String,
    treaty_scope_sha256: String,
    ladder_intersection_id: String,
    ladder_intersection_sha256: String,
    action_class_id: String,
    continuation: Option<TreatyEvidenceReference>,
    lineage_bundle: Option<TreatyEvidenceReference>,
    bilateral_dsse: Option<TreatyEvidenceReference>,
    bilateral_invocation: Option<TreatyEvidenceReference>,
}

#[derive(Debug, Clone)]
struct TreatyEvidenceReference {
    evidence_id: String,
    artifact_sha256: String,
}

fn admission_ref_from_request(
    request: &ToolCallRequest,
) -> Result<AdmissionReference, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Err("missing_governed_intent");
    };
    let Some(context) = intent.context.as_ref() else {
        return Err("missing_chiodos_admission_context");
    };
    let Some(admission) = context.get("chiodosAdmission") else {
        return Err("missing_chiodos_admission_context");
    };
    let Some(object) = admission.as_object() else {
        return Err("invalid_chiodos_admission_context");
    };
    let Some(admission_id) = object.get("admissionId").and_then(|value| value.as_str()) else {
        return Err("missing_admission_id");
    };
    if admission_id.trim().is_empty() {
        return Err("missing_admission_id");
    }
    let bundle_sha256 = object
        .get("bundleSha256")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    Ok(AdmissionReference {
        admission_id: admission_id.to_string(),
        bundle_sha256,
    })
}

fn treaty_ref_from_request(
    request: &ToolCallRequest,
) -> Result<Option<TreatyReference>, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };
    let Some(context) = intent.context.as_ref() else {
        return Ok(None);
    };
    let Some(treaty) = context.get("chiodosTreaty") else {
        return Ok(None);
    };
    let Some(object) = treaty.as_object() else {
        return Err("invalid_chiodos_treaty_context");
    };
    for forbidden in [
        "trustRoot",
        "trustRoots",
        "trustBundle",
        "treatyScope",
        "ladderManifest",
        "signingKey",
        "peerDirectory",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_trust_root");
        }
    }
    for forbidden in [
        "dynamicTrust",
        "dynamicTrustBundle",
        "runtimeTrustInput",
        "peerDiscovery",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_dynamic_trust");
        }
    }
    let Some(treaty_scope_id) = object.get("treatyScopeId").and_then(|value| value.as_str()) else {
        return Err("missing_treaty_scope_id");
    };
    let Some(treaty_scope_sha256) = object
        .get("treatyScopeSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_treaty_scope_hash");
    };
    let Some(ladder_intersection_id) = object
        .get("ladderIntersectionId")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_id");
    };
    let Some(ladder_intersection_sha256) = object
        .get("ladderIntersectionSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_hash");
    };
    let Some(action_class_id) = object.get("actionClassId").and_then(|value| value.as_str()) else {
        return Err("missing_action_class_id");
    };
    if treaty_scope_id.trim().is_empty()
        || ladder_intersection_id.trim().is_empty()
        || action_class_id.trim().is_empty()
    {
        return Err("invalid_chiodos_treaty_context");
    }
    if !is_sha256_hex(treaty_scope_sha256) || !is_sha256_hex(ladder_intersection_sha256) {
        return Err("invalid_chiodos_treaty_hash");
    }
    let continuation = treaty_evidence_ref_from_context(
        object,
        &["crossKernelContinuation", "continuation"],
        &["continuationId"],
        &["continuationSha256"],
    )?;
    let lineage_bundle = treaty_evidence_ref_from_context(
        object,
        &["receiptLineageBundle", "lineageBundle"],
        &["receiptLineageBundleId", "lineageBundleId"],
        &["receiptLineageBundleSha256", "lineageBundleSha256"],
    )?;
    let bilateral_dsse = treaty_evidence_ref_from_context(
        object,
        &["bilateralDsse", "bilateralDsseEnvelope"],
        &["bilateralDsseId", "bilateralDsseEnvelopeId"],
        &["bilateralDsseSha256", "bilateralDsseEnvelopeSha256"],
    )?;
    let bilateral_invocation = treaty_evidence_ref_from_context(
        object,
        &["bilateralInvocation"],
        &["bilateralInvocationId"],
        &["bilateralInvocationSha256"],
    )?;
    Ok(Some(TreatyReference {
        treaty_scope_id: treaty_scope_id.to_string(),
        treaty_scope_sha256: treaty_scope_sha256.to_string(),
        ladder_intersection_id: ladder_intersection_id.to_string(),
        ladder_intersection_sha256: ladder_intersection_sha256.to_string(),
        action_class_id: action_class_id.to_string(),
        continuation,
        lineage_bundle,
        bilateral_dsse,
        bilateral_invocation,
    }))
}

fn treaty_evidence_ref_from_context(
    object: &serde_json::Map<String, serde_json::Value>,
    object_fields: &[&str],
    id_fields: &[&str],
    hash_fields: &[&str],
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    for field in object_fields {
        if let Some(value) = object.get(*field) {
            let Some(ref_object) = value.as_object() else {
                return Err("invalid_chiodos_treaty_evidence_ref");
            };
            let evidence_id = ref_object
                .get("id")
                .or_else(|| ref_object.get("evidenceId"))
                .or_else(|| ref_object.get("artifactId"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chiodos_treaty_evidence_ref")?;
            let artifact_sha256 = ref_object
                .get("sha256")
                .or_else(|| ref_object.get("artifactSha256"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chiodos_treaty_evidence_ref")?;
            return treaty_evidence_ref(evidence_id, artifact_sha256);
        }
    }

    let evidence_id = id_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    let artifact_sha256 = hash_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    match (evidence_id, artifact_sha256) {
        (Some(evidence_id), Some(artifact_sha256)) => {
            treaty_evidence_ref(evidence_id, artifact_sha256)
        }
        (None, None) => Ok(None),
        _ => Err("missing_chiodos_treaty_evidence_ref"),
    }
}

fn treaty_evidence_ref(
    evidence_id: &str,
    artifact_sha256: &str,
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    if evidence_id.trim().is_empty() || !is_sha256_hex(artifact_sha256) {
        return Err("invalid_chiodos_treaty_evidence_ref");
    }
    Ok(Some(TreatyEvidenceReference {
        evidence_id: evidence_id.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
    }))
}

fn verify_treaty_reference_from_store<S: RuntimeAdmissionStore>(
    store: &S,
    admission_id: &str,
    treaty_ref: &TreatyReference,
    now_unix_ms: u64,
) -> Result<Option<String>, ChiodosRuntimeError> {
    let Some(bundle) = store.bundle(admission_id)? else {
        return rejected(
            "missing_admission_bundle",
            "cross-boundary request referenced an admission bundle that is not in the verifier-owned store",
        );
    };
    let Some(treaty_scope_record) =
        store.treaty_runtime_artifact("treaty_scope", &treaty_ref.treaty_scope_id)?
    else {
        return rejected(
            "chiodos_treaty_missing_scope",
            "cross-boundary request referenced a treaty scope that is not in the verifier-owned store",
        );
    };
    if treaty_scope_record.artifact_sha256 != treaty_ref.treaty_scope_sha256 {
        return rejected(
            "chiodos_treaty_scope_hash_mismatch",
            "cross-boundary request treaty scope hash does not match verifier-owned store",
        );
    }
    let treaty_scope: TreatyScope = serde_json::from_value(treaty_scope_record.raw_json)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    if treaty_scope.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return rejected(
            "chiodos_treaty_scope_hash_mismatch",
            "treaty scope trust bundle hash does not match the verifier-owned admission bundle",
        );
    }

    let Some(intersection_record) =
        store.treaty_runtime_artifact("ladder_intersection", &treaty_ref.ladder_intersection_id)?
    else {
        return rejected(
            "chiodos_treaty_missing_intersection",
            "cross-boundary request referenced a ladder intersection that is not in the verifier-owned store",
        );
    };
    if intersection_record.artifact_sha256 != treaty_ref.ladder_intersection_sha256 {
        return rejected(
            "chiodos_treaty_intersection_mismatch",
            "cross-boundary request ladder intersection hash does not match verifier-owned store",
        );
    }
    let ladder_intersection: LadderIntersection =
        serde_json::from_value(intersection_record.raw_json)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    let action = ladder_intersection
        .action_classes
        .iter()
        .find(|action| action.action_class_id == treaty_ref.action_class_id);
    let requires_lineage = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "receipt_lineage")
    });
    let requires_bilateral = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    });

    let continuation = treaty_ref
        .continuation
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, CrossKernelContinuation>(
                store,
                "cross_kernel_continuation",
                reference,
                "chiodos_treaty_missing_continuation",
                "chiodos_treaty_continuation_hash_mismatch",
            )
        })
        .transpose()?;
    let lineage_bundle = treaty_ref
        .lineage_bundle
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, ReceiptLineageBundle>(
                store,
                "receipt_lineage_bundle",
                reference,
                "chiodos_treaty_missing_required_evidence",
                "chiodos_treaty_lineage_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_invocation = treaty_ref
        .bilateral_invocation
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, BilateralInvocation>(
                store,
                "bilateral_invocation",
                reference,
                "chiodos_treaty_missing_bilateral_evidence",
                "chiodos_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_dsse = treaty_ref
        .bilateral_dsse
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, chio_federation::DsseEnvelope>(
                store,
                "bilateral_dsse_envelope",
                reference,
                "chiodos_treaty_missing_bilateral_evidence",
                "chiodos_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;

    let mut present_evidence = Vec::new();
    let mut verified_evidence = Vec::new();
    if let Some((continuation, continuation_sha256)) = continuation.as_ref() {
        verify_continuation_evidence(
            continuation,
            &treaty_scope,
            &bundle.binding,
            &treaty_ref.action_class_id,
            now_unix_ms,
        )?;
        if let Some((lineage_bundle, _lineage_bundle_sha256)) = lineage_bundle.as_ref() {
            let lineage_statement_sha256 =
                verify_lineage_bundle_evidence(lineage_bundle, continuation, continuation_sha256)?;
            present_evidence.push("receipt_lineage".to_string());
            verified_evidence.push(CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_statement_sha256,
                verified: true,
            });
        }
        if let Some((invocation, _invocation_sha256)) = bilateral_invocation.as_ref() {
            let consistency_model = action
                .map(|action| action.consistency_model.as_str())
                .unwrap_or("totally_ordered");
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model,
                continuation_sha256,
            };
            let invocation_binding_sha256 = verify_bilateral_invocation_evidence(
                invocation,
                &treaty_evidence,
                lineage_bundle.as_ref().map(|(bundle, _)| bundle),
            )?;
            present_evidence.push("bilateral_invocation".to_string());
            verified_evidence.push(CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: invocation_binding_sha256,
                verified: true,
            });
        }
        if let Some((envelope, _envelope_sha256)) = bilateral_dsse.as_ref() {
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model: action
                    .map(|action| action.consistency_model.as_str())
                    .unwrap_or("totally_ordered"),
                continuation_sha256,
            };
            verify_treaty_dsse_evidence(
                envelope,
                &treaty_evidence,
                lineage_bundle.as_ref(),
                bilateral_invocation
                    .as_ref()
                    .map(|(invocation, _)| invocation),
            )?;
        }
    } else if requires_lineage
        || requires_bilateral
        || treaty_ref.lineage_bundle.is_some()
        || treaty_ref.bilateral_invocation.is_some()
        || treaty_ref.bilateral_dsse.is_some()
    {
        return rejected(
            "chiodos_treaty_missing_continuation",
            "cross-boundary request did not reference a stored continuation",
        );
    }

    let report = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty_scope,
        ladder_intersection: &ladder_intersection,
        expected_ladder_intersection_sha256: Some(treaty_ref.ladder_intersection_sha256.clone()),
        action_class_id: &treaty_ref.action_class_id,
        present_evidence,
        verified_evidence,
        now_unix_ms,
    })?;
    if report.accepted {
        Ok(continuation
            .as_ref()
            .map(|(continuation, _)| continuation.continuation_id.clone()))
    } else {
        rejected(
            static_treaty_failure_code(report.failure_code.as_deref()),
            "cross-boundary treaty admission rejected",
        )
    }
}

fn load_treaty_artifact<S, T>(
    store: &S,
    evidence_kind: &str,
    reference: &TreatyEvidenceReference,
    missing_code: &'static str,
    mismatch_code: &'static str,
) -> Result<(T, String), ChiodosRuntimeError>
where
    S: RuntimeAdmissionStore,
    T: DeserializeOwned,
{
    let Some(record) = store.treaty_runtime_artifact(evidence_kind, &reference.evidence_id)? else {
        return rejected(
            missing_code,
            "cross-boundary request referenced treaty evidence that is not in the verifier-owned store",
        );
    };
    if record.artifact_sha256 != reference.artifact_sha256 {
        return rejected(
            mismatch_code,
            "cross-boundary request treaty evidence hash does not match verifier-owned store",
        );
    }
    let artifact_sha256 = record.artifact_sha256;
    let artifact: T = serde_json::from_value(record.raw_json)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    Ok((artifact, artifact_sha256))
}

fn verify_continuation_evidence(
    continuation: &CrossKernelContinuation,
    treaty_scope: &TreatyScope,
    request: &RuntimeRequestBinding,
    action_class_id: &str,
    now_unix_ms: u64,
) -> Result<(), ChiodosRuntimeError> {
    validate_cross_kernel_continuation(continuation)?;
    if now_unix_ms < continuation.issued_at_unix_ms
        || now_unix_ms >= continuation.expires_at_unix_ms
    {
        return rejected(
            "chiodos_treaty_continuation_stale",
            "cross-kernel continuation is outside its validity window",
        );
    }
    let audience = format!("{}.{}", request.server_id, request.tool_name);
    if continuation.capability_id != request.capability_id
        || continuation.action_class_id != action_class_id
        || continuation.target_kernel_id != request.host_kernel_id
        || request.origin_kernel_id.as_deref() != Some(continuation.source_kernel_id.as_str())
        || (continuation.audience_tool != audience
            && continuation.audience_tool != request.tool_name)
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.source_kernel_id)
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.target_kernel_id)
    {
        return rejected(
            "chiodos_treaty_continuation_mismatch",
            "cross-kernel continuation does not bind the requested treaty dispatch",
        );
    }
    Ok(())
}

fn verify_lineage_bundle_evidence(
    bundle: &ReceiptLineageBundle,
    continuation: &CrossKernelContinuation,
    continuation_sha256: &str,
) -> Result<String, ChiodosRuntimeError> {
    verify_receipt_lineage_bundle(bundle)?;
    for statement in &bundle.statements {
        if statement.continuation_sha256 == continuation_sha256
            && statement.source_kernel_id == continuation.source_kernel_id
            && statement.target_kernel_id == continuation.target_kernel_id
            && statement.parent_receipt_sha256 == continuation.parent_receipt_sha256
        {
            return receipt_lineage_statement_sha256(statement);
        }
    }
    rejected(
        "chiodos_treaty_lineage_mismatch",
        "receipt lineage bundle does not bind the referenced continuation",
    )
}

struct TreatyEvidenceReview<'a> {
    treaty_scope: &'a TreatyScope,
    bundle: &'a RuntimeAdmissionBundle,
    request: &'a RuntimeRequestBinding,
    action_class_id: &'a str,
    ladder_intersection_sha256: &'a str,
    consistency_model: &'a str,
    continuation_sha256: &'a str,
}

fn verify_bilateral_invocation_evidence(
    invocation: &BilateralInvocation,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&ReceiptLineageBundle>,
) -> Result<String, ChiodosRuntimeError> {
    validate_bilateral_invocation(invocation)?;
    if review.treaty_scope.participant_kernel_ids.len() != 2
        || invocation.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation requires exactly two treaty participants and signers",
        );
    }
    if invocation.treaty_id != review.treaty_scope.treaty_id
        || invocation.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || invocation.continuation_sha256 != review.continuation_sha256
        || invocation.action_class_id != review.action_class_id
        || invocation.consistency_model != review.consistency_model
        || invocation.capability_id != review.request.capability_id
        || invocation.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation does not bind the requested treaty dispatch",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = invocation.signer_kernel_ids.iter().collect();
    if participants != signers {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation signer set does not match treaty participants",
        );
    }
    let invocation_sha256 = bilateral_invocation_binding_sha256(invocation)?;
    if let Some(bundle) = lineage_bundle {
        if invocation.local_receipt_sha256 != bundle.root_receipt_sha256
            || invocation.remote_receipt_sha256 != bundle.leaf_receipt_sha256
            || !bundle.statements.iter().any(|statement| {
                statement.bilateral_invocation_sha256 == invocation_sha256
                    && receipt_lineage_statement_sha256(statement)
                        .is_ok_and(|hash| hash == invocation.lineage_statement_sha256)
            })
        {
            return rejected(
                "chiodos_treaty_bilateral_mismatch",
                "bilateral invocation does not bind the receipt lineage bundle",
            );
        }
    }
    Ok(invocation_sha256)
}

fn verify_treaty_dsse_evidence(
    envelope: &chio_federation::DsseEnvelope,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&(ReceiptLineageBundle, String)>,
    invocation: Option<&BilateralInvocation>,
) -> Result<(), ChiodosRuntimeError> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence could not be decoded",
        );
    };
    if statement.predicate_type != chio_federation::PREDICATE_TYPE_CHIODOS_BILATERAL {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is not a strict Chiodos predicate",
        );
    }
    let Some(treaty) = statement.predicate.treaty_binding_ref.as_ref() else {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing treaty binding refs",
        );
    };
    if treaty.treaty_id != review.treaty_scope.treaty_id
        || treaty.treaty_scope_sha256 != treaty_scope_sha256(review.treaty_scope)?
        || treaty.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || treaty.continuation_sha256 != review.continuation_sha256
        || treaty.action_class_id != review.action_class_id
        || treaty.consistency_model != review.consistency_model
        || treaty.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE treaty binding does not match the requested dispatch",
        );
    }
    if statement
        .predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(treaty.request_sha256.as_str())
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE tool argument hash does not match the treaty request binding",
        );
    }
    if treaty.lease_refs != review.bundle.lease_id.iter().cloned().collect::<Vec<_>>() {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE lease refs do not match the verifier-owned admission bundle",
        );
    }
    if treaty.governance_refs
        != review
            .bundle
            .governance_receipt_id
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE governance refs do not match the verifier-owned admission bundle",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = treaty.signer_kernel_ids.iter().collect();
    if review.treaty_scope.participant_kernel_ids.len() != 2 || treaty.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE evidence requires exactly two treaty participants and signers",
        );
    }
    if participants != signers {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE signer set does not match treaty participants",
        );
    }
    let signer_a_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[0])?;
    let signer_b_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[1])?;
    if signer_a_public_key == signer_b_public_key {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE signer public keys are not independent",
        );
    }
    chio_federation::verify_chiodos_dsse_envelope(
        envelope,
        signer_a_public_key,
        signer_b_public_key,
    )
    .map_err(|_| ChiodosRuntimeError::Rejected {
        code: "chiodos_treaty_unverified_required_evidence",
        detail: "bilateral DSSE signature verification failed".to_string(),
    })?;
    if let Some((bundle, bundle_sha256)) = lineage_bundle {
        if treaty.lineage_bundle_sha256 != bundle_sha256.as_str()
            || treaty.local_receipt_sha256 != bundle.root_receipt_sha256
            || treaty.remote_receipt_sha256 != bundle.leaf_receipt_sha256
        {
            return rejected(
                "chiodos_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match lineage bundle",
            );
        }
    }
    if let Some(invocation) = invocation {
        if treaty.consistency_model != invocation.consistency_model
            || treaty.outcome_sha256 != invocation.outcome_sha256
            || treaty.local_receipt_sha256 != invocation.local_receipt_sha256
            || treaty.remote_receipt_sha256 != invocation.remote_receipt_sha256
            || treaty.signer_kernel_ids != invocation.signer_kernel_ids
        {
            return rejected(
                "chiodos_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match bilateral invocation",
            );
        }
    }
    Ok(())
}

fn treaty_participant_public_key<'a>(
    treaty_scope: &'a TreatyScope,
    kernel_id: &str,
) -> Result<&'a PublicKey, ChiodosRuntimeError> {
    let Some(index) = treaty_scope
        .participant_kernel_ids
        .iter()
        .position(|participant| participant == kernel_id)
    else {
        return rejected(
            "chiodos_treaty_missing_participant",
            "treaty participant public key is missing",
        );
    };
    treaty_scope
        .participant_public_keys
        .get(index)
        .ok_or_else(|| ChiodosRuntimeError::Rejected {
            code: "chiodos_treaty_missing_participant",
            detail: "treaty participant public key is missing".to_string(),
        })
}

fn static_treaty_failure_code(code: Option<&str>) -> &'static str {
    match code {
        Some("chiodos_treaty_stale") => "chiodos_treaty_stale",
        Some("chiodos_treaty_intersection_mismatch") => "chiodos_treaty_intersection_mismatch",
        Some("chiodos_treaty_missing_intersection_binding") => {
            "chiodos_treaty_missing_intersection_binding"
        }
        Some("chiodos_treaty_action_class_not_allowed") => {
            "chiodos_treaty_action_class_not_allowed"
        }
        Some("chiodos_treaty_missing_required_evidence") => {
            "chiodos_treaty_missing_required_evidence"
        }
        Some("chiodos_treaty_unverified_required_evidence") => {
            "chiodos_treaty_unverified_required_evidence"
        }
        _ => "chiodos_treaty_unverified_required_evidence",
    }
}

fn passed(code: &str) -> RuntimeAdmissionCheck {
    RuntimeAdmissionCheck {
        code: code.to_string(),
        passed: true,
    }
}

fn validate_runtime_step_evidence(step: &RuntimeStepEvidence) -> Result<(), ChiodosRuntimeError> {
    if step.schema != CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_step_evidence_schema",
            detail: format!(
                "runtime step evidence declared unsupported schema {}",
                step.schema
            ),
        });
    }
    if step.admission_id.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_admission_id",
            detail: "runtime step evidence must bind admission id".to_string(),
        });
    }
    ensure_sha256_hash(
        &step.admission_report_sha256,
        "runtime_step_evidence_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &step.tool_receipt_sha256,
        "runtime_step_evidence_invalid_tool_receipt_hash",
    )?;
    ensure_sha256_hash(
        &step.output_sha256,
        "runtime_step_evidence_invalid_output_hash",
    )?;
    ensure_sha256_hash(
        &step.bilateral_dsse_sha256,
        "runtime_step_evidence_invalid_dsse_hash",
    )?;
    ensure_sha256_hash(
        &step.workflow_step_sha256,
        "runtime_step_evidence_invalid_workflow_step_hash",
    )?;
    if let Some(parent) = step.parent_receipt_sha256.as_deref() {
        ensure_sha256_hash(parent, "runtime_step_evidence_invalid_parent_hash")?;
    }
    if step.consistency_anchor.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_consistency_anchor",
            detail: "runtime step evidence must bind consistency anchor".to_string(),
        });
    }
    if step.destructive && step.governance_receipt_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_governance",
            detail: "destructive runtime step evidence must bind governance receipt".to_string(),
        });
    }
    Ok(())
}

fn rejected<T>(code: &'static str, detail: &str) -> Result<T, ChiodosRuntimeError> {
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: detail.to_string(),
    })
}

fn ladder_mode_rank(mode: &str) -> Result<u8, ChiodosRuntimeError> {
    match mode {
        "observation" => Ok(0),
        "guarded" => Ok(1),
        "receipt_backed" => Ok(2),
        "partition_contingency" => Ok(3),
        "quorum_required" => Ok(4),
        _ => rejected(
            "chiodos_ladder_invalid_mode",
            "governance ladder mode is not supported",
        ),
    }
}

fn validate_consistency_model(model: &str) -> Result<(), ChiodosRuntimeError> {
    match model {
        "crdt_commutative" | "totally_ordered" | "single_kernel" | "quorum_required" => Ok(()),
        _ => rejected(
            "chiodos_ladder_invalid_consistency_model",
            "governance ladder consistency model is not supported",
        ),
    }
}

fn validate_co_sign_mode(mode: &str) -> Result<(), ChiodosRuntimeError> {
    match mode {
        "none" | "bilateral_required" | "quorum_required" => Ok(()),
        _ => rejected(
            "chiodos_ladder_invalid_cosign_mode",
            "governance ladder co-sign mode is not supported",
        ),
    }
}

fn find_ladder_action<'a>(
    manifest: &'a GovernanceLadderManifest,
    action_class_id: &str,
) -> Option<&'a GovernanceLadderActionClass> {
    manifest.action_classes.iter().find(|action| {
        action.action_class_id == action_class_id
            || action.aliases.iter().any(|alias| alias == action_class_id)
    })
}

fn cross_boundary_rejection_report(
    input: CrossBoundaryAdmissionInput<'_>,
    treaty_scope_sha256: String,
    ladder_intersection_sha256: String,
    failure_code: &'static str,
    checks: Vec<String>,
) -> CrossBoundaryAdmissionReport {
    CrossBoundaryAdmissionReport {
        schema: CHIODOS_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: input.treaty_scope.treaty_id.clone(),
        action_class_id: input.action_class_id.to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        mode: "observation".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "none".to_string(),
        required_evidence: Vec::new(),
        present_evidence: input.present_evidence,
        verified_evidence: input.verified_evidence,
        treaty_scope_sha256,
        ladder_intersection_sha256,
        expected_ladder_intersection_sha256: input.expected_ladder_intersection_sha256,
        checks,
    }
}

fn validate_receipt_lineage_statement(
    statement: &ReceiptLineageStatement,
) -> Result<(), ChiodosRuntimeError> {
    if statement.schema != CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA {
        return rejected(
            "unsupported_receipt_lineage_statement_schema",
            "receipt lineage statement declared an unsupported schema",
        );
    }
    validate_non_empty(&statement.statement_id, "receipt_lineage_empty_id")?;
    ensure_sha256_hash(
        &statement.parent_receipt_sha256,
        "receipt_lineage_invalid_parent_hash",
    )?;
    ensure_sha256_hash(
        &statement.child_receipt_sha256,
        "receipt_lineage_invalid_child_hash",
    )?;
    ensure_sha256_hash(
        &statement.continuation_sha256,
        "receipt_lineage_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &statement.bilateral_invocation_sha256,
        "receipt_lineage_invalid_bilateral_hash",
    )?;
    match statement.evidence_class.as_str() {
        "verified" | "observed" | "asserted" | "unverifiable" | "rejected" => {}
        _ => {
            return rejected(
                "receipt_lineage_invalid_evidence_class",
                "receipt lineage statement evidence class is unsupported",
            );
        }
    }
    validate_non_empty(
        &statement.source_kernel_id,
        "receipt_lineage_empty_source_kernel",
    )?;
    validate_non_empty(
        &statement.target_kernel_id,
        "receipt_lineage_empty_target_kernel",
    )
}

fn validate_cross_kernel_continuation(
    continuation: &CrossKernelContinuation,
) -> Result<(), ChiodosRuntimeError> {
    if continuation.schema != CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA {
        return rejected(
            "unsupported_cross_kernel_continuation_schema",
            "cross-kernel continuation declared an unsupported schema",
        );
    }
    validate_non_empty(&continuation.continuation_id, "continuation_empty_id")?;
    validate_non_empty(
        &continuation.source_kernel_id,
        "continuation_empty_source_kernel",
    )?;
    validate_non_empty(
        &continuation.target_kernel_id,
        "continuation_empty_target_kernel",
    )?;
    ensure_sha256_hash(
        &continuation.parent_receipt_sha256,
        "continuation_invalid_parent_hash",
    )?;
    ensure_sha256_hash(
        &continuation.parent_session_anchor_sha256,
        "continuation_invalid_session_anchor_hash",
    )?;
    validate_non_empty(&continuation.capability_id, "continuation_empty_capability")?;
    validate_non_empty(
        &continuation.action_class_id,
        "continuation_empty_action_class",
    )?;
    validate_non_empty(&continuation.audience_tool, "continuation_empty_audience")?;
    validate_non_empty(&continuation.nonce, "continuation_empty_nonce")?;
    if continuation.issued_at_unix_ms >= continuation.expires_at_unix_ms {
        return rejected(
            "continuation_invalid_window",
            "cross-kernel continuation validity window is empty",
        );
    }
    Ok(())
}

fn validate_bilateral_invocation(
    invocation: &BilateralInvocation,
) -> Result<(), ChiodosRuntimeError> {
    if invocation.schema != CHIODOS_BILATERAL_INVOCATION_SCHEMA {
        return rejected(
            "unsupported_bilateral_invocation_schema",
            "bilateral invocation declared an unsupported schema",
        );
    }
    validate_non_empty(&invocation.invocation_id, "bilateral_invocation_empty_id")?;
    validate_non_empty(&invocation.treaty_id, "bilateral_invocation_empty_treaty")?;
    ensure_sha256_hash(
        &invocation.ladder_intersection_sha256,
        "bilateral_invocation_invalid_intersection_hash",
    )?;
    ensure_sha256_hash(
        &invocation.continuation_sha256,
        "bilateral_invocation_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &invocation.lineage_statement_sha256,
        "bilateral_invocation_invalid_lineage_hash",
    )?;
    validate_non_empty(
        &invocation.action_class_id,
        "bilateral_invocation_empty_action_class",
    )?;
    validate_consistency_model(&invocation.consistency_model)?;
    validate_non_empty(
        &invocation.capability_id,
        "bilateral_invocation_empty_capability",
    )?;
    ensure_sha256_hash(
        &invocation.request_sha256,
        "bilateral_invocation_invalid_request_hash",
    )?;
    ensure_sha256_hash(
        &invocation.outcome_sha256,
        "bilateral_invocation_invalid_outcome_hash",
    )?;
    ensure_sha256_hash(
        &invocation.local_receipt_sha256,
        "bilateral_invocation_invalid_local_receipt_hash",
    )?;
    ensure_sha256_hash(
        &invocation.remote_receipt_sha256,
        "bilateral_invocation_invalid_remote_receipt_hash",
    )?;
    if invocation.signer_kernel_ids.len() != 2 {
        return rejected(
            "bilateral_invocation_signer_count_mismatch",
            "bilateral invocation must include exactly two kernel signers",
        );
    }
    let mut signers = BTreeSet::new();
    for signer in &invocation.signer_kernel_ids {
        validate_non_empty(signer, "bilateral_invocation_empty_signer")?;
        if !signers.insert(signer) {
            return rejected(
                "bilateral_invocation_duplicate_signer",
                "bilateral invocation signer kernels must be distinct",
            );
        }
    }
    Ok(())
}

const BUYER_REVIEW_REQUIRED_ROLES: &[&str] = &[
    "buyer_attestation_packet",
    "receipt_lineage_statement",
    "receipt_lineage_bundle",
    "cross_kernel_continuation",
    "cross_boundary_admission_report",
    "bilateral_invocation",
    "bilateral_dsse_envelope",
    "workflow_receipt",
    "proof_package",
    "verifier_report",
    "proof_regeneration_report",
    "runtime_run_report",
    "runtime_evidence_manifest",
    "proof_regeneration_input",
];

fn validate_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<(), ChiodosRuntimeError> {
    if bundle.schema != CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA {
        return rejected(
            "unsupported_receipt_lineage_bundle_schema",
            "receipt lineage bundle declared an unsupported schema",
        );
    }
    validate_non_empty(&bundle.bundle_id, "receipt_lineage_bundle_empty_id")?;
    ensure_sha256_hash(
        &bundle.root_receipt_sha256,
        "receipt_lineage_bundle_invalid_root_hash",
    )?;
    ensure_sha256_hash(
        &bundle.leaf_receipt_sha256,
        "receipt_lineage_bundle_invalid_leaf_hash",
    )
}

fn validate_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
) -> Result<(), ChiodosRuntimeError> {
    if package.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_package_schema",
            "buyer attestation review package declared an unsupported schema",
        );
    }
    validate_non_empty(&package.package_id, "buyer_review_package_empty_id")?;
    validate_non_empty(&package.packet_id, "buyer_review_package_empty_packet")?;
    validate_non_empty(&package.buyer_id, "buyer_review_package_empty_buyer")?;
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for artifact in &package.artifacts {
        validate_non_empty(&artifact.role, "buyer_review_artifact_empty_role")?;
        validate_non_empty(
            &artifact.relative_path,
            "buyer_review_artifact_empty_relative_path",
        )?;
        validate_relative_evidence_path(
            &artifact.relative_path,
            "buyer_review_artifact_unsafe_path",
        )?;
        ensure_sha256_hash(
            &artifact.artifact_sha256,
            "buyer_review_artifact_invalid_hash",
        )?;
        if artifact.byte_count == 0 {
            return rejected(
                "buyer_review_artifact_empty_bytes",
                "buyer review artifact byte count must be nonzero",
            );
        }
        if !roles.insert(artifact.role.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_path",
                "buyer review package contains duplicate artifact path",
            );
        }
    }
    Ok(())
}

fn validate_buyer_attestation_review_report(
    report: &BuyerAttestationReviewReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_report_schema",
            "buyer attestation review report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.package_id, "buyer_review_report_empty_package")?;
    validate_non_empty(&report.packet_id, "buyer_review_report_empty_packet")?;
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_review_report_missing_failure_code",
            "rejected buyer attestation review report must include failure code",
        );
    }
    Ok(())
}

fn review_refs_by_role(
    package: &BuyerAttestationReviewPackage,
) -> Result<BTreeMap<String, BuyerAttestationReviewArtifactRef>, ChiodosRuntimeError> {
    let mut refs = BTreeMap::new();
    for artifact in &package.artifacts {
        if refs
            .insert(artifact.role.clone(), artifact.clone())
            .is_some()
        {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
    }
    Ok(refs)
}

fn parse_review_json<T: serde::de::DeserializeOwned>(
    sources_by_role: &BTreeMap<String, Vec<u8>>,
    role: &str,
) -> Result<T, ChiodosRuntimeError> {
    let bytes = sources_by_role
        .get(role)
        .ok_or_else(|| ChiodosRuntimeError::Rejected {
            code: "chiodos_buyer_review_missing_artifact_role",
            detail: format!("buyer review package is missing artifact role {role}"),
        })?;
    serde_json::from_slice(bytes).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

fn buyer_review_check(
    code: &str,
    passed: bool,
    severity: &str,
    artifact_role: &str,
    expected_sha256: Option<String>,
    observed_sha256: Option<String>,
    message: &str,
) -> BuyerAttestationReviewCheck {
    BuyerAttestationReviewCheck {
        code: code.to_string(),
        passed,
        severity: severity.to_string(),
        artifact_role: artifact_role.to_string(),
        expected_sha256,
        observed_sha256,
        message: message.to_string(),
    }
}

fn buyer_review_rejection_report(
    package: &BuyerAttestationReviewPackage,
    failure_code: &str,
    checks: Vec<BuyerAttestationReviewCheck>,
) -> BuyerAttestationReviewReport {
    BuyerAttestationReviewReport {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}

fn validate_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
) -> Result<(), ChiodosRuntimeError> {
    if packet.schema != CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_packet_schema",
            "buyer attestation packet declared an unsupported schema",
        );
    }
    validate_non_empty(&packet.packet_id, "buyer_packet_empty_id")?;
    validate_non_empty(&packet.buyer_id, "buyer_packet_empty_buyer")?;
    validate_non_empty(&packet.capability_id, "buyer_packet_empty_capability")?;
    ensure_sha256_hash(
        &packet.treaty_scope_sha256,
        "buyer_packet_invalid_treaty_hash",
    )?;
    ensure_sha256_hash(
        &packet.ladder_intersection_sha256,
        "buyer_packet_invalid_intersection_hash",
    )?;
    ensure_sha256_hash(
        &packet.cross_boundary_admission_report_sha256,
        "buyer_packet_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &packet.continuation_sha256,
        "buyer_packet_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &packet.receipt_lineage_statement_sha256,
        "buyer_packet_invalid_lineage_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_invocation_sha256,
        "buyer_packet_invalid_bilateral_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_dsse_sha256,
        "buyer_packet_invalid_bilateral_dsse_hash",
    )?;
    ensure_sha256_hash(
        &packet.workflow_receipt_sha256,
        "buyer_packet_invalid_workflow_hash",
    )?;
    ensure_sha256_hash(
        &packet.proof_package_sha256,
        "buyer_packet_invalid_package_hash",
    )?;
    ensure_sha256_hash(
        &packet.verifier_report_sha256,
        "buyer_packet_invalid_verifier_hash",
    )
}

fn validate_buyer_attestation_verification_report(
    report: &BuyerAttestationVerificationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_verification_report_schema",
            "buyer attestation verification report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.packet_id, "buyer_verification_empty_packet")?;
    match (report.accepted, report.verification_state.as_str()) {
        (true, "hash_only") | (false, "rejected") => {}
        _ => {
            return rejected(
                "buyer_verification_invalid_state",
                "buyer attestation packet verification state must describe hash-only or rejected review",
            )
        }
    }
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_verification_missing_failure_code",
            "rejected buyer attestation verification report must include failure code",
        );
    }
    Ok(())
}

fn buyer_packet_rejection_report(
    packet: &BuyerAttestationPacket,
    failure_code: &'static str,
    checks: Vec<String>,
) -> BuyerAttestationVerificationReport {
    BuyerAttestationVerificationReport {
        schema: CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "rejected".to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}

fn ensure_sha256_hash(hash: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if is_sha256_hex(hash) {
        return Ok(());
    }
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: format!("runtime evidence hash {hash} is not sha256 hex"),
    })
}

fn ensure_optional_sha256(
    hash: Option<&str>,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(hash) = hash {
        ensure_sha256_hash(hash, code)?;
    }
    Ok(())
}

fn validate_non_empty(value: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: "runtime orchestration field must not be empty".to_string(),
        });
    }
    Ok(())
}

fn validate_state_label(value: &str, code: &'static str) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime orchestration label {value:?} is invalid"),
        });
    }
    Ok(())
}

fn validate_planned_steps(
    steps: &[RuntimeOrchestrationPlannedStep],
) -> Result<(), ChiodosRuntimeError> {
    let mut indices = BTreeSet::new();
    for step in steps {
        if !indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_plan_duplicate_step",
                detail: format!(
                    "runtime orchestration plan repeats step {}",
                    step.step_index
                ),
            });
        }
        validate_non_empty(
            &step.admission_id,
            "runtime_orchestration_plan_empty_admission_id",
        )?;
        validate_state_label(&step.state, "runtime_orchestration_plan_invalid_step_state")?;
    }
    Ok(())
}

fn validate_runtime_orchestration_step_state(
    state: &RuntimeOrchestrationStepState,
) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(
        &state.admission_id,
        "runtime_orchestration_step_empty_admission_id",
    )?;
    validate_state_label(&state.state, "runtime_orchestration_step_invalid_state")?;
    ensure_optional_sha256(
        state.admission_report_sha256.as_deref(),
        "runtime_orchestration_step_invalid_admission_hash",
    )?;
    ensure_optional_sha256(
        state.tool_receipt_sha256.as_deref(),
        "runtime_orchestration_step_invalid_receipt_hash",
    )?;
    if state.destructive && state.lease_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_step_missing_destructive_lease",
            detail: "destructive runtime orchestration step must bind lease id".to_string(),
        });
    }
    Ok(())
}

fn validate_runtime_proof_drift(drift: &RuntimeProofDrift) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(&drift.field, "runtime_proof_drift_empty_field")?;
    ensure_sha256_hash(
        &drift.baseline_value_sha256,
        "runtime_proof_drift_invalid_baseline_value_hash",
    )?;
    ensure_sha256_hash(
        &drift.candidate_value_sha256,
        "runtime_proof_drift_invalid_candidate_value_hash",
    )?;
    validate_state_label(&drift.severity, "runtime_proof_drift_invalid_severity")
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosRuntimeError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosRuntimeError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn compare_semantic_field<T: Serialize + PartialEq>(
    field: &str,
    baseline: &T,
    candidate: &T,
    drifts: &mut Vec<RuntimeProofDrift>,
) -> Result<(), ChiodosRuntimeError> {
    if baseline != candidate {
        drifts.push(RuntimeProofDrift {
            field: field.to_string(),
            baseline_value_sha256: canonical_sha256(baseline)?,
            candidate_value_sha256: canonical_sha256(candidate)?,
            severity: "error".to_string(),
        });
    }
    Ok(())
}

fn compare_verifier_field<T: Serialize + PartialEq>(
    field: &str,
    baseline: &T,
    candidate: &T,
    drifts: &mut Vec<RuntimeProofDrift>,
) -> Result<(), ChiodosRuntimeError> {
    compare_semantic_field(field, baseline, candidate, drifts)
}

fn evidence_sink_write_probe(evidence_root: &Path) -> (bool, bool) {
    let probe = evidence_root.join(".chiodos-runtime-health-probe.tmp");
    let committed = evidence_root.join(".chiodos-runtime-health-probe.done");
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    let write_ok = fs::write(&probe, b"runtime-evidence-health").is_ok();
    let rename_ok = write_ok && fs::rename(&probe, &committed).is_ok();
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&committed);
    (write_ok, rename_ok)
}

fn runtime_run_counts(
    connection: &Connection,
) -> Result<BTreeMap<String, u64>, ChiodosRuntimeError> {
    let mut run_counts = BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT status, COUNT(*) FROM runtime_runs GROUP BY status")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (status, count) = row.map_err(sqlite_error)?;
        run_counts.insert(status, sqlite_u64(count, "runtime run count")?);
    }
    Ok(run_counts)
}

fn lease_count_by_state(connection: &Connection, state: &str) -> Result<u64, ChiodosRuntimeError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = ?1",
            params![state],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime lease count")
}

fn stale_lease_count(
    connection: &Connection,
    now_unix_ms: u64,
    stale_run_after_ms: u64,
) -> Result<u64, ChiodosRuntimeError> {
    let stale_before = now_unix_ms.saturating_sub(stale_run_after_ms);
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
            params![
                sqlite_i64(now_unix_ms, "runtime stale lease timestamp")?,
                sqlite_i64(stale_before, "runtime stale heartbeat timestamp")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime stale lease count")
}

fn sqlite_error(error: rusqlite::Error) -> ChiodosRuntimeError {
    ChiodosRuntimeError::Store(format!("runtime orchestration sqlite: {error}"))
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, ChiodosRuntimeError> {
    i64::try_from(value).map_err(|_| ChiodosRuntimeError::Rejected {
        code: "runtime_sqlite_integer_out_of_range",
        detail: format!("{field} does not fit sqlite i64"),
    })
}

fn sqlite_u64(value: i64, field: &str) -> Result<u64, ChiodosRuntimeError> {
    u64::try_from(value).map_err(|_| ChiodosRuntimeError::Rejected {
        code: "runtime_sqlite_integer_negative",
        detail: format!("{field} is negative"),
    })
}

fn query_count(connection: &Connection, table: &str) -> Result<u64, ChiodosRuntimeError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sqlite_error)?;
    sqlite_u64(count, table)
}

fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn required_string_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<String, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value
            .get(*field)
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
        {
            return Ok(item.to_string());
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn required_u64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<u64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_u64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn required_f64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<f64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_f64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

fn validate_runtime_trust_input(
    envelope: &SignedRuntimeVerifierTrustBundle,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    bundle: &RuntimeAdmissionBundle,
    now_unix_ms: u64,
    checks: &mut Vec<RuntimeAdmissionCheck>,
) -> Result<RuntimeTrustFloorEntry, &'static str> {
    let body = &envelope.body;
    if body.schema != CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4 {
        return Err("unsupported_runtime_trust_schema");
    }
    checks.push(passed("runtime_trust.schema"));

    let signature_valid = envelope
        .verify_signature()
        .map_err(|_| "runtime_trust_signature_invalid")?;
    if !signature_valid {
        return Err("runtime_trust_signature_invalid");
    }
    checks.push(passed("runtime_trust.signature"));

    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == body.verifier_id
            && trusted.key_id == body.key_id
            && trusted.public_key == envelope.signer_key
    }) else {
        return Err("runtime_trust_signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("runtime_trust_signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("runtime_trust_signer_stale");
    }
    checks.push(passed("runtime_trust.signer"));

    if now_unix_ms < body.issued_at_unix_ms || now_unix_ms >= body.expires_at_unix_ms {
        return Err("runtime_trust_stale");
    }
    checks.push(passed("runtime_trust.freshness"));

    if body.version == 0 {
        return Err("runtime_trust_version_zero");
    }
    if body.version > 1 && body.previous_hash_sha256.is_none() {
        return Err("runtime_trust_previous_hash_missing");
    }
    checks.push(passed("runtime_trust.version"));

    let body_hash =
        runtime_verifier_trust_bundle_sha256(body).map_err(|_| "runtime_trust_hash_failed")?;

    if body.revocation_authority_roots.is_empty() {
        return Err("runtime_trust_revocation_roots_missing");
    }
    checks.push(passed("runtime_trust.revocation_roots"));

    if body.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return Err("runtime_trust_bundle_hash_mismatch");
    }
    if body.verification_context_sha256 != bundle.verification_context_sha256 {
        return Err("runtime_trust_context_hash_mismatch");
    }
    checks.push(passed("runtime_trust.bundle_binding"));
    Ok(RuntimeTrustFloorEntry {
        verifier_id: body.verifier_id.clone(),
        key_id: body.key_id.clone(),
        highest_version: body.version,
        latest_bundle_sha256: body_hash,
        latest_revocation_checkpoint_sha256: body.revocation_checkpoint_sha256.clone(),
    })
}

fn validate_runtime_trust_floor_transition(
    existing: Option<RuntimeTrustFloorEntry>,
    next: &RuntimeTrustFloorEntry,
    previous_hash_sha256: Option<&str>,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(floor) = existing {
        if next.highest_version < floor.highest_version {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_rollback",
                detail: "runtime trust input version is below persisted floor".to_string(),
            });
        }
        if next.highest_version == floor.highest_version
            && next.latest_bundle_sha256 != floor.latest_bundle_sha256
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_same_version_mismatch",
                detail: "runtime trust input reused a floor version with different content"
                    .to_string(),
            });
        }
        if next.highest_version > floor.highest_version
            && previous_hash_sha256 != Some(floor.latest_bundle_sha256.as_str())
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_trust_previous_hash_mismatch",
                detail: "runtime trust input does not extend the persisted floor".to_string(),
            });
        }
    } else if next.highest_version > 1 && previous_hash_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_trust_previous_hash_missing",
            detail: "runtime trust input above version one must carry a previous hash".to_string(),
        });
    }
    Ok(())
}

struct RuntimePolicyEvaluationInput<'a, 'b> {
    policy: Option<&'a SignedRuntimePheromonePolicy>,
    peer_weights: Option<&'a SignedRuntimePeerWeights>,
    query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    bundle: &'a RuntimeAdmissionBundle,
    now_unix_ms: u64,
    checks: &'b mut Vec<RuntimeAdmissionCheck>,
}

fn evaluate_runtime_pheromone_policy(
    input: RuntimePolicyEvaluationInput<'_, '_>,
) -> Result<
    (
        Option<RuntimePheromonePolicyDecision>,
        Option<RuntimePheromoneAdvisory>,
    ),
    &'static str,
> {
    if input.bundle.destructive
        && (input.policy.is_none() || input.peer_weights.is_none() || input.query_report.is_none())
    {
        return Err("runtime_pheromone_required_for_destructive");
    }
    match (input.policy, input.peer_weights) {
        (None, None) => return Ok((None, None)),
        (Some(_), None) => return Err("missing_runtime_peer_weights"),
        (None, Some(_)) => return Err("missing_runtime_pheromone_policy"),
        (Some(_), Some(_)) => {}
    }
    let Some(runtime_trust_input) = input.runtime_trust_input else {
        return Err("missing_runtime_trust_input");
    };
    let Some(query_report) = input.query_report else {
        return Err("missing_runtime_pheromone_advisory");
    };

    let policy = input.policy.ok_or("missing_runtime_pheromone_policy")?;
    let peer_weights = input.peer_weights.ok_or("missing_runtime_peer_weights")?;
    validate_signed_verifier_material(
        &policy.body.verifier_id,
        &policy.body.key_id,
        &policy.signer_key,
        || policy.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_pheromone_policy_untrusted")?;
    input.checks.push(passed("runtime_policy.signature"));
    if query_report.signer_key != policy.signer_key {
        return Err("runtime_pheromone_policy_query_report_signer_mismatch");
    }
    if !query_report
        .verify_signature()
        .map_err(|_| "runtime_pheromone_query_report_signature_invalid")?
    {
        return Err("runtime_pheromone_query_report_signature_invalid");
    }
    input
        .checks
        .push(passed("runtime_pheromone_query_report.signature"));
    let advisory = runtime_pheromone_advisory_from_query_report_value(&query_report.body)
        .map_err(|_| "invalid_pheromone_query_report")?;
    if !advisory.observe_only {
        return Err("runtime_pheromone_advisory_not_observe_only");
    }
    if !advisory.accepted {
        return Err("runtime_pheromone_advisory_rejected");
    }
    if advisory.evaluated_at_unix_ms > input.now_unix_ms {
        return Err("runtime_pheromone_advisory_future_dated");
    }
    validate_signed_verifier_material(
        &peer_weights.body.verifier_id,
        &peer_weights.body.key_id,
        &peer_weights.signer_key,
        || peer_weights.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_peer_weights_untrusted")?;
    input.checks.push(passed("runtime_peer_weights.signature"));

    let policy_body = &policy.body;
    let weights_body = &peer_weights.body;
    if policy_body.schema != CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA {
        return Err("unsupported_runtime_pheromone_policy_schema");
    }
    if weights_body.schema != CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA {
        return Err("unsupported_runtime_peer_weights_schema");
    }
    if policy_body.mode != "observe" && policy_body.mode != "enforce" {
        return Err("runtime_pheromone_policy_mode_unsupported");
    }
    if input.now_unix_ms < policy_body.issued_at_unix_ms
        || input.now_unix_ms >= policy_body.expires_at_unix_ms
    {
        return Err("runtime_pheromone_policy_stale");
    }
    if input.now_unix_ms < weights_body.issued_at_unix_ms
        || input.now_unix_ms >= weights_body.expires_at_unix_ms
    {
        return Err("runtime_peer_weights_stale");
    }
    if policy_body.verifier_id != runtime_trust_input.body.verifier_id {
        return Err("runtime_pheromone_policy_verifier_mismatch");
    }
    if policy_body.runtime_trust_bundle_sha256 != runtime_trust_input.body.trust_bundle_sha256 {
        return Err("runtime_pheromone_policy_trust_mismatch");
    }
    let weights_hash = runtime_peer_weights_sha256(weights_body)
        .map_err(|_| "runtime_peer_weights_hash_failed")?;
    if policy_body.peer_weights_sha256 != weights_hash {
        return Err("runtime_peer_weights_hash_mismatch");
    }
    if weights_body.reputation_epoch != advisory.reputation_epoch
        || !policy_body
            .allowed_reputation_epochs
            .contains(&advisory.reputation_epoch)
    {
        return Err("runtime_reputation_epoch_mismatch");
    }
    if input
        .now_unix_ms
        .saturating_sub(advisory.evaluated_at_unix_ms)
        > policy_body.max_query_report_age_ms
    {
        return Err("runtime_pheromone_advisory_stale");
    }
    if advisory.distinct_origin_pairs < policy_body.min_distinct_origin_pairs {
        return Err("runtime_pheromone_distinct_origin_floor");
    }
    validate_peer_weights(weights_body)?;
    input.checks.push(passed("runtime_policy.bindings"));

    let policy_hash =
        runtime_pheromone_policy_sha256(policy_body).map_err(|_| "runtime_policy_hash_failed")?;
    let mut decision = RuntimePheromonePolicyDecision {
        schema: CHIODOS_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA.to_string(),
        enforced: policy_body.mode == "enforce",
        decision: "allow".to_string(),
        policy_id: policy_body.policy_id.clone(),
        policy_sha256: policy_hash,
        query_report_sha256: advisory.source_report_sha256.clone(),
        peer_weights_sha256: weights_hash,
        reputation_epoch: advisory.reputation_epoch,
        matched_rule_id: None,
        reason_code: "runtime_pheromone_policy_allow".to_string(),
    };

    for rule in &policy_body.rules {
        if rule.subject_class != advisory.subject_class
            || rule.subject_class_namespace != advisory.subject_class_namespace
        {
            continue;
        }
        if rule.action_class_id != input.bundle.binding.tool_name && rule.action_class_id != "*" {
            continue;
        }
        let matched = match rule.direction.as_str() {
            "deny_if_at_or_above" => advisory.total_strength >= rule.threshold_total_strength,
            "require_at_or_above" => advisory.total_strength < rule.threshold_total_strength,
            _ => return Err("runtime_pheromone_policy_direction_unsupported"),
        };
        if !matched {
            continue;
        }
        decision.matched_rule_id = Some(rule.rule_id.clone());
        decision.reason_code = format!("runtime_pheromone_policy_{}", rule.effect);
        if policy_body.mode == "enforce" {
            decision.decision = match rule.effect.as_str() {
                "deny" => "deny".to_string(),
                "require_review" => "escalate".to_string(),
                "receipt_tag" => "allow".to_string(),
                _ => return Err("runtime_pheromone_policy_effect_unsupported"),
            };
        }
        break;
    }
    Ok((Some(decision), Some(advisory)))
}

fn validate_peer_weights(weights: &RuntimePeerWeights) -> Result<(), &'static str> {
    let mut peers = BTreeSet::new();
    for weight in &weights.weights {
        if weight.peer_kernel_id.trim().is_empty() {
            return Err("runtime_peer_weights_invalid");
        }
        if !peers.insert(weight.peer_kernel_id.as_str()) {
            return Err("runtime_peer_weights_duplicate_peer");
        }
        if !weight.weight.is_finite() || weight.weight < 0.0 {
            return Err("runtime_peer_weights_invalid");
        }
    }
    Ok(())
}

fn validate_signed_verifier_material<F>(
    verifier_id: &str,
    key_id: &str,
    signer_key: &PublicKey,
    verify_signature: F,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    now_unix_ms: u64,
) -> Result<(), &'static str>
where
    F: FnOnce() -> Result<bool, chio_core_types::Error>,
{
    if !verify_signature().map_err(|_| "signature_invalid")? {
        return Err("signature_invalid");
    }
    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == verifier_id
            && trusted.key_id == key_id
            && trusted.public_key == *signer_key
    }) else {
        return Err("signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("signer_stale");
    }
    Ok(())
}

fn rejected_report(
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
) -> RuntimeAdmissionReport {
    rejected_report_with_policy(admission_id, failure_code, checks, None)
}

fn rejected_report_with_policy(
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
    pheromone_policy_decision: Option<RuntimePheromonePolicyDecision>,
) -> RuntimeAdmissionReport {
    RuntimeAdmissionReport {
        schema: CHIODOS_RUNTIME_ADMISSION_REPORT_SCHEMA.to_string(),
        admission_id: admission_id.to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
        pheromone_advisory: None,
        pheromone_policy_decision: pheromone_policy_decision.clone(),
        receipt_metadata: serde_json::json!({
            "chiodos_runtime": {
                "admission_id": admission_id,
                "accepted": false,
                "failure_code": failure_code,
                "pheromone_policy_decision": pheromone_policy_decision
            }
        }),
    }
}

fn receipt_metadata(
    bundle: &RuntimeAdmissionBundle,
    accepted: bool,
    failure_code: Option<&str>,
    reserved_destructive_lease_id: Option<&str>,
    pheromone_advisory: Option<&RuntimePheromoneAdvisory>,
    pheromone_policy_decision: Option<&RuntimePheromonePolicyDecision>,
) -> serde_json::Value {
    serde_json::json!({
        "chiodos_runtime": {
            "admission_id": bundle.admission_id,
            "accepted": accepted,
            "failure_code": failure_code,
            "workflow_id": bundle.workflow_id,
            "workflow_grant_id": bundle.workflow_grant_id,
            "step_index": bundle.step_index,
            "destructive": bundle.destructive,
            "lease_id": bundle.lease_id,
            "reserved_destructive_lease_id": reserved_destructive_lease_id,
            "governance_receipt_id": bundle.governance_receipt_id,
            "trust_bundle_sha256": bundle.trust_bundle_sha256,
            "verification_context_sha256": bundle.verification_context_sha256,
            "pheromone_advisory": pheromone_advisory,
            "pheromone_policy_decision": pheromone_policy_decision
        }
    })
}

fn trust_floor_identity(verifier_id: &str, key_id: &str) -> String {
    format!("{verifier_id}:{key_id}")
}
