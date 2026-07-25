//! Live Chio runtime admission.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::{receipt::lineage::SignedExportEnvelope, PublicKey};
use chio_kernel::{
    KernelError, RuntimeAdmissionContext as KernelRuntimeAdmissionContext,
    RuntimeAdmissionDecision as KernelRuntimeAdmissionDecision, RuntimeAdmissionHook,
};
use serde::{Deserialize, Serialize};

mod admission;
mod admission_hook;
mod buyer;
mod error;
mod hash;
mod ops;
mod orchestration;
mod pheromone_policy;
mod schema;
mod serde_io;
mod store;
pub(crate) mod treaty;
mod types;
mod validation;

pub use admission::{evaluate_runtime_admission, RuntimeAdmissionInput};
pub(crate) use admission::{trust_floor_identity, validate_runtime_trust_floor_transition};
pub use admission_hook::ChioRuntimeAdmissionHook;
pub use buyer::{
    verify_buyer_attestation_packet, verify_buyer_attestation_review_package,
    verify_buyer_attestation_review_package_with_trust, verify_receipt_lineage_bundle,
};
pub use error::ChioRuntimeError;
pub(crate) use hash::canonical_sha256;
pub use hash::{
    buyer_attestation_packet_sha256, runtime_admission_bundle_sha256,
    runtime_artifact_retention_profile_sha256, runtime_orchestration_profile_sha256,
    runtime_peer_weights_sha256, runtime_pheromone_policy_sha256, runtime_run_contract_sha256,
    runtime_supervisor_profile_sha256, runtime_verifier_trust_bundle_sha256, tool_args_sha256,
};
pub use ops::{
    build_runtime_orchestration_plan, generate_runtime_artifact_retention_plan,
    generate_runtime_evidence_sink_health_report, generate_runtime_proof_drift_report,
    generate_runtime_provider_health_report,
    generate_runtime_provider_health_report_with_model_card_evidence,
    generate_runtime_provider_health_report_with_model_cards,
};
pub use orchestration::{
    load_runtime_orchestration_evidence, runtime_orchestration_evidence_is_fresh,
    runtime_orchestration_evidence_sink_healthy, validate_runtime_orchestration_evidence_binding,
    validate_runtime_orchestration_evidence_integrity, RuntimeOrchestrationEvidence,
    RuntimeOrchestrationEvidenceFailure,
};
pub use schema::{
    CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA,
    CHIO_ATTEST_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA, CHIO_BILATERAL_INVOCATION_SCHEMA,
    CHIO_BUYER_ATTESTATION_PACKET_SCHEMA, CHIO_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA,
    CHIO_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA, CHIO_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA,
    CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA,
    CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA,
    CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_FEDERATION_TREATY_SCOPE_SCHEMA,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_LADDER_INTERSECTION_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_REPORT_SCHEMA, CHIO_RUNTIME_ADMISSION_STORE_SCHEMA,
    CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA, CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA,
    CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA, CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA,
    CHIO_RUNTIME_FAILURE_CODES, CHIO_RUNTIME_FAILURE_CODE_REGISTRY_SCHEMA,
    CHIO_RUNTIME_OPS_NEGATIVE_CORPUS_SCHEMA, CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_NEGATIVE_CORPUS_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA,
    CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA,
    CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA, CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
    CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA, CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA,
    CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA, CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA,
    CHIO_RUNTIME_RUN_CONTRACT_SCHEMA, CHIO_RUNTIME_RUN_LEASE_SCHEMA,
    CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA, CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA,
    CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA, CHIO_RUNTIME_TRUSTED_VERIFIERS_SCHEMA,
    CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
    CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA, CHIO_TREATY_NEGATIVE_CORPUS_SCHEMA,
    CHIO_TREATY_RUNTIME_NEGATIVE_CORPUS_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};
pub use serde_io::{
    buyer_attestation_packet_from_json, buyer_attestation_review_package_from_json,
    buyer_attestation_review_report_json, buyer_attestation_verification_report_json,
    runtime_admission_bundle_from_json, runtime_admission_profile_from_json,
    runtime_admission_report_json, runtime_artifact_retention_plan_json,
    runtime_artifact_retention_profile_from_json, runtime_evidence_manifest_json,
    runtime_evidence_sink_health_report_json, runtime_ops_status_report_json,
    runtime_orchestration_plan_json, runtime_orchestration_profile_from_json,
    runtime_orchestration_resume_plan_json, runtime_orchestration_run_report_json,
    runtime_orchestration_status_report_json, runtime_pheromone_advisory_from_query_report_json,
    runtime_proof_drift_report_json, runtime_proof_parity_report_json,
    runtime_proof_regeneration_input_json, runtime_proof_regeneration_report_json,
    runtime_provider_bindings_from_json, runtime_provider_health_report_json,
    runtime_recovery_drill_report_json, runtime_request_binding_from_json,
    runtime_run_contract_from_json, runtime_scheduler_tick_report_json,
    runtime_supervisor_profile_from_json, runtime_trusted_verifier_keys_from_json,
    runtime_workflow_run_report_json, sign_runtime_admission_report,
    signed_runtime_admission_report_from_json, signed_runtime_admission_report_json,
    signed_runtime_peer_weights_from_json, signed_runtime_pheromone_policy_from_json,
    signed_runtime_pheromone_query_report_from_json, signed_runtime_pheromone_query_report_json,
    signed_runtime_verifier_trust_bundle_from_json, verify_signed_runtime_admission_report,
};
pub use store::{
    InMemoryRuntimeAdmissionStore, JsonRuntimeAdmissionStore, JsonRuntimeTrustFloorStateStore,
    LayeredRuntimeAdmissionStore, RuntimeAdmissionStore, RuntimeTrustFloorStore,
    SqliteRuntimeOrchestrationStore,
};
pub use treaty::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256,
    compute_ladder_intersection, cross_boundary_admission_report_json,
    evaluate_cross_boundary_admission, governance_ladder_manifest_from_json,
    governance_ladder_manifest_sha256, ladder_co_sign_mode, ladder_intersection_from_json,
    ladder_intersection_json, ladder_intersection_semantic_sha256, ladder_intersection_sha256,
    receipt_lineage_bundle_from_json, receipt_lineage_statement_from_json,
    receipt_lineage_statement_sha256, treaty_scope_from_json,
    treaty_scope_semantic_intersection_sha256, treaty_scope_sha256,
    validate_cross_boundary_admission_report, validate_governance_ladder_manifest,
    validate_ladder_intersection, validate_treaty_scope,
};
pub use types::{
    BilateralInvocation, BuyerAttestationPacket, BuyerAttestationReviewArtifactRef,
    BuyerAttestationReviewCheck, BuyerAttestationReviewPackage, BuyerAttestationReviewReport,
    BuyerAttestationReviewSource, BuyerAttestationReviewTrustContext,
    BuyerAttestationVerificationReport, CrossBoundaryAdmissionInput, CrossBoundaryAdmissionReport,
    CrossBoundaryEvidenceRef, CrossKernelContinuation, GovernanceLadderActionClass,
    GovernanceLadderManifest, GovernanceLadderQuorum, LadderIntersection,
    LadderIntersectionActionClass, ReceiptLineageBundle, ReceiptLineageStatement,
    RuntimeAdmissionBundle, RuntimeAdmissionCheck, RuntimeAdmissionProfile, RuntimeAdmissionReport,
    RuntimeArtifactRetentionAction, RuntimeArtifactRetentionPlan, RuntimeArtifactRetentionProfile,
    RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry, RuntimeEvidenceSinkHealthReport,
    RuntimeOpsStatusReport, RuntimeOrchestrationPlan, RuntimeOrchestrationPlannedStep,
    RuntimeOrchestrationProfile, RuntimeOrchestrationResumePlan, RuntimeOrchestrationRunReport,
    RuntimeOrchestrationStatusReport, RuntimeOrchestrationStepState, RuntimePeerWeight,
    RuntimePeerWeights, RuntimePheromoneAdvisory, RuntimePheromonePolicy,
    RuntimePheromonePolicyDecision, RuntimePheromonePolicyRule, RuntimeProofArtifactDrift,
    RuntimeProofDrift, RuntimeProofDriftReport, RuntimeProofParityMismatch,
    RuntimeProofParityReport, RuntimeProofRegenerationInput, RuntimeProofRegenerationReport,
    RuntimeProofSourceRecord, RuntimeProviderBinding, RuntimeProviderBindingsDocument,
    RuntimeProviderHealthCheck, RuntimeProviderHealthReport, RuntimeProviderLoadedWeightsEvidence,
    RuntimeRecoveryDrillReport, RuntimeRequestBinding, RuntimeRunContract, RuntimeRunLease,
    RuntimeSchedulerTickReport, RuntimeStepEvidence, RuntimeSupervisorProfile,
    RuntimeTrustFloorEntry, RuntimeTrustFloorState, RuntimeTrustedVerifierKey,
    RuntimeTrustedVerifierKeysDocument, RuntimeVerifierTrustBundleV4, RuntimeWorkflowRunReport,
    SignedRuntimeAdmissionReport, SignedRuntimePeerWeights, SignedRuntimePheromonePolicy,
    SignedRuntimePheromoneQueryReport, SignedRuntimeVerifierTrustBundle,
    TreatyRuntimeArtifactRecord, TreatyScope, WeightsBindingMode,
};
pub(crate) use validation::{ensure_sha256_hash, is_sha256_hex, rejected};
pub use validation::{
    validate_runtime_artifact_retention_plan, validate_runtime_artifact_retention_profile,
    validate_runtime_evidence_manifest, validate_runtime_evidence_sink_health_report,
    validate_runtime_ops_status_report, validate_runtime_orchestration_plan,
    validate_runtime_orchestration_profile, validate_runtime_orchestration_profile_fresh,
    validate_runtime_orchestration_resume_plan, validate_runtime_orchestration_run_report,
    validate_runtime_orchestration_status_report, validate_runtime_proof_drift_report,
    validate_runtime_proof_parity_report, validate_runtime_proof_regeneration_artifacts,
    validate_runtime_proof_regeneration_input, validate_runtime_proof_regeneration_report,
    validate_runtime_provider_bindings, validate_runtime_provider_health_report,
    validate_runtime_recovery_drill_report, validate_runtime_run_contract,
    validate_runtime_run_lease, validate_runtime_scheduler_tick_report,
    validate_runtime_supervisor_profile, validate_runtime_workflow_run_report,
    RuntimeProofRegenerationArtifacts,
};
