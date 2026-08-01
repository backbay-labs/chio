//! Chio runtime admission and orchestration boundary.
//!
//! Facade over `chio-runtime-core`. It intentionally exposes only the
//! runtime admission, trust-floor, orchestration, operations, and
//! proof-regeneration APIs needed by Chio runtime callers.

#![forbid(unsafe_code)]

use std::{fmt, path::Path};

mod stores;

use stores::RuntimeCoreAdmissionStoreAdapter;
pub use stores::{
    ChioRuntimeAdmissionStore, ChioRuntimeTrustFloorStore, InMemoryRuntimeAdmissionStore,
    JsonRuntimeAdmissionStore, JsonRuntimeTrustFloorStateStore, LayeredRuntimeAdmissionStore,
    SqliteRuntimeOrchestrationStore,
};

pub type RuntimeAdmissionBundle = chio_runtime_core::RuntimeAdmissionBundle;
pub type RuntimeAdmissionCheck = chio_runtime_core::RuntimeAdmissionCheck;
pub type RuntimeAdmissionProfile = chio_runtime_core::RuntimeAdmissionProfile;
pub type RuntimeAdmissionReport = chio_runtime_core::RuntimeAdmissionReport;
pub type RuntimeArtifactRetentionAction = chio_runtime_core::RuntimeArtifactRetentionAction;
pub type RuntimeArtifactRetentionPlan = chio_runtime_core::RuntimeArtifactRetentionPlan;
pub type RuntimeArtifactRetentionProfile = chio_runtime_core::RuntimeArtifactRetentionProfile;
pub type RuntimeEvidenceManifest = chio_runtime_core::RuntimeEvidenceManifest;
pub type RuntimeEvidenceManifestEntry = chio_runtime_core::RuntimeEvidenceManifestEntry;
pub type RuntimeEvidenceSinkHealthReport = chio_runtime_core::RuntimeEvidenceSinkHealthReport;
pub type RuntimeOpsStatusReport = chio_runtime_core::RuntimeOpsStatusReport;
pub type RuntimeOrchestrationEvidence = chio_runtime_core::RuntimeOrchestrationEvidence;
pub type RuntimeOrchestrationEvidenceFailure =
    chio_runtime_core::RuntimeOrchestrationEvidenceFailure;
pub type RuntimeOrchestrationPlan = chio_runtime_core::RuntimeOrchestrationPlan;
pub type RuntimeOrchestrationPlannedStep = chio_runtime_core::RuntimeOrchestrationPlannedStep;
pub type RuntimeOrchestrationProfile = chio_runtime_core::RuntimeOrchestrationProfile;
pub type RuntimeOrchestrationResumePlan = chio_runtime_core::RuntimeOrchestrationResumePlan;
pub type RuntimeOrchestrationRunReport = chio_runtime_core::RuntimeOrchestrationRunReport;
pub type RuntimeOrchestrationStatusReport = chio_runtime_core::RuntimeOrchestrationStatusReport;
pub type RuntimeOrchestrationStepState = chio_runtime_core::RuntimeOrchestrationStepState;
pub type RuntimePeerWeight = chio_runtime_core::RuntimePeerWeight;
pub type RuntimePeerWeights = chio_runtime_core::RuntimePeerWeights;
pub type RuntimePheromoneAdvisory = chio_runtime_core::RuntimePheromoneAdvisory;
pub type RuntimePheromonePolicy = chio_runtime_core::RuntimePheromonePolicy;
pub type RuntimePheromonePolicyDecision = chio_runtime_core::RuntimePheromonePolicyDecision;
pub type RuntimePheromonePolicyRule = chio_runtime_core::RuntimePheromonePolicyRule;
pub type RuntimeProofArtifactDrift = chio_runtime_core::RuntimeProofArtifactDrift;
pub type RuntimeProofDrift = chio_runtime_core::RuntimeProofDrift;
pub type RuntimeProofDriftReport = chio_runtime_core::RuntimeProofDriftReport;
pub type RuntimeProofParityMismatch = chio_runtime_core::RuntimeProofParityMismatch;
pub type RuntimeProofParityReport = chio_runtime_core::RuntimeProofParityReport;
pub type RuntimeProofRegenerationInput = chio_runtime_core::RuntimeProofRegenerationInput;
pub type RuntimeProofRegenerationReport = chio_runtime_core::RuntimeProofRegenerationReport;
pub type RuntimeProofSourceRecord = chio_runtime_core::RuntimeProofSourceRecord;
pub type RuntimeProviderBinding = chio_runtime_core::RuntimeProviderBinding;
pub type RuntimeProviderBindingsDocument = chio_runtime_core::RuntimeProviderBindingsDocument;
pub type RuntimeProviderHealthCheck = chio_runtime_core::RuntimeProviderHealthCheck;
pub type RuntimeProviderHealthReport = chio_runtime_core::RuntimeProviderHealthReport;
pub type RuntimeProviderLoadedWeightsEvidence =
    chio_runtime_core::RuntimeProviderLoadedWeightsEvidence;
pub type RuntimeRecoveryDrillReport = chio_runtime_core::RuntimeRecoveryDrillReport;
pub type RuntimeRequestBinding = chio_runtime_core::RuntimeRequestBinding;
pub type RuntimeRunContract = chio_runtime_core::RuntimeRunContract;
pub type RuntimeRunLease = chio_runtime_core::RuntimeRunLease;
pub type RuntimeSchedulerTickReport = chio_runtime_core::RuntimeSchedulerTickReport;
pub type RuntimeStepEvidence = chio_runtime_core::RuntimeStepEvidence;
pub type RuntimeSupervisorProfile = chio_runtime_core::RuntimeSupervisorProfile;
pub type RuntimeTrustFloorEntry = chio_runtime_core::RuntimeTrustFloorEntry;
pub type RuntimeTrustFloorState = chio_runtime_core::RuntimeTrustFloorState;
pub type RuntimeTrustedVerifierKey = chio_runtime_core::RuntimeTrustedVerifierKey;
pub type RuntimeTrustedVerifierKeysDocument = chio_runtime_core::RuntimeTrustedVerifierKeysDocument;
pub type RuntimeVerifierTrustBundleV4 = chio_runtime_core::RuntimeVerifierTrustBundleV4;
pub type RuntimeWorkflowRunReport = chio_runtime_core::RuntimeWorkflowRunReport;
pub type SignedRuntimeAdmissionReport = chio_runtime_core::SignedRuntimeAdmissionReport;
pub type SignedRuntimePeerWeights = chio_runtime_core::SignedRuntimePeerWeights;
pub type SignedRuntimePheromonePolicy = chio_runtime_core::SignedRuntimePheromonePolicy;
pub type SignedRuntimePheromoneQueryReport = chio_runtime_core::SignedRuntimePheromoneQueryReport;
pub type SignedRuntimeVerifierTrustBundle = chio_runtime_core::SignedRuntimeVerifierTrustBundle;
pub type SwarmAuthorityBundle = chio_swarm_authority::SwarmAuthorityBundle;
pub type TreatyRuntimeArtifactRecord = chio_runtime_core::TreatyRuntimeArtifactRecord;
pub type WeightsBindingMode = chio_runtime_core::WeightsBindingMode;

pub const CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA: &str = "chio.runtime.admission-profile.v1";
pub const CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA: &str = "chio.runtime.admission-bundle.v1";
pub const CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA: &str = "chio.runtime.verifier-trust-bundle.v1";
pub const CHIO_RUNTIME_ADMISSION_REPORT_SCHEMA: &str = "chio.runtime.admission-report.v1";
pub const CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA: &str = "chio.runtime.workflow-run-report.v1";
pub const CHIO_RUNTIME_STEP_EVIDENCE_SCHEMA: &str = "chio.runtime.step-evidence.v1";
pub const CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA: &str = "chio.runtime.evidence-manifest.v1";
pub const CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA: &str =
    "chio.runtime.proof-regeneration-input.v1";
pub const CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA: &str =
    "chio.runtime.proof-regeneration-report.v1";
pub const CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA: &str = "chio.runtime.proof-parity-report.v1";
pub const CHIO_RUNTIME_ADMISSION_STORE_SCHEMA: &str = "chio.runtime.admission-store.v1";
pub const CHIO_RUNTIME_TRUSTED_VERIFIERS_SCHEMA: &str = "chio.runtime.trusted-verifiers.v1";
pub const CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA: &str = "chio.runtime.pheromone-policy.v1";
pub const CHIO_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA: &str =
    "chio.runtime.pheromone-policy-decision.v1";
pub const CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA: &str = "chio.runtime.peer-weights.v1";
pub const CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA: &str = "chio.runtime.trust-floor-state.v1";
pub const CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA: &str = "chio.runtime.orchestration-plan.v1";
pub const CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA: &str = "chio.runtime.orchestration-profile.v1";
pub const CHIO_RUNTIME_RUN_CONTRACT_SCHEMA: &str = "chio.runtime.run-contract.v1";
pub const CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA: &str =
    "chio.runtime.orchestration-run-report.v1";
pub const CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA: &str =
    "chio.runtime.orchestration-resume-plan.v1";
pub const CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA: &str =
    "chio.runtime.orchestration-status-report.v1";
pub const CHIO_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA: &str = "chio.runtime.proof-drift-report.v1";
pub const CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA: &str = "chio.runtime.supervisor-profile.v1";
pub const CHIO_RUNTIME_RUN_LEASE_SCHEMA: &str = "chio.runtime.run-lease.v1";
pub const CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA: &str = "chio.runtime.scheduler-tick-report.v1";
pub const CHIO_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA: &str =
    "chio.runtime.evidence-sink-health-report.v1";
pub const CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA: &str = "chio.runtime.recovery-drill-report.v1";
pub const CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA: &str =
    "chio.runtime.artifact-retention-profile.v1";
pub const CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA: &str =
    "chio.runtime.artifact-retention-plan.v1";
pub const CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA: &str = "chio.runtime.provider-bindings.v1";
pub const CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA: &str =
    "chio.runtime.provider-health-report.v1";
pub const CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA: &str = "chio.runtime.ops-status-report.v1";

#[derive(Debug, Clone)]
pub struct ChioRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
    swarm_witness_keys: Vec<chio_core_types::PublicKey>,
    fixed_now_unix_ms: Option<u64>,
}

impl<S> ChioRuntimeAdmissionHook<S> {
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
            swarm_witness_keys: Vec::new(),
            fixed_now_unix_ms: None,
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

    #[must_use]
    pub fn with_swarm_witness_keys(
        mut self,
        witness_keys: Vec<chio_core_types::PublicKey>,
    ) -> Self {
        self.swarm_witness_keys = witness_keys;
        self
    }

    #[must_use]
    pub fn with_fixed_now_unix_ms(mut self, now_unix_ms: u64) -> Self {
        self.fixed_now_unix_ms = Some(now_unix_ms);
        self
    }

    fn core_hook(
        &self,
    ) -> chio_runtime_core::ChioRuntimeAdmissionHook<RuntimeCoreAdmissionStoreAdapter<'_>>
    where
        S: ChioRuntimeAdmissionStore,
    {
        let mut hook = chio_runtime_core::ChioRuntimeAdmissionHook::new(
            self.profile.clone(),
            RuntimeCoreAdmissionStoreAdapter { inner: &self.store },
        );
        if let Some(runtime_trust_input) = &self.runtime_trust_input {
            hook = hook.with_runtime_trust_input(
                runtime_trust_input.clone(),
                self.trusted_verifier_keys.clone(),
            );
        }
        if let Some(pheromone_query_report) = &self.pheromone_query_report {
            hook = hook.with_pheromone_query_report(pheromone_query_report.clone());
        }
        if let (Some(policy), Some(peer_weights)) =
            (&self.runtime_pheromone_policy, &self.runtime_peer_weights)
        {
            hook = hook.with_runtime_pheromone_policy(policy.clone(), peer_weights.clone());
        }
        hook = hook.with_swarm_witness_keys(self.swarm_witness_keys.clone());
        if let Some(now_unix_ms) = self.fixed_now_unix_ms {
            hook = hook.with_fixed_now_unix_ms(now_unix_ms);
        }
        hook
    }
}

impl<S> chio_kernel::RuntimeAdmissionHook for ChioRuntimeAdmissionHook<S>
where
    S: ChioRuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chio-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &chio_kernel::RuntimeAdmissionContext<'_>,
    ) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::evaluate(&self.core_hook(), context)
    }

    fn release_reserved(
        &self,
        metadata: &serde_json::Value,
    ) -> Result<(), chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::release_reserved(&self.core_hook(), metadata)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        chio_kernel::RuntimeAdmissionHook::requires_dispatch_revalidation(&self.core_hook())
    }

    fn revalidate_before_dispatch(
        &self,
        context: &chio_kernel::RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::revalidate_before_dispatch(&self.core_hook(), context)
    }
}

pub(crate) type RuntimeCoreError = chio_runtime_core::ChioRuntimeError;

/// Chio-owned runtime boundary error.
#[derive(Debug)]
pub struct ChioRuntimeError {
    code: &'static str,
    source: RuntimeCoreError,
}

impl ChioRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    fn from_runtime_core(source: RuntimeCoreError) -> Self {
        Self {
            code: source.code(),
            source,
        }
    }

    fn into_runtime_core(self) -> RuntimeCoreError {
        self.source
    }
}

impl fmt::Display for ChioRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for ChioRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) fn wrap_runtime<T>(result: Result<T, RuntimeCoreError>) -> Result<T, ChioRuntimeError> {
    result.map_err(ChioRuntimeError::from_runtime_core)
}

pub(crate) fn unwrap_runtime<T>(
    result: Result<T, ChioRuntimeError>,
) -> Result<T, RuntimeCoreError> {
    result.map_err(ChioRuntimeError::into_runtime_core)
}

pub struct ChioRuntimeAdmissionInput<'a> {
    pub profile: &'a RuntimeAdmissionProfile,
    pub store: &'a dyn ChioRuntimeAdmissionStore,
    pub admission_id: &'a str,
    pub request: &'a RuntimeRequestBinding,
    pub action_class_id: Option<&'a str>,
    pub runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    pub trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    pub pheromone_query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    pub runtime_pheromone_policy: Option<&'a SignedRuntimePheromonePolicy>,
    pub runtime_peer_weights: Option<&'a SignedRuntimePeerWeights>,
    pub now_unix_ms: u64,
}

pub fn evaluate_runtime_admission(
    input: ChioRuntimeAdmissionInput<'_>,
) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
    let store = RuntimeCoreAdmissionStoreAdapter { inner: input.store };
    wrap_runtime(chio_runtime_core::evaluate_runtime_admission(
        chio_runtime_core::RuntimeAdmissionInput {
            profile: input.profile,
            store: &store,
            admission_id: input.admission_id,
            request: input.request,
            action_class_id: input.action_class_id,
            runtime_trust_input: input.runtime_trust_input,
            trusted_verifier_keys: input.trusted_verifier_keys,
            pheromone_query_report: input.pheromone_query_report,
            runtime_pheromone_policy: input.runtime_pheromone_policy,
            runtime_peer_weights: input.runtime_peer_weights,
            now_unix_ms: input.now_unix_ms,
        },
    ))
}

pub fn runtime_admission_profile_from_json(
    json: &str,
) -> Result<RuntimeAdmissionProfile, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_admission_profile_from_json(json))
}

pub fn runtime_admission_bundle_from_json(
    json: &str,
) -> Result<RuntimeAdmissionBundle, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_admission_bundle_from_json(json))
}

pub fn runtime_request_binding_from_json(
    json: &str,
) -> Result<RuntimeRequestBinding, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_request_binding_from_json(json))
}

pub fn signed_runtime_verifier_trust_bundle_from_json(
    json: &str,
) -> Result<SignedRuntimeVerifierTrustBundle, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_verifier_trust_bundle_from_json(json))
}

pub fn runtime_trusted_verifier_keys_from_json(
    json: &str,
) -> Result<RuntimeTrustedVerifierKeysDocument, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_trusted_verifier_keys_from_json(
        json,
    ))
}

pub fn signed_runtime_pheromone_policy_from_json(
    json: &str,
) -> Result<SignedRuntimePheromonePolicy, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_pheromone_policy_from_json(json))
}

pub fn signed_runtime_peer_weights_from_json(
    json: &str,
) -> Result<SignedRuntimePeerWeights, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_peer_weights_from_json(
        json,
    ))
}

pub fn runtime_admission_report_json(
    report: &RuntimeAdmissionReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_admission_report_json(report))
}

pub fn sign_runtime_admission_report(
    report: RuntimeAdmissionReport,
    keypair: &chio_core_types::crypto::Keypair,
) -> Result<SignedRuntimeAdmissionReport, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::sign_runtime_admission_report(
        report, keypair,
    ))
}

pub fn signed_runtime_admission_report_from_json(
    json: &str,
) -> Result<SignedRuntimeAdmissionReport, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_admission_report_from_json(json))
}

pub fn signed_runtime_admission_report_json(
    report: &SignedRuntimeAdmissionReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_admission_report_json(
        report,
    ))
}

pub fn verify_signed_runtime_admission_report(
    report: &SignedRuntimeAdmissionReport,
) -> Result<bool, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::verify_signed_runtime_admission_report(
        report,
    ))
}

pub fn runtime_pheromone_advisory_from_query_report_json(
    json: &str,
) -> Result<RuntimePheromoneAdvisory, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_pheromone_advisory_from_query_report_json(json))
}

pub fn signed_runtime_pheromone_query_report_from_json(
    json: &str,
) -> Result<SignedRuntimePheromoneQueryReport, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_pheromone_query_report_from_json(json))
}

pub fn signed_runtime_pheromone_query_report_json(
    report: &SignedRuntimePheromoneQueryReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::signed_runtime_pheromone_query_report_json(report))
}

pub fn runtime_workflow_run_report_json(
    report: &RuntimeWorkflowRunReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_workflow_run_report_json(report))
}

pub fn runtime_proof_regeneration_report_json(
    report: &RuntimeProofRegenerationReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_proof_regeneration_report_json(
        report,
    ))
}

pub fn runtime_evidence_manifest_json(
    manifest: &RuntimeEvidenceManifest,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_evidence_manifest_json(manifest))
}

pub fn runtime_proof_regeneration_input_json(
    input: &RuntimeProofRegenerationInput,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_proof_regeneration_input_json(
        input,
    ))
}

pub fn runtime_proof_parity_report_json(
    report: &RuntimeProofParityReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_proof_parity_report_json(report))
}

pub fn runtime_orchestration_profile_from_json(
    json: &str,
) -> Result<RuntimeOrchestrationProfile, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_profile_from_json(
        json,
    ))
}

pub fn runtime_run_contract_from_json(json: &str) -> Result<RuntimeRunContract, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_run_contract_from_json(json))
}

pub fn runtime_supervisor_profile_from_json(
    json: &str,
) -> Result<RuntimeSupervisorProfile, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_supervisor_profile_from_json(
        json,
    ))
}

pub fn runtime_artifact_retention_profile_from_json(
    json: &str,
) -> Result<RuntimeArtifactRetentionProfile, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_artifact_retention_profile_from_json(json))
}

pub fn runtime_provider_bindings_from_json(
    json: &str,
) -> Result<RuntimeProviderBindingsDocument, ChioRuntimeError> {
    let document = wrap_runtime(chio_runtime_core::runtime_provider_bindings_from_json(json))?;
    validate_runtime_provider_bindings(&document)?;
    Ok(document)
}

pub fn runtime_orchestration_plan_json(
    plan: &RuntimeOrchestrationPlan,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_plan_json(plan))
}

pub fn runtime_orchestration_run_report_json(
    report: &RuntimeOrchestrationRunReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_run_report_json(
        report,
    ))
}

pub fn runtime_orchestration_resume_plan_json(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_resume_plan_json(
        plan,
    ))
}

pub fn runtime_orchestration_status_report_json(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_status_report_json(
        report,
    ))
}

pub fn runtime_proof_drift_report_json(
    report: &RuntimeProofDriftReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_proof_drift_report_json(report))
}

pub fn runtime_scheduler_tick_report_json(
    report: &RuntimeSchedulerTickReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_scheduler_tick_report_json(
        report,
    ))
}

pub fn runtime_evidence_sink_health_report_json(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_evidence_sink_health_report_json(
        report,
    ))
}

pub fn runtime_recovery_drill_report_json(
    report: &RuntimeRecoveryDrillReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_recovery_drill_report_json(
        report,
    ))
}

pub fn runtime_artifact_retention_plan_json(
    report: &RuntimeArtifactRetentionPlan,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_artifact_retention_plan_json(
        report,
    ))
}

pub fn runtime_provider_health_report_json(
    report: &RuntimeProviderHealthReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_provider_health_report_json(
        report,
    ))
}

pub fn runtime_ops_status_report_json(
    report: &RuntimeOpsStatusReport,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_ops_status_report_json(report))
}

pub fn runtime_orchestration_profile_sha256(
    profile: &RuntimeOrchestrationProfile,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_orchestration_profile_sha256(
        profile,
    ))
}

pub fn runtime_run_contract_sha256(
    contract: &RuntimeRunContract,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_run_contract_sha256(contract))
}

pub fn runtime_supervisor_profile_sha256(
    profile: &RuntimeSupervisorProfile,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_supervisor_profile_sha256(
        profile,
    ))
}

pub fn runtime_peer_weights_sha256(
    weights: &RuntimePeerWeights,
) -> Result<String, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::runtime_peer_weights_sha256(weights))
}

pub fn build_runtime_orchestration_plan(
    profile: &RuntimeOrchestrationProfile,
    contract: &RuntimeRunContract,
    now_unix_ms: u64,
) -> Result<RuntimeOrchestrationPlan, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::build_runtime_orchestration_plan(
        profile,
        contract,
        now_unix_ms,
    ))
}

pub fn generate_runtime_proof_drift_report(
    baseline_manifest: &RuntimeEvidenceManifest,
    candidate_manifest: &RuntimeEvidenceManifest,
    baseline_proof: &RuntimeProofRegenerationReport,
    candidate_proof: &RuntimeProofRegenerationReport,
    now_unix_ms: u64,
) -> Result<RuntimeProofDriftReport, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::generate_runtime_proof_drift_report(
        baseline_manifest,
        candidate_manifest,
        baseline_proof,
        candidate_proof,
        now_unix_ms,
    ))
}

pub fn generate_runtime_evidence_sink_health_report(
    run_id: &str,
    evidence_root: &Path,
    manifest: &RuntimeEvidenceManifest,
    required_roles: &[String],
    now_unix_ms: u64,
    perform_write_probe: bool,
) -> Result<RuntimeEvidenceSinkHealthReport, ChioRuntimeError> {
    wrap_runtime(
        chio_runtime_core::generate_runtime_evidence_sink_health_report(
            run_id,
            evidence_root,
            manifest,
            required_roles,
            now_unix_ms,
            perform_write_probe,
        ),
    )
}

pub fn generate_runtime_provider_health_report(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::generate_runtime_provider_health_report(
        profile,
        bindings,
        now_unix_ms,
    ))
}

pub fn generate_runtime_provider_health_report_with_model_cards(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    model_cards_by_id: &std::collections::BTreeMap<String, chio_weights::card::ModelCard>,
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    wrap_runtime(
        chio_runtime_core::generate_runtime_provider_health_report_with_model_cards(
            profile,
            bindings,
            model_cards_by_id,
            now_unix_ms,
        ),
    )
}

pub fn generate_runtime_provider_health_report_with_model_card_evidence(
    profile: &RuntimeSupervisorProfile,
    bindings: &RuntimeProviderBindingsDocument,
    model_cards_by_id: &std::collections::BTreeMap<String, chio_weights::card::ModelCard>,
    loaded_weights_evidence: &[RuntimeProviderLoadedWeightsEvidence],
    now_unix_ms: u64,
) -> Result<RuntimeProviderHealthReport, ChioRuntimeError> {
    wrap_runtime(
        chio_runtime_core::generate_runtime_provider_health_report_with_model_card_evidence(
            profile,
            bindings,
            model_cards_by_id,
            loaded_weights_evidence,
            now_unix_ms,
        ),
    )
}

pub fn generate_runtime_artifact_retention_plan(
    profile: &RuntimeArtifactRetentionProfile,
    run_ids: &[String],
    now_unix_ms: u64,
) -> Result<RuntimeArtifactRetentionPlan, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::generate_runtime_artifact_retention_plan(
        profile,
        run_ids,
        now_unix_ms,
    ))
}

pub fn load_runtime_orchestration_evidence(
    evidence_dir: &Path,
) -> Result<RuntimeOrchestrationEvidence, ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::load_runtime_orchestration_evidence(
        evidence_dir,
    ))
}

pub fn runtime_orchestration_evidence_sink_healthy(
    profile: &RuntimeOrchestrationProfile,
    evidence_dir: &Path,
    now_unix_ms: u64,
) -> Result<bool, ChioRuntimeError> {
    wrap_runtime(
        chio_runtime_core::runtime_orchestration_evidence_sink_healthy(
            profile,
            evidence_dir,
            now_unix_ms,
        ),
    )
}

#[must_use]
pub fn runtime_orchestration_evidence_is_fresh(
    profile: &RuntimeOrchestrationProfile,
    evidence: &RuntimeOrchestrationEvidence,
    now_unix_ms: u64,
) -> bool {
    chio_runtime_core::runtime_orchestration_evidence_is_fresh(profile, evidence, now_unix_ms)
}

pub fn validate_runtime_orchestration_evidence_binding(
    run_contract: &RuntimeRunContract,
    evidence: &RuntimeOrchestrationEvidence,
) -> Result<(), RuntimeOrchestrationEvidenceFailure> {
    chio_runtime_core::validate_runtime_orchestration_evidence_binding(run_contract, evidence)
}

pub fn validate_runtime_orchestration_evidence_integrity(
    evidence: &RuntimeOrchestrationEvidence,
) -> Result<(), RuntimeOrchestrationEvidenceFailure> {
    chio_runtime_core::validate_runtime_orchestration_evidence_integrity(evidence)
}

pub fn validate_runtime_evidence_sink_health_report(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_evidence_sink_health_report(report))
}

pub fn validate_runtime_workflow_run_report(
    report: &RuntimeWorkflowRunReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_workflow_run_report(
        report,
    ))
}

pub fn validate_runtime_evidence_manifest(
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_evidence_manifest(
        manifest,
    ))
}

pub fn validate_runtime_supervisor_profile(
    profile: &RuntimeSupervisorProfile,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_supervisor_profile(
        profile,
    ))
}

pub fn validate_runtime_run_lease(lease: &RuntimeRunLease) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_run_lease(lease))
}

pub fn validate_runtime_scheduler_tick_report(
    report: &RuntimeSchedulerTickReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_scheduler_tick_report(
        report,
    ))
}

pub fn validate_runtime_recovery_drill_report(
    report: &RuntimeRecoveryDrillReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_recovery_drill_report(
        report,
    ))
}

pub fn validate_runtime_artifact_retention_profile(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_artifact_retention_profile(profile))
}

pub fn validate_runtime_artifact_retention_plan(
    plan: &RuntimeArtifactRetentionPlan,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_artifact_retention_plan(
        plan,
    ))
}

pub fn validate_runtime_provider_bindings(
    document: &RuntimeProviderBindingsDocument,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_provider_bindings(
        document,
    ))
}

pub fn validate_runtime_provider_health_report(
    report: &RuntimeProviderHealthReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_provider_health_report(
        report,
    ))
}

pub fn validate_runtime_ops_status_report(
    report: &RuntimeOpsStatusReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_ops_status_report(
        report,
    ))
}

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_proof_drift_report(
        report,
    ))
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_proof_regeneration_input(input))
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_proof_regeneration_report(report))
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_proof_parity_report(
        report,
    ))
}

pub fn validate_runtime_orchestration_profile(
    profile: &RuntimeOrchestrationProfile,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_orchestration_profile(
        profile,
    ))
}

pub fn validate_runtime_orchestration_profile_fresh(
    profile: &RuntimeOrchestrationProfile,
    now_unix_ms: u64,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(
        chio_runtime_core::validate_runtime_orchestration_profile_fresh(profile, now_unix_ms),
    )
}

pub fn validate_runtime_run_contract(
    contract: &RuntimeRunContract,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_run_contract(contract))
}

pub fn validate_runtime_orchestration_plan(
    plan: &RuntimeOrchestrationPlan,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_orchestration_plan(plan))
}

pub fn validate_runtime_orchestration_run_report(
    report: &RuntimeOrchestrationRunReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_orchestration_run_report(report))
}

pub fn validate_runtime_orchestration_resume_plan(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_orchestration_resume_plan(plan))
}

pub fn validate_runtime_orchestration_status_report(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<(), ChioRuntimeError> {
    wrap_runtime(chio_runtime_core::validate_runtime_orchestration_status_report(report))
}
