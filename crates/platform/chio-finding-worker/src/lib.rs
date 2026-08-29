//! Firecracker-isolated execution for hosted cognition-market jobs.
//!
//! The worker stages immutable, digest-pinned guest assets into a unique jail,
//! starts Firecracker only through its jailer, and exchanges bounded canonical
//! JSON frames over virtio-vsock. No guest network interface is configured.

#![cfg(target_os = "linux")]

mod executor;
mod protocol;
mod service;

pub use executor::{
    FirecrackerExecutionResult, FirecrackerExecutor, FirecrackerIdentity, FirecrackerWorkerConfig,
    WorkerExecutionError,
};
pub use protocol::{
    sign_job_capability, verify_attested_result, verify_job_capability, FindingWorkerArtifact,
    FindingWorkerAttestedResult, FindingWorkerCapabilityBody, FindingWorkerDiagnostic,
    FindingWorkerExitClassification, FindingWorkerInputDescriptor, FindingWorkerInputEnd,
    FindingWorkerInputKind, FindingWorkerJobPayload, FindingWorkerJobSpec, FindingWorkerRepository,
    FindingWorkerRepositoryKind, FindingWorkerRequest, FindingWorkerResourceLimits,
    FindingWorkerResourceUsage, FindingWorkerResult, SignedFindingWorkerCapability,
    SignedFindingWorkerResult, FINDING_WORKER_ATTESTED_RESULT_SCHEMA,
    FINDING_WORKER_CAPABILITY_SCHEMA, FINDING_WORKER_INPUT_END_SCHEMA, FINDING_WORKER_INPUT_SCHEMA,
    FINDING_WORKER_JOB_SCHEMA, FINDING_WORKER_REQUEST_SCHEMA, FINDING_WORKER_RESULT_SCHEMA,
};
pub use service::{
    HostedFindingWorker, HostedWorkerJobEvidence, HostedWorkerRun, HostedWorkerServiceError,
};
