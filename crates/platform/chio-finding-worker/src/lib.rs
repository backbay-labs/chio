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
    verify_attested_result, FindingWorkerAttestedResult, FindingWorkerRequest, FindingWorkerResult,
    FindingWorkerResultStatus, SignedFindingWorkerResult, FINDING_WORKER_ATTESTED_RESULT_SCHEMA,
    FINDING_WORKER_REQUEST_SCHEMA, FINDING_WORKER_RESULT_SCHEMA,
};
pub use service::{HostedFindingWorker, HostedWorkerRun, HostedWorkerServiceError};
