mod load;
mod model;
mod native_suite;
pub mod peers;
mod report;
mod runner;

pub use load::{load_results_from_dir, load_scenarios_from_dir, LoadError};
pub use model::{
    AssertionOutcome, AssertionResult, CompatibilityReport, DeploymentMode, PeerRole,
    RequiredCapabilities, ResultStatus, ScenarioCategory, ScenarioDescriptor, ScenarioResult,
    Transport,
};
pub use native_suite::{
    default_native_run_options, fixture_messages_for_request, load_native_scenarios_from_dir,
    run_native_conformance_suite, NativeConformanceRunOptions, NativeConformanceRunSummary,
    NativeDriver, NativeFixtureRequest, NativeFixtureResponse, NativeScenarioCategory,
    NativeScenarioDescriptor, NativeScenarioResult, NativeStatus, NativeSuiteError,
};
pub use peers::{
    default_peers_lock_path, sha256_hex, PeerEntry, PeersLock, PeersLockError, PEERS_LOCK_FILENAME,
    PEERS_LOCK_SCHEMA, SUPPORTED_LANGUAGES,
};
pub use report::generate_markdown_report;
pub use runner::{
    default_repo_root, default_run_options, run_conformance_harness, unique_run_dir,
    ConformanceAuthMode, ConformanceRunOptions, ConformanceRunSummary, PeerTarget, RunnerError,
};
