use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioRuntimeCommands {
    /// Evaluate a runtime admission request against verifier-owned local state.
    Admit {
        /// Stable request binding JSON.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,

        /// Runtime admission profile JSON.
        #[arg(long = "admission-profile", value_name = "PATH")]
        admission_profile: PathBuf,

        /// Runtime admission bundle JSON to pin into local admission state.
        #[arg(long = "admission-bundle", value_name = "PATH")]
        admission_bundle: PathBuf,

        /// Signed strict runtime trust input JSON.
        #[arg(long = "runtime-trust-input", value_name = "PATH")]
        runtime_trust_input: Option<PathBuf>,

        /// Caller-supplied trusted verifier keys JSON.
        #[arg(long = "trusted-verifiers", value_name = "PATH")]
        trusted_verifiers: Option<PathBuf>,

        /// Signed pheromone query report to record as observe-only advice.
        #[arg(long = "pheromone-query-report", value_name = "PATH")]
        pheromone_query_report: Option<PathBuf>,

        /// Signed verifier-owned runtime pheromone policy JSON.
        #[arg(long = "runtime-pheromone-policy", value_name = "PATH")]
        runtime_pheromone_policy: Option<PathBuf>,

        /// Signed verifier-owned runtime peer weights JSON.
        #[arg(long = "runtime-peer-weights", value_name = "PATH")]
        runtime_peer_weights: Option<PathBuf>,

        /// Treaty or governance action class id used for runtime policy matching.
        #[arg(long = "action-class-id", value_name = "ACTION_CLASS_ID")]
        action_class_id: Option<String>,

        /// Durable trust-floor state path. Uses --store when omitted.
        #[arg(long = "trust-floor-state", value_name = "PATH")]
        trust_floor_state: Option<PathBuf>,

        /// Durable local admission store JSON.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Admission evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for runtime admission report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Sign a strict runtime trust input from verifier-owned local material.
    SignTrustInput {
        /// Runtime trust input body JSON.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,

        /// Hex-encoded 32-byte Ed25519 signing seed file.
        #[arg(long = "signing-seed-file", value_name = "PATH")]
        signing_seed_file: PathBuf,

        /// Output path for signed runtime trust input JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Sign verifier-owned runtime pheromone policy material.
    Policy {
        #[command(subcommand)]
        command: ChioRuntimePolicyCommands,
    },

    /// Sign verifier-owned runtime peer weights material.
    PeerWeights {
        #[command(subcommand)]
        command: ChioRuntimePeerWeightsCommands,
    },

    /// Evaluate runtime pheromone policy without mutating admission state.
    Pheromone {
        #[command(subcommand)]
        command: ChioRuntimePheromoneCommands,
    },

    /// Run production local Chio runtime orchestration checks.
    Orchestrate {
        #[command(subcommand)]
        command: ChioRuntimeOrchestrateCommands,
    },

    /// Run local Chio runtime operations supervision checks.
    Ops {
        #[command(subcommand)]
        command: ChioRuntimeOpsCommands,
    },

    /// Generate a local loopback runtime scenario report.
    RunLoopback {
        /// Runtime loopback scenario JSON.
        #[arg(long, value_name = "PATH")]
        scenario: PathBuf,

        /// Static proof package used as the parity baseline.
        #[arg(
            long = "static-package",
            value_name = "PATH",
            requires = "static_report"
        )]
        static_package: Option<PathBuf>,

        /// Static verifier report used as the parity baseline.
        #[arg(
            long = "static-report",
            value_name = "PATH",
            requires = "static_package"
        )]
        static_report: Option<PathBuf>,

        /// Directory for local runtime stores.
        #[arg(long = "store-dir", value_name = "PATH")]
        store_dir: PathBuf,

        /// Scenario evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output directory for generated runtime evidence.
        #[arg(long = "out-dir", value_name = "PATH")]
        out_dir: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimeOpsCommands {
    /// Supervise local runtime operations and emit aggregate status.
    Supervise {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long = "provider-bindings", value_name = "PATH")]
        provider_bindings: Option<PathBuf>,

        #[arg(long)]
        now_unix_ms: u64,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Run one bounded local scheduler tick.
    Tick {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long = "owner-id")]
        owner_id: String,

        #[arg(long)]
        now_unix_ms: u64,

        #[arg(long = "max-runs")]
        max_runs: u64,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Summarize local runtime operations status.
    Status {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long = "provider-bindings", value_name = "PATH")]
        provider_bindings: Option<PathBuf>,

        #[arg(long)]
        now_unix_ms: Option<u64>,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Dry-run local recovery classification for a runtime run.
    RecoveryDrill {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long = "run-id")]
        run_id: String,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long)]
        now_unix_ms: u64,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify local runtime evidence sink health for one run.
    EvidenceHealth {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long = "run-id")]
        run_id: String,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long)]
        now_unix_ms: Option<u64>,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify static local provider bindings.
    ProviderHealth {
        #[arg(long = "supervisor-profile", value_name = "PATH")]
        supervisor_profile: PathBuf,

        #[arg(long = "provider-bindings", value_name = "PATH")]
        provider_bindings: PathBuf,

        #[arg(long)]
        now_unix_ms: Option<u64>,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Plan runtime artifact retention without mutating evidence.
    Retention {
        #[command(subcommand)]
        command: ChioRuntimeOpsRetentionCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimeOpsRetentionCommands {
    /// Plan dry-run runtime artifact retention.
    Plan {
        #[arg(long = "retention-profile", value_name = "PATH")]
        retention_profile: PathBuf,

        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        #[arg(long = "evidence-root", value_name = "DIR")]
        evidence_root: PathBuf,

        #[arg(long)]
        now_unix_ms: u64,

        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimeOrchestrateCommands {
    /// Validate a runtime orchestration profile.
    Lint {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Output path for schema-valid status report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Build a local runtime orchestration plan.
    Plan {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Runtime run contract JSON.
        #[arg(long = "run-contract", value_name = "PATH")]
        run_contract: PathBuf,

        /// SQLite runtime orchestration store path.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Runtime evidence directory.
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,

        /// Plan time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for orchestration plan JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Record a local runtime orchestration run from verifier-accepted evidence.
    Run {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Runtime run contract JSON.
        #[arg(long = "run-contract", value_name = "PATH")]
        run_contract: PathBuf,

        /// SQLite runtime orchestration store path.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Runtime evidence directory produced by run-loopback.
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,

        /// Run time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for orchestration run report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Build a local runtime orchestration resume plan.
    Resume {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Runtime orchestration resume plan input JSON.
        #[arg(long = "resume-plan", value_name = "PATH")]
        resume_plan: PathBuf,

        /// SQLite runtime orchestration store path.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Runtime evidence directory.
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,

        /// Resume time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for resolved resume plan JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Summarize local runtime orchestration state.
    Status {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// SQLite runtime orchestration store path.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Runtime evidence directory.
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,

        /// Status time in Unix milliseconds. Defaults to current wall time.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Output path for status report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Compare repeated local runtime proof regeneration outputs.
    Drift {
        /// Runtime orchestration profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Directory containing per-run runtime evidence directories.
        #[arg(long = "runs-dir", value_name = "DIR")]
        runs_dir: PathBuf,

        /// Inclusive lower time bound in Unix milliseconds.
        #[arg(long)]
        since_unix_ms: u64,

        /// Inclusive upper time bound in Unix milliseconds.
        #[arg(long)]
        until_unix_ms: u64,

        /// Output path for proof drift report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimePolicyCommands {
    /// Sign a runtime pheromone policy body.
    Sign {
        /// Runtime pheromone policy body JSON.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,

        /// Hex-encoded 32-byte Ed25519 signing seed file.
        #[arg(long = "signing-seed-file", value_name = "PATH")]
        signing_seed_file: PathBuf,

        /// Output path for signed runtime pheromone policy JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimePeerWeightsCommands {
    /// Compute the canonical hash of a runtime peer weights body.
    Hash {
        /// Runtime peer weights body JSON.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,

        /// Output path for the canonical hash.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Sign a runtime peer weights body.
    Sign {
        /// Runtime peer weights body JSON.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,

        /// Hex-encoded 32-byte Ed25519 signing seed file.
        #[arg(long = "signing-seed-file", value_name = "PATH")]
        signing_seed_file: PathBuf,

        /// Output path for signed runtime peer weights JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimePheromoneCommands {
    /// Sign a pheromone query report for runtime admission.
    SignQueryReport {
        /// Pheromone query report body JSON.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,

        /// Hex seed file for the verifier signing key.
        #[arg(long = "signing-seed-file", value_name = "PATH")]
        signing_seed_file: PathBuf,

        /// Output path for signed pheromone query report JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Evaluate a signed runtime pheromone policy over a query report.
    Evaluate {
        /// Runtime admission bundle JSON for request binding.
        #[arg(long = "admission-bundle", value_name = "PATH")]
        admission_bundle: PathBuf,

        /// Signed strict runtime trust input JSON.
        #[arg(long = "runtime-trust-input", value_name = "PATH")]
        runtime_trust_input: PathBuf,

        /// Caller-supplied trusted verifier keys JSON.
        #[arg(long = "trusted-verifiers", value_name = "PATH")]
        trusted_verifiers: PathBuf,

        /// Signed pheromone query report JSON.
        #[arg(long = "pheromone-query-report", value_name = "PATH")]
        pheromone_query_report: PathBuf,

        /// Signed verifier-owned runtime pheromone policy JSON.
        #[arg(long = "runtime-pheromone-policy", value_name = "PATH")]
        runtime_pheromone_policy: PathBuf,

        /// Signed verifier-owned runtime peer weights JSON.
        #[arg(long = "runtime-peer-weights", value_name = "PATH")]
        runtime_peer_weights: PathBuf,

        /// Treaty or governance action class id used for runtime policy matching.
        #[arg(long = "action-class-id", value_name = "ACTION_CLASS_ID")]
        action_class_id: Option<String>,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for policy decision JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}
