#[derive(Subcommand)]
enum ChiodosCommands {
    /// Verify a buyer and auditor proof package and write a verifier report.
    Verify {
        /// Path to the proof package JSON.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,

        /// Path to the verifier-owned trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Path to the verifier context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Path where verifier report JSON should be written.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Produce local Chiodos authority artifacts for offline verification.
    Authority {
        #[command(subcommand)]
        command: ChiodosAuthorityCommands,
    },

    /// Evaluate local live-runtime Chiodos admission artifacts.
    Runtime {
        #[command(subcommand)]
        command: ChiodosRuntimeCommands,
    },

    /// Verify treaty-bound cross-kernel Chiodos provenance artifacts.
    Treaty {
        #[command(subcommand)]
        command: ChiodosTreatyCommands,
    },

    /// Package, verify, and explain buyer-facing Chiodos attestation evidence.
    Buyer {
        #[command(subcommand)]
        command: ChiodosBuyerCommands,
    },

    /// Receive and query local Chiodos pheromone artifacts.
    Pheromone {
        #[command(subcommand)]
        command: ChiodosPheromoneCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosBuyerCommands {
    /// Build a buyer review package from a local runtime output directory.
    Package {
        /// Runtime output directory containing buyer review artifacts.
        #[arg(long = "run-output", value_name = "DIR")]
        run_output: PathBuf,

        /// Output path for buyer attestation review package JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Verify a buyer review package against verifier-owned Chiodos inputs.
    Verify {
        /// Buyer attestation review package JSON.
        #[arg(long = "package", value_name = "PATH")]
        package: PathBuf,

        /// Verifier-owned Chiodos trust bundle JSON.
        #[arg(long = "trust-bundle", value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Chiodos verifier context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Output path for buyer attestation review report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Render a buyer review report as JSON or plain text.
    Explain {
        /// Buyer attestation review report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,

        /// Explanation format.
        #[arg(long, value_parser = ["json", "text"], default_value = "text")]
        format: String,

        /// Output path for explanation.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosTreatyCommands {
    /// Compute a local ladder intersection from verifier-owned treaty inputs.
    Intersect {
        /// Treaty scope JSON.
        #[arg(long = "treaty-scope", value_name = "PATH")]
        treaty_scope: PathBuf,

        /// Governance ladder manifest JSON. Pass once per participant.
        #[arg(long = "manifest", value_name = "PATH")]
        manifest: Vec<PathBuf>,

        /// Intersection generation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for ladder intersection JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Evaluate treaty-bound cross-boundary admission evidence.
    Admit {
        /// Treaty scope JSON.
        #[arg(long = "treaty-scope", value_name = "PATH")]
        treaty_scope: PathBuf,

        /// Ladder intersection JSON.
        #[arg(long = "ladder-intersection", value_name = "PATH")]
        ladder_intersection: PathBuf,

        /// Expected ladder intersection SHA-256 from verifier-owned computation.
        #[arg(long = "expected-ladder-intersection-sha256")]
        expected_ladder_intersection_sha256: String,

        /// Action class id to admit.
        #[arg(long = "action-class-id")]
        action_class_id: String,

        /// Verified evidence ref as evidence_class=artifact_sha256. Pass once per item.
        #[arg(long = "evidence")]
        evidence: Vec<String>,

        /// Admission evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for cross-boundary admission report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a buyer packet against receipt-lineage evidence.
    VerifyPacket {
        /// Buyer attestation packet JSON.
        #[arg(long, value_name = "PATH")]
        packet: PathBuf,

        /// Receipt lineage statement JSON.
        #[arg(long = "lineage-statement", value_name = "PATH")]
        lineage_statement: PathBuf,

        /// Cross-kernel continuation JSON.
        #[arg(long, value_name = "PATH")]
        continuation: PathBuf,

        /// Cross-boundary admission report JSON.
        #[arg(long = "admission-report", value_name = "PATH")]
        admission_report: PathBuf,

        /// Bilateral invocation JSON.
        #[arg(long = "bilateral-invocation", value_name = "PATH")]
        bilateral_invocation: PathBuf,

        /// Output path for buyer attestation verification report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosRuntimeCommands {
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
        command: ChiodosRuntimePolicyCommands,
    },

    /// Sign verifier-owned runtime peer weights material.
    PeerWeights {
        #[command(subcommand)]
        command: ChiodosRuntimePeerWeightsCommands,
    },

    /// Evaluate runtime pheromone policy without mutating admission state.
    Pheromone {
        #[command(subcommand)]
        command: ChiodosRuntimePheromoneCommands,
    },

    /// Run production local Chiodos runtime orchestration checks.
    Orchestrate {
        #[command(subcommand)]
        command: ChiodosRuntimeOrchestrateCommands,
    },

    /// Run local Chiodos runtime operations supervision checks.
    Ops {
        #[command(subcommand)]
        command: ChiodosRuntimeOpsCommands,
    },

    /// Generate a local loopback runtime scenario report.
    RunLoopback {
        /// Runtime loopback scenario JSON.
        #[arg(long, value_name = "PATH")]
        scenario: PathBuf,

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
enum ChiodosRuntimeOpsCommands {
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
        command: ChiodosRuntimeOpsRetentionCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosRuntimeOpsRetentionCommands {
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
enum ChiodosRuntimeOrchestrateCommands {
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
enum ChiodosRuntimePolicyCommands {
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
enum ChiodosRuntimePeerWeightsCommands {
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
enum ChiodosRuntimePheromoneCommands {
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

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for policy decision JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneCommands {
    /// Verify and store a local pheromone gossip batch.
    Receive {
        /// Pheromone gossip batch JSON.
        #[arg(long, value_name = "PATH")]
        batch: PathBuf,

        /// Local transit policy JSON with receiver admission material.
        #[arg(long, value_name = "PATH")]
        transit_policy: PathBuf,

        /// Verified Chiodos proof package JSON.
        #[arg(long, value_name = "PATH")]
        proof_package: PathBuf,

        /// Verifier-owned Chiodos trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Chiodos verification context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// SQLite store path for local pheromone state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Receiver evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Output path for receive report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Query local pheromone concentration from a durable store.
    Query {
        /// SQLite store path for local pheromone state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Subject class id.
        #[arg(long, value_name = "ID")]
        subject_class: String,

        /// Subject class namespace.
        #[arg(long, value_name = "NS")]
        namespace: String,

        /// Reputation epoch for advisory weighting.
        #[arg(long)]
        reputation_epoch: u64,

        /// Peer weights JSON.
        #[arg(long, value_name = "PATH")]
        peer_weights: PathBuf,

        /// Query evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Output path for query report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Run or inspect live pheromone relay state.
    Relay {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayCommands {
    /// Lint a relay peer directory against an operational profile.
    Lint {
        /// Raw peer directory or signed peer-directory bundle JSON.
        #[arg(long, value_name = "PATH", required_unless_present = "peer_directory_state")]
        peer_directory: Option<PathBuf>,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        peer_directory_state: Option<PathBuf>,

        /// Relay operational profile.
        #[arg(long, value_enum)]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config required for production bundles.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: Option<PathBuf>,

        /// Output path for lint report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Serve signed pheromone relay HTTP endpoints.
    Serve {
        /// Listen address for the relay HTTP service.
        #[arg(long, value_name = "ADDR")]
        listen: String,

        /// SQLite store path for runtime and relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Verifier-owned peer directory JSON.
        #[arg(long, value_name = "PATH", required_unless_present = "peer_directory_state")]
        peer_directory: Option<PathBuf>,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        peer_directory_state: Option<PathBuf>,

        /// Relay operational profile.
        #[arg(long, value_enum, default_value = "local-dev")]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config for signed bundles.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: Option<PathBuf>,

        /// Local transit policy JSON with receiver admission material.
        #[arg(long, value_name = "PATH")]
        transit_policy: PathBuf,

        /// Verified Chiodos proof package JSON.
        #[arg(long, value_name = "PATH")]
        proof_package: PathBuf,

        /// Verifier-owned Chiodos trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Chiodos verification context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Directory for per-request relay reports.
        #[arg(long, value_name = "DIR")]
        report_dir: PathBuf,

        /// Environment variable containing the operator token for observability endpoints.
        #[arg(long, value_name = "ENV")]
        operator_token_env: Option<String>,
    },

    /// Queue accepted local relay work for subscribed peers.
    Enqueue {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Pheromone gossip batch JSON to queue for a subscribed peer.
        #[arg(long, value_name = "PATH")]
        batch: PathBuf,

        /// Local transit policy JSON used to verify non-empty relay batches.
        #[arg(long = "transit-policy", value_name = "PATH")]
        transit_policy: PathBuf,

        /// Verifier-owned peer directory JSON.
        #[arg(long, value_name = "PATH", required_unless_present = "peer_directory_state")]
        peer_directory: Option<PathBuf>,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        peer_directory_state: Option<PathBuf>,

        /// Relay operational profile.
        #[arg(long, value_enum, default_value = "local-dev")]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config for signed bundles.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: Option<PathBuf>,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for enqueue report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Run one deterministic relay scheduler tick.
    Tick {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Verifier-owned peer directory JSON.
        #[arg(long, value_name = "PATH", required_unless_present = "peer_directory_state")]
        peer_directory: Option<PathBuf>,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        peer_directory_state: Option<PathBuf>,

        /// Relay operational profile.
        #[arg(long, value_enum, default_value = "local-dev")]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config for signed bundles.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: Option<PathBuf>,

        /// Evaluation time in Unix milliseconds. Defaults to the local clock.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Maximum batches to lease this tick.
        #[arg(long)]
        max_batches: usize,

        /// Local relay signing key JSON for the sender kernel.
        #[arg(long, value_name = "PATH")]
        signing_key: PathBuf,

        /// Output path for tick report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,

        /// Directory for bounded outbound delivery event reports.
        #[arg(long, value_name = "DIR")]
        report_dir: Option<PathBuf>,
    },

    /// Request bounded catch-up metadata from local relay state.
    Catchup {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Peer kernel id requesting catch-up.
        #[arg(long, value_name = "ID")]
        peer: String,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH", required = true)]
        peer_directory_state: Option<PathBuf>,

        /// Relay operational profile for state validation.
        #[arg(long, value_enum, default_value = "local-dev")]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config for signed active state.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: Option<PathBuf>,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Treaty id for the catch-up window.
        #[arg(long, value_name = "ID")]
        treaty: String,

        /// Cursor after which frames are requested.
        #[arg(long, value_name = "CURSOR")]
        after_cursor: String,

        /// Maximum frames to return.
        #[arg(long)]
        limit: usize,

        /// Output path for catch-up report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Write local relay operator status.
    Status {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Output path for status report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Write the relay observability report from durable local evidence.
    Observe {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Verifier-owned active peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        peer_directory_state: PathBuf,

        /// Relay operational profile.
        #[arg(long, value_enum)]
        profile: RelayProfileArg,

        /// Trusted peer-directory issuer config for signed active state.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: PathBuf,

        /// Directory containing bounded relay event reports.
        #[arg(long, value_name = "DIR")]
        report_dir: PathBuf,

        /// Maximum recent failure codes to include.
        #[arg(long, default_value_t = 25)]
        limit: usize,

        /// Output path for observability report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Export relay metrics from durable local state.
    Metrics {
        /// SQLite store path for relay state.
        #[arg(long, value_name = "PATH")]
        store: PathBuf,

        /// Output encoding for relay metrics.
        #[arg(
            long = "format",
            id = "relay_metrics_format",
            value_enum,
            default_value = "prometheus"
        )]
        format: RelayMetricsFormatArg,

        /// Output path for relay metrics.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },

    /// Evaluate relay alert routing from canonical observability artifacts.
    Alert {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertCommands,
    },

    /// Aggregate long-horizon relay operations trends from report artifacts.
    Trend {
        /// Directory containing relay observability reports.
        #[arg(long, value_name = "DIR")]
        reports_dir: PathBuf,

        /// Directory containing bounded relay event reports.
        #[arg(long, value_name = "DIR")]
        event_dir: PathBuf,

        /// Relay alert routing profile JSON.
        #[arg(long, value_name = "PATH")]
        routing_profile: PathBuf,

        /// Lower bound in Unix milliseconds.
        #[arg(long)]
        since_unix_ms: u64,

        /// Upper bound in Unix milliseconds.
        #[arg(long)]
        until_unix_ms: u64,

        /// Output path for relay trend report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Inspect, promote, or reject verifier-owned relay peer-directory state.
    Directory {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayDirectoryCommands,
    },

    /// Validate local relay supervisor deployment profiles.
    Supervisor {
        #[command(subcommand)]
        command: ChiodosPheromoneRelaySupervisorCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertCommands {
    /// Evaluate routeable relay alerts from current observability.
    Evaluate {
        /// Canonical relay observability report JSON.
        #[arg(long, value_name = "PATH")]
        observability_report: PathBuf,

        /// Directory containing bounded relay event reports.
        #[arg(long, value_name = "DIR")]
        event_dir: PathBuf,

        /// Relay alert routing profile JSON.
        #[arg(long, value_name = "PATH")]
        routing_profile: PathBuf,

        /// Relay alert suppression state JSON.
        #[arg(long, value_name = "PATH")]
        suppression_state: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Dry-run downstream relay alert handoff readiness.
    Handoff {
        /// Relay alert report JSON.
        #[arg(long, value_name = "PATH")]
        alert_report: PathBuf,

        /// Relay trend report JSON.
        #[arg(long, value_name = "PATH")]
        trend_report: PathBuf,

        /// Relay alert routing profile JSON.
        #[arg(long, value_name = "PATH")]
        routing_profile: PathBuf,

        /// Relay alert handoff profile JSON.
        #[arg(long, value_name = "PATH")]
        handoff_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Normalize local downstream alert exports into Chio delivery evidence.
    Normalize {
        /// Relay alert normalization profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Directory containing local downstream alert export JSON.
        #[arg(long, value_name = "DIR")]
        input_dir: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Directory for canonical Chio delivery evidence JSON.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Output path for relay alert normalization report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Import downstream delivery, acknowledgement, or drift evidence.
    Delivery {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertDeliveryCommands,
    },

    /// Generate route-owner review evidence.
    Review {
        /// Relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        handoff_report: PathBuf,

        /// Relay alert delivery report JSON.
        #[arg(long, value_name = "PATH")]
        delivery_report: PathBuf,

        /// Relay alert acknowledgement report JSON.
        #[arg(long, value_name = "PATH")]
        acknowledgement_report: PathBuf,

        /// Relay alert delivery drift report JSON.
        #[arg(long, value_name = "PATH")]
        drift_report: PathBuf,

        /// Relay alert route-owner profile JSON.
        #[arg(long, value_name = "PATH")]
        route_owner_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert route review packet JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Build relay alert assurance packages.
    Assurance {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertAssuranceCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertDeliveryCommands {
    /// Import local downstream delivery-result artifacts.
    Import {
        /// Relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        handoff_report: PathBuf,

        /// Relay alert delivery profile JSON.
        #[arg(long, value_name = "PATH")]
        delivery_profile: PathBuf,

        /// Directory containing local downstream delivery evidence JSON.
        #[arg(long, value_name = "DIR")]
        evidence_dir: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert delivery report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Summarize downstream acknowledgement evidence from a delivery report.
    Acknowledge {
        /// Relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        handoff_report: PathBuf,

        /// Relay alert delivery report JSON.
        #[arg(long, value_name = "PATH")]
        delivery_report: PathBuf,

        /// Relay alert delivery profile JSON.
        #[arg(long, value_name = "PATH")]
        delivery_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert acknowledgement report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Compare handoff and delivery report directories for bounded drift.
    Drift {
        /// Directory containing relay alert handoff reports.
        #[arg(long, value_name = "DIR")]
        handoff_reports_dir: PathBuf,

        /// Directory containing relay alert delivery reports.
        #[arg(long, value_name = "DIR")]
        delivery_reports_dir: PathBuf,

        /// Relay alert delivery profile JSON.
        #[arg(long, value_name = "PATH")]
        delivery_profile: PathBuf,

        /// Lower bound in Unix milliseconds.
        #[arg(long)]
        since_unix_ms: u64,

        /// Upper bound in Unix milliseconds.
        #[arg(long)]
        until_unix_ms: u64,

        /// Output path for relay alert handoff drift report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Compare handoff and delivery report directories with source-bound delivery drift.
    DriftWindow {
        /// Directory containing relay alert handoff reports.
        #[arg(long, value_name = "DIR")]
        handoff_reports_dir: PathBuf,

        /// Directory containing relay alert delivery reports.
        #[arg(long, value_name = "DIR")]
        delivery_reports_dir: PathBuf,

        /// Relay alert delivery profile JSON.
        #[arg(long, value_name = "PATH")]
        delivery_profile: PathBuf,

        /// Lower bound in Unix milliseconds.
        #[arg(long)]
        since_unix_ms: u64,

        /// Upper bound in Unix milliseconds.
        #[arg(long)]
        until_unix_ms: u64,

        /// Output path for source-bound relay alert delivery drift report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertAssuranceCommands {
    /// Bind alert evidence into one operator-safe assurance package.
    Package {
        /// Relay alert report JSON.
        #[arg(long, value_name = "PATH")]
        alert_report: PathBuf,

        /// Relay trend report JSON.
        #[arg(long, value_name = "PATH")]
        trend_report: PathBuf,

        /// Relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        handoff_report: PathBuf,

        /// Relay alert normalization report JSON.
        #[arg(long, value_name = "PATH")]
        normalization_report: PathBuf,

        /// Relay alert delivery report JSON.
        #[arg(long, value_name = "PATH")]
        delivery_report: PathBuf,

        /// Relay alert acknowledgement report JSON.
        #[arg(long, value_name = "PATH")]
        acknowledgement_report: PathBuf,

        /// Source-bound relay alert delivery drift report JSON.
        #[arg(long, value_name = "PATH")]
        drift_report: PathBuf,

        /// Relay alert route review packet JSON.
        #[arg(long, value_name = "PATH")]
        review_packet: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance package JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Export signed local alert assurance evidence.
    Export {
        /// Relay alert assurance package JSON.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,

        /// Relay alert report JSON.
        #[arg(long, value_name = "PATH")]
        alert_report: PathBuf,

        /// Relay trend report JSON.
        #[arg(long, value_name = "PATH")]
        trend_report: PathBuf,

        /// Relay alert handoff report JSON.
        #[arg(long, value_name = "PATH")]
        handoff_report: PathBuf,

        /// Relay alert normalization report JSON.
        #[arg(long, value_name = "PATH")]
        normalization_report: PathBuf,

        /// Relay alert delivery report JSON.
        #[arg(long, value_name = "PATH")]
        delivery_report: PathBuf,

        /// Relay alert acknowledgement report JSON.
        #[arg(long, value_name = "PATH")]
        acknowledgement_report: PathBuf,

        /// Source-bound relay alert delivery drift report JSON.
        #[arg(long, value_name = "PATH")]
        drift_report: PathBuf,

        /// Relay alert route review packet JSON.
        #[arg(long, value_name = "PATH")]
        review_packet: PathBuf,

        /// Relay alert assurance retention profile JSON.
        #[arg(long, value_name = "PATH")]
        retention_profile: PathBuf,

        /// Local relay export signing key JSON.
        #[arg(long, value_name = "PATH")]
        signing_key: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output bundle directory.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Output path for relay alert assurance export report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a signed local alert assurance export bundle.
    Verify {
        /// Export bundle directory.
        #[arg(long, value_name = "DIR")]
        bundle_dir: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance export report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Replay a signed local alert assurance export bundle.
    Replay {
        /// Export bundle directory.
        #[arg(long, value_name = "DIR")]
        bundle_dir: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance replay report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Plan retention for signed local alert assurance export bundles.
    Retention {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertAssuranceRetentionCommands,
    },

    /// Run offline recovery drills against an export bundle.
    RecoveryDrill {
        /// Export bundle directory.
        #[arg(long, value_name = "DIR")]
        bundle_dir: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Recovery case id or all.
        #[arg(long, value_name = "ID")]
        case: String,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance recovery drill report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Plan verifier-owned archive lifecycle over signed export bundles.
    Archive {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertAssuranceArchiveCommands,
    },

    /// Review signed export bundles for operator-managed closeout.
    Closeout {
        #[command(subcommand)]
        command: ChiodosPheromoneRelayAlertAssuranceCloseoutCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertAssuranceRetentionCommands {
    /// Plan retention over local export bundle directories without deleting evidence.
    Plan {
        /// Directory containing export bundle directories.
        #[arg(long, value_name = "DIR")]
        bundle_root: PathBuf,

        /// Relay alert assurance retention profile JSON.
        #[arg(long, value_name = "PATH")]
        retention_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance retention report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertAssuranceArchiveCommands {
    /// Plan archive lifecycle over local export bundle directories without moving evidence.
    Plan {
        /// Directory containing export bundle directories.
        #[arg(long, value_name = "DIR")]
        bundle_root: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Relay alert assurance archive profile JSON.
        #[arg(long, value_name = "PATH")]
        archive_profile: PathBuf,

        /// Relay alert assurance retention profile JSON.
        #[arg(long, value_name = "PATH")]
        retention_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance archive report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayAlertAssuranceCloseoutCommands {
    /// Review local export bundle directories for operator-managed closeout.
    Review {
        /// Directory containing export bundle directories.
        #[arg(long, value_name = "DIR")]
        bundle_root: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Relay alert assurance closeout profile JSON.
        #[arg(long, value_name = "PATH")]
        closeout_profile: PathBuf,

        /// Relay alert assurance retention profile JSON.
        #[arg(long, value_name = "PATH")]
        retention_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for relay alert assurance closeout report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelayDirectoryCommands {
    /// Inspect active peer-directory state.
    Inspect {
        /// Peer-directory state JSON.
        #[arg(long, value_name = "PATH")]
        state: PathBuf,

        /// Output path for inspection report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Promote a signed peer-directory candidate into active state.
    Promote {
        /// Peer-directory state JSON to update.
        #[arg(long, value_name = "PATH")]
        state: PathBuf,

        /// Signed peer-directory bundle candidate JSON.
        #[arg(long, value_name = "PATH")]
        candidate: PathBuf,

        /// Trusted peer-directory issuer config.
        #[arg(long, value_name = "PATH")]
        trusted_issuers: PathBuf,

        /// Relay operational profile.
        #[arg(long, value_enum)]
        profile: RelayProfileArg,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Output path for rotation report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Reject a signed peer-directory candidate without changing active state.
    Reject {
        /// Peer-directory state JSON to update.
        #[arg(long, value_name = "PATH")]
        state: PathBuf,

        /// Signed peer-directory bundle candidate JSON.
        #[arg(long, value_name = "PATH")]
        candidate: PathBuf,

        /// Stable rejection reason code.
        #[arg(long, value_name = "CODE")]
        reason: String,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: Option<u64>,

        /// Output path for rotation report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
enum ChiodosPheromoneRelaySupervisorCommands {
    /// Lint a relay supervisor deployment profile.
    Lint {
        /// Relay supervisor profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Output path for drill report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum RelayProfileArg {
    LocalDev,
    Production,
}

impl From<RelayProfileArg> for chio_pheromone_relay::RelayProfile {
    fn from(value: RelayProfileArg) -> Self {
        match value {
            RelayProfileArg::LocalDev => Self::LocalDev,
            RelayProfileArg::Production => Self::Production,
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum RelayMetricsFormatArg {
    Prometheus,
    Json,
}

impl From<RelayMetricsFormatArg> for chio_pheromone_relay::RelayMetricsFormat {
    fn from(value: RelayMetricsFormatArg) -> Self {
        match value {
            RelayMetricsFormatArg::Prometheus => Self::Prometheus,
            RelayMetricsFormatArg::Json => Self::Json,
        }
    }
}

#[derive(Subcommand)]
enum ChiodosAuthorityCommands {
    /// Issue capability leases, lease-scope bindings, and governance receipts.
    Issue {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Chiodos issuance request JSON.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output directory for the issuance bundle and split artifacts.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// Publish a signed revocation checkpoint from local authority state.
    Checkpoint {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Revocation publication request JSON.
        #[arg(long, value_name = "PATH")]
        revocations: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output path for the signed checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Assemble verifier-owned trust inputs.
    TrustBundle {
        #[command(subcommand)]
        command: ChiodosTrustBundleCommands,
    },
}

#[derive(Subcommand)]
enum ChiodosTrustBundleCommands {
    /// Assemble a strict verifier trust bundle.
    Assemble {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Verifier-owned peer, vendor, and action-class pins JSON.
        #[arg(long, value_name = "PATH")]
        peer_pins: PathBuf,

        /// Workflow intersection artifact JSON.
        #[arg(long, value_name = "PATH")]
        workflow_intersection: PathBuf,

        /// Disclosure policy JSON.
        #[arg(long, value_name = "PATH")]
        disclosure_policy: PathBuf,

        /// Signed revocation checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        checkpoint: PathBuf,

        /// Output path for the verifier trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}
