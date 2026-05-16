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
