use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceCommands {
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
        command: ChioPheromoneRelayAlertAssuranceRetentionCommands,
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
        command: ChioPheromoneRelayAlertAssuranceArchiveCommands,
    },

    /// Review signed export bundles for operator-managed closeout.
    Closeout {
        #[command(subcommand)]
        command: ChioPheromoneRelayAlertAssuranceCloseoutCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceRetentionCommands {
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
    /// Review local-only retention handoff readiness evidence.
    Handoff {
        #[command(subcommand)]
        command: ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands,
    },

    /// Review local evidence for operator-managed external retention readiness.
    ExternalReview {
        /// Directory containing archive packages or archive package report JSON files.
        #[arg(long, value_name = "DIR")]
        package_dir: PathBuf,

        /// Directory containing source archive, closeout, restore, physical, and handoff reports.
        #[arg(long, value_name = "DIR")]
        source_report_dir: PathBuf,

        /// Trusted archive packager profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_packagers: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// External retention review profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Start of review window in Unix milliseconds.
        #[arg(long)]
        since_unix_ms: u64,

        /// End of review window in Unix milliseconds.
        #[arg(long)]
        until_unix_ms: u64,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for external retention review report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceArchiveCommands {
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
    /// Create, verify, or safely extract signed archive packages.
    Package {
        #[command(subcommand)]
        command: ChioPheromoneRelayAlertAssuranceArchivePackageCommands,
    },

    /// Review operator-managed physical archive readback evidence.
    PhysicalDrill {
        #[command(subcommand)]
        command: ChioPheromoneRelayAlertAssurancePhysicalDrillCommands,
    },

    /// Review multi-generation archive package restore evidence.
    RestoreDrill {
        #[command(subcommand)]
        command: ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceCloseoutCommands {
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
pub(crate) enum ChioPheromoneRelayAlertAssuranceArchivePackageCommands {
    /// Create a signed local tar.gz archive package from export bundles.
    Create {
        /// Directory containing export bundle directories.
        #[arg(long, value_name = "DIR")]
        bundle_root: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Source archive report JSON.
        #[arg(long, value_name = "PATH")]
        archive_report: PathBuf,

        /// Source closeout report JSON.
        #[arg(long, value_name = "PATH")]
        closeout_report: PathBuf,

        /// Local relay archive packager signing key JSON.
        #[arg(long, value_name = "PATH")]
        signing_key: PathBuf,

        /// Archive package id.
        #[arg(long, value_name = "ID")]
        package_id: String,

        /// Archive packager key id.
        #[arg(long, default_value = "default")]
        packager_key_id: String,

        /// Archive package generation.
        #[arg(long, default_value_t = 1)]
        package_generation: u64,

        /// Previous archive package report JSON. Required when generation is greater than 1.
        #[arg(long, value_name = "PATH")]
        previous_package_report: Option<PathBuf>,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output tar.gz package path.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,

        /// Output path for archive package report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a signed local tar.gz archive package without extracting it.
    Verify {
        /// Archive package tar.gz path.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,

        /// Trusted archive packager profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_packagers: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Source archive report JSON.
        #[arg(long, value_name = "PATH")]
        archive_report: PathBuf,

        /// Source closeout report JSON.
        #[arg(long, value_name = "PATH")]
        closeout_report: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for archive package report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify then safely extract a signed archive package into a new path.
    Extract {
        /// Archive package tar.gz path.
        #[arg(long, value_name = "PATH")]
        package: PathBuf,

        /// Trusted archive packager profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_packagers: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Source archive report JSON.
        #[arg(long, value_name = "PATH")]
        archive_report: PathBuf,

        /// Source closeout report JSON.
        #[arg(long, value_name = "PATH")]
        closeout_report: PathBuf,

        /// Fresh output directory. The path must not exist.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for archive extraction report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssurancePhysicalDrillCommands {
    /// Review local physical archive readback evidence without media claims.
    Review {
        /// Physical archive evidence JSON.
        #[arg(long, value_name = "PATH")]
        evidence: PathBuf,

        /// Expected archive package report JSON.
        #[arg(long, value_name = "PATH")]
        package_report: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for physical archive drill report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands {
    /// Review local archive package generations and readback evidence.
    Review {
        /// Directory containing archive package report JSON files.
        #[arg(long, value_name = "DIR")]
        package_dir: PathBuf,

        /// Directory containing physical drill and retention handoff reports.
        #[arg(long, value_name = "DIR")]
        source_report_dir: PathBuf,

        /// Trusted archive packager profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_packagers: PathBuf,

        /// Trusted exporter profile JSON.
        #[arg(long, value_name = "PATH")]
        trusted_exporters: PathBuf,

        /// Archive restore profile JSON.
        #[arg(long, value_name = "PATH")]
        restore_profile: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for archive restore drill report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands {
    /// Review local evidence that is ready for external retention handoff.
    Review {
        /// Retention handoff evidence JSON.
        #[arg(long, value_name = "PATH")]
        evidence: PathBuf,

        /// Retention handoff profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Expected archive package report JSON.
        #[arg(long, value_name = "PATH")]
        package_report: PathBuf,

        /// Evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for retention handoff report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}
