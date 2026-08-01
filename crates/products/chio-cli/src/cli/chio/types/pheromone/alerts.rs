use super::{ChioPheromoneRelayAlertAssuranceCommands, ChioPheromoneRelayAlertDeliveryCommands};
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayAlertCommands {
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
        command: ChioPheromoneRelayAlertDeliveryCommands,
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
        command: ChioPheromoneRelayAlertAssuranceCommands,
    },
}
