use super::*;

#[derive(Subcommand)]
pub(crate) enum ChiodosPheromoneRelayAlertDeliveryCommands {
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
