use super::*;

#[derive(Subcommand)]
pub(crate) enum ChiodosPheromoneRelayDirectoryCommands {
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
pub(crate) enum ChiodosPheromoneRelaySupervisorCommands {
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
