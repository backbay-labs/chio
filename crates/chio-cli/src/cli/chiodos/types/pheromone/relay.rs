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
