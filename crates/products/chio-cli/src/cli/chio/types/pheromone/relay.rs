use super::{
    ChioPheromoneRelayAlertCommands, ChioPheromoneRelayDirectoryCommands,
    ChioPheromoneRelaySupervisorCommands,
};
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioPheromoneRelayCommands {
    /// Lint a relay peer directory against an operational profile.
    Lint {
        /// Raw peer directory or signed peer-directory bundle JSON.
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "peer_directory_state"
        )]
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
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "peer_directory_state"
        )]
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

        /// Verified Chio proof package JSON.
        #[arg(long, value_name = "PATH")]
        proof_package: PathBuf,

        /// Verifier-owned Chio trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Chio verification context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Directory for per-request relay reports.
        #[arg(long, value_name = "DIR")]
        report_dir: PathBuf,

        /// Environment variable containing the operator token for observability endpoints.
        #[arg(long, value_name = "ENV")]
        operator_token_env: Option<String>,

        /// Mount the iroh federation-transport mesh alongside the HTTP relay (DUAL).
        /// OFF by default: with it off the serve path is byte-for-byte unchanged.
        #[arg(long, default_value_t = false)]
        iroh_enable: bool,

        /// Issuer-signed iroh transport-directory bundle JSON. Required with
        /// --iroh-enable; verified fail-closed against --trusted-issuers.
        #[arg(long, value_name = "PATH")]
        iroh_transport_directory: Option<PathBuf>,

        /// Optional rotation-state pin ({ "versionFloor": N,
        /// "expectedPreviousVersionSha256": ".." }) for the transport-directory
        /// bundle. Without it only a GENESIS bundle loads (floor 0, no
        /// predecessor); a rotated successor bundle needs this to pin the rollback
        /// floor and the predecessor hash it must chain onto.
        #[arg(long, value_name = "PATH")]
        iroh_transport_directory_state: Option<PathBuf>,

        /// Dedicated rotatable ed25519 transport key file ({ "seedHex": ".." }),
        /// SEPARATE from the passport/relay signing key. Required with --iroh-enable.
        #[arg(long, value_name = "PATH")]
        iroh_transport_key: Option<PathBuf>,

        /// Socket address the iroh endpoint binds. Default 0.0.0.0:0 (ephemeral
        /// port) is convenient for a quick DUAL trial, but a random port cannot be
        /// found by peers under the default RelayMode::Disabled. For a DURABLE
        /// deployment set a STABLE address here and pair it with a discovery
        /// mechanism / --iroh-relay-url so peers can reach a fixed EndpointId at a
        /// fixed address. The actual bound address(es) + EndpointId are logged at
        /// startup (tracing target "chio.iroh.transport").
        #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:0")]
        iroh_bind_addr: String,

        /// Self-hosted relay URL(s). Repeatable. Omitted -> RelayMode::Disabled
        /// (direct addressing; never the n0 free relays).
        #[arg(long, value_name = "URL")]
        iroh_relay_url: Vec<String>,

        /// Comma-separated iroh lanes to mount. Default: pheromone (the only lane
        /// that shares the relay receiver + store on this hook).
        #[arg(long, value_name = "LANES", default_value = "pheromone")]
        iroh_lanes: String,
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

        /// Verifier-owned Chio trust bundle that authorizes the signed transit policy issuer.
        #[arg(long, value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Verifier-owned peer directory JSON.
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "peer_directory_state"
        )]
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
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "peer_directory_state"
        )]
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

        /// Drain due batches over the iroh federation transport INSTEAD of HTTP for
        /// this tick (DUAL). OFF by default: with it off the tick delivers over HTTP
        /// exactly as before. A single tick drains over exactly one transport (an iroh
        /// tick and an HTTP tick would both lease the same outbox rows).
        #[arg(long, default_value_t = false)]
        iroh_enable: bool,

        /// Issuer-signed iroh transport-directory bundle JSON. Required with
        /// --iroh-enable; verified fail-closed against --trusted-issuers. Supplies the
        /// recipient kernel_id -> transport EndpointId resolution the drain dials.
        #[arg(long, value_name = "PATH")]
        iroh_transport_directory: Option<PathBuf>,

        /// Optional rotation-state pin ({ "versionFloor": N,
        /// "expectedPreviousVersionSha256": ".." }) for the transport-directory
        /// bundle. Without it only a GENESIS bundle loads (floor 0, no predecessor); a
        /// rotated successor bundle needs this to pin the rollback floor and the
        /// predecessor hash it must chain onto.
        #[arg(long, value_name = "PATH")]
        iroh_transport_directory_state: Option<PathBuf>,

        /// Dedicated rotatable ed25519 transport key file ({ "seedHex": ".." }),
        /// SEPARATE from the passport/relay signing key. Required with --iroh-enable.
        #[arg(long, value_name = "PATH")]
        iroh_transport_key: Option<PathBuf>,

        /// Socket address the outbound iroh endpoint binds. Default 0.0.0.0:0
        /// (ephemeral port); the drain only dials, so an ephemeral local port is fine.
        #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:0")]
        iroh_bind_addr: String,

        /// Self-hosted relay URL(s). Repeatable. Omitted -> RelayMode::Disabled
        /// (direct addressing; never the n0 free relays).
        #[arg(long, value_name = "URL")]
        iroh_relay_url: Vec<String>,

        /// Direct dialable socket address(es) for a recipient in the relay-disabled /
        /// direct-address deployment, as `KERNEL_ID=HOST:PORT`. Repeatable; repeat the
        /// same KERNEL_ID to add multiple sockets. The verified transport directory
        /// binds `kernel_id -> transport EndpointId` but carries NO socket address, so
        /// without discovery / --iroh-relay-url the drain cannot reach a peer known only
        /// by EndpointId + socket. Each entry threads its socket(s) onto the resolved
        /// EndpointId so the drain dials directly. The EndpointId binding still comes
        /// from the verified directory and iroh authenticates it at the handshake, so a
        /// wrong/hostile socket cannot redirect delivery to an unauthorized peer.
        #[arg(long, value_name = "KERNEL_ID=HOST:PORT")]
        iroh_peer_addr: Vec<String>,

        /// Comma-separated iroh lanes to drain. Default: pheromone (the only outbound
        /// lane on this hook).
        #[arg(long, value_name = "LANES", default_value = "pheromone")]
        iroh_lanes: String,
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
        command: ChioPheromoneRelayAlertCommands,
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
        command: ChioPheromoneRelayDirectoryCommands,
    },

    /// Validate local relay supervisor deployment profiles.
    Supervisor {
        #[command(subcommand)]
        command: ChioPheromoneRelaySupervisorCommands,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum RelayProfileArg {
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
pub(crate) enum RelayMetricsFormatArg {
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
