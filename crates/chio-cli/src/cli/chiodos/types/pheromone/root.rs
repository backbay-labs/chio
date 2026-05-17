use clap::Subcommand;
use std::path::PathBuf;
use super::{
    ChiodosPheromoneRelayCommands,
};


#[derive(Subcommand)]
pub(crate) enum ChiodosPheromoneCommands {
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
