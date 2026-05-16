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

