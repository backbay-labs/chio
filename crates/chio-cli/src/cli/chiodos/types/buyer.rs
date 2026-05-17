use clap::Subcommand;
use std::path::PathBuf;


#[derive(Subcommand)]
pub(crate) enum ChiodosBuyerCommands {
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

