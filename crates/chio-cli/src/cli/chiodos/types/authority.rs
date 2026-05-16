use super::*;

#[derive(Subcommand)]
pub(crate) enum ChiodosAuthorityCommands {
    /// Issue capability leases, lease-scope bindings, and governance receipts.
    Issue {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Chiodos issuance request JSON.
        #[arg(long, value_name = "PATH")]
        request: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output directory for the issuance bundle and split artifacts.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// Publish a signed revocation checkpoint from local authority state.
    Checkpoint {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Revocation publication request JSON.
        #[arg(long, value_name = "PATH")]
        revocations: PathBuf,

        /// Local signing-key JSON. Keep this outside committed fixtures.
        #[arg(long, value_name = "PATH")]
        signing_keys: PathBuf,

        /// Output path for the signed checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Assemble verifier-owned trust inputs.
    TrustBundle {
        #[command(subcommand)]
        command: ChiodosTrustBundleCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChiodosTrustBundleCommands {
    /// Assemble a strict verifier trust bundle.
    Assemble {
        /// Public authority profile JSON.
        #[arg(long, value_name = "PATH")]
        profile: PathBuf,

        /// Verifier-owned peer, vendor, and action-class pins JSON.
        #[arg(long, value_name = "PATH")]
        peer_pins: PathBuf,

        /// Workflow intersection artifact JSON.
        #[arg(long, value_name = "PATH")]
        workflow_intersection: PathBuf,

        /// Disclosure policy JSON.
        #[arg(long, value_name = "PATH")]
        disclosure_policy: PathBuf,

        /// Signed revocation checkpoint JSON.
        #[arg(long, value_name = "PATH")]
        checkpoint: PathBuf,

        /// Output path for the verifier trust bundle JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}
