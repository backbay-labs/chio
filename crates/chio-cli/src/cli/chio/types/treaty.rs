use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum ChioTreatyCommands {
    /// Compute a local ladder intersection from verifier-owned treaty inputs.
    Intersect {
        /// Treaty scope JSON.
        #[arg(long = "treaty-scope", value_name = "PATH")]
        treaty_scope: PathBuf,

        /// Governance ladder manifest JSON. Pass once per participant.
        #[arg(long = "manifest", value_name = "PATH")]
        manifest: Vec<PathBuf>,

        /// Intersection generation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for ladder intersection JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Evaluate treaty-bound cross-boundary admission evidence.
    Admit {
        /// Treaty scope JSON.
        #[arg(long = "treaty-scope", value_name = "PATH")]
        treaty_scope: PathBuf,

        /// Ladder intersection JSON.
        #[arg(long = "ladder-intersection", value_name = "PATH")]
        ladder_intersection: PathBuf,

        /// Expected ladder intersection SHA-256 from verifier-owned computation.
        #[arg(long = "expected-ladder-intersection-sha256")]
        expected_ladder_intersection_sha256: String,

        /// Action class id to admit.
        #[arg(long = "action-class-id")]
        action_class_id: String,

        /// Verified evidence ref as evidence_class=artifact_sha256. Pass once per item.
        #[arg(long = "evidence")]
        evidence: Vec<String>,

        /// Admission evaluation time in Unix milliseconds.
        #[arg(long)]
        now_unix_ms: u64,

        /// Output path for cross-boundary admission report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a buyer packet against receipt-lineage evidence.
    VerifyPacket {
        /// Buyer attestation packet JSON.
        #[arg(long, value_name = "PATH")]
        packet: PathBuf,

        /// Receipt lineage statement JSON.
        #[arg(long = "lineage-statement", value_name = "PATH")]
        lineage_statement: PathBuf,

        /// Cross-kernel continuation JSON.
        #[arg(long, value_name = "PATH")]
        continuation: PathBuf,

        /// Cross-boundary admission report JSON.
        #[arg(long = "admission-report", value_name = "PATH")]
        admission_report: PathBuf,

        /// Bilateral invocation JSON.
        #[arg(long = "bilateral-invocation", value_name = "PATH")]
        bilateral_invocation: PathBuf,

        /// Output path for buyer attestation verification report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },
}
