use super::*;

/// Cognition-market finding surfaces: publish a canonical artifact to a
/// venue index, discover published artifacts, verify one against its
/// pinned evidence, and purchase a reveal.
#[derive(Subcommand)]
pub(crate) enum FindingCommands {
    /// Publish a canonical `chio.finding.v1` artifact to the venue index.
    Publish {
        /// Canonical artifact file. The bytes are sent verbatim; the venue
        /// rejects any spelling that is not the canonical serialization.
        #[arg(long)]
        file: PathBuf,
    },

    /// Search the venue descriptor index.
    Search {
        /// Topic prefix to match.
        #[arg(long)]
        topic_prefix: String,
        /// Optional exact context digest filter (64 lowercase hex characters).
        #[arg(long)]
        context_sha256: Option<String>,
        /// Resume after this finding id, using the cursor from a prior page.
        #[arg(long)]
        after: Option<String>,
        /// Maximum number of rows to request. The venue clamps its own bounds.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Verify a finding: strict canonical ingress first, then the pinned
    /// evidence facet report.
    Verify {
        /// Local artifact file to verify without contacting a venue.
        #[arg(long, conflicts_with = "id")]
        file: Option<PathBuf>,
        /// Finding id to fetch verbatim from the venue before verifying.
        #[arg(long)]
        id: Option<String>,
        /// Pinned verifier trust roots (governance authority, admitted
        /// verifier profile, admitted kernel keys, collateral authority).
        #[arg(long, conflicts_with = "integrity_only")]
        trust_roots: Option<PathBuf>,
        /// Resolved evidence bundle: receipts with inclusion proofs,
        /// checkpoints, and the collateral allocation snapshot.
        #[arg(long, conflicts_with = "integrity_only")]
        evidence: Option<PathBuf>,
        /// Raw replay-recipe preimage bytes the artifact commits to.
        #[arg(long, conflicts_with = "integrity_only")]
        recipe: Option<PathBuf>,
        /// Assert artifact integrity alone and name every facet left
        /// unevaluated instead of failing on absent evidence.
        #[arg(long, default_value_t = false)]
        integrity_only: bool,
    },

    /// Purchase a reveal of a published finding.
    Buy {
        /// Finding id to purchase.
        #[arg(long)]
        id: String,
        /// Maximum acceptable price in minor units of `--currency`.
        #[arg(long)]
        max_price: u64,
        /// Currency the price ceiling is denominated in.
        #[arg(long)]
        currency: String,
        /// Buyer principal the purchase context binds.
        #[arg(long)]
        payer: Option<String>,
        /// Seconds the buyer allows for delivery before the failed-delivery
        /// terminal applies.
        #[arg(long)]
        deadline_secs: Option<u64>,
    },
}
