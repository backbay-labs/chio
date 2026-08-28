use super::*;

/// Cognition-market finding surfaces: publish a canonical artifact to a
/// venue index, discover published artifacts, verify one against its
/// pinned evidence, purchase a reveal, and open a dispute.
#[derive(Subcommand)]
pub(crate) enum FindingCommands {
    /// Initialize, serve, or reconcile a single-operator cognition market.
    Operator {
        #[command(subcommand)]
        command: FindingOperatorCommands,
    },

    /// Build a signed cognition-market package from ordinary development files.
    Package {
        #[command(subcommand)]
        command: FindingPackageCommands,
    },

    /// Admit a verified-fix draft through the running local operator.
    Admit {
        /// Strict canonical operator profile.
        #[arg(long)]
        profile: PathBuf,
        /// Draft emitted by `chio finding package verified-fix`.
        #[arg(long)]
        package: PathBuf,
    },

    /// Re-run the Rust reference verifier over a public proof bundle.
    VerifyBundle {
        /// Proof bundle file, or `-` for standard input.
        #[arg(long)]
        input: PathBuf,
        /// Strict canonical operator profile containing public deployment pins.
        #[arg(long)]
        profile: PathBuf,
        /// Exact canonical purchase request to bind to an optional result.
        #[arg(long, requires = "purchase_result")]
        purchase_request: Option<PathBuf>,
        /// Exact canonical purchase result whose signed terminal is verified.
        #[arg(long, requires = "purchase_request")]
        purchase_result: Option<PathBuf>,
    },

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
        /// verifier profile, admitted kernel keys, collateral authority, and
        /// optional status operator authorization and freshness policy).
        #[arg(long, conflicts_with = "integrity_only")]
        trust_roots: Option<PathBuf>,
        /// Resolved evidence bundle: receipts with inclusion proofs,
        /// checkpoints, the collateral allocation snapshot, and an optional
        /// exact canonical status proof encoded as base64.
        #[arg(long, conflicts_with = "integrity_only")]
        evidence: Option<PathBuf>,
        /// Raw replay-recipe preimage bytes the artifact commits to.
        #[arg(long, conflicts_with = "integrity_only")]
        recipe: Option<PathBuf>,
        /// Durable per-feed status rollback floor. Required whenever the
        /// evidence bundle carries a portable status proof. This may point to
        /// the same floor file used by `chio finding status`.
        #[arg(long, conflicts_with = "integrity_only")]
        status_rollback_floor: Option<PathBuf>,
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

    /// Inspect the venue-verified portable status proof for one finding.
    Status {
        /// Finding id whose current status proof should be fetched.
        #[arg(long)]
        id: String,
        /// Governance-pinned status feed configured by the venue.
        #[arg(long)]
        feed: String,
        /// Governance-pinned status operator authorization (strict canonical JSON).
        #[arg(long)]
        operator_authorization: PathBuf,
        /// Governance-pinned current status service bond (strict canonical JSON).
        #[arg(long)]
        service_bond: PathBuf,
        /// Durable rollback floor; retain its sibling `.retractions` directory.
        #[arg(long)]
        rollback_floor: PathBuf,
        /// Maximum accepted age of the signed status epoch in seconds.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        max_epoch_age_secs: u64,
    },

    /// Open a dispute against one admitted finding listing.
    ///
    /// Exactly one authorization branch and exactly one mechanical evidence
    /// class per challenge. A buyer submission carries a dispute fee, a
    /// dispute bond, and standing, and is signed by the challenger it names.
    /// A venue audit carries none of those and is signed by the venue's
    /// pinned audit authority, which this surface does not hold.
    Challenge {
        /// Finding id the challenge targets. The venue's stored artifact is
        /// fetched verbatim, re-derived through the strict ingress, and its
        /// exact digest is bound into the challenge.
        #[arg(long)]
        finding: String,

        /// Mechanical evidence class presented. Must name the same class as
        /// the evidence union the document carries; the closed
        /// guarantee/evidence compatibility matrix is checked against the
        /// fetched finding before anything is signed.
        #[arg(long, value_enum)]
        class: FindingChallengeClassArg,

        /// Challenge evidence document (JSON).
        ///
        /// Strict canonical I-JSON: the file bytes must be exactly their own
        /// canonical serialization, and every field is required. The document
        /// carries the operator-supplied half of the challenge; the fetched
        /// artifact supplies `schema`, `challenge_id`, `finding_id`, and
        /// `finding_artifact_sha256`. Every key below, at every depth, is in
        /// canonical order, which is the order the file must use.
        ///
        /// {
        ///   "affected_deliveries": [
        ///     {"checkpoint_ref": "...", "checkpoint_sha256": "<64 hex>",
        ///      "receipt_id": "...", "receipt_sha256": "<64 hex>"}
        ///   ],
        ///   "authorization": {"buyer_submission": {"challenger": "<64 hex>",
        ///     "dispute_fee_terminal": {...}, "dispute_lock_ref": {...},
        ///     "standing": {"failed_delivery": {...}}}}
        ///     | {"venue_audit": {"audit_epoch_envelope_sha256": "<64 hex>",
        ///        "authorization_digest": "<64 hex>",
        ///        "selection_digest": "<64 hex>"}},
        ///   "evidence": {"digest_mismatch": {"deny_checkpoint_ref": {...},
        ///        "deny_receipt_ref": {...},
        ///        "failed_delivery_envelope_sha256": "<64 hex>"}}
        ///     | {"evidence_invalid": {"challenged_checkpoint_ref": {...},
        ///        "challenged_evidence_receipt_refs": [...],
        ///        "purchase_record_envelope_sha256": "<64 hex>"}}
        ///     | {"replay_contradiction": {
        ///        "purchase_record_envelope_sha256": "<64 hex>",
        ///        "recipe_preimage": "<canonical recipe text>",
        ///        "reproduction": [...]}},
        ///   "filed_at": 1750000000,
        ///   "listing": {"backing_envelope_sha256": "<64 hex>",
        ///     "listing_id": "...",
        ///     "profile_envelope_sha256": "<64 hex>",
        ///     "terms_envelope_sha256": "<64 hex>",
        ///     "venue_admission_envelope_sha256": "<64 hex>"}
        /// }
        ///
        /// Both unions and every branch member use the registered
        /// `chio.finding.challenge.v1` spelling. Copy the `listing` block
        /// from the venue's current signed admission envelope.
        #[arg(long, verbatim_doc_comment)]
        evidence: PathBuf,

        /// Ed25519 seed file for the challenger the document names: 64 hex
        /// characters, optional `0x` prefix, surrounding whitespace ignored.
        /// Required for a buyer submission, because the signer must be that
        /// challenger. Refused for a venue audit, which carries no
        /// challenger at all.
        #[arg(long, conflicts_with = "venue_audit")]
        challenger_key: Option<PathBuf>,

        /// Build the bondless venue-audit branch. The document's
        /// authorization must be the matching branch, so a submission
        /// carrying a dispute fee or a dispute bond is refused rather than
        /// stripped.
        #[arg(long, default_value_t = false)]
        venue_audit: bool,

        /// Emit the canonical challenge, the signed envelope when one was
        /// produced, and their digests, without transmitting anything.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum FindingPackageCommands {
    /// Prove a failing baseline and passing candidate, then package their patch.
    VerifiedFix {
        /// Strict canonical operator profile.
        #[arg(long)]
        profile: PathBuf,
        /// Git repository containing both revisions.
        #[arg(long)]
        repository: PathBuf,
        /// Baseline commit or revision that must fail at least one test.
        #[arg(long)]
        base: String,
        /// Candidate commit or revision that must pass every test.
        #[arg(long)]
        candidate: String,
        /// Test command. Repeat this flag to run more than one command.
        #[arg(long = "test", required = true)]
        tests: Vec<String>,
        /// Finding topic used by market discovery.
        #[arg(long)]
        topic: String,
        /// Configured seller principal used to sign the Finding.
        #[arg(long, default_value = "coding-agent-seller")]
        seller: String,
        /// Listing price in USD minor units.
        #[arg(long, default_value_t = 300)]
        price: u64,
        /// Output path. Defaults to the profile's packages directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FindingOperatorCommands {
    /// Create a strict local operator profile and its durable stores.
    Init {
        /// New or empty deployment directory.
        #[arg(long)]
        directory: PathBuf,
        /// HTTP address for the operator service.
        #[arg(long, default_value = "127.0.0.1:7143")]
        listen: std::net::SocketAddr,
        /// Existing root containing every seller-accessible source repository.
        #[arg(long)]
        repository_root: PathBuf,
        /// Initial buyer principal installed in the profile.
        #[arg(long, default_value = "coding-agent-buyer")]
        buyer_principal: String,
        /// Canonical EVM destination used for initial buyer compensation.
        #[arg(long, default_value = "0x1111111111111111111111111111111111111111")]
        buyer_payout: String,
        /// Initial seller principal installed in the profile.
        #[arg(long, default_value = "coding-agent-seller")]
        seller_principal: String,
        /// Canonical EVM destination used for initial seller proceeds.
        #[arg(long, default_value = "0x2222222222222222222222222222222222222222")]
        seller_payout: String,
    },

    /// Run the production-composed purchase service from one profile.
    Serve {
        /// Strict canonical operator profile created by `operator init`.
        #[arg(long)]
        profile: PathBuf,
    },

    /// Reconcile durable operator work and print current health counters.
    Tick {
        /// Strict canonical operator profile created by `operator init`.
        #[arg(long)]
        profile: PathBuf,
    },

    /// Validate a hosted profile, its referenced files, and secret references.
    ValidateHosted {
        /// Strict canonical hosted operator profile.
        #[arg(long)]
        profile: PathBuf,
    },

    /// Evaluate a bounded hosted canary observation and fail on rollback.
    EvaluateCanary {
        /// Strict canonical hosted operator profile.
        #[arg(long)]
        profile: PathBuf,
        /// Strict canonical canary observation.
        #[arg(long)]
        observation: PathBuf,
    },
}

/// The mechanical evidence class a challenge presents, as an operator-facing
/// flag value. Naming it on the command line rather than inferring it from
/// the document makes a document that carries the wrong branch a refusal
/// instead of a silent reinterpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum FindingChallengeClassArg {
    DigestMismatch,
    EvidenceInvalid,
    ReplayContradiction,
}

impl FindingChallengeClassArg {
    pub(crate) fn kind(self) -> chio_finding::FindingChallengeEvidenceKind {
        match self {
            Self::DigestMismatch => chio_finding::FindingChallengeEvidenceKind::DigestMismatch,
            Self::EvidenceInvalid => chio_finding::FindingChallengeEvidenceKind::EvidenceInvalid,
            Self::ReplayContradiction => {
                chio_finding::FindingChallengeEvidenceKind::ReplayContradiction
            }
        }
    }
}
