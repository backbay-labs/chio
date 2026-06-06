use super::*;

#[derive(Subcommand)]
pub(crate) enum PassportCommands {
    /// Synthesize a trust-tier-enriched Agent Passport for a named agent.
    ///
    /// Computes the agent's compliance score and behavioral
    /// anomaly, collapses them into a `TrustTier`, and emits
    /// a minimal passport JSON document with that tier populated.
    Generate {
        /// Agent identifier (DID or opaque subject) to stamp on the passport.
        #[arg(long)]
        agent: String,
        /// Optional output path for the passport JSON. When omitted, the
        /// passport is printed to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Compliance score override (0..=1000). Defaults to 1000 when
        /// omitted so that a freshly provisioned agent surfaces as
        /// `Premier` rather than `Unverified`.
        #[arg(long)]
        compliance_score: Option<u32>,
        /// When set, treats the agent as having an active behavioral
        /// anomaly and caps the synthesized tier below `Premier`.
        #[arg(long, default_value_t = false)]
        behavioral_anomaly: bool,
        /// Passport validity period in days.
        #[arg(long, default_value_t = 30)]
        validity_days: u32,
    },

    /// Create a single-issuer Agent Passport from local receipt and lineage data.
    Create {
        /// Subject Ed25519 public key in hex.
        #[arg(long)]
        subject_public_key: String,
        /// Output path for the passport JSON.
        #[arg(long)]
        output: PathBuf,
        /// Persistent seed file used to sign the embedded reputation credential.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// Passport validity period in days.
        #[arg(long, default_value_t = 30)]
        validity_days: u32,
        /// Optional lower bound for the attested receipt window, in Unix seconds.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper bound for the attested receipt window, in Unix seconds.
        #[arg(long)]
        until: Option<u64>,
        /// Optional receipt log service endpoint(s) to embed in attestation evidence.
        #[arg(long = "receipt-log-url")]
        receipt_log_urls: Vec<String>,
        /// Fail if any selected receipt lacks checkpoint coverage.
        #[arg(long, default_value_t = false)]
        require_checkpoints: bool,
        /// Optional enterprise identity context JSON to embed as portable provenance.
        #[arg(long)]
        enterprise_identity: Option<PathBuf>,
    },

    /// Verify a passport and every embedded credential without external glue code.
    Verify {
        /// Passport JSON file to verify.
        #[arg(long)]
        input: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Evaluate a passport against a relying-party verifier policy.
    Evaluate {
        /// Passport JSON file to evaluate.
        #[arg(long)]
        input: PathBuf,
        /// YAML or JSON verifier policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Produce a filtered presentation from an existing passport.
    Present {
        /// Input passport JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Output path for the presented passport JSON.
        #[arg(long)]
        output: PathBuf,
        /// Optional issuer DID allowlist. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuers: Vec<String>,
        /// Maximum number of credentials to include in the presentation.
        #[arg(long)]
        max_credentials: Option<usize>,
    },

    /// Create, verify, and manage signed verifier-policy artifacts.
    Policy {
        #[command(subcommand)]
        command: PassportPolicyCommands,
    },

    /// Create and verify challenge-bound passport presentations.
    Challenge {
        #[command(subcommand)]
        command: PassportChallengeCommands,
    },

    /// Publish, resolve, and revoke passport lifecycle state.
    Status {
        #[command(subcommand)]
        command: PassportStatusCommands,
    },

    /// Deliver Chio passports through an OID4VCI-style pre-authorized issuance flow.
    Issuance {
        #[command(subcommand)]
        command: PassportIssuanceCommands,
    },

    /// Create and consume Chio's narrow OID4VP verifier and holder interop flow.
    Oid4vp {
        #[command(subcommand)]
        command: PassportOid4vpCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassportChallengeCommands {
    /// Create a presentation challenge for a relying party.
    Create {
        /// Output path for the challenge JSON.
        #[arg(long)]
        output: PathBuf,
        /// Relying-party identifier or audience string.
        #[arg(long)]
        verifier: String,
        /// Challenge lifetime in seconds.
        #[arg(long, default_value_t = 300)]
        ttl_secs: u64,
        /// Optional issuer DID allowlist for selective disclosure. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuers: Vec<String>,
        /// Maximum number of credentials a holder may disclose.
        #[arg(long)]
        max_credentials: Option<usize>,
        /// Optional verifier policy to embed in the challenge.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Optional stored verifier policy ID to reference instead of embedding raw policy.
        #[arg(long)]
        policy_id: Option<String>,
        /// Optional verifier policy registry file used when resolving --policy-id locally.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
        /// Optional SQLite challenge-state database used for replay-safe local verification.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,
    },

    /// Respond to a presentation challenge using the passport subject key.
    Respond {
        /// Input passport JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Input challenge JSON file.
        #[arg(long, conflicts_with = "challenge_url")]
        challenge: Option<PathBuf>,
        /// Public holder-facing challenge URL.
        #[arg(long, conflicts_with = "challenge")]
        challenge_url: Option<String>,
        /// Existing seed file for the passport subject key.
        #[arg(long)]
        holder_seed_file: PathBuf,
        /// Output path for the signed response JSON.
        #[arg(long)]
        output: PathBuf,
        /// Response timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// Submit a signed challenge response to a public verifier transport URL.
    Submit {
        /// Input response JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Public submit URL returned by the verifier transport.
        #[arg(long)]
        submit_url: String,
    },

    /// Verify a challenge-bound passport presentation response.
    Verify {
        /// Input response JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Optional expected challenge JSON file for exact-match verification.
        #[arg(long)]
        challenge: Option<PathBuf>,
        /// Optional verifier policy registry file used to resolve policy references locally.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
        /// Optional SQLite challenge-state database used for replay-safe local verification.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassportOid4vpCommands {
    /// Create a replay-safe verifier request on the running trust-control service.
    Create {
        /// Optional output path for the verifier request JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Requested selective-disclosure claims. Repeat to request multiple claims.
        #[arg(long = "claim")]
        disclosure_claims: Vec<String>,
        /// Optional issuer allowlist. Repeat to allow multiple issuers.
        #[arg(long = "issuer")]
        issuer_allowlist: Vec<String>,
        /// Optional request lifetime in seconds.
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Optional continuity subject to embed in the bounded identity assertion lane.
        #[arg(long)]
        identity_subject: Option<String>,
        /// Optional continuity ID to embed in the bounded identity assertion lane.
        #[arg(long)]
        identity_continuity_id: Option<String>,
        /// Optional upstream provider label for the bounded identity assertion lane.
        #[arg(long)]
        identity_provider: Option<String>,
        /// Optional session hint for the bounded identity assertion lane.
        #[arg(long)]
        identity_session_hint: Option<String>,
        /// Optional identity-assertion lifetime in seconds. Defaults to the request TTL.
        #[arg(long)]
        identity_ttl_secs: Option<u64>,
    },

    /// Build one holder response from a verifier request or launch URL.
    Respond {
        /// Input portable SD-JWT VC credential file.
        #[arg(long)]
        input: PathBuf,
        /// Direct verifier request URI.
        #[arg(long, conflicts_with_all = ["same_device_url", "cross_device_url"])]
        request_url: Option<String>,
        /// Same-device `openid4vp://authorize?...` launch URL.
        #[arg(long, conflicts_with_all = ["request_url", "cross_device_url"])]
        same_device_url: Option<String>,
        /// Cross-device HTTPS launch URL.
        #[arg(long, conflicts_with_all = ["request_url", "same_device_url"])]
        cross_device_url: Option<String>,
        /// Existing seed file for the portable credential subject key.
        #[arg(long)]
        holder_seed_file: PathBuf,
        /// Optional output path for the signed response JWT.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Submit to the verifier's response URI after building the response.
        #[arg(long)]
        submit: bool,
        /// Override submit URL instead of using the request's response_uri.
        #[arg(long)]
        submit_url: Option<String>,
        /// Response timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// Submit a previously created OID4VP response JWT.
    Submit {
        /// Input response JWT file.
        #[arg(long)]
        input: PathBuf,
        /// Public verifier response URL.
        #[arg(long)]
        submit_url: String,
    },

    /// Fetch and display the public verifier metadata document.
    Metadata {
        /// Base verifier URL, for example `https://verifier.example.com`.
        #[arg(long)]
        verifier_url: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassportPolicyCommands {
    /// Create a signed verifier-policy artifact from a raw policy file.
    Create {
        /// Output path for the signed verifier-policy document JSON.
        #[arg(long)]
        output: PathBuf,
        /// Stable verifier policy ID.
        #[arg(long)]
        policy_id: String,
        /// Relying-party identifier or audience string that owns this policy.
        #[arg(long)]
        verifier: String,
        /// Persistent seed file used to sign the verifier policy.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// YAML or JSON file containing the raw verifier policy body.
        #[arg(long)]
        policy: PathBuf,
        /// Policy expiration as Unix seconds.
        #[arg(long)]
        expires_at: u64,
        /// Optional local verifier policy registry to update after creation.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Verify a signed verifier-policy artifact.
    Verify {
        /// Signed verifier-policy document JSON file.
        #[arg(long)]
        input: PathBuf,
        /// Verification timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        at: Option<u64>,
    },

    /// List verifier-policy artifacts from a local registry or remote service.
    List {
        /// Local verifier policy registry file to inspect when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Read one verifier-policy artifact.
    Get {
        /// Verifier policy ID to fetch.
        #[arg(long)]
        policy_id: String,
        /// Local verifier policy registry file to inspect when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Create or update one verifier-policy artifact in a local registry or remote service.
    Upsert {
        /// Input JSON file containing a signed verifier-policy document.
        #[arg(long)]
        input: PathBuf,
        /// Local verifier policy registry file to update when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },

    /// Delete one verifier-policy artifact from a local registry or remote service.
    Delete {
        /// Verifier policy ID to delete.
        #[arg(long)]
        policy_id: String,
        /// Local verifier policy registry file to update when not using --control-url.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassportStatusCommands {
    /// Publish one passport into the lifecycle registry as the current active artifact.
    Publish {
        /// Passport JSON file to publish.
        #[arg(long)]
        input: PathBuf,
        /// Local passport lifecycle registry file to update when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional resolve endpoint verifiers can query for lifecycle state.
        #[arg(long = "resolve-url")]
        resolve_urls: Vec<String>,
        /// Optional cache TTL verifiers may apply to lifecycle state.
        #[arg(long)]
        cache_ttl_secs: Option<u64>,
    },

    /// List lifecycle records from a local registry or remote service.
    List {
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Read one lifecycle record by passport id.
    Get {
        /// Passport artifact id to fetch.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Resolve lifecycle state for a passport artifact id.
    Resolve {
        /// Passport artifact id to resolve.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to inspect when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
    },

    /// Revoke one passport lifecycle record.
    Revoke {
        /// Passport artifact id to revoke.
        #[arg(long)]
        passport_id: String,
        /// Local passport lifecycle registry file to update when not using --control-url.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional revocation reason.
        #[arg(long)]
        reason: Option<String>,
        /// Optional revocation timestamp override in Unix seconds.
        #[arg(long)]
        revoked_at: Option<u64>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PassportIssuanceCommands {
    /// Render OID4VCI-style issuer metadata for Chio passport issuance.
    Metadata {
        /// Local credential issuer base URL when not using --control-url.
        #[arg(long)]
        issuer_url: Option<String>,
        /// Optional local signing seed used to advertise the standards-native portable credential profile.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional public passport lifecycle resolve endpoint to advertise in local metadata.
        #[arg(long)]
        passport_status_url: Option<String>,
        /// Optional cache hint paired with --passport-status-url in local metadata.
        #[arg(long)]
        passport_status_cache_ttl_secs: Option<u64>,
    },

    /// Create a pre-authorized credential offer for one Chio passport.
    Offer {
        /// Input passport JSON file to deliver.
        #[arg(long)]
        input: PathBuf,
        /// Optional output path for the credential offer JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local credential issuer base URL when not using --control-url.
        #[arg(long)]
        issuer_url: Option<String>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
        /// Optional local passport lifecycle registry used to require published active status before portable issuance.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional local signing seed required when offering portable compact credential configurations.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional credential configuration ID. Defaults to Chio's single passport profile.
        #[arg(long)]
        credential_configuration_id: Option<String>,
        /// Offer lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        ttl_secs: u64,
    },

    /// Redeem a pre-authorized code into an issuance access token.
    Token {
        /// Input credential offer JSON file.
        #[arg(long)]
        offer: PathBuf,
        /// Optional output path for the token response JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
    },

    /// Redeem an issuance access token into the delivered Chio passport.
    Credential {
        /// Input credential offer JSON file.
        #[arg(long)]
        offer: PathBuf,
        /// Input token response JSON file.
        #[arg(long)]
        token: PathBuf,
        /// Optional output path for the delivered passport JSON.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Local issuance registry file to update when not using --control-url.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,
        /// Optional local passport lifecycle registry used to attach portable lifecycle status references.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,
        /// Optional local signing seed required when redeeming portable compact credential configurations without --control-url.
        #[arg(long)]
        signing_seed_file: Option<PathBuf>,
        /// Optional credential configuration ID override used for fail-closed validation.
        #[arg(long)]
        credential_configuration_id: Option<String>,
        /// Optional format override used for fail-closed validation.
        #[arg(long = "credential-format")]
        credential_format: Option<String>,
    },
}

