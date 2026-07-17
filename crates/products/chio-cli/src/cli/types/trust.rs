use super::*;

#[derive(Subcommand)]
pub(crate) enum TrustCommands {
    /// Serve the shared trust-control plane over HTTP.
    Serve {
        /// Socket address to bind the trust-control service to.
        #[arg(long, default_value = "127.0.0.1:8940")]
        listen: SocketAddr,

        /// Bearer token required for trust-control service requests.
        ///
        /// Prefer `CHIO_TRUST_SERVICE_TOKEN` over `--service-token` so the
        /// secret is not visible to other users via `ps`/`/proc`.
        #[arg(long, env = "CHIO_TRUST_SERVICE_TOKEN", hide_env_values = true)]
        service_token: String,

        /// Tenant-scoped read token mapping in `tenant_id=token` form. Repeat
        /// for multiple tenants. Requests presenting one of these tokens are
        /// confined to reading the matching tenant's receipts; the
        /// `--service-token` retains administrative cross-tenant access.
        #[arg(long = "tenant-read-token", value_name = "TENANT=TOKEN")]
        tenant_read_tokens: Vec<String>,

        /// Public base URL this trust-control node advertises to peers and clients.
        #[arg(long)]
        advertise_url: Option<String>,

        /// Peer trust-control base URL. Repeat for multiple peers.
        #[arg(long = "peer-url")]
        peer_urls: Vec<String>,

        /// Allow loopback/private cluster peer URLs for local development only.
        #[arg(long, default_value_t = false)]
        allow_local_peer_urls: bool,

        /// Background cluster sync interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        cluster_sync_interval_ms: u64,

        /// Optional policy file whose reputation issuance extension is enforced by the service.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Optional file-backed enterprise provider registry shared with remote MCP edges.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,

        /// Optional file-backed permissionless federation policy registry.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,

        /// Optional file-backed SCIM lifecycle registry for external IdP provisioning and deprovisioning.
        #[arg(long)]
        scim_lifecycle_file: Option<PathBuf>,

        /// Optional file-backed signed verifier policy registry for remote verifier flows.
        #[arg(long)]
        verifier_policies_file: Option<PathBuf>,

        /// Optional SQLite verifier challenge-state database for replay-safe remote verifier flows.
        #[arg(long)]
        verifier_challenge_db: Option<PathBuf>,

        /// Optional file-backed passport lifecycle registry for publish/resolve/revoke flows.
        #[arg(long)]
        passport_statuses_file: Option<PathBuf>,

        /// Optional file-backed passport issuance registry for OID4VCI-style pre-authorized offers.
        #[arg(long)]
        passport_issuance_offers_file: Option<PathBuf>,

        /// Optional file-backed certification registry for publish/resolve/revoke flows.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,

        /// Optional multi-operator certification discovery network file.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,

        /// Public certification metadata TTL in seconds.
        #[arg(long, default_value_t = 3600)]
        certification_public_metadata_ttl_seconds: u64,

        /// JSON file containing the operator roster policy (roster, allowed decision rules,
        /// roster anchor) for liability adjudication enforcement.
        #[arg(long)]
        roster_policy_file: Option<PathBuf>,
    },

    /// Manage enterprise federation provider-admin records.
    Provider {
        #[command(subcommand)]
        command: TrustProviderCommands,
    },

    /// Manage permissionless federation admission policies.
    FederationPolicy {
        #[command(subcommand)]
        command: TrustFederationPolicyCommands,
    },

    /// Inspect shared remote evidence references used by local delegated activity.
    EvidenceShare {
        #[command(subcommand)]
        command: TrustEvidenceShareCommands,
    },

    /// Render derived external authorization context from governed receipts.
    AuthorizationContext {
        #[command(subcommand)]
        command: TrustAuthorizationContextCommands,
    },

    /// Export a signed runtime-attestation appraisal report.
    Appraisal {
        #[command(subcommand)]
        command: TrustRuntimeAttestationAppraisalCommands,
    },

    /// Export a signed insurer-facing behavioral feed from canonical trust data.
    BehavioralFeed {
        #[command(subcommand)]
        command: TrustBehavioralFeedCommands,
    },

    /// Export a signed exposure ledger from canonical trust and underwriting data.
    ExposureLedger {
        #[command(subcommand)]
        command: TrustExposureLedgerCommands,
    },

    /// Export a signed subject-scoped credit scorecard from exposure and reputation data.
    CreditScorecard {
        #[command(subcommand)]
        command: TrustCreditScorecardCommands,
    },

    /// Export a signed live capital book with explicit source-of-funds attribution.
    CapitalBook {
        #[command(subcommand)]
        command: TrustCapitalBookCommands,
    },

    /// Issue one custody-neutral escrow or reserve instruction artifact.
    CapitalInstruction {
        #[command(subcommand)]
        command: TrustCapitalInstructionCommands,
    },

    /// Issue one simulation-first capital-allocation decision for a governed action.
    CapitalAllocation {
        #[command(subcommand)]
        command: TrustCapitalAllocationCommands,
    },

    /// Evaluate, issue, and list bounded credit facilities from subject-scoped evidence.
    Facility {
        #[command(subcommand)]
        command: TrustCreditFacilityCommands,
    },

    /// Evaluate, issue, and list reserve-lock bond artifacts from credit evidence.
    Bond {
        #[command(subcommand)]
        command: TrustCreditBondCommands,
    },

    /// Evaluate, issue, and list immutable bond loss-lifecycle artifacts.
    Loss {
        #[command(subcommand)]
        command: TrustCreditLossLifecycleCommands,
    },

    /// Export deterministic credit backtests over historical subject-scoped evidence.
    CreditBacktest {
        #[command(subcommand)]
        command: TrustCreditBacktestCommands,
    },

    /// Export one signed provider-facing risk package over canonical credit truth.
    ProviderRiskPackage {
        #[command(subcommand)]
        command: TrustProviderRiskPackageCommands,
    },

    /// Issue, list, and resolve curated liability-market provider registry entries.
    LiabilityProvider {
        #[command(subcommand)]
        command: TrustLiabilityProviderCommands,
    },

    /// Issue quote, placement, and bound-coverage artifacts and list workflow state.
    LiabilityMarket {
        #[command(subcommand)]
        command: TrustLiabilityMarketCommands,
    },

    /// Export a signed underwriting policy-input snapshot from canonical trust data.
    UnderwritingInput {
        #[command(subcommand)]
        command: TrustUnderwritingInputCommands,
    },

    /// Evaluate a bounded underwriting decision from canonical trust data.
    UnderwritingDecision {
        #[command(subcommand)]
        command: TrustUnderwritingDecisionCommands,
    },

    /// Create or resolve underwriting appeals against persisted decisions.
    UnderwritingAppeal {
        #[command(subcommand)]
        command: TrustUnderwritingAppealCommands,
    },

    /// Persist a capability revocation into the configured revocation database.
    Revoke {
        /// Capability ID to revoke.
        #[arg(long)]
        capability_id: String,
    },

    /// Issue one local capability after verifying a challenge-bound portable presentation.
    FederatedIssue {
        /// Signed passport presentation response from the external agent.
        #[arg(long)]
        presentation_response: PathBuf,

        /// Exact expected challenge JSON used to bind the presentation to this verifier.
        #[arg(long)]
        challenge: PathBuf,

        /// Policy file whose default capability definition is the single capability to issue.
        #[arg(long)]
        capability_policy: PathBuf,

        /// Optional enterprise identity context JSON used for provider-admin-gated admission.
        #[arg(long)]
        enterprise_identity: Option<PathBuf>,

        /// Optional signed federated delegation policy that sets the parent scope/TTL ceiling.
        #[arg(long)]
        delegation_policy: Option<PathBuf>,

        /// Optional imported upstream capability ID used as the parent for multi-hop federated delegation.
        #[arg(long)]
        upstream_capability_id: Option<String>,
    },

    /// Create a signed federated delegation policy from a single default capability.
    FederatedDelegationPolicyCreate {
        /// Output path for the signed policy JSON.
        #[arg(long)]
        output: PathBuf,

        /// Persistent seed file used to sign the federated delegation policy.
        #[arg(long)]
        signing_seed_file: PathBuf,

        /// Local issuer name or organization identifier.
        #[arg(long)]
        issuer: String,

        /// External partner name or organization identifier.
        #[arg(long)]
        partner: String,

        /// Trust-control verifier URL this policy is bound to.
        #[arg(long)]
        verifier: String,

        /// Capability policy whose single default capability becomes the delegation ceiling.
        #[arg(long)]
        capability_policy: PathBuf,

        /// Policy expiration as Unix seconds.
        #[arg(long)]
        expires_at: u64,

        /// Optional reason or purpose string embedded in the policy document.
        #[arg(long)]
        purpose: Option<String>,

        /// Optional upstream capability ID that this delegation policy is allowed to continue from.
        #[arg(long)]
        parent_capability_id: Option<String>,
    },

    /// Query whether a capability ID is currently revoked.
    Status {
        /// Capability ID to check.
        #[arg(long)]
        capability_id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustProviderCommands {
    /// List enterprise provider records from the shared registry.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Read one enterprise provider record.
    Get {
        /// Provider ID to fetch.
        #[arg(long)]
        provider_id: String,

        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Create or update one enterprise provider record from JSON.
    Upsert {
        /// Input JSON file containing an EnterpriseProviderRecord.
        #[arg(long)]
        input: PathBuf,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },

    /// Delete one enterprise provider record.
    Delete {
        /// Provider ID to delete.
        #[arg(long)]
        provider_id: String,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustFederationPolicyCommands {
    /// List published permissionless federation policies.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Read one published permissionless federation policy.
    Get {
        /// Policy ID to fetch.
        #[arg(long)]
        policy_id: String,

        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Create or update one permissionless federation policy record from JSON.
    Upsert {
        /// Input JSON file containing a FederationAdmissionPolicyRecord.
        #[arg(long)]
        input: PathBuf,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Delete one permissionless federation policy record.
    Delete {
        /// Policy ID to delete.
        #[arg(long)]
        policy_id: String,

        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        federation_policies_file: Option<PathBuf>,
    },

    /// Evaluate admission for one peer under a published federation policy.
    Evaluate {
        /// Input JSON file containing a FederationAdmissionEvaluationRequest.
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustEvidenceShareCommands {
    /// List shared-evidence references visible from local activity or the remote trust service.
    List {
        /// Filter by local capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by local agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by local tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by local tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter: receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Filter: receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Filter by remote share issuer.
        #[arg(long)]
        issuer: Option<String>,
        /// Filter by remote share partner.
        #[arg(long)]
        partner: Option<String>,
        /// Maximum number of shared-evidence references to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustAuthorizationContextCommands {
    /// Export machine-readable Chio authorization-profile metadata for enterprise IAM review.
    Metadata,

    /// List derived authorization-context mappings from local state or trust-control.
    List {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of derived authorization-context rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Export an enterprise reviewer pack tying authorization context back to governed receipt truth.
    ReviewPack {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of derived authorization-context rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustRuntimeAttestationAppraisalCommands {
    /// Export a signed runtime-attestation appraisal report from local input or trust-control.
    Export {
        /// Input JSON or YAML file containing a RuntimeAttestationEvidence payload.
        #[arg(long)]
        input: PathBuf,

        /// Optional HushSpec policy used to evaluate policy-visible outcomes locally.
        #[arg(long)]
        policy_file: Option<PathBuf>,
    },
    /// Export a signed portable runtime-attestation appraisal result artifact.
    ExportResult {
        /// Issuer identifier recorded in the exported result.
        #[arg(long)]
        issuer: String,

        /// Input JSON or YAML file containing a RuntimeAttestationEvidence payload.
        #[arg(long)]
        input: PathBuf,

        /// Optional HushSpec policy used to evaluate exporter-visible outcomes locally.
        #[arg(long)]
        policy_file: Option<PathBuf>,
    },
    /// Evaluate a signed external runtime-attestation appraisal result against local import policy.
    Import {
        /// Input JSON or YAML file containing a signed appraisal result envelope.
        #[arg(long)]
        input: PathBuf,

        /// JSON or YAML file containing a RuntimeAttestationImportedAppraisalPolicy payload.
        #[arg(long)]
        policy_file: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustBehavioralFeedCommands {
    /// Export a signed behavioral feed from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt detail rows to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustExposureLedgerCommands {
    /// Export a signed exposure ledger from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to embed.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCreditScorecardCommands {
    /// Export a signed credit scorecard from local state or trust-control.
    Export {
        /// Subject public key to score.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCapitalBookCommands {
    /// Export a signed live capital book from canonical facility, bond, and loss posture.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to inspect for disbursement provenance.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of facility rows to inspect.
        #[arg(long, default_value_t = 10)]
        facility_limit: usize,
        /// Maximum number of bond rows to inspect.
        #[arg(long, default_value_t = 10)]
        bond_limit: usize,
        /// Maximum number of loss-lifecycle rows to inspect.
        #[arg(long, default_value_t = 25)]
        loss_event_limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCapitalInstructionCommands {
    /// Issue one custody-neutral escrow or reserve instruction artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML capital-instruction input file.
        #[arg(long)]
        input_file: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCapitalAllocationCommands {
    /// Issue one live capital-allocation decision artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML capital-allocation input file.
        #[arg(long)]
        input_file: PathBuf,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCreditFacilityCommands {
    /// Evaluate a deterministic facility-policy report without persisting an artifact.
    Evaluate {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed facility artifact from deterministic facility policy.
    Issue {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional previously active facility to supersede.
        #[arg(long)]
        supersedes_facility_id: Option<String>,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// List persisted credit facility artifacts.
    List {
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by disposition (`grant`, `manual_review`, `deny`).
        #[arg(long)]
        disposition: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`, `denied`, `expired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of facility rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCreditBondCommands {
    /// Evaluate a deterministic bond-policy report without persisting an artifact.
    Evaluate {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed bond artifact from deterministic bond policy.
    Issue {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Optional previously active bond to supersede.
        #[arg(long)]
        supersedes_bond_id: Option<String>,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Simulate bonded execution under an operator control policy without mutating state.
    Simulate {
        /// Bond artifact ID to evaluate.
        #[arg(long)]
        bond_id: String,
        /// Requested autonomy tier (`direct`, `delegated`, `autonomous`).
        #[arg(long)]
        autonomy_tier: String,
        /// Runtime assurance tier attached to the simulated request.
        #[arg(long)]
        runtime_assurance_tier: String,
        /// Whether delegated call-chain context is present.
        #[arg(long, default_value_t = false)]
        call_chain_present: bool,
        /// YAML or JSON operator control policy file.
        #[arg(long)]
        policy_file: PathBuf,
    },

    /// List persisted credit bond artifacts.
    List {
        /// Filter by bond ID.
        #[arg(long)]
        bond_id: Option<String>,
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by disposition (`lock`, `hold`, `release`, `impair`).
        #[arg(long)]
        disposition: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`, `released`, `impaired`, `expired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of bond rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCreditLossLifecycleCommands {
    /// Evaluate a deterministic bond loss-lifecycle transition without persisting an artifact.
    Evaluate {
        /// Bond ID to evaluate against.
        #[arg(long)]
        bond_id: String,
        /// Event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: String,
        /// Optional explicit amount in minor units.
        #[arg(long)]
        amount_units: Option<u64>,
        /// Optional explicit amount currency.
        #[arg(long)]
        amount_currency: Option<String>,
    },

    /// Issue and persist a signed bond loss-lifecycle artifact.
    Issue {
        /// Bond ID to evaluate against.
        #[arg(long)]
        bond_id: String,
        /// Event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: String,
        /// Optional explicit amount in minor units.
        #[arg(long)]
        amount_units: Option<u64>,
        /// Optional explicit amount currency.
        #[arg(long)]
        amount_currency: Option<String>,
        /// Optional JSON/YAML file containing Vec<CapitalExecutionAuthorityStep>.
        #[arg(long)]
        authority_chain_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionWindow.
        #[arg(long)]
        execution_window_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionRail.
        #[arg(long)]
        rail_file: Option<PathBuf>,
        /// Optional JSON/YAML file containing CapitalExecutionObservation.
        #[arg(long)]
        observed_execution_file: Option<PathBuf>,
        /// Optional reserve-control appeal window close timestamp.
        #[arg(long)]
        appeal_window_ends_at: Option<u64>,
        /// Optional reserve-control description recorded on the lifecycle artifact.
        #[arg(long)]
        description: Option<String>,
    },

    /// List persisted bond loss-lifecycle artifacts.
    List {
        /// Filter by event ID.
        #[arg(long)]
        event_id: Option<String>,
        /// Filter by bond ID.
        #[arg(long)]
        bond_id: Option<String>,
        /// Filter by facility ID.
        #[arg(long)]
        facility_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by event kind (`delinquency`, `recovery`, `reserve_release`, `reserve_slash`, `write_off`).
        #[arg(long)]
        event_kind: Option<String>,
        /// Maximum number of event rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustCreditBacktestCommands {
    /// Export one deterministic credit backtest report over historical evidence windows.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate per window.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate per window.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Width of each replay window in seconds.
        #[arg(long, default_value_t = 7 * 86_400)]
        window_seconds: u64,
        /// Number of windows to replay.
        #[arg(long, default_value_t = 4)]
        window_count: usize,
        /// Evidence older than this threshold is flagged stale.
        #[arg(long, default_value_t = 30 * 86_400)]
        stale_after_seconds: u64,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustProviderRiskPackageCommands {
    /// Export one signed provider-facing risk package over canonical subject-scoped evidence.
    Export {
        /// Subject public key to evaluate.
        #[arg(long)]
        agent_subject: String,
        /// Optional filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Optional filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Optional filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt rows to evaluate.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Maximum number of underwriting decision rows to evaluate.
        #[arg(long, default_value_t = 50)]
        decision_limit: usize,
        /// Maximum number of recent loss events to include.
        #[arg(long, default_value_t = 10)]
        recent_loss_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustLiabilityProviderCommands {
    /// Issue and persist a signed curated liability-provider artifact from JSON or YAML input.
    Issue {
        /// JSON or YAML provider report input file.
        #[arg(long)]
        input_file: PathBuf,
        /// Optional previously active provider record to supersede.
        #[arg(long)]
        supersedes_provider_record_id: Option<String>,
    },

    /// List persisted liability-provider artifacts.
    List {
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by coverage class (`tool_execution`, `data_breach`, `financial_loss`, `professional_liability`, `regulatory_response`).
        #[arg(long)]
        coverage_class: Option<String>,
        /// Filter by currency.
        #[arg(long)]
        currency: Option<String>,
        /// Filter by lifecycle state (`active`, `suspended`, `superseded`, `retired`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Maximum number of provider rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// Resolve one provider + jurisdiction + coverage + currency combination fail closed.
    Resolve {
        /// Provider ID to resolve.
        #[arg(long)]
        provider_id: String,
        /// Jurisdiction to resolve.
        #[arg(long)]
        jurisdiction: String,
        /// Coverage class to resolve.
        #[arg(long)]
        coverage_class: String,
        /// Currency to resolve.
        #[arg(long)]
        currency: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustLiabilityMarketCommands {
    /// Issue and persist a signed liability quote request from JSON or YAML input.
    QuoteRequestIssue {
        /// JSON or YAML quote-request input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability quote response from JSON or YAML input.
    QuoteResponseIssue {
        /// JSON or YAML quote-response input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed delegated pricing-authority artifact.
    PricingAuthorityIssue {
        /// JSON or YAML pricing-authority input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability placement from JSON or YAML input.
    PlacementIssue {
        /// JSON or YAML placement input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed bound-coverage artifact from JSON or YAML input.
    BoundCoverageIssue {
        /// JSON or YAML bound-coverage input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Evaluate and persist one automatic bind decision plus issued placement/bound coverage.
    AutoBindIssue {
        /// JSON or YAML auto-bind input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim package from JSON or YAML input.
    ClaimIssue {
        /// JSON or YAML claim input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim response from JSON or YAML input.
    ClaimResponseIssue {
        /// JSON or YAML claim-response input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim dispute from JSON or YAML input.
    DisputeIssue {
        /// JSON or YAML dispute input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim adjudication from JSON or YAML input.
    AdjudicationIssue {
        /// JSON or YAML adjudication input file.
        #[arg(long)]
        input_file: PathBuf,
        /// JSON file containing the operator roster policy (roster, allowed decision rules,
        /// roster anchor). Required when --control-url is not set.
        #[arg(long)]
        roster_policy_file: Option<PathBuf>,
    },

    /// Issue and persist a signed liability claim payout instruction from JSON or YAML input.
    ClaimPayoutInstructionIssue {
        /// JSON or YAML claim payout instruction input file.
        #[arg(long)]
        input_file: PathBuf,
        /// JSON file containing the operator roster policy. Required when --control-url is not set.
        #[arg(long)]
        roster_policy_file: Option<PathBuf>,
    },

    /// Issue and persist a signed liability claim payout receipt from JSON or YAML input.
    ClaimPayoutReceiptIssue {
        /// JSON or YAML claim payout receipt input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// Issue and persist a signed liability claim settlement instruction from JSON or YAML input.
    ClaimSettlementInstructionIssue {
        /// JSON or YAML claim settlement instruction input file.
        #[arg(long)]
        input_file: PathBuf,
        /// JSON file containing the operator roster policy. Required when --control-url is not set.
        #[arg(long)]
        roster_policy_file: Option<PathBuf>,
    },

    /// Issue and persist a signed liability claim settlement receipt from JSON or YAML input.
    ClaimSettlementReceiptIssue {
        /// JSON or YAML claim settlement receipt input file.
        #[arg(long)]
        input_file: PathBuf,
    },

    /// List quote-request to bound-coverage workflow rows.
    List {
        /// Filter by quote request ID.
        #[arg(long)]
        quote_request_id: Option<String>,
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by coverage class (`tool_execution`, `data_breach`, `financial_loss`, `professional_liability`, `regulatory_response`).
        #[arg(long)]
        coverage_class: Option<String>,
        /// Filter by currency.
        #[arg(long)]
        currency: Option<String>,
        /// Maximum number of workflow rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },

    /// List claim-package to adjudication workflow rows.
    ClaimsList {
        /// Filter by claim ID.
        #[arg(long)]
        claim_id: Option<String>,
        /// Filter by provider ID.
        #[arg(long)]
        provider_id: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by jurisdiction.
        #[arg(long)]
        jurisdiction: Option<String>,
        /// Filter by policy number.
        #[arg(long)]
        policy_number: Option<String>,
        /// Maximum number of claim rows to embed.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustUnderwritingInputCommands {
    /// Export a signed underwriting policy-input snapshot from local state or trust-control.
    Export {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to embed.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustUnderwritingDecisionCommands {
    /// Evaluate a bounded underwriting decision from local state or trust-control.
    Evaluate {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Simulate an alternative underwriting policy against canonical evidence without persisting a decision.
    Simulate {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// YAML or JSON underwriting decision policy file.
        #[arg(long)]
        policy_file: PathBuf,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Issue and persist a signed underwriting decision artifact.
    Issue {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Include receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Maximum number of receipt references to inspect.
        #[arg(long, default_value_t = 100)]
        receipt_limit: usize,
        /// Optional local certification registry file used when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
        /// Optional prior decision ID this new artifact supersedes.
        #[arg(long)]
        supersedes_decision_id: Option<String>,
    },

    /// List persisted underwriting decision artifacts and appeal status.
    List {
        /// Filter by decision ID.
        #[arg(long)]
        decision_id: Option<String>,
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Filter by tool server.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by outcome (`approve`, `reduce_ceiling`, `step_up`, `deny`).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by lifecycle state (`active`, `superseded`).
        #[arg(long)]
        lifecycle_state: Option<String>,
        /// Filter by latest appeal status (`open`, `accepted`, `rejected`).
        #[arg(long)]
        appeal_status: Option<String>,
        /// Maximum number of persisted decision rows to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum TrustUnderwritingAppealCommands {
    /// Create an underwriting appeal record for one persisted decision.
    Create {
        /// Decision ID to appeal.
        #[arg(long)]
        decision_id: String,
        /// Operator or system subject opening the appeal.
        #[arg(long)]
        requested_by: String,
        /// Short appeal reason.
        #[arg(long)]
        reason: String,
        /// Optional freeform note.
        #[arg(long)]
        note: Option<String>,
    },

    /// Resolve one open underwriting appeal.
    Resolve {
        /// Appeal ID to resolve.
        #[arg(long)]
        appeal_id: String,
        /// Resolution outcome (`accepted` or `rejected`).
        #[arg(long)]
        resolution: String,
        /// Operator or system subject resolving the appeal.
        #[arg(long)]
        resolved_by: String,
        /// Optional freeform note.
        #[arg(long)]
        note: Option<String>,
        /// Optional replacement decision ID when an appeal resolution references a superseding artifact.
        #[arg(long)]
        replacement_decision_id: Option<String>,
    },
}
