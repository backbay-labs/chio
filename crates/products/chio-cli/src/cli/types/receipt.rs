use super::*;

#[derive(Subcommand)]
pub(crate) enum ReceiptCommands {
    /// List receipts with optional filters. Output: one JSON receipt per line (JSON Lines).
    List {
        /// Filter by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter by tool server ID.
        #[arg(long)]
        tool_server: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool_name: Option<String>,
        /// Filter by decision outcome (allow, deny, cancelled, incomplete).
        #[arg(long)]
        outcome: Option<String>,
        /// Filter: receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Filter: receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Filter: minimum cost in minor currency units (only financial receipts).
        #[arg(long, requires = "cost_currency")]
        min_cost: Option<u64>,
        /// Filter: maximum cost in minor currency units (only financial receipts).
        #[arg(long, requires = "cost_currency")]
        max_cost: Option<u64>,
        /// Currency for cost filters as a three-letter uppercase code.
        #[arg(long)]
        cost_currency: Option<String>,
        /// Maximum number of receipts per page.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Cursor for pagination (seq value to start after).
        #[arg(long)]
        cursor: Option<u64>,
        /// Tenant read boundary for the listing. The reading path fails closed
        /// when neither `--tenant` nor `--admin-all` is supplied.
        #[arg(long)]
        tenant: Option<String>,
        /// Explicitly read across all tenants as an administrative operation.
        #[arg(long, default_value_t = false, conflicts_with = "tenant")]
        admin_all: bool,
    },
    /// Report receipt-store write health and durability status.
    Health,
    /// Flush pending receipt writes to durable storage, bounded by a timeout.
    Flush {
        /// Maximum time to wait for the flush to complete, in milliseconds.
        #[arg(long, default_value_t = 5000, value_parser = clap::value_parser!(u64).range(1..))]
        timeout_ms: u64,
    },
    /// Run the full receipt-log audit: claim-log projection validation plus a
    /// complete checkpoint-chain verification (the deep check).
    Audit {
        /// OFFLINE on-disk repair: revalidate the on-disk receipt chain on a
        /// local connection before reporting. Run this with the kernel STOPPED.
        /// A running kernel keeps its verified head in-memory in a separate
        /// process that the CLI cannot reach, so this does NOT clear a live
        /// poisoned writer; restart the kernel to reseed a clean head from the
        /// validated on-disk state.
        #[arg(long, default_value_t = false)]
        repair: bool,
    },
    /// Inspect or repair the receipt-store retention state.
    Retention {
        #[command(subcommand)]
        command: ReceiptRetentionCommands,
    },
    /// Inspect or advance the receipt-checkpoint chain.
    Checkpoint {
        #[command(subcommand)]
        command: ReceiptCheckpointCommands,
    },
    /// Explain why a receipt was allowed or denied.
    ///
    /// When `--input-file` points at a `BilateralCoSignArtifacts` JSON
    /// document (the federation signature-slice API emission with both a
    /// `dualSignedReceipt` and a `dsseEnvelope`), the renderer auto-detects
    /// the bilateral shape and prints both the non-section-6-conformant DualSignedReceipt
    /// section (NON-SECTION-6-CONFORMANT per B4) and the DSSE signature-slice
    /// section. It does not claim strict Chio DSSE section 6 predicate conformance.
    ///
    /// Pass `--inspect-bilateral` to additionally emit a structural
    /// **inspection trace** of the envelope (structural / schema checks
    /// only). Ed25519 signature verification is NOT performed: the CLI
    /// does not carry the org A / org B passport public keys, so the
    /// trace makes no cryptographic-verification claim.
    /// `--explain-bilateral` is retained as an alias.
    Explain {
        /// Receipt ID. Use a sentinel (e.g. `bilateral`) when reading a
        /// bilateral artifact via `--input-file`; the receipt_id is
        /// informational for that path.
        receipt_id: String,
        /// Optional JSON file containing one receipt, or a
        /// `BilateralCoSignArtifacts` document.
        #[arg(long)]
        input_file: Option<PathBuf>,
        /// Maximum parent depth to render.
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// Maximum fanout siblings to render per level.
        #[arg(long, default_value_t = 32)]
        fanout_limit: usize,
        /// Emit a structural inspection trace of the bilateral envelope.
        /// Note: this trace does NOT perform Ed25519 signature
        /// verification. For real verification, use the kernel-resident
        /// `chio_federation::bilateral_dsse::verify_dsse_envelope`
        /// against pinned passport keys.
        #[arg(long, alias = "explain-bilateral", default_value_t = false)]
        inspect_bilateral: bool,
        /// Tenant read boundary for the explanation. The reading path fails
        /// closed when neither `--tenant` nor `--admin-all` is supplied.
        #[arg(long)]
        tenant: Option<String>,
        /// Explicitly read across all tenants as an administrative operation.
        #[arg(long, default_value_t = false, conflicts_with = "tenant")]
        admin_all: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReceiptRetentionCommands {
    /// Repair a receipt store bricked by a retention rotation that left
    /// orphaned claim-log rows: remove the rows whose source receipts were
    /// archived and deleted, restoring a writable, reopenable store.
    /// Fail-closed.
    Repair {
        /// Archive file that holds the co-archived claim-log rows to validate
        /// the removal against.
        #[arg(long)]
        archive: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ReceiptCheckpointCommands {
    /// Report the current receipt-checkpoint chain status.
    Status {
        /// Maximum number of receipts to consider per checkpoint batch.
        #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
        max_batch: u64,
    },
    /// Create the next receipt checkpoint, signed by the kernel keypair.
    Create {
        /// Kernel checkpoint signing-seed file.
        #[arg(long)]
        kernel_seed_file: PathBuf,
        /// Maximum number of receipts to include in the checkpoint batch.
        #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
        max_batch: u64,
    },
    /// Verify the integrity of the receipt-checkpoint chain.
    Verify,
}

#[derive(Subcommand)]
pub(crate) enum EvidenceCommands {
    /// Export a verifiable local evidence package into a directory.
    Export {
        /// Output directory for the evidence package. Must not already contain files.
        #[arg(long)]
        output: PathBuf,
        /// Filter tool receipts by capability ID.
        #[arg(long)]
        capability: Option<String>,
        /// Filter tool receipts by agent subject public key.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Include tool receipts with timestamp >= this Unix seconds value.
        #[arg(long)]
        since: Option<u64>,
        /// Include tool receipts with timestamp <= this Unix seconds value.
        #[arg(long)]
        until: Option<u64>,
        /// Tenant read boundary for the export. Derived from operator auth in service paths.
        #[arg(long)]
        tenant: Option<String>,
        /// Explicitly export across all tenants as an administrative operation.
        #[arg(long, default_value_t = false, conflicts_with = "tenant")]
        admin_all: bool,
        /// Optional policy file to attach to the export package.
        #[arg(long)]
        policy_file: Option<PathBuf>,
        /// Optional signed bilateral federation policy that constrains the export scope.
        #[arg(long)]
        federation_policy: Option<PathBuf>,
        /// Fail the export if any selected tool receipt lacks checkpoint coverage.
        #[arg(long, default_value_t = false)]
        require_proofs: bool,
    },
    /// Verify an exported evidence package offline.
    Verify {
        /// Input directory containing a previously exported evidence package.
        #[arg(long)]
        input: PathBuf,
    },
    /// Import a verified bilateral evidence package for later federated delegation.
    Import {
        /// Input directory containing a previously exported evidence package.
        #[arg(long)]
        input: PathBuf,
    },
    /// Create a signed bilateral receipt-sharing policy document.
    FederationPolicy {
        #[command(subcommand)]
        command: EvidenceFederationPolicyCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum EvidenceFederationPolicyCommands {
    /// Create a signed bilateral federation policy for receipt sharing.
    Create {
        /// Output JSON file for the signed policy document.
        #[arg(long)]
        output: PathBuf,
        /// Persistent seed file used to sign the policy document.
        #[arg(long)]
        signing_seed_file: PathBuf,
        /// Human-readable identifier for the issuing organization.
        #[arg(long)]
        issuer: String,
        /// Human-readable identifier for the receiving organization.
        #[arg(long)]
        partner: String,
        /// Optional capability scope for the shared export.
        #[arg(long)]
        capability: Option<String>,
        /// Optional agent subject scope for the shared export.
        #[arg(long)]
        agent_subject: Option<String>,
        /// Optional lower timestamp bound for the allowed export window.
        #[arg(long)]
        since: Option<u64>,
        /// Optional upper timestamp bound for the allowed export window.
        #[arg(long)]
        until: Option<u64>,
        /// Tenant read boundary for exports performed under this policy.
        #[arg(long)]
        tenant: Option<String>,
        /// Explicitly allow administrative exports across all tenants under this policy.
        #[arg(long, default_value_t = false, conflicts_with = "tenant")]
        admin_all: bool,
        /// Expiration time for the policy document, in Unix seconds.
        #[arg(long)]
        expires_at: u64,
        /// Require full checkpoint coverage for any export performed under this policy.
        #[arg(long, default_value_t = false)]
        require_proofs: bool,
        /// Optional reason or purpose string embedded in the policy document.
        #[arg(long)]
        purpose: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum CertifyCommands {
    /// Evaluate conformance evidence and emit a signed pass/fail certification artifact.
    Check {
        /// Directory containing conformance scenario descriptor JSON files.
        #[arg(long)]
        scenarios_dir: PathBuf,
        /// Directory containing conformance result JSON files.
        #[arg(long)]
        results_dir: PathBuf,
        /// Output path for the signed certification artifact JSON.
        #[arg(long)]
        output: PathBuf,
        /// Stable identifier for the tool server being checked.
        #[arg(long)]
        tool_server_id: String,
        /// Optional human-readable name for the tool server being checked.
        #[arg(long)]
        tool_server_name: Option<String>,
        /// Optional path to write a generated markdown report for the evaluated corpus.
        #[arg(long)]
        report_output: Option<PathBuf>,
        /// Certification criteria profile to apply.
        #[arg(long, default_value = "conformance-all-pass-v1")]
        criteria_profile: String,
        /// Persistent seed file used to sign certification artifacts.
        #[arg(long)]
        signing_seed_file: PathBuf,
    },

    /// Verify a signed certification artifact.
    Verify {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
    },

    /// Publish, resolve, and revoke certification artifacts in a registry.
    Registry {
        #[command(subcommand)]
        command: CertifyRegistryCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum CertifyRegistryCommands {
    /// Publish one signed certification artifact into a local or remote registry.
    Publish {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Publish one certification artifact across configured discovery-network operators.
    PublishNetwork {
        /// Input path for the signed certification artifact JSON.
        #[arg(long)]
        input: PathBuf,
        /// Local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// List certification artifacts from a local or remote registry.
    List {
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Read one certification artifact from a local or remote registry.
    Get {
        /// Certification artifact ID to fetch.
        #[arg(long)]
        artifact_id: String,
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Resolve the current certification status for one tool server.
    Resolve {
        /// Stable tool-server identifier whose current certification should be resolved.
        #[arg(long)]
        tool_server_id: String,
        /// Local registry file to inspect when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Discover certification status across multiple configured operators.
    Discover {
        /// Stable tool-server identifier whose discovery state should be queried.
        #[arg(long)]
        tool_server_id: String,
        /// Local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
    },

    /// Search public certification listings across configured operators.
    Search {
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional exact tool-server id filter.
        #[arg(long)]
        tool_server_id: Option<String>,
        /// Optional criteria profile filter.
        #[arg(long)]
        criteria_profile: Option<String>,
        /// Optional evidence profile filter.
        #[arg(long)]
        evidence_profile: Option<String>,
        /// Optional listing state filter (`active`, `superseded`, or `revoked`).
        #[arg(long)]
        status: Option<String>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// Render the public certification transparency feed across configured operators.
    Transparency {
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional exact tool-server id filter.
        #[arg(long)]
        tool_server_id: Option<String>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
    },

    /// Evaluate public certification listings against a local import policy.
    Consume {
        /// Stable tool-server identifier whose public listing should be consumed.
        #[arg(long)]
        tool_server_id: String,
        /// Optional local discovery-network file to use when not using --control-url.
        #[arg(long)]
        certification_discovery_file: Option<PathBuf>,
        /// Optional operator id allowlist. Repeat to target specific operators.
        #[arg(long = "operator-id")]
        operator_ids: Vec<String>,
        /// Optional allowed criteria profile. Repeat to allow multiple profiles.
        #[arg(long = "criteria-profile")]
        allowed_criteria_profiles: Vec<String>,
        /// Optional allowed evidence profile. Repeat to allow multiple profiles.
        #[arg(long = "evidence-profile")]
        allowed_evidence_profiles: Vec<String>,
    },

    /// Revoke one certification artifact in a local or remote registry.
    Revoke {
        /// Certification artifact ID to revoke.
        #[arg(long)]
        artifact_id: String,
        /// Optional human-readable revocation reason.
        #[arg(long)]
        reason: Option<String>,
        /// Optional revocation timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        revoked_at: Option<u64>,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },

    /// Open or resolve a public certification dispute record.
    Dispute {
        /// Certification artifact ID to update.
        #[arg(long)]
        artifact_id: String,
        /// Dispute state (`open`, `under-review`, `resolved-no-change`, `resolved-revoked`).
        #[arg(long)]
        state: String,
        /// Optional dispute note or resolution summary.
        #[arg(long)]
        note: Option<String>,
        /// Optional dispute timestamp override in Unix seconds. Defaults to now.
        #[arg(long)]
        updated_at: Option<u64>,
        /// Local registry file to update when not using --control-url.
        #[arg(long)]
        certification_registry_file: Option<PathBuf>,
    },
}
