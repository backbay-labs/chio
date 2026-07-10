use super::*;

#[derive(Subcommand)]
pub(crate) enum ProofCommands {
    /// Assemble Transaction Passport roots from evidence artifacts.
    Assemble {
        /// Directory containing evidence artifacts.
        #[arg(long, value_name = "DIR")]
        artifact_dir: PathBuf,

        /// Verifier policy JSON to bind into the passport.
        #[arg(long, value_name = "FILE")]
        verifier_policy: PathBuf,

        /// Transaction Passport id to write.
        #[arg(long)]
        passport_id: String,

        /// Issued-at timestamp to write into deterministic roots.
        #[arg(long)]
        issued_at: String,

        /// Directory where assembled roots will be written.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },

    /// Collect a verifier-backed proof bundle from proof artifacts.
    Collect {
        /// Proof bundle kind to collect.
        #[arg(long, value_enum)]
        kind: ProofCollectKind,

        /// Directory containing source proof artifacts.
        #[arg(long, value_name = "DIR")]
        artifact_dir: PathBuf,

        /// Directory where the collected proof bundle will be written.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },

    /// Verify a Transaction Passport proof bundle rooted at a passport JSON file.
    Verify {
        /// Path to transaction-passport.json.
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Require a verified proof claim family.
        #[arg(long = "require", value_enum)]
        require: Vec<ProofVerifyRequirement>,

        /// Write the verifier report to this JSON file.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Explain a verifier claim from a proof bundle.
    Explain {
        /// Proof bundle directory, exported archive, or transaction-passport.json path.
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,

        /// Claim id to explain.
        #[arg(long)]
        claim: String,
    },

    /// List and generate bundled proof fixtures.
    Fixture {
        #[command(subcommand)]
        command: ProofFixtureCommands,
    },

    /// Serve a static Proof Room bundle.
    Serve {
        /// Proof Room bundle directory.
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,

        /// Listen address for the static server.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,

        /// Validate and print the serving report without opening a server.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Export a verified proof bundle as a tar archive.
    Export {
        /// Proof bundle directory.
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,

        /// Output .tgz, .tar.gz, or .tar.zst file path.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,

        /// Redaction profile to apply before writing the archive.
        #[arg(long, value_enum)]
        redact: Option<ProofExportRedactProfile>,
    },

    /// Check proof evidence required for a proof scenario.
    Doctor {
        /// Proof scenario to check.
        #[arg(long, value_enum)]
        scenario: Option<ProofDoctorScenario>,

        /// Workspace root containing fixtures and proof evidence.
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum CommerceCommands {
    /// Verify a commerce Transaction Passport proof bundle.
    Verify {
        /// Proof bundle directory, exported archive, or transaction-passport.json path.
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Write the verifier report to this JSON file.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProofCollectKind {
    AgentWebEnvelope,
    BuyerPackage,
    DisclosureAgentWebEnvelope,
    Evidence,
    IoaWeb3,
    Replay,
    TransactionPassport,
    RuntimeSpine,
}

impl ProofCollectKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AgentWebEnvelope => "agent-web-envelope",
            Self::BuyerPackage => "buyer-package",
            Self::DisclosureAgentWebEnvelope => "disclosure-agent-web-envelope",
            Self::Evidence => "evidence",
            Self::IoaWeb3 => "ioa-web3",
            Self::Replay => "replay",
            Self::TransactionPassport => "transaction-passport",
            Self::RuntimeSpine => "runtime-spine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProofExportRedactProfile {
    AdminFullEvidenceV1,
    Public,
}

impl ProofExportRedactProfile {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AdminFullEvidenceV1 => "admin-full-evidence-v1",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProofVerifyRequirement {
    Commerce,
    Delegation,
    Denials,
    Disclosure,
    Enterprise,
    ExternalEnvelope,
    Risk,
    Runtime,
    RuntimeParity,
    Settlement,
    TrustMarket,
}

impl ProofVerifyRequirement {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Commerce => "commerce",
            Self::Delegation => "delegation",
            Self::Denials => "denials",
            Self::Disclosure => "disclosure",
            Self::Enterprise => "enterprise",
            Self::ExternalEnvelope => "external-envelope",
            Self::Risk => "risk",
            Self::Runtime => "runtime",
            Self::RuntimeParity => "runtime-parity",
            Self::Settlement => "settlement",
            Self::TrustMarket => "trust-market",
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum ProofFixtureCommands {
    /// List built-in proof fixtures.
    List,

    /// Generate a built-in proof fixture into a directory.
    Generate {
        /// Fixture id to generate.
        fixture_id: String,

        /// Output directory.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ProofDoctorScenario {
    AgentWebInterop,
    CommercePayments,
    DisclosureLineage,
    EnterpriseExport,
    #[value(name = "proof-package", alias = "launch-package")]
    ProofPackage,
    PublicSettlement,
    RuntimeSecurity,
    SingleCallAuthority,
    SwarmAuthority,
    TrustMarket,
    WorkflowPreflight,
}

impl ProofDoctorScenario {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AgentWebInterop => "agent-web-interop",
            Self::CommercePayments => "commerce-payments",
            Self::DisclosureLineage => "disclosure-lineage",
            Self::EnterpriseExport => "enterprise-export",
            Self::ProofPackage => "proof-package",
            Self::PublicSettlement => "public-settlement",
            Self::RuntimeSecurity => "runtime-security",
            Self::SingleCallAuthority => "single-call-authority",
            Self::SwarmAuthority => "swarm-authority",
            Self::TrustMarket => "trust-market",
            Self::WorkflowPreflight => "workflow-preflight",
        }
    }
}
