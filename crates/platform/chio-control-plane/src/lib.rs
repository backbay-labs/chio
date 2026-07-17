#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use std::fs;
use std::path::Path;

use chio_core::crypto::Keypair;
use chio_errors::_generated::error_codes::{
    ATTEST_PROVENANCE_MISSING, CAPABILITY_SCOPE_EXCEEDED, CAPABILITY_SUBJECT_MISMATCH, CLI_IO,
    CLI_JSON, CLI_OTHER, CLI_YAML, GUARD_DENIED, GUARD_WASM_TRAP, MANIFEST_SCHEMA_INVALID,
    MANIFEST_SIGNATURE_INVALID, POLICY_CONSTRAINT_INVALID, POLICY_DECISION_DENIED,
    PROVIDER_TOOL_SERVER_ERROR, REPLAY_DETERMINISTIC_MISMATCH, REPLAY_FIXTURE_DRIFT,
    REPLAY_TRACE_NOT_FOUND, TRANSPORT_HTTP_FAILED, TRANSPORT_INVALID_REQUEST_SHAPE,
};
use chio_errors::{ChioError, ErrorCodeSpec};
use chio_kernel::transport::TransportError;
use chio_kernel::{ChioKernel, KernelConfig, StructuredErrorReport};

pub use chio_agent_web_interop as agent_web;
pub mod attestation;
pub mod certify;
pub use chio_enterprise_export as enterprise_export;
pub mod enterprise_federation;
pub mod evidence_export;
pub mod federation_policy;
pub mod issuance;
pub mod passport_verifier;
pub mod policy;
pub mod reputation;
pub use chio_risk_comptroller as risk_comptroller;
pub mod scim_lifecycle;
pub mod seller_rail;
pub use chio_commerce_order as commerce_order;
pub use chio_transaction_passport as transaction_passport;
pub mod transaction_passport_risk;
pub mod trust_control;
pub use chio_trust_market_context as trust_market;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
pub enum JwtProviderProfile {
    Generic,
    Auth0,
    Okta,
    AzureAd,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Core(#[from] chio_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] chio_mcp_adapter::edge::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] chio_kernel::CheckpointError),

    #[error("evidence export error: {0}")]
    EvidenceExport(#[from] chio_kernel::EvidenceExportError),

    #[error("credential error: {0}")]
    Credential(#[from] chio_credentials::CredentialError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] chio_kernel::ReceiptStoreError),

    #[error("conformance load error: {0}")]
    ConformanceLoad(#[from] chio_conformance::LoadError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] chio_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] chio_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] chio_kernel::BudgetStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Chio(#[from] ChioError),

    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn registry_error(spec: &'static ErrorCodeSpec, message: impl Into<String>) -> Self {
        Self::Chio(ChioError::from_spec(spec, message))
    }

    pub fn capability_error(message: impl Into<String>) -> Self {
        Self::cli_other_error(message)
    }

    pub fn capability_scope_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SCOPE_EXCEEDED, message)
    }

    pub fn capability_subject_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SUBJECT_MISMATCH, message)
    }

    pub fn policy_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_DECISION_DENIED, message)
    }

    pub fn policy_constraint_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_CONSTRAINT_INVALID, message)
    }

    pub fn guard_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_DENIED, message)
    }

    pub fn guard_wasm_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_WASM_TRAP, message)
    }

    pub fn replay_trace_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_TRACE_NOT_FOUND, message)
    }

    pub fn replay_mismatch_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_DETERMINISTIC_MISMATCH, message)
    }

    pub fn replay_fixture_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_FIXTURE_DRIFT, message)
    }

    pub fn provider_error(message: impl Into<String>) -> Self {
        Self::registry_error(&PROVIDER_TOOL_SERVER_ERROR, message)
    }

    pub fn attest_error(message: impl Into<String>) -> Self {
        Self::registry_error(&ATTEST_PROVENANCE_MISSING, message)
    }

    pub fn manifest_schema_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SCHEMA_INVALID, message)
    }

    pub fn manifest_signature_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SIGNATURE_INVALID, message)
    }

    pub fn transport_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_HTTP_FAILED, message)
    }

    pub fn transport_shape_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_INVALID_REQUEST_SHAPE, message)
    }

    pub fn cli_io_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_IO, message)
    }

    pub fn cli_json_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_JSON, message)
    }

    pub fn cli_yaml_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_YAML, message)
    }

    pub fn cli_other_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_OTHER, message)
    }

    fn report_with_context(
        &self,
        code: &str,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> StructuredErrorReport {
        StructuredErrorReport::new(code, self.to_string(), context, suggested_fix)
    }

    pub fn report(&self) -> StructuredErrorReport {
        match self {
            Self::Core(error) => self.report_with_context(
                "CHIO-CLI-CORE",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the Chio artifact or request payload that triggered the core validation failure and correct it before retrying.",
            ),
            Self::Policy(error) => self.report_with_context(
                "CHIO-CLI-POLICY",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the policy file contents or path so the requested command can load a valid policy document.",
            ),
            Self::Adapter(error) => self.report_with_context(
                "CHIO-CLI-ADAPTER",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the MCP adapter configuration and upstream server compatibility before retrying.",
            ),
            Self::Kernel(error) => error.report(),
            Self::Checkpoint(error) => self.report_with_context(
                "CHIO-CLI-CHECKPOINT",
                serde_json::json!({ "source": error.to_string() }),
                "Check the checkpoint input and configured receipt store, then retry once the checkpoint lane is valid.",
            ),
            Self::EvidenceExport(error) => self.report_with_context(
                "CHIO-CLI-EVIDENCE-EXPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the evidence export inputs, output path, and receipt-store state before retrying.",
            ),
            Self::Credential(error) => self.report_with_context(
                "CHIO-CLI-CREDENTIAL",
                serde_json::json!({ "source": error.to_string() }),
                "Validate the credential, issuer, and subject inputs before retrying the command.",
            ),
            Self::ReceiptStore(error) => self.report_with_context(
                "CHIO-CLI-RECEIPT-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured receipt store path, permissions, and schema health before retrying.",
            ),
            Self::ConformanceLoad(error) => self.report_with_context(
                "CHIO-CLI-CONFORMANCE-LOAD",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the conformance corpus path or file contents so the requested scenarios can be loaded successfully.",
            ),
            Self::RevocationStore(error) => self.report_with_context(
                "CHIO-CLI-REVOCATION-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured revocation store path, permissions, and schema health before retrying.",
            ),
            Self::AuthorityStore(error) => self.report_with_context(
                "CHIO-CLI-AUTHORITY-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured authority store path, permissions, and schema health before retrying.",
            ),
            Self::BudgetStore(error) => self.report_with_context(
                "CHIO-CLI-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured budget store path, permissions, and schema health before retrying.",
            ),
            Self::Sqlite(error) => self.report_with_context(
                "CHIO-CLI-SQLITE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the SQLite path, file permissions, and database schema state before retrying.",
            ),
            Self::Transport(error) => self.report_with_context(
                "CHIO-CLI-TRANSPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Verify the remote endpoint or subprocess transport is reachable and speaking the expected protocol.",
            ),
            Self::Io(error) => self.report_with_context(
                "CHIO-CLI-IO",
                serde_json::json!({ "source": error.to_string() }),
                "Check file paths, permissions, and parent directories before retrying.",
            ),
            Self::Json(error) => self.report_with_context(
                "CHIO-CLI-JSON",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the JSON input so it is syntactically valid and matches the expected Chio schema.",
            ),
            Self::Yaml(error) => self.report_with_context(
                "CHIO-CLI-YAML",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the YAML syntax or schema mismatch in the provided configuration before retrying.",
            ),
            Self::Reqwest(error) => self.report_with_context(
                "CHIO-CLI-HTTP",
                serde_json::json!({ "source": error.to_string() }),
                "Check network reachability, TLS settings, and remote endpoint availability before retrying.",
            ),
            Self::Chio(error) => {
                let diagnostic = error.diagnostic();
                let spec = diagnostic.registry_spec();
                StructuredErrorReport::new(
                    diagnostic.code().as_str(),
                    diagnostic.message(),
                    serde_json::json!({
                        "domain": diagnostic.domain().as_str(),
                        "severity": diagnostic.severity().as_str(),
                        "string_code": spec.map(|entry| entry.string_code),
                        "stability": spec.map(|entry| entry.stability),
                    }),
                    diagnostic
                        .help()
                        .or_else(|| spec.map(|entry| entry.help))
                        .unwrap_or(
                            "Inspect the Chio diagnostic and retry after correcting the request.",
                        ),
                )
            }
            Self::Other(message) => self.report_with_context(
                "CHIO-CLI-OTHER",
                serde_json::json!({ "detail": message }),
                "Read the error detail, correct the conflicting inputs or missing prerequisite, and retry the command.",
            ),
        }
    }
}

pub fn build_kernel(loaded_policy: policy::LoadedPolicy, kernel_kp: &Keypair) -> ChioKernel {
    let policy::LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        post_invocation_pipeline,
        runtime_assurance_policy,
        ..
    } = loaded_policy;

    let config = KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: kernel_policy.delegation_depth_limit,
        policy_hash: identity.runtime_hash,
        allow_sampling: kernel_policy.allow_sampling,
        allow_sampling_tool_use: kernel_policy.allow_sampling_tool_use,
        allow_elicitation: kernel_policy.allow_elicitation,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: kernel_policy.require_web3_evidence,
        allow_ephemeral_receipt_log: kernel_policy.allow_ephemeral_receipt_log,
        allow_ephemeral_revocation_store: kernel_policy.allow_ephemeral_revocation_store,
        checkpoint_batch_size: kernel_policy.checkpoint_batch_size,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: kernel_policy.dispatch_intent_journal,
    };

    let mut kernel = ChioKernel::new(config);

    let default_guard_profile = chio_guards::default_runtime_guard_profile();
    if !default_guard_profile.pre_invocation_guards.is_empty() {
        tracing::info!(
            guard_count = default_guard_profile.pre_invocation_guards.len(),
            "registering default runtime guard profile"
        );
        for guard in default_guard_profile.pre_invocation_guards {
            kernel.add_guard(guard);
        }
    }

    if !guard_pipeline.is_empty() {
        tracing::info!(
            guard_count = guard_pipeline.len(),
            "registering guard pipeline"
        );
        kernel.add_guard(Box::new(guard_pipeline));
    }

    let mut post_invocation_pipeline = post_invocation_pipeline;
    post_invocation_pipeline.append(default_guard_profile.post_invocation_pipeline);

    if !post_invocation_pipeline.is_empty() {
        tracing::info!(
            hook_count = post_invocation_pipeline.len(),
            "registering post-invocation pipeline"
        );
        kernel.set_post_invocation_pipeline(post_invocation_pipeline);
    }

    if let Some(attestation_trust_policy) =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy)
    {
        kernel.set_attestation_trust_policy(attestation_trust_policy);
    }

    kernel
}

pub fn configure_receipt_store(
    kernel: &mut ChioKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            // An in-memory SQLite path (`:memory:`, `file::memory:`, or a
            // `?mode=memory` URI) opens a database that is discarded when the
            // process exits. Attaching it here would satisfy the kernel's
            // receipt-persistence gate (`receipt_store.is_some()`) while silently
            // losing every receipt on restart, so refuse it: durable receipts
            // require a filesystem path, and an intentionally ephemeral log is
            // requested by omitting the path and setting
            // `allow_ephemeral_receipt_log` in policy.
            if path
                .to_str()
                .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
            {
                return Err(CliError::cli_other_error(
                    "refusing to attach an in-memory receipt database as a durable store: an \
                     in-memory SQLite path loses every receipt on restart. Point --receipt-db at \
                     a filesystem path for durable receipts, or omit it and set \
                     allow_ephemeral_receipt_log in policy to run with an in-memory receipt log."
                        .to_string(),
                ));
            }
            kernel
                .set_receipt_store(Box::new(chio_store_sqlite::SqliteReceiptStore::open(path)?))?;
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_receipt_store(
                trust_control::service_runtime::remote_stores::build_remote_receipt_store(
                    url, token,
                )?,
            )?;
        }
        (None, None) => {}
    }
    kernel.validate_web3_evidence_prerequisites()?;
    Ok(())
}

pub fn configure_revocation_store(
    kernel: &mut ChioKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(chio_store_sqlite::SqliteRevocationStore::open(
                path,
            )?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(
                trust_control::service_runtime::remote_stores::build_remote_revocation_store(
                    url, token,
                )?,
            );
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn configure_capability_authority(
    kernel: &mut ChioKernel,
    default_authority_keypair: &Keypair,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<policy::RuntimeAssuranceIssuancePolicy>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::cli_other_error(
            "use either local authority flags or --control-url, not both".to_string(),
        ));
    }
    if let Some(url) = control_url {
        if issuance_policy.is_some() || runtime_assurance_policy.is_some() {
            return Err(CliError::cli_other_error(
                "policy-gated issuance must be enforced by the trust-control service itself; start `chio trust serve --policy <path>` instead of relying on client-side --control-url issuance".to_string(),
            ));
        }
        let token = require_control_token(control_token)?;
        kernel.set_capability_authority(
            trust_control::service_runtime::remote_authority::build_remote_capability_authority(
                url, token,
            )?,
        );
        return Ok(());
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(chio_kernel::LocalCapabilityAuthority::new(keypair)),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, Some(path)) => {
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(chio_store_sqlite::SqliteCapabilityAuthority::open(path)?),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, None) => {
            if issuance_policy.is_some()
                || runtime_assurance_policy.is_some()
                || receipt_db_path.is_some()
            {
                kernel.set_capability_authority(issuance::wrap_capability_authority(
                    Box::new(chio_kernel::LocalCapabilityAuthority::new(
                        default_authority_keypair.clone(),
                    )),
                    issuance_policy,
                    runtime_assurance_policy,
                    receipt_db_path,
                    budget_db_path,
                ));
            }
        }
    }
    Ok(())
}

pub fn configure_budget_store(
    kernel: &mut ChioKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(chio_store_sqlite::SqliteBudgetStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(
                trust_control::service_runtime::budget::build_remote_budget_store(url, token)?,
            );
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::cli_other_error(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<chio_core::PublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(seed_hex) => Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub fn rotate_authority_keypair(path: &Path) -> Result<chio_core::PublicKey, CliError> {
    let keypair = Keypair::generate();
    write_authority_seed_file(path, &keypair)?;
    Ok(keypair.public_key())
}

pub fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    match authority_public_key_from_seed_file(path)? {
        Some(_) => {
            let seed_hex = fs::read_to_string(path)?;
            Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
        }
        None => {
            let keypair = Keypair::generate();
            write_authority_seed_file(path, &keypair)?;
            Ok(keypair)
        }
    }
}

pub fn issue_default_capabilities(
    kernel: &ChioKernel,
    agent_pk: &chio_core::PublicKey,
    default_capabilities: &[policy::DefaultCapability],
) -> Result<Vec<chio_core::capability::token::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to issue initial capability: {error}"
                    ))
                })
        })
        .collect()
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, format!("{}\n", keypair.seed_hex()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temp_path, path)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_guards::PostInvocationPipeline;

    fn make_kernel(require_web3_evidence: bool) -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "control-plane-test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
        })
    }

    fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn assert_registry_error(
        err: &CliError,
        expected: &'static ErrorCodeSpec,
        expected_domain: &str,
    ) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected.urn);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    #[test]
    fn migrated_cli_error_helpers_emit_registry_codes_and_domains() {
        let cases = [
            (
                CliError::manifest_signature_error("bad manifest signature"),
                &MANIFEST_SIGNATURE_INVALID,
                "manifest",
            ),
            (
                CliError::manifest_schema_error("bad manifest schema"),
                &MANIFEST_SCHEMA_INVALID,
                "manifest",
            ),
            (
                CliError::guard_error("guard denied request"),
                &GUARD_DENIED,
                "guard",
            ),
            (
                CliError::replay_mismatch_error("replay diverged"),
                &REPLAY_DETERMINISTIC_MISMATCH,
                "replay",
            ),
            (
                CliError::provider_error("provider adapter failed"),
                &PROVIDER_TOOL_SERVER_ERROR,
                "provider",
            ),
            (
                CliError::cli_io_error("could not read input"),
                &CLI_IO,
                "cli",
            ),
            (
                CliError::cli_yaml_error("could not parse yaml"),
                &CLI_YAML,
                "cli",
            ),
        ];

        for (err, expected, expected_domain) in cases {
            assert_registry_error(&err, expected, expected_domain);
        }
    }

    #[test]
    fn cli_error_report_rejects_mismatched_registry_metadata() {
        let spec = &chio_errors::_generated::error_codes::CAPABILITY_EXPIRED;
        let error = CliError::Chio(
            chio_errors::diagnostic(
                spec.urn,
                chio_errors::Domain::Manifest,
                spec.severity,
                "registered code with mismatched diagnostic domain",
            )
            .into_error(),
        );

        let report = error.report();

        assert_eq!(report.code, spec.urn);
        assert_eq!(report.context["domain"], "manifest");
        assert_eq!(report.context["severity"], spec.severity.as_str());
        assert_eq!(report.context["string_code"], serde_json::Value::Null);
        assert_eq!(report.context["stability"], serde_json::Value::Null);
        assert_eq!(
            report.suggested_fix,
            "Inspect the Chio diagnostic and retry after correcting the request."
        );
    }

    #[test]
    fn web3_evidence_requires_local_receipt_store() {
        let mut kernel = make_kernel(true);

        let error = configure_receipt_store(&mut kernel, None, None, None).unwrap_err();
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
    }

    #[test]
    fn configure_receipt_store_refuses_in_memory_sqlite_paths() {
        // Every in-memory SQLite spelling must be refused so no store-wiring
        // caller can attach an ephemeral database while claiming durable
        // receipts. A durable filesystem path is accepted so the guard does not
        // over-reject real receipt databases.
        for path in [
            ":memory:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
        ] {
            let mut kernel = make_kernel(false);
            let error = configure_receipt_store(&mut kernel, Some(Path::new(path)), None, None)
                .unwrap_err();
            assert!(
                error.to_string().contains("in-memory receipt database"),
                "{path} must be refused as a non-durable receipt store, got: {error}"
            );
        }

        let durable = unique_receipt_db_path("chio-control-plane-durable-receipts");
        let mut kernel = make_kernel(false);
        configure_receipt_store(&mut kernel, Some(&durable), None, None)
            .expect("durable filesystem receipt path must be accepted");
        let _ = std::fs::remove_file(durable);
    }

    #[test]
    fn web3_evidence_accepts_checkpoint_capable_sqlite_receipt_store() {
        let path = unique_receipt_db_path("chio-control-plane-web3-evidence");
        let mut kernel = make_kernel(true);

        configure_receipt_store(&mut kernel, Some(&path), None, None).unwrap();
        kernel.validate_web3_evidence_prerequisites().unwrap();

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web3_evidence_rejects_remote_append_only_receipt_store() {
        let mut kernel = make_kernel(true);

        let error = configure_receipt_store(
            &mut kernel,
            None,
            Some("http://127.0.0.1:8080"),
            Some("test-token"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
        assert!(error
            .to_string()
            .contains("append-only remote receipt mirrors are unsupported"));
    }

    #[test]
    fn cli_error_report_passes_through_kernel_metadata() {
        let report = CliError::Kernel(chio_kernel::KernelError::OutOfScope {
            tool: "read_file".to_string(),
            server: "fs".to_string(),
        })
        .report();

        assert_eq!(report.code, "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
        assert_eq!(report.context["tool"], "read_file");
        assert_eq!(report.context["server"], "fs");
        assert!(report
            .suggested_fix
            .contains("Issue a capability that grants this tool"));
    }

    #[test]
    fn cli_error_report_captures_io_context() {
        let report = CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing file",
        ))
        .report();

        assert_eq!(report.code, "CHIO-CLI-IO");
        assert!(report.message.contains("i/o error"));
        assert!(report.context["source"]
            .as_str()
            .expect("io source string")
            .contains("missing file"));
        assert!(report.suggested_fix.contains("Check file paths"));
    }

    #[test]
    fn build_kernel_registers_post_invocation_pipeline() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: {
                let mut pipeline = PostInvocationPipeline::new();
                pipeline.add(Box::new(chio_guards::SanitizerHook::new()));
                pipeline
            },
            issuance_policy: None,
            runtime_assurance_policy: None,
        };

        let kernel = build_kernel(loaded_policy, &keypair);
        assert_eq!(kernel.post_invocation_hook_count(), 2);
    }

    #[test]
    fn build_kernel_registers_default_guard_profile() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: PostInvocationPipeline::new(),
            issuance_policy: None,
            runtime_assurance_policy: None,
        };

        let kernel = build_kernel(loaded_policy, &keypair);

        assert!(kernel.guard_count() >= 2);
        assert!(kernel.post_invocation_hook_count() >= 1);
    }
}
