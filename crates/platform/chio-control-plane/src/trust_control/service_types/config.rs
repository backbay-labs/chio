use super::*;

#[derive(Clone)]
pub struct TrustFiscalRuntimeConfig {
    pub genesis_policy: chio_fiscal::FiscalGenesisPolicy,
    pub anchor_url: String,
    pub anchor_bearer_token: String,
    pub anchor_timeout: Duration,
    pub admission_authority_id: String,
    pub admission_signer_key_epoch: u64,
    pub admission_signing_seed_path: PathBuf,
}

impl std::fmt::Debug for TrustFiscalRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustFiscalRuntimeConfig")
            .field("policy_id", &self.genesis_policy.policy_id)
            .field("anchor_url", &self.anchor_url)
            .field("anchor_bearer_token", &"[REDACTED]")
            .field("anchor_timeout", &self.anchor_timeout)
            .field("admission_authority_id", &self.admission_authority_id)
            .field(
                "admission_signer_key_epoch",
                &self.admission_signer_key_epoch,
            )
            .field(
                "admission_signing_seed_path",
                &self.admission_signing_seed_path,
            )
            .finish()
    }
}

impl TrustFiscalRuntimeConfig {
    pub fn from_policy_file(
        policy_path: &Path,
        anchor_url: String,
        anchor_bearer_token: String,
        anchor_timeout: Duration,
        admission_authority_id: String,
        admission_signer_key_epoch: u64,
        admission_signing_seed_path: PathBuf,
    ) -> Result<Self, CliError> {
        let bytes = std::fs::read(policy_path).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to read fiscal genesis policy {}: {error}",
                policy_path.display()
            ))
        })?;
        let genesis_policy = serde_json::from_slice(&bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to parse fiscal genesis policy {}: {error}",
                policy_path.display()
            ))
        })?;
        Ok(Self {
            genesis_policy,
            anchor_url,
            anchor_bearer_token,
            anchor_timeout,
            admission_authority_id,
            admission_signer_key_epoch,
            admission_signing_seed_path,
        })
    }
}

#[derive(Clone)]
pub struct TrustServiceConfig {
    pub listen: SocketAddr,
    pub service_token: String,
    pub tenant_read_tokens: BTreeMap<String, String>,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub joint_authority_db_path: Option<PathBuf>,
    pub fiscal_runtime: Option<TrustFiscalRuntimeConfig>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub federation_policies_file: Option<PathBuf>,
    pub scim_lifecycle_file: Option<PathBuf>,
    pub verifier_policies_file: Option<PathBuf>,
    pub verifier_challenge_db_path: Option<PathBuf>,
    pub passport_statuses_file: Option<PathBuf>,
    pub passport_issuance_offers_file: Option<PathBuf>,
    pub certification_registry_file: Option<PathBuf>,
    pub certification_discovery_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<crate::policy::RuntimeAssuranceIssuancePolicy>,
    pub advertise_url: Option<String>,
    pub allow_local_peer_urls: bool,
    pub certification_public_metadata_ttl_seconds: u64,
    pub peer_urls: Vec<String>,
    pub cluster_sync_interval: Duration,
    pub roster_policy: Option<RosterPolicy>,
    /// Process memory budget for the trust control service. Its
    /// `admission_key_cap` bounds the federation admission rate limiter, so
    /// lowering it here actually tightens that guard rather than being silently
    /// overridden by the compiled-in default.
    pub memory_budget: chio_kernel::MemoryBudgetConfig,
}

impl TrustServiceConfig {
    pub fn validate(&self) -> Result<(), CliError> {
        validate_control_secret(&self.service_token, "control service token")?;
        for (tenant_id, token) in &self.tenant_read_tokens {
            if tenant_id.trim().is_empty() {
                return Err(CliError::cli_other_error(
                    "tenant read token id must be non-empty".to_string(),
                ));
            }
            if tenant_id.trim() != tenant_id {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain surrounding whitespace".to_string(),
                ));
            }
            if tenant_id.chars().any(char::is_control) {
                return Err(CliError::cli_other_error(
                    "tenant read token id must not contain control characters".to_string(),
                ));
            }
            let token_label = format!("tenant read token for `{tenant_id}`");
            validate_control_secret(token, &token_label)?;
            if token == &self.service_token {
                return Err(CliError::cli_other_error(
                    "control tenant read token must not equal service token".to_string(),
                ));
            }
        }
        if self.cluster_sync_interval.is_zero() {
            return Err(CliError::cli_other_error(
                "cluster sync interval must be non-zero".to_string(),
            ));
        }
        if self.certification_public_metadata_ttl_seconds == 0 {
            return Err(CliError::cli_other_error(
                "certification public metadata TTL must be non-zero".to_string(),
            ));
        }
        if self.joint_authority_db_path.is_some()
            && (self.budget_db_path.is_some() || self.revocation_db_path.is_some())
        {
            return Err(CliError::cli_other_error(
                "a joint authority database replaces separate budget and revocation databases"
                    .to_string(),
            ));
        }
        if self.joint_authority_db_path.is_some() && !self.peer_urls.is_empty() {
            return Err(CliError::cli_other_error(
                "a local joint authority database cannot run with the legacy cluster coordinator"
                    .to_string(),
            ));
        }
        if let Some(fiscal) = &self.fiscal_runtime {
            if self.joint_authority_db_path.is_none() {
                return Err(CliError::cli_other_error(
                    "fiscal runtime requires the joint authority database".to_string(),
                ));
            }
            if fiscal.anchor_timeout.is_zero() {
                return Err(CliError::cli_other_error(
                    "fiscal anchor timeout must be non-zero".to_string(),
                ));
            }
            validate_control_secret(&fiscal.anchor_bearer_token, "fiscal anchor bearer token")?;
            if fiscal.admission_authority_id.trim().is_empty()
                || fiscal.admission_authority_id.trim() != fiscal.admission_authority_id
                || fiscal.admission_signer_key_epoch == 0
            {
                return Err(CliError::cli_other_error(
                    "fiscal admission authority configuration is invalid".to_string(),
                ));
            }
        }
        let mut database_paths = Vec::new();
        for (label, path) in [
            (
                "joint authority database",
                self.joint_authority_db_path.as_deref(),
            ),
            ("receipt database", self.receipt_db_path.as_deref()),
            ("revocation database", self.revocation_db_path.as_deref()),
            (
                "capability authority database",
                self.authority_db_path.as_deref(),
            ),
            ("budget database", self.budget_db_path.as_deref()),
            (
                "verifier challenge database",
                self.verifier_challenge_db_path.as_deref(),
            ),
        ] {
            if let Some(path) = path {
                database_paths.push((label, path));
            }
        }
        crate::validate_distinct_database_paths(&database_paths)?;
        Ok(())
    }
}

pub(crate) fn validate_control_secret(secret: &str, label: &str) -> Result<(), CliError> {
    if secret.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be non-empty"
        )));
    }
    if secret.trim() != secret {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain surrounding whitespace"
        )));
    }
    if secret.chars().any(char::is_control) {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod service_config_tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        let listen = match "127.0.0.1:0".parse() {
            Ok(addr) => addr,
            Err(error) => panic!("test listen address should parse: {error}"),
        };
        TrustServiceConfig {
            listen,
            service_token: "token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            joint_authority_db_path: None,
            fiscal_runtime: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: PUBLIC_DISCOVERY_TTL_SECS,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    fn fiscal_runtime_config() -> TrustFiscalRuntimeConfig {
        let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../spec/schemas/chio-fiscal/v1/fixtures/genesis-policy.positive.json");
        TrustFiscalRuntimeConfig::from_policy_file(
            &policy_path,
            "https://fiscal-anchor.example".to_owned(),
            "fiscal-anchor-token".to_owned(),
            Duration::from_secs(5),
            "fiscal-admission".to_owned(),
            1,
            PathBuf::from("fiscal-admission.seed"),
        )
        .test_expect("fiscal fixture config")
    }

    #[test]
    fn fiscal_runtime_config_is_redacted_and_requires_joint_authority() {
        let fiscal = fiscal_runtime_config();
        assert!(!format!("{fiscal:?}").contains("fiscal-anchor-token"));
        let mut config = base_config();
        config.fiscal_runtime = Some(fiscal);

        let error = config
            .validate()
            .test_expect_err("fiscal runtime without joint authority must fail");
        assert!(error
            .to_string()
            .contains("fiscal runtime requires the joint authority database"));
    }

    #[test]
    fn trust_service_config_rejects_padded_service_token_at_startup() {
        for token in [" token", "token "] {
            let mut config = base_config();
            config.service_token = token.to_string();

            let error = match config.validate() {
                Ok(()) => panic!("padded service token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("control service token must not contain surrounding whitespace"),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_split_stores_with_joint_authority() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("joint.sqlite3"));
        config.budget_db_path = Some(PathBuf::from("budget.sqlite3"));

        let error = config
            .validate()
            .test_expect_err("split budget store must conflict with joint authority");

        assert!(error
            .to_string()
            .contains("joint authority database replaces separate budget and revocation"));
    }

    #[test]
    fn trust_service_config_rejects_joint_authority_with_legacy_cluster() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("joint.sqlite3"));
        config.peer_urls = vec!["https://peer.example".to_string()];

        let error = config
            .validate()
            .test_expect_err("joint authority must not use the legacy cluster coordinator");

        assert!(error
            .to_string()
            .contains("joint authority database cannot run with the legacy cluster"));
    }

    #[test]
    fn trust_service_config_rejects_joint_authority_path_aliases() {
        let mut config = base_config();
        config.joint_authority_db_path = Some(PathBuf::from("authority.sqlite3"));
        config.receipt_db_path = Some(PathBuf::from("./authority.sqlite3"));

        let error = config
            .validate()
            .test_expect_err("joint authority must not alias the receipt store");

        assert!(error
            .to_string()
            .contains("joint authority database must not alias receipt database"));
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_tokens_at_startup() {
        for token in [" tenant-token", "tenant-token "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert("tenant-a".to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains(
                    "tenant read token for `tenant-a` must not contain surrounding whitespace"
                ),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_padded_tenant_read_token_ids_at_startup() {
        for tenant_id in [" tenant-a", "tenant-a "] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), "tenant-token".to_string());

            let error = match config.validate() {
                Ok(()) => panic!("padded tenant read token id should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("tenant read token id must not contain surrounding whitespace"),
                "unexpected error for tenant id `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_control_bearing_tenant_read_tokens_at_startup() {
        for (tenant_id, token) in [
            ("tenant-\na", "tenant-token"),
            ("tenant-a", "tenant\u{7f}token"),
        ] {
            let mut config = base_config();
            config
                .tenant_read_tokens
                .insert(tenant_id.to_string(), token.to_string());

            let error = match config.validate() {
                Ok(()) => panic!("control-bearing tenant read token should fail closed at startup"),
                Err(error) => error,
            };

            assert!(
                error.to_string().contains("control characters"),
                "unexpected error for tenant token mapping `{tenant_id:?}`: {error}",
            );
        }
    }

    #[test]
    fn trust_service_config_rejects_zero_public_certification_metadata_ttl() {
        let mut config = base_config();
        config.certification_public_metadata_ttl_seconds = 0;

        let error = config.validate().test_unwrap_err();

        assert!(
            error
                .to_string()
                .contains("certification public metadata TTL must be non-zero"),
            "unexpected zero TTL error: {error}",
        );
    }
}
