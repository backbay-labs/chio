use super::*;

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
