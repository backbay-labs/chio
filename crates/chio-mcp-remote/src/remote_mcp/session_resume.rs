#[derive(Serialize)]
struct RemoteAuthContractFingerprint {
    mode: &'static str,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: String,
    static_token_fingerprint: Option<String>,
    verification_key_identity: Option<String>,
    discovery_url: Option<String>,
    introspection_url: Option<String>,
    enterprise_provider_registry_hash: Option<String>,
}

fn enterprise_provider_registry_hash(path: Option<&FsPath>) -> Result<Option<String>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = std::fs::read(path)?;
    Ok(Some(sha256_hex(&bytes)))
}

fn fingerprint_remote_auth_contract(config: &RemoteServeHttpConfig) -> Result<String, CliError> {
    let provider_profile = config
        .auth_jwt_provider_profile
        .unwrap_or(JwtProviderProfile::Generic);
    let enterprise_provider_registry_hash =
        enterprise_provider_registry_hash(config.enterprise_providers_file.as_deref())?;
    let fingerprint = if let Some(token) = config.auth_token.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "static_bearer",
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: Some(sha256_hex(token.as_bytes())),
            verification_key_identity: None,
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    } else if let Some(seed_path) = config.auth_server_seed_path.as_deref() {
        let verification_key_identity = authority_public_key_from_seed_file(seed_path)?
            .map(|public_key| public_key.to_hex())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "auth server seed file `{}` did not yield a public key",
                    seed_path.display()
                ))
            })?;
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: Some(verification_key_identity),
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    } else if let Some(introspection_url) = config.auth_introspection_url.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "introspection_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: None,
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: Some(introspection_url.to_string()),
            enterprise_provider_registry_hash,
        }
    } else {
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: config.auth_jwt_public_key.clone(),
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    };

    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        CliError::cli_other_error(format!("serialize auth contract fingerprint: {error}"))
    })?;
    Ok(sha256_hex(&encoded))
}

fn fingerprint_remote_policy_contract(loaded_policy: &LoadedPolicy) -> Result<String, CliError> {
    let fingerprint = json!({
        "format": loaded_policy.format_name(),
        "identity": {
            "source_hash": loaded_policy.identity.source_hash,
            "runtime_hash": loaded_policy.identity.runtime_hash,
        },
        "default_capabilities": loaded_policy.default_capabilities,
        "issuance_policy": loaded_policy.issuance_policy,
        "runtime_assurance_policy": loaded_policy.runtime_assurance_policy,
    });
    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        CliError::cli_other_error(format!(
            "serialize resumable policy contract fingerprint: {error}"
        ))
    })?;
    Ok(sha256_hex(&encoded))
}

fn derive_session_agent_keypair(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Keypair, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(Keypair::generate());
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => derive_federated_agent_keypair(seed_path, principal),
        _ => Ok(Keypair::generate()),
    }
}

#[derive(Serialize)]
struct RemoteSessionResumeIntegrityEnvelope<'a> {
    session_id: &'a str,
    agent_id: &'a str,
    auth_context: &'a SessionAuthContext,
    auth_mode_fingerprint: Option<&'a str>,
    policy_fingerprint: Option<&'a str>,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle: &'a RemoteSessionLifecycleSnapshot,
    protocol_version: Option<&'a str>,
    initialize_params: &'a Value,
    issued_capabilities: &'a [CapabilityToken],
}

fn derive_resume_integrity_seed_from_secret(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REMOTE_SESSION_RESUME_INTEGRITY_LABEL);
    hasher.update([0u8]);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn derive_resume_record_integrity_seed(
    config: &RemoteServeHttpConfig,
) -> Result<Option<[u8; 32]>, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let authority = chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let keypair = authority
            .local_keypair()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        return Ok(Some(keypair.seed_bytes()));
    }
    if let Some(seed_path) = [
        config.authority_seed_path.as_deref(),
        config.auth_server_seed_path.as_deref(),
        config.identity_federation_seed_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .next()
    {
        let keypair = load_or_create_authority_keypair(seed_path)?;
        return Ok(Some(keypair.seed_bytes()));
    }
    if let Some(secret) = config.control_token.as_deref() {
        return Ok(Some(derive_resume_integrity_seed_from_secret(
            secret.as_bytes(),
        )));
    }
    if let Some(secret) = config.auth_token.as_deref() {
        return Ok(Some(derive_resume_integrity_seed_from_secret(
            secret.as_bytes(),
        )));
    }
    Ok(None)
}

fn expected_resume_agent_id(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Option<String>, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(None);
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => Ok(Some(
            derive_federated_agent_keypair(seed_path, principal)?
                .public_key()
                .to_hex(),
        )),
        _ => Ok(None),
    }
}

fn compute_resume_record_integrity_tag(
    seed: &[u8; 32],
    record: &RemoteSessionResumeRecord,
) -> Result<String, CliError> {
    let envelope = RemoteSessionResumeIntegrityEnvelope {
        session_id: &record.session_id,
        agent_id: &record.agent_id,
        auth_context: &record.auth_context,
        auth_mode_fingerprint: record.auth_mode_fingerprint.as_deref(),
        policy_fingerprint: record.policy_fingerprint.as_deref(),
        hosted_isolation: record.hosted_isolation,
        lifecycle: &record.lifecycle,
        protocol_version: record.protocol_version.as_deref(),
        initialize_params: &record.initialize_params,
        issued_capabilities: &record.issued_capabilities,
    };
    let canonical = canonical_json_bytes(&envelope)
        .map_err(|error| CliError::cli_other_error(format!("serialize resumable session envelope: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(REMOTE_SESSION_RESUME_INTEGRITY_LABEL);
    hasher.update([0u8]);
    hasher.update(seed);
    hasher.update([0u8]);
    hasher.update(&canonical);
    Ok(sha256_hex(&hasher.finalize()))
}

fn validate_resume_record_integrity(
    config: &RemoteServeHttpConfig,
    record: &RemoteSessionResumeRecord,
) -> Result<(), CliError> {
    let Some(stored_tag) = record.resume_integrity_tag.as_deref() else {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} predates resumable integrity binding and must be re-initialized",
            record.session_id
        )));
    };
    let Some(seed) = derive_resume_record_integrity_seed(config)? else {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} cannot be restored because this server has no local secret material for resumable session integrity",
            record.session_id
        )));
    };
    let expected_tag = compute_resume_record_integrity_tag(&seed, record)?;
    if stored_tag != expected_tag {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} failed resumable integrity validation",
            record.session_id
        )));
    }
    Ok(())
}

fn validate_restored_peer_capabilities(
    record: &RemoteSessionResumeRecord,
) -> Result<PeerCapabilities, CliError> {
    let derived = parse_remote_session_peer_capabilities(&record.initialize_params);
    if derived != record.peer_capabilities {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} failed peer capability re-validation against initialize params",
            record.session_id
        )));
    }
    Ok(derived)
}
