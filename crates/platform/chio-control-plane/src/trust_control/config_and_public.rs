use super::report_validation::authority_status_response;
use super::*;

#[path = "config_and_public/generic_listing.rs"]
mod generic_listing;

pub(crate) use generic_listing::{
    build_public_generic_listing_report, build_signed_generic_namespace,
    public_generic_registry_publisher,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevokeCapabilityRequest {
    pub(crate) capability_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCapabilityResponse {
    pub capability_id: String,
    pub revoked: bool,
    pub newly_revoked: bool,
}

pub fn serve(config: TrustServiceConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Liability, credential, and attestation artifacts can be deeply nested
        // during request validation and response serialization.
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to start async runtime: {error}"))
        })?;
    runtime.block_on(async move { service_runtime::serve_async(config).await })
}

pub(crate) fn load_enterprise_provider_registry(
    path: Option<&std::path::Path>,
    surface: &str,
) -> Result<Option<Arc<EnterpriseProviderRegistry>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let registry = EnterpriseProviderRegistry::load(path)?;
    for record in registry.providers.values() {
        if !record.validation_errors.is_empty() {
            warn!(
                surface,
                provider_id = %record.provider_id,
                errors = ?record.validation_errors,
                "enterprise provider record is invalid and will stay unavailable for admission"
            );
        }
    }
    Ok(Some(Arc::new(registry)))
}

pub(crate) fn load_verifier_policy_registry(
    path: Option<&std::path::Path>,
    surface: &str,
) -> Result<Option<Arc<VerifierPolicyRegistry>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let registry = VerifierPolicyRegistry::load(path)?;
    for document in registry.policies.values() {
        if let Err(error) =
            ensure_signed_passport_verifier_policy_active(document, unix_timestamp_now())
        {
            warn!(
                surface,
                policy_id = %document.body.policy_id,
                error = %error,
                "stored verifier policy is structurally valid but currently inactive"
            );
        }
    }
    Ok(Some(Arc::new(registry)))
}

fn configured_enterprise_provider_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.enterprise_providers_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "enterprise provider admin requires --enterprise-providers-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_federation_policy_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.federation_policies_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "permissionless federation administration requires --federation-policies-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_scim_lifecycle_registry_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.scim_lifecycle_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "scim lifecycle automation requires --scim-lifecycle-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_verifier_policy_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.verifier_policies_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "verifier policy administration requires --verifier-policies-file on the trust-control service"
                .to_string(),
        )
    })
}

pub(crate) fn configured_verifier_challenge_db_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.verifier_challenge_db_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "remote verifier challenge flows require --verifier-challenge-db on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_passport_status_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.passport_statuses_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "passport lifecycle administration requires --passport-statuses-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_passport_issuance_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.passport_issuance_offers_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "passport issuance requires --passport-issuance-offers-file on the trust-control service"
                .to_string(),
        )
    })
}

pub(crate) fn configured_passport_credential_issuer(
    config: &TrustServiceConfig,
) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "passport issuance requires --advertise-url on the trust-control service".to_string(),
        )
    })?;
    let passport_status_distribution = default_passport_status_distribution(config);
    let portable_signing_public_key =
        if config.authority_seed_path.is_some() || config.authority_db_path.is_some() {
            Some(resolve_oid4vp_verifier_signing_key(config)?.public_key())
        } else {
            None
        };
    default_oid4vci_passport_issuer_metadata_with_signing_key(
        advertise_url,
        passport_status_distribution,
        portable_signing_public_key.as_ref(),
    )
    .map_err(CliError::from)
}

fn configured_certification_registry_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.certification_registry_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "certification registry administration requires --certification-registry-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_certification_discovery_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.certification_discovery_file.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "certification discovery requires --certification-discovery-file on the trust-control service"
                .to_string(),
        )
    })
}

pub(crate) fn configured_public_certification_metadata(
    config: &TrustServiceConfig,
) -> Result<CertificationPublicMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "public certification metadata requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let registry_url = advertise_url.trim_end_matches('/').to_string();
    if registry_url.is_empty() {
        return Err(CliError::cli_other_error(
            "public certification metadata requires a non-empty advertise_url".to_string(),
        ));
    }
    let generated_at = unix_timestamp_now();
    Ok(CertificationPublicMetadata {
        schema: "chio.certify.discovery-metadata.v1".to_string(),
        generated_at,
        expires_at: generated_at.saturating_add(config.certification_public_metadata_ttl_seconds),
        publisher: crate::certify::CertificationPublicPublisher {
            publisher_id: registry_url.clone(),
            publisher_name: None,
            registry_url: registry_url.clone(),
        },
        public_resolve_path_template: format!(
            "{registry_url}/v1/public/certifications/resolve/{{tool_server_id}}"
        ),
        public_search_path: format!("{registry_url}{PUBLIC_CERTIFICATION_SEARCH_PATH}"),
        public_transparency_path: format!("{registry_url}{PUBLIC_CERTIFICATION_TRANSPARENCY_PATH}"),
        supported_profiles: vec![crate::certify::CertificationSupportedProfile {
            criteria_profile: "conformance-all-pass-v1".to_string(),
            evidence_profile: "conformance-report-bundle-v1".to_string(),
        }],
        discovery_informational_only: true,
    })
}

pub(crate) fn load_enterprise_provider_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, EnterpriseProviderRegistry), CliError> {
    let path = configured_enterprise_provider_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        EnterpriseProviderRegistry::load(&path)?
    } else {
        EnterpriseProviderRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_federation_policy_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, FederationAdmissionPolicyRegistry), CliError> {
    let path = configured_federation_policy_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        FederationAdmissionPolicyRegistry::load(&path)?
    } else {
        FederationAdmissionPolicyRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_scim_lifecycle_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, ScimLifecycleRegistry), CliError> {
    let path = configured_scim_lifecycle_registry_path(config)?.to_path_buf();
    let registry = ScimLifecycleRegistry::load(&path)?;
    Ok((path, registry))
}

pub(crate) fn load_verifier_policy_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, VerifierPolicyRegistry), CliError> {
    let path = configured_verifier_policy_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        VerifierPolicyRegistry::load(&path)?
    } else {
        VerifierPolicyRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_passport_issuance_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, PassportIssuanceOfferRegistry), CliError> {
    let path = configured_passport_issuance_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        PassportIssuanceOfferRegistry::load(&path)?
    } else {
        PassportIssuanceOfferRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_passport_status_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, PassportStatusRegistry), CliError> {
    let path = configured_passport_status_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        PassportStatusRegistry::load(&path)?
    } else {
        PassportStatusRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_certification_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, CertificationRegistry), CliError> {
    let path = configured_certification_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        CertificationRegistry::load(&path)?
    } else {
        CertificationRegistry::default()
    };
    Ok((path, registry))
}

pub(crate) fn load_certification_discovery_network_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, CertificationDiscoveryNetwork), CliError> {
    let path = configured_certification_discovery_path(config)?.to_path_buf();
    let network = CertificationDiscoveryNetwork::load(&path)?;
    Ok((path, network))
}

pub(crate) fn resolve_verifier_policy_for_challenge(
    registry: Option<&VerifierPolicyRegistry>,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<(Option<PassportVerifierPolicy>, Option<String>), CliError> {
    if let Some(policy) = challenge.policy.as_ref() {
        return Ok((Some(policy.clone()), Some("embedded".to_string())));
    }
    let Some(reference) = challenge.policy_ref.as_ref() else {
        return Ok((None, None));
    };
    let Some(registry) = registry else {
        return Err(CliError::cli_other_error(
            "verifier policy reference requires a configured verifier policy registry".to_string(),
        ));
    };
    let document = registry.active_policy(&reference.policy_id, now)?;
    if document.body.verifier != challenge.verifier {
        return Err(CliError::cli_other_error(format!(
            "verifier policy `{}` is bound to verifier `{}` but challenge expects `{}`",
            document.body.policy_id, document.body.verifier, challenge.verifier
        )));
    }
    Ok((
        Some(document.body.policy.clone()),
        Some(format!("registry:{}", document.body.policy_id)),
    ))
}

pub(crate) fn passport_lifecycle_reason(lifecycle: &PassportLifecycleResolution) -> String {
    match lifecycle.state {
        PassportLifecycleState::Active => "passport lifecycle state is active".to_string(),
        PassportLifecycleState::Stale => lifecycle
            .updated_at
            .map(|updated_at| {
                format!("passport lifecycle state is stale: last updated at {updated_at}")
            })
            .unwrap_or_else(|| "passport lifecycle state is stale".to_string()),
        PassportLifecycleState::Superseded => lifecycle
            .superseded_by
            .as_deref()
            .map(|passport_id| format!("passport lifecycle state is superseded by {passport_id}"))
            .unwrap_or_else(|| "passport lifecycle state is superseded".to_string()),
        PassportLifecycleState::Revoked => lifecycle
            .revoked_reason
            .as_deref()
            .map(|reason| format!("passport lifecycle state is revoked: {reason}"))
            .unwrap_or_else(|| "passport lifecycle state is revoked".to_string()),
        PassportLifecycleState::NotFound => "passport lifecycle record was not found".to_string(),
    }
}

pub(crate) fn default_passport_status_distribution(
    config: &TrustServiceConfig,
) -> PassportStatusDistribution {
    if config.passport_statuses_file.is_none() {
        return PassportStatusDistribution::default();
    }
    config
        .advertise_url
        .as_deref()
        .map(|advertise_url| PassportStatusDistribution {
            resolve_urls: vec![format!(
                "{advertise_url}/v1/public/passport/statuses/resolve"
            )],
            cache_ttl_secs: Some(300),
        })
        .unwrap_or_default()
}

pub(crate) fn resolve_passport_lifecycle_for_service(
    config: &TrustServiceConfig,
    passport: &AgentPassport,
    at: u64,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    let Some(_) = config.passport_statuses_file.as_deref() else {
        return Ok(None);
    };
    let (_, registry) = load_passport_status_registry_for_admin(config)?;
    let mut lifecycle = registry.resolve_for_passport(passport, at)?;
    lifecycle.source = Some("registry:trust-control".to_string());
    Ok(Some(lifecycle))
}

pub(crate) fn portable_passport_status_reference_for_service(
    config: &TrustServiceConfig,
    passport: &AgentPassport,
    at: u64,
) -> Result<Option<chio_credentials::Oid4vciChioPassportStatusReference>, CliError> {
    let Some(_) = config.passport_statuses_file.as_deref() else {
        return Ok(None);
    };
    let (_, registry) = load_passport_status_registry_for_admin(config)?;
    registry
        .portable_status_reference_for_passport(passport, at)
        .map(Some)
}

pub(crate) fn passport_presentation_transport_for_service(
    config: &TrustServiceConfig,
    challenge: &PassportPresentationChallenge,
) -> Result<Option<PassportPresentationTransport>, CliError> {
    let Some(advertise_url) = config.advertise_url.as_deref() else {
        return Ok(None);
    };
    let challenge_id = challenge
        .challenge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::cli_other_error(
                "public holder transport requires challenges to include a non-empty challenge_id"
                    .to_string(),
            )
        })?;
    Ok(Some(PassportPresentationTransport {
        challenge_id: challenge_id.to_string(),
        challenge_url: format!("{advertise_url}/v1/public/passport/challenges/{challenge_id}"),
        submit_url: format!("{advertise_url}/v1/public/passport/challenges/verify"),
    }))
}

pub(crate) fn consume_challenge_if_configured(
    config: &TrustServiceConfig,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<Option<String>, CliError> {
    let Some(path) = config.verifier_challenge_db_path.as_deref() else {
        if challenge.policy_ref.is_some() {
            return Err(CliError::cli_other_error(
                "stored verifier challenges require --verifier-challenge-db on the trust-control service"
                    .to_string(),
            ));
        }
        return Ok(None);
    };
    let store = PassportVerifierChallengeStore::open(path)?;
    store.consume(challenge, now)?;
    Ok(Some("consumed".to_string()))
}

fn generate_oid4vp_token(prefix: &str, seed: &str) -> String {
    let digest = sha256_hex(seed.as_bytes());
    format!("{prefix}-{}", &digest[..24])
}

pub(crate) fn oid4vp_same_device_url(request_uri: &str) -> String {
    format!(
        "{OID4VP_OPENID4VP_SCHEME}?request_uri={}",
        utf8_percent_encode(request_uri, NON_ALPHANUMERIC)
    )
}

fn oid4vp_wallet_exchange_url(
    config: &TrustServiceConfig,
    request_id: &str,
) -> Result<String, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "wallet exchange descriptor requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    Ok(format!(
        "{advertise_url}{}",
        service_runtime::client::path_with_encoded_param(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            "request_id",
            request_id
        )
    ))
}

pub(crate) fn oid4vp_cross_device_url(
    config: &TrustServiceConfig,
    request_id: &str,
    request_uri: &str,
) -> Result<String, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier requests require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    Ok(format!(
        "{advertise_url}{}?request_uri={}",
        service_runtime::client::path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH,
            "request_id",
            request_id
        ),
        utf8_percent_encode(request_uri, NON_ALPHANUMERIC)
    ))
}

pub(crate) fn build_oid4vp_wallet_exchange_response(
    config: &TrustServiceConfig,
    request: &Oid4vpRequestObject,
    request_jwt: &str,
    transaction: WalletExchangeTransactionState,
    same_device_url: &str,
    cross_device_url: &str,
) -> Result<WalletExchangeStatusResponse, CliError> {
    let descriptor = build_wallet_exchange_descriptor_for_oid4vp(
        request,
        request_jwt,
        &oid4vp_wallet_exchange_url(config, &request.jti)?,
        same_device_url,
        cross_device_url,
        Some(cross_device_url),
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    transaction
        .validate()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(WalletExchangeStatusResponse {
        descriptor,
        transaction,
        identity_assertion: request.identity_assertion.clone(),
    })
}

pub(crate) fn authority_status_for_config(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)?.status()?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(CliError::cli_other_error(
            "OID4VP verifier trust material requires --authority-seed-file or --authority-db"
                .to_string(),
        ));
    };
    match authority_public_key_from_seed_file(path)? {
        Some(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        None => Err(CliError::cli_other_error(
            "OID4VP verifier trust material requires a configured authority public key".to_string(),
        )),
    }
}

fn trusted_public_keys_from_status(
    status: &TrustAuthorityStatus,
) -> Result<Vec<PublicKey>, CliError> {
    if !status.configured {
        return Err(CliError::cli_other_error(
            "OID4VP verifier trust material requires a configured authority".to_string(),
        ));
    }
    let mut trusted = status
        .trusted_public_keys
        .iter()
        .map(|value| PublicKey::from_hex(value))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(current) = status.public_key.as_deref() {
        let current = PublicKey::from_hex(current)?;
        if !trusted.iter().any(|public_key| public_key == &current) {
            trusted.push(current);
        }
    }
    if trusted.is_empty() {
        return Err(CliError::cli_other_error(
            "OID4VP verifier trust material did not publish any signing keys".to_string(),
        ));
    }
    Ok(trusted)
}

pub(crate) fn resolve_oid4vp_verifier_trusted_public_keys(
    config: &TrustServiceConfig,
) -> Result<Vec<PublicKey>, CliError> {
    trusted_public_keys_from_status(&authority_status_for_config(config)?)
}

pub(crate) fn build_oid4vp_verifier_metadata(
    config: &TrustServiceConfig,
) -> Result<Oid4vpVerifierMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier metadata requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let status = authority_status_for_config(config)?;
    let trusted_public_keys = trusted_public_keys_from_status(&status)?;
    let metadata = Oid4vpVerifierMetadata {
        verifier_id: advertise_url.to_string(),
        client_id: advertise_url.to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        request_uri_prefix: format!("{advertise_url}/v1/public/passport/oid4vp/requests/"),
        response_uri: format!("{advertise_url}{PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH}"),
        same_device_launch_prefix: format!("{OID4VP_OPENID4VP_SCHEME}?request_uri="),
        jwks_uri: format!("{advertise_url}{OID4VCI_JWKS_PATH}"),
        request_object_signing_alg_values_supported: vec!["EdDSA".to_string()],
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        credential_format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
        credential_vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
        authority_generation: status.generation,
        authority_rotated_at: status.rotated_at,
        trusted_key_count: trusted_public_keys.len(),
    };
    metadata
        .validate()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(metadata)
}

pub(crate) fn build_oid4vp_verifier_jwks(
    config: &TrustServiceConfig,
) -> Result<PortableJwkSet, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier jwks requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let trusted_public_keys = resolve_oid4vp_verifier_trusted_public_keys(config)?;
    build_portable_jwks(advertise_url, &trusted_public_keys)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub(crate) fn now_unix_secs() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CliError::cli_other_error(format!("system clock error: {error}")))
        .map(|duration| duration.as_secs())
}

fn public_discovery_version(config: &TrustServiceConfig) -> Result<u64, CliError> {
    Ok(authority_status_for_config(config)?
        .generation
        .unwrap_or(1)
        .max(1))
}

fn public_discovery_guardrails() -> PublicDiscoveryImportGuardrails {
    PublicDiscoveryImportGuardrails::default()
}

pub(crate) fn build_public_issuer_discovery(
    config: &TrustServiceConfig,
) -> Result<SignedPublicIssuerDiscovery, CliError> {
    let signing_key = resolve_oid4vp_verifier_signing_key(config)?;
    let metadata = configured_passport_credential_issuer(config)?;
    let now = now_unix_secs()?;
    let metadata_sha256 = sha256_hex(&canonical_json_bytes(&metadata)?);
    let credential_configuration_ids = metadata
        .credential_configurations_supported
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let passport_status_distribution = metadata
        .chio_profile
        .as_ref()
        .map(|profile| profile.passport_status_distribution.clone())
        .unwrap_or_default();
    create_signed_public_issuer_discovery(
        &signing_key,
        chio_credentials::SignedPublicIssuerDiscoveryInput {
            discovery_id: format!("issuer-discovery:{}", metadata.credential_issuer),
            issuer: metadata.credential_issuer.clone(),
            version: public_discovery_version(config)?,
            published_at: now,
            expires_at: now.saturating_add(PUBLIC_DISCOVERY_TTL_SECS),
            metadata_url: format!(
                "{}{OID4VCI_ISSUER_METADATA_PATH}",
                metadata.credential_issuer
            ),
            metadata_sha256,
            jwks_uri: metadata.jwks_uri.clone(),
            credential_configuration_ids,
            passport_status_distribution,
            import_guardrails: public_discovery_guardrails(),
        },
    )
    .map_err(CliError::from)
}

pub(crate) fn build_public_verifier_discovery(
    config: &TrustServiceConfig,
) -> Result<SignedPublicVerifierDiscovery, CliError> {
    let signing_key = resolve_oid4vp_verifier_signing_key(config)?;
    let metadata = build_oid4vp_verifier_metadata(config)?;
    let now = now_unix_secs()?;
    let metadata_sha256 = sha256_hex(&canonical_json_bytes(&metadata)?);
    create_signed_public_verifier_discovery(
        &signing_key,
        chio_credentials::SignedPublicVerifierDiscoveryInput {
            discovery_id: format!("verifier-discovery:{}", metadata.verifier_id),
            verifier: metadata.verifier_id.clone(),
            version: public_discovery_version(config)?,
            published_at: now,
            expires_at: now.saturating_add(PUBLIC_DISCOVERY_TTL_SECS),
            metadata_url: format!("{}{OID4VP_VERIFIER_METADATA_PATH}", metadata.verifier_id),
            metadata_sha256,
            jwks_uri: metadata.jwks_uri.clone(),
            request_uri_prefix: metadata.request_uri_prefix.clone(),
            import_guardrails: public_discovery_guardrails(),
        },
    )
    .map_err(CliError::from)
}

pub(crate) fn build_public_discovery_transparency(
    config: &TrustServiceConfig,
) -> Result<SignedPublicDiscoveryTransparency, CliError> {
    let signing_key = resolve_oid4vp_verifier_signing_key(config)?;
    let issuer = build_public_issuer_discovery(config)?;
    let verifier = build_public_verifier_discovery(config)?;
    let now = now_unix_secs()?;
    let publisher = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "public discovery transparency requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let entries = vec![
        PublicDiscoveryTransparencyEntry {
            kind: PublicDiscoveryEntryKind::Issuer,
            discovery_id: issuer.body.discovery_id.clone(),
            metadata_url: issuer.body.metadata_url.clone(),
            document_sha256: sha256_hex(&canonical_json_bytes(&issuer)?),
            published_at: issuer.body.published_at,
            expires_at: issuer.body.expires_at,
        },
        PublicDiscoveryTransparencyEntry {
            kind: PublicDiscoveryEntryKind::Verifier,
            discovery_id: verifier.body.discovery_id.clone(),
            metadata_url: verifier.body.metadata_url.clone(),
            document_sha256: sha256_hex(&canonical_json_bytes(&verifier)?),
            published_at: verifier.body.published_at,
            expires_at: verifier.body.expires_at,
        },
    ];
    create_signed_public_discovery_transparency(
        &signing_key,
        chio_credentials::SignedPublicDiscoveryTransparencyInput {
            transparency_id: format!("public-discovery-transparency:{publisher}"),
            publisher: publisher.to_string(),
            version: public_discovery_version(config)?,
            published_at: now,
            expires_at: now.saturating_add(PUBLIC_DISCOVERY_TTL_SECS),
            entries,
            import_guardrails: public_discovery_guardrails(),
        },
    )
    .map_err(CliError::from)
}

pub(crate) fn build_oid4vp_request_for_service(
    config: &TrustServiceConfig,
    payload: &CreateOid4vpRequest,
    now: u64,
) -> Result<Oid4vpRequestObject, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier requests require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let _ = configured_verifier_challenge_db_path(config)?;
    let ttl_seconds = payload.ttl_seconds.unwrap_or(300).clamp(30, 600);
    let entropy = Keypair::generate().public_key().to_hex();
    let request_id = generate_oid4vp_token(
        "oid4vp",
        &format!(
            "{advertise_url}:{now}:{entropy}:{}",
            payload.disclosure_claims.join(",")
        ),
    );
    let nonce = generate_oid4vp_token(
        "nonce",
        &format!(
            "{request_id}:{entropy}:{}",
            payload.issuer_allowlist.join(",")
        ),
    );
    let state = generate_oid4vp_token("state", &format!("{request_id}:{ttl_seconds}:{entropy}"));
    let response_uri = format!("{advertise_url}{PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH}");
    let request_uri = format!(
        "{advertise_url}{}",
        service_runtime::client::path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            "request_id",
            &request_id
        )
    );
    let identity_assertion = payload
        .identity_assertion
        .as_ref()
        .map(|assertion| {
            if assertion.subject.trim().is_empty() {
                return Err(CliError::cli_other_error(
                    "OID4VP identity assertion subject must not be empty".to_string(),
                ));
            }
            if assertion.continuity_id.trim().is_empty() {
                return Err(CliError::cli_other_error(
                    "OID4VP identity assertion continuity_id must not be empty".to_string(),
                ));
            }
            if assertion
                .provider
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(CliError::cli_other_error(
                    "OID4VP identity assertion provider must not be empty when present".to_string(),
                ));
            }
            if assertion
                .session_hint
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(CliError::cli_other_error(
                    "OID4VP identity assertion session_hint must not be empty when present"
                        .to_string(),
                ));
            }
            let assertion_ttl = assertion.ttl_seconds.unwrap_or(ttl_seconds).clamp(30, 600);
            let identity_assertion = ChioIdentityAssertion {
                verifier_id: advertise_url.to_string(),
                subject: assertion.subject.clone(),
                continuity_id: assertion.continuity_id.clone(),
                issued_at: now,
                expires_at: now
                    .saturating_add(assertion_ttl)
                    .min(now.saturating_add(ttl_seconds)),
                provider: assertion.provider.clone(),
                session_hint: assertion.session_hint.clone(),
                bound_request_id: Some(request_id.clone()),
            };
            identity_assertion
                .validate_at(now)
                .map_err(CliError::cli_other_error)?;
            Ok(identity_assertion)
        })
        .transpose()?;
    let request = Oid4vpRequestObject {
        client_id: advertise_url.to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri,
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce,
        state,
        iat: now,
        exp: now.saturating_add(ttl_seconds),
        jti: request_id,
        request_uri,
        dcql_query: chio_credentials::Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: payload.disclosure_claims.clone(),
                issuer_allowlist: payload.issuer_allowlist.clone(),
            }],
        },
        identity_assertion,
    };
    request
        .validate(now)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(request)
}

pub(crate) fn resolve_oid4vp_verifier_signing_key(
    config: &TrustServiceConfig,
) -> Result<Keypair, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        return Ok(SqliteCapabilityAuthority::open(path)?.local_keypair()?);
    }
    let path = config.authority_seed_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier requests require a configured authority signing seed".to_string(),
        )
    })?;
    load_or_create_authority_keypair(path)
}

pub(crate) fn resolve_portable_issuer_public_keys(
    config: &TrustServiceConfig,
    issuer: &str,
) -> Result<Vec<PublicKey>, CliError> {
    if config.advertise_url.as_deref() == Some(issuer) {
        return resolve_oid4vp_verifier_trusted_public_keys(config);
    }
    let jwks_url = format!("{issuer}{OID4VCI_JWKS_PATH}");
    let response = ureq::get(&jwks_url).call().map_err(|error| match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            CliError::cli_other_error(format!(
                "failed to fetch portable issuer JWKS from `{jwks_url}` with status {status}: {body}"
            ))
        }
        ureq::Error::Transport(transport) => CliError::cli_other_error(format!(
            "failed to fetch portable issuer JWKS from `{jwks_url}`: {transport}"
        )),
    })?;
    let jwks: chio_credentials::PortableJwkSet = serde_json::from_reader(response.into_reader())
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to decode portable issuer JWKS from `{jwks_url}`: {error}"
            ))
        })?;
    jwks.keys.first().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "portable issuer JWKS at `{jwks_url}` did not publish any keys"
        ))
    })?;
    let mut public_keys = Vec::with_capacity(jwks.keys.len());
    for entry in &jwks.keys {
        public_keys.push(
            entry
                .jwk
                .to_public_key()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        );
    }
    if public_keys.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "portable issuer JWKS at `{jwks_url}` did not publish any keys"
        )));
    }
    Ok(public_keys)
}

pub(crate) fn resolve_oid4vp_passport_lifecycle(
    config: &TrustServiceConfig,
    passport_id: &str,
    status_ref: Option<&chio_credentials::Oid4vciChioPassportStatusReference>,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    if let Some(path) = config.passport_statuses_file.as_deref() {
        let registry = PassportStatusRegistry::load(path)?;
        return Ok(Some(registry.resolve_at(passport_id, unix_timestamp_now())));
    }
    let Some(status_ref) = status_ref else {
        return Ok(None);
    };
    let resolve_url = status_ref
        .distribution
        .resolve_urls
        .first()
        .cloned()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "OID4VP passport status validation requires at least one resolve URL".to_string(),
            )
        })?;
    let url = format!(
        "{}/{}",
        resolve_url.trim_end_matches('/'),
        utf8_percent_encode(passport_id, NON_ALPHANUMERIC)
    );
    let response = ureq::get(&url).call().map_err(|error| match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            CliError::cli_other_error(format!(
                "failed to resolve portable passport lifecycle from `{url}` with status {status}: {body}"
            ))
        }
        ureq::Error::Transport(transport) => CliError::cli_other_error(format!(
            "failed to resolve portable passport lifecycle from `{url}`: {transport}"
        )),
    })?;
    let lifecycle: PassportLifecycleResolution = serde_json::from_reader(response.into_reader())
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to decode portable passport lifecycle from `{url}`: {error}"
            ))
        })?;
    lifecycle
        .validate()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(Some(lifecycle))
}

pub(crate) fn build_enterprise_admission_audit(
    identity: &EnterpriseIdentityContext,
    subject_public_key: &str,
    provider: Option<&EnterpriseProviderRecord>,
) -> EnterpriseAdmissionAudit {
    EnterpriseAdmissionAudit {
        provider_id: identity.provider_id.clone(),
        provider_record_id: identity.provider_record_id.clone(),
        provider_kind: provider
            .map(|record| match &record.kind {
                crate::enterprise_federation::EnterpriseProviderKind::OidcJwks => "oidc_jwks",
                crate::enterprise_federation::EnterpriseProviderKind::OauthIntrospection => {
                    "oauth_introspection"
                }
                crate::enterprise_federation::EnterpriseProviderKind::Scim => "scim",
                crate::enterprise_federation::EnterpriseProviderKind::Saml => "saml",
            })
            .unwrap_or(identity.provider_kind.as_str())
            .to_string(),
        federation_method: match &identity.federation_method {
            chio_core::EnterpriseFederationMethod::Jwt => "jwt",
            chio_core::EnterpriseFederationMethod::Introspection => "introspection",
            chio_core::EnterpriseFederationMethod::Scim => "scim",
            chio_core::EnterpriseFederationMethod::Saml => "saml",
        }
        .to_string(),
        principal: identity.principal.clone(),
        subject_key: identity.subject_key.clone(),
        subject_public_key: subject_public_key.to_string(),
        tenant_id: identity.tenant_id.clone(),
        organization_id: identity.organization_id.clone(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        attribute_sources: identity.attribute_sources.clone(),
        trust_material_ref: provider
            .and_then(|record| record.provenance.trust_material_ref.clone())
            .or_else(|| identity.trust_material_ref.clone()),
        matched_origin_profile: None,
        decision_reason: None,
    }
}

pub(crate) fn enterprise_origin_context(
    identity: &EnterpriseIdentityContext,
) -> chio_policy::OriginContext {
    chio_policy::OriginContext {
        provider: Some(identity.provider_id.clone()),
        tenant_id: identity.tenant_id.clone(),
        organization_id: identity.organization_id.clone(),
        space_id: None,
        space_type: None,
        visibility: None,
        external_participants: None,
        tags: Vec::new(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        sensitivity: None,
        actor_role: None,
    }
}

pub(crate) fn enterprise_admission_response(
    status: StatusCode,
    message: &str,
    audit: &EnterpriseAdmissionAudit,
) -> Response {
    (
        status,
        Json(json!({
            "error": message,
            "enterpriseAudit": audit,
        })),
    )
        .into_response()
}

pub(crate) fn scim_json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            status,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("application/scim+json"),
            )],
            body,
        )
            .into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) fn scim_error_response(status: StatusCode, detail: &str) -> Response {
    scim_json_response(status, &build_scim_error(status.as_u16(), detail))
}

pub(crate) fn scim_user_location(user_id: &str) -> String {
    service_runtime::client::path_with_encoded_param(SCIM_USER_PATH, "user_id", user_id)
}

pub(crate) fn validated_scim_provider_for_request(
    config: &TrustServiceConfig,
    user: &ScimUserResource,
) -> Result<EnterpriseProviderRecord, CliError> {
    let extension = required_chio_extension(user)?;
    if extension
        .provider_record_id
        .as_deref()
        .is_some_and(|value| value != extension.provider_id)
    {
        return Err(CliError::cli_other_error(
            "scim user chio extension providerRecordId must match providerId when present"
                .to_string(),
        ));
    }
    let (_, registry) = load_enterprise_provider_registry_for_admin(config)?;
    let Some(provider) = registry.validated_provider(&extension.provider_id).cloned() else {
        return Err(CliError::cli_other_error(format!(
            "validated scim provider `{}` was not found",
            extension.provider_id
        )));
    };
    ensure_scim_provider(&provider)?;
    Ok(provider)
}

pub(crate) fn resolve_scim_lifecycle_record_for_federated_issue(
    config: &TrustServiceConfig,
    provider: &EnterpriseProviderRecord,
    identity: &EnterpriseIdentityContext,
) -> Result<Option<crate::scim_lifecycle::ScimLifecycleUserRecord>, CliError> {
    if !matches!(provider.kind, EnterpriseProviderKind::Scim) {
        return Ok(None);
    }
    let Some(path) = config.scim_lifecycle_file.as_deref() else {
        return Ok(None);
    };
    let registry = ScimLifecycleRegistry::load(path)?;
    let Some(record) = registry
        .find_by_identity(&provider.provider_id, &identity.subject_key)
        .cloned()
    else {
        return Err(CliError::cli_other_error(format!(
            "scim lifecycle registry has no Chio identity for provider `{}` and subject `{}`",
            provider.provider_id, identity.subject_key
        )));
    };
    if !record.active() {
        return Err(CliError::cli_other_error(format!(
            "scim lifecycle identity `{}` is inactive",
            record.user_id
        )));
    }
    Ok(Some(record))
}

pub(crate) fn bind_scim_capability_to_identity(
    config: &TrustServiceConfig,
    provider_id: &str,
    subject_key: &str,
    capability_id: &str,
    now: u64,
) -> Result<(), CliError> {
    let Some(path) = config.scim_lifecycle_file.as_deref() else {
        return Ok(());
    };
    let mut registry = ScimLifecycleRegistry::load(path)?;
    let bound = registry.bind_capability(provider_id, subject_key, capability_id, now)?;
    if !bound {
        return Err(CliError::cli_other_error(format!(
            "scim lifecycle registry has no Chio identity for provider `{provider_id}` and subject `{subject_key}`"
        )));
    }
    registry.save(path)
}

pub(crate) fn build_scim_deprovision_receipt(
    config: &TrustServiceConfig,
    record: &crate::scim_lifecycle::ScimLifecycleUserRecord,
    revoked_capability_ids: &[String],
    now: u64,
) -> Result<ChioReceipt, CliError> {
    let tenant_id = record
        .enterprise_identity
        .tenant_id
        .clone()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "scim deprovision receipts require an enterprise tenant_id".to_string(),
            )
        })?;
    let keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let action = ToolCallAction::from_parameters(json!({
        "providerId": record.provider_id,
        "userId": record.user_id,
        "userName": record.scim_user.user_name,
        "subjectKey": record.enterprise_identity.subject_key,
        "revokedCapabilityIds": revoked_capability_ids,
    }))?;
    let content_hash = sha256_hex(&canonical_json_bytes(&json!({
        "providerId": record.provider_id,
        "userId": record.user_id,
        "subjectKey": record.enterprise_identity.subject_key,
        "revokedCapabilityIds": revoked_capability_ids,
    }))?);
    let policy_hash = sha256_hex(
        format!(
            "chio.scim-lifecycle-delete.v1:{}:{}",
            record.provider_id, record.enterprise_identity.subject_key
        )
        .as_bytes(),
    );
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: format!(
                "scim-deprovision-{}",
                sha256_hex(format!("{}:{}:{now}", record.provider_id, record.user_id).as_bytes())
            ),
            timestamp: now,
            capability_id: format!("scim-user:{}", record.user_id),
            tool_server: "chio.scim".to_string(),
            tool_name: "delete_user".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash,
            policy_hash,
            evidence: Vec::new(),
            metadata: Some(json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: record.enterprise_identity.subject_key.clone(),
                    issuer_key: keypair.public_key().to_hex(),
                    delegation_depth: 0,
                    grant_index: None,
                },
                "scimLifecycle": {
                    "providerId": record.provider_id,
                    "providerRecordId": record.enterprise_identity.provider_record_id,
                    "principal": record.enterprise_identity.principal,
                    "subjectKey": record.enterprise_identity.subject_key,
                    "userId": record.user_id,
                    "userName": record.scim_user.user_name,
                    "revokedCapabilityIds": revoked_capability_ids,
                    "entitlements": record
                        .scim_user
                        .entitlements
                        .iter()
                        .map(|value| value.value.clone())
                        .collect::<Vec<_>>(),
                    "receiptKind": "deprovisioning",
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: Some(tenant_id),
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )?)
}

#[cfg(test)]
mod config_and_public_tests {
    use super::*;
    use chio_credentials::verify_signed_public_issuer_discovery;
    use chio_test_support::prelude::*;
    use std::path::PathBuf;

    fn base_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_expect("parse listen addr"),
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
            allow_local_peer_urls: false,
            certification_public_metadata_ttl_seconds: 900,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(200),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }

    #[test]
    fn configured_public_certification_metadata_validates_advertise_url_and_builds_paths() {
        let missing_error = configured_public_certification_metadata(&base_config())
            .test_expect_err("missing advertise URL should fail");
        assert!(missing_error
            .to_string()
            .contains("requires --advertise-url"));

        let mut blank_config = base_config();
        blank_config.advertise_url = Some("/".to_string());
        let blank_error = configured_public_certification_metadata(&blank_config)
            .test_expect_err("blank advertise URL should fail");
        assert!(blank_error.to_string().contains("non-empty advertise_url"));

        let mut config = base_config();
        config.advertise_url = Some("https://trust.example.com/".to_string());
        config.certification_public_metadata_ttl_seconds = 120;

        let metadata = configured_public_certification_metadata(&config)
            .test_expect("build certification metadata");

        assert_eq!(metadata.publisher.publisher_id, "https://trust.example.com");
        assert_eq!(metadata.publisher.registry_url, "https://trust.example.com");
        assert_eq!(metadata.expires_at - metadata.generated_at, 120);
        assert_eq!(
            metadata.public_resolve_path_template,
            "https://trust.example.com/v1/public/certifications/resolve/{tool_server_id}"
        );
        assert_eq!(
            metadata.public_search_path,
            "https://trust.example.com/v1/public/certifications/search"
        );
        assert_eq!(
            metadata.public_transparency_path,
            "https://trust.example.com/v1/public/certifications/transparency"
        );
    }

    #[test]
    fn public_generic_registry_publisher_requires_and_normalizes_advertise_url() {
        let missing_error = public_generic_registry_publisher(&base_config())
            .test_expect_err("missing advertise URL");
        assert!(missing_error
            .to_string()
            .contains("require --advertise-url"));

        let mut blank_config = base_config();
        blank_config.advertise_url = Some("///".to_string());
        let blank_error = public_generic_registry_publisher(&blank_config)
            .test_expect_err("blank normalized advertise URL");
        assert!(blank_error.to_string().contains("non-empty advertise_url"));

        let mut config = base_config();
        config.advertise_url = Some("https://trust.example.com/".to_string());
        let publisher = public_generic_registry_publisher(&config)
            .test_expect("build generic registry publisher");

        assert_eq!(publisher.role, GenericRegistryPublisherRole::Origin);
        assert_eq!(publisher.operator_id, "https://trust.example.com");
        assert_eq!(publisher.registry_url, "https://trust.example.com");
        assert!(publisher.upstream_registry_urls.is_empty());
    }

    #[test]
    fn trusted_public_keys_require_configuration_and_add_current_key_once() {
        let not_configured = trusted_public_keys_from_status(&TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: false,
            trusted_public_keys: Vec::new(),
        })
        .test_expect_err("unconfigured authority should fail");
        assert!(not_configured
            .to_string()
            .contains("requires a configured authority"));

        let current = Keypair::generate().public_key().to_hex();
        let trusted = trusted_public_keys_from_status(&TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(current.clone()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![current.clone()],
        })
        .test_expect("current key should be trusted once");
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].to_hex(), current);

        let missing_material = trusted_public_keys_from_status(&TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        })
        .test_expect_err("empty trust material should fail");
        assert!(missing_material
            .to_string()
            .contains("did not publish any signing keys"));
    }

    #[test]
    fn oid4vp_url_helpers_encode_request_values() {
        let token = generate_oid4vp_token("req", "portable-seed");
        assert!(token.starts_with("req-"));
        assert_eq!(token.len(), 28);

        let request_uri = "https://wallet.example/request?id=a/b";
        let encoded_request_uri = utf8_percent_encode(request_uri, NON_ALPHANUMERIC).to_string();
        let same_device = oid4vp_same_device_url(request_uri);
        assert!(same_device.starts_with("openid4vp://authorize?request_uri="));
        assert!(same_device.ends_with(&encoded_request_uri));

        let mut config = base_config();
        config.advertise_url = Some("https://trust.example.com".to_string());

        let wallet_exchange =
            oid4vp_wallet_exchange_url(&config, "request/alpha").test_expect("wallet exchange URL");
        assert_eq!(
            wallet_exchange,
            "https://trust.example.com/v1/public/passport/wallet-exchanges/request%2Falpha"
        );

        let cross_device = oid4vp_cross_device_url(&config, "request/alpha", request_uri)
            .test_expect("cross-device URL");
        assert!(cross_device.starts_with(
            "https://trust.example.com/v1/public/passport/oid4vp/launch/request%2Falpha?request_uri="
        ));
        assert!(cross_device.ends_with(&encoded_request_uri));
    }

    #[test]
    fn verifier_metadata_and_jwks_can_be_built_from_seed_authority() {
        let seed_path = unique_temp_path("chio-trust-control-authority", "seed");
        let authority_keypair =
            load_or_create_authority_keypair(&seed_path).test_expect("create authority seed file");

        let mut config = base_config();
        config.advertise_url = Some("https://trust.example.com".to_string());
        config.authority_seed_path = Some(seed_path);

        let status =
            authority_status_for_config(&config).test_expect("authority status from seed file");
        assert!(status.configured);
        assert_eq!(status.backend.as_deref(), Some("seed_file"));
        let authority_public_key = authority_keypair.public_key().to_hex();
        assert_eq!(
            status.public_key.as_deref(),
            Some(authority_public_key.as_str())
        );
        assert_eq!(status.trusted_public_keys.len(), 1);

        let metadata =
            build_oid4vp_verifier_metadata(&config).test_expect("build OID4VP verifier metadata");
        assert_eq!(metadata.verifier_id, "https://trust.example.com");
        assert_eq!(metadata.client_id, "https://trust.example.com");
        assert_eq!(
            metadata.request_uri_prefix,
            "https://trust.example.com/v1/public/passport/oid4vp/requests/"
        );
        assert_eq!(
            metadata.response_uri,
            "https://trust.example.com/v1/public/passport/oid4vp/direct-post"
        );
        assert_eq!(metadata.trusted_key_count, 1);
        assert!(metadata.authority_generation.is_none());

        let jwks = build_oid4vp_verifier_jwks(&config).test_expect("build verifier JWKS");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].alg, "EdDSA");
        assert_eq!(jwks.keys[0].use_, "sig");

        let discovery_version =
            public_discovery_version(&config).test_expect("derive public discovery version");
        assert_eq!(discovery_version, 1);
    }

    #[test]
    fn public_discovery_uses_local_db_signer_after_replica_snapshot() {
        let source_path = unique_temp_path("chio-trust-control-authority-source", "sqlite");
        let follower_path = unique_temp_path("chio-trust-control-authority-follower", "sqlite");
        let source =
            SqliteCapabilityAuthority::open(&source_path).test_expect("open source authority");
        let follower =
            SqliteCapabilityAuthority::open(&follower_path).test_expect("open follower authority");
        let follower_local_key = follower.local_keypair().test_expect("read follower seed");

        source.rotate().test_expect("rotate source authority");
        let snapshot = source.snapshot().test_expect("snapshot source authority");
        assert!(follower
            .apply_snapshot(&snapshot)
            .test_expect("apply source snapshot"));
        assert!(follower.current_keypair().is_err());

        let mut config = base_config();
        config.advertise_url = Some("https://trust.example.com".to_string());
        config.authority_db_path = Some(follower_path.clone());

        let signing_key =
            resolve_oid4vp_verifier_signing_key(&config).test_expect("resolve follower signer");
        assert_eq!(signing_key.public_key(), follower_local_key.public_key());

        let issuer = build_public_issuer_discovery(&config).test_expect("build issuer discovery");
        assert_eq!(
            issuer.body.signer_public_key,
            follower_local_key.public_key()
        );
        verify_signed_public_issuer_discovery(&issuer).test_expect("verify issuer discovery");
    }
}
