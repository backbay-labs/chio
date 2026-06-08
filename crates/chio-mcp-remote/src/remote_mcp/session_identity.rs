fn canonicalize_federated_issuer(issuer: &str) -> String {
    let trimmed = issuer.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

impl JwtSignatureAlgorithm {
    fn from_header(
        header: &JwtHeader,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<Self, Response> {
        match header.alg.as_str() {
            "EdDSA" => Ok(Self::EdDsa),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "PS256" => Ok(Self::Ps256),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            _ => Err(unauthorized_bearer_response(
                "JWT bearer token uses unsupported alg",
                protected_resource_metadata,
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }
}

fn verify_ed25519_jwt_signature(
    public_key: &PublicKey,
    signed_input: &[u8],
    signature_bytes: &[u8],
) -> bool {
    if signature_bytes.len() != 64 {
        return false;
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    public_key.verify(signed_input, &Ed25519Signature::from_bytes(&signature))
}

fn validate_identity_provider_url(url: &Url, field_name: &str) -> Result<(), CliError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme == "https" || (scheme == "http" && localhost) {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "{field_name} must use https, or localhost http during local testing: {url}"
        )))
    }
}

fn parse_identity_provider_url(value: &str, field_name: &str) -> Result<Url, CliError> {
    let url = Url::parse(value)
        .map_err(|error| CliError::cli_other_error(format!("{field_name} is not a valid URL: {error}")))?;
    validate_identity_provider_url(&url, field_name)?;
    Ok(url)
}

fn derive_oidc_discovery_url_from_issuer(issuer: &str) -> Result<Url, CliError> {
    let issuer = parse_identity_provider_url(issuer, "--auth-jwt-issuer")?;
    let mut path = issuer.path().trim_end_matches('/').to_string();
    path.push_str("/.well-known/openid-configuration");
    let mut discovery = issuer;
    discovery.set_path(&path);
    discovery.set_query(None);
    discovery.set_fragment(None);
    Ok(discovery)
}

/// Test-friendly entry point that runs the typed `HttpEgressContract`
/// gate against an OIDC discovery or JWKS URL using the same code path
/// as production OIDC discovery. Returns `Ok(())` when the URL passes
/// the contract; surfaces a `CliError` when it is denied. This lets
/// negative-conformance tests assert that loopback / link-local targets
/// are rejected before a TCP connect is attempted.
pub fn enforce_oidc_egress_contract(
    url: &Url,
    egress_contract: &HttpEgressContract,
) -> Result<(), CliError> {
    egress_contract
        .enforce_url_with_dns(url.as_str(), 0)
        .map(|_| ())
        .map_err(|err| {
            CliError::cli_other_error(format!(
                "HttpEgressContract rejects OIDC fetch `{url}`: {err}"
            ))
        })
}

async fn fetch_identity_provider_json<T: DeserializeOwned>(
    url: &Url,
    field_name: &str,
    egress_contract: Option<&HttpEgressContract>,
) -> Result<T, CliError> {
    // HttpEgressContract: every OIDC discovery and JWKS fetch goes through
    // send_with_contract so target URL, DNS answers, redirects, and response
    // body size are enforced before bytes cross the substrate boundary.
    let contract = egress_contract.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "{field_name} `{url}` requires an HttpEgressContract; substrate fails closed"
        ))
    })?;
    let client = client_builder_with_contract(contract)
        .timeout(Duration::from_secs(IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to build {field_name} HTTP client for `{url}`: {error}"
            ))
        })?;
    let request = client.get(url.as_str()).build().map_err(|error| {
        CliError::cli_other_error(format!("failed to build {field_name} request `{url}`: {error}"))
    })?;
    let response = send_with_contract(contract, &client, request)
        .await
        .map_err(|err| {
            CliError::cli_other_error(format!(
                "HttpEgressContract rejects {field_name} `{url}`: {err}"
            ))
        })?;
    response.json::<T>().await.map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse JSON from {field_name} `{}`: {error}",
            url
        ))
    })
}

fn resolve_identity_provider_discovery_url(
    config: &RemoteServeHttpConfig,
) -> Result<Option<Url>, CliError> {
    if let Some(discovery_url) = config.auth_jwt_discovery_url.as_deref() {
        return parse_identity_provider_url(discovery_url, "--auth-jwt-discovery-url").map(Some);
    }
    if config.auth_jwt_provider_profile.is_some() {
        let issuer = config.auth_jwt_issuer.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "--auth-jwt-provider-profile requires --auth-jwt-issuer or --auth-jwt-discovery-url"
                    .to_string(),
            )
        })?;
        return derive_oidc_discovery_url_from_issuer(issuer).map(Some);
    }
    Ok(None)
}

async fn resolve_jwks_key_set(
    jwks_uri: &Url,
    field_name: &str,
    egress_contract: Option<&HttpEgressContract>,
) -> Result<JwtJwksKeySet, CliError> {
    let document: JwksDocument =
        fetch_identity_provider_json(jwks_uri, field_name, egress_contract).await?;
    let mut keys_by_kid = HashMap::new();
    let mut anonymous_keys = Vec::new();
    for key in document.keys {
        let kid = key.kid.clone();
        let alg_hint = key.alg.clone();
        if let Some(key_use) = key.key_use.as_deref() {
            if key_use != "sig" {
                continue;
            }
        }
        let Some(resolved_key) =
            resolve_jwk_public_key(key, jwks_uri, field_name, alg_hint.clone())?
        else {
            continue;
        };
        if let Some(kid) = kid {
            keys_by_kid.insert(kid, resolved_key);
        } else {
            anonymous_keys.push(resolved_key);
        }
    }
    if keys_by_kid.is_empty() && anonymous_keys.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{field_name} `{}` did not expose any supported signing keys",
            jwks_uri
        )));
    }
    Ok(JwtJwksKeySet {
        keys_by_kid,
        anonymous_keys,
    })
}

fn decode_jwk_component(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<Vec<u8>, CliError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to decode {component_name} from {field_name} `{}`: {error}",
            jwks_uri
        ))
    })
}

fn decode_fixed_jwk_component<const N: usize>(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<[u8; N], CliError> {
    let bytes = decode_jwk_component(value, component_name, jwks_uri, field_name)?;
    if bytes.len() != N {
        return Err(CliError::cli_other_error(format!(
            "{component_name} from {field_name} `{}` had invalid length {}, expected {}",
            jwks_uri,
            bytes.len(),
            N
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_jwk_public_key(
    key: JwkDocumentKey,
    jwks_uri: &Url,
    field_name: &str,
    alg_hint: Option<String>,
) -> Result<Option<JwtResolvedJwkPublicKey>, CliError> {
    let resolved = match key.kty.as_str() {
        "OKP" if key.crv.as_deref() == Some("Ed25519") => {
            let Some(x) = key.x.as_deref() else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            JwtResolvedPublicKey::Ed25519(PublicKey::from_bytes(&x)?)
        }
        "EC" if key.crv.as_deref() == Some("P-256") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<32>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 65];
            encoded[0] = 0x04;
            encoded[1..33].copy_from_slice(&x);
            encoded[33..65].copy_from_slice(&y);
            JwtResolvedPublicKey::P256(P256VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "failed to parse P-256 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "EC" if key.crv.as_deref() == Some("P-384") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<48>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<48>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 97];
            encoded[0] = 0x04;
            encoded[1..49].copy_from_slice(&x);
            encoded[49..97].copy_from_slice(&y);
            JwtResolvedPublicKey::P384(P384VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "failed to parse P-384 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "RSA" => {
            let (Some(n), Some(e)) = (key.n.as_deref(), key.e.as_deref()) else {
                return Ok(None);
            };
            let modulus =
                BigUint::from_bytes_be(&decode_jwk_component(n, "n", jwks_uri, field_name)?);
            let exponent =
                BigUint::from_bytes_be(&decode_jwk_component(e, "e", jwks_uri, field_name)?);
            JwtResolvedPublicKey::Rsa(JwtRsaPublicKey::new(modulus, exponent).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to parse RSA JWK from {field_name} `{}`: {error}",
                    jwks_uri
                ))
            })?)
        }
        _ => return Ok(None),
    };
    Ok(Some(JwtResolvedJwkPublicKey {
        key: resolved,
        alg_hint,
    }))
}

async fn resolve_discovered_identity_provider(
    config: &RemoteServeHttpConfig,
) -> Result<Option<DiscoveredIdentityProvider>, CliError> {
    let Some(discovery_url) = resolve_identity_provider_discovery_url(config)? else {
        return Ok(None);
    };
    let egress_contract = config.egress_contract.as_ref();
    let document: OidcDiscoveryDocument = fetch_identity_provider_json(
        &discovery_url,
        "--auth-jwt-discovery-url",
        egress_contract,
    )
    .await?;
    let issuer_url = parse_identity_provider_url(&document.issuer, "discovered OIDC issuer")?;
    let issuer = canonicalize_federated_issuer(issuer_url.as_str());
    if let Some(expected_issuer) = config.auth_jwt_issuer.as_deref() {
        if canonicalize_federated_issuer(expected_issuer) != issuer {
            return Err(CliError::cli_other_error(format!(
                "OIDC discovery issuer `{issuer}` did not match configured --auth-jwt-issuer `{expected_issuer}`"
            )));
        }
    }

    let authorization_endpoint = document.authorization_endpoint;
    let token_endpoint = document.token_endpoint;
    let registration_endpoint = document.registration_endpoint;
    let jwks_uri = match document.jwks_uri {
        Some(uri) => Some(parse_identity_provider_url(
            &uri,
            "discovered OIDC jwks_uri",
        )?),
        None => None,
    };
    let jwks_keys = if config.auth_jwt_public_key.is_none()
        && config.auth_server_seed_path.is_none()
        && config.auth_introspection_url.is_none()
    {
        let jwks_uri = jwks_uri.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "OIDC discovery metadata did not include `jwks_uri` for JWT verification"
                    .to_string(),
            )
        })?;
        Some(resolve_jwks_key_set(
            jwks_uri,
            "discovered OIDC jwks_uri",
            egress_contract,
        )
        .await?)
    } else {
        None
    };

    Ok(Some(DiscoveredIdentityProvider {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: jwks_uri.map(|url| url.to_string()),
        jwks_keys,
    }))
}

fn build_federated_principal(
    claims: &JwtClaims,
    expected_issuer: Option<&str>,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    provider_profile: JwtProviderProfile,
) -> Result<String, Response> {
    let issuer = claims
        .iss
        .as_deref()
        .or(expected_issuer)
        .map(canonicalize_federated_issuer)
        .ok_or_else(|| {
            unauthorized_bearer_response(
                "JWT bearer token missing issuer for identity federation",
                protected_resource_metadata,
            )
        })?;

    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if let Some(object_id) = claims.oid.as_deref() {
                return Ok(format!("oidc:{issuer}#oid:{object_id}"));
            }
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims
                .azp
                .as_deref()
                .or(claims.appid.as_deref())
                .or(claims.client_id.as_deref())
            {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing oid, subject, and client claims for Azure AD identity federation",
                protected_resource_metadata,
            ))
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims.client_id.as_deref() {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing subject and client_id for identity federation",
                protected_resource_metadata,
            ))
        }
    }
}

fn build_federated_claims(
    claims: &JwtClaims,
    _provider_profile: JwtProviderProfile,
) -> OAuthBearerFederatedClaims {
    OAuthBearerFederatedClaims {
        client_id: claims
            .client_id
            .clone()
            .or_else(|| claims.azp.clone())
            .or_else(|| claims.appid.clone()),
        object_id: claims.oid.clone(),
        tenant_id: claims.tid.clone().or_else(|| claims.tenant_id.clone()),
        organization_id: claims
            .org_id
            .clone()
            .or_else(|| claims.organization_id.clone()),
        groups: normalize_claim_list(&claims.groups),
        roles: normalize_claim_list(&claims.roles),
    }
}

fn matched_bearer_enterprise_provider<'a>(
    registry: Option<&'a EnterpriseProviderRegistry>,
    issuer: Option<&str>,
    kind: EnterpriseProviderKind,
) -> Option<&'a EnterpriseProviderRecord> {
    let issuer = issuer.map(canonicalize_federated_issuer)?;
    registry?.providers.values().find(|record| {
        record.kind == kind
            && record.is_validated_enabled()
            && record
                .issuer
                .as_deref()
                .map(canonicalize_federated_issuer)
                .as_deref()
                == Some(issuer.as_str())
    })
}

fn derive_enterprise_subject_key(provider_scope: &str, canonical_principal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([1u8]);
    hasher.update(provider_scope.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical_principal.as_bytes());
    let digest = hasher.finalize();
    sha256_hex(digest.as_slice())
}

fn build_enterprise_identity_context(
    claims: &JwtClaims,
    federated_claims: &OAuthBearerFederatedClaims,
    principal: &str,
    provider_profile: JwtProviderProfile,
    provider_kind: EnterpriseProviderKind,
    matched_provider: Option<&EnterpriseProviderRecord>,
) -> EnterpriseIdentityContext {
    let issuer = claims
        .iss
        .as_deref()
        .map(canonicalize_federated_issuer)
        .unwrap_or_default();
    let provider_id = matched_provider
        .map(|provider| provider.provider_id.clone())
        .unwrap_or_else(|| issuer.clone());
    let mut attribute_sources = BTreeMap::new();

    if let Some(source) = matched_provider
        .map(|provider| provider.subject_mapping.principal_source.trim())
        .filter(|source| !source.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| bearer_principal_source_field(claims, provider_profile).map(ToOwned::to_owned))
    {
        attribute_sources.insert("principal".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.client_id_field.clone())
        .or_else(|| bearer_client_id_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("clientId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.object_id_field.clone())
        .or_else(|| claims.oid.as_ref().map(|_| "oid".to_string()))
    {
        attribute_sources.insert("objectId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.tenant_id_field.clone())
        .or_else(|| bearer_tenant_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("tenantId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.organization_id_field.clone())
        .or_else(|| bearer_organization_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("organizationId".to_string(), source);
    }
    if !federated_claims.groups.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.groups_field.clone())
            .unwrap_or_else(|| "groups".to_string());
        attribute_sources.insert("groups".to_string(), source);
    }
    if !federated_claims.roles.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.roles_field.clone())
            .unwrap_or_else(|| "roles".to_string());
        attribute_sources.insert("roles".to_string(), source);
    }

    EnterpriseIdentityContext {
        provider_id: provider_id.clone(),
        provider_record_id: matched_provider.map(|provider| provider.provider_id.clone()),
        provider_kind: enterprise_provider_kind_name(&provider_kind).to_string(),
        federation_method: enterprise_federation_method(&provider_kind),
        principal: principal.to_string(),
        subject_key: derive_enterprise_subject_key(&provider_id, principal),
        client_id: federated_claims.client_id.clone(),
        object_id: federated_claims.object_id.clone(),
        tenant_id: federated_claims.tenant_id.clone(),
        organization_id: federated_claims.organization_id.clone(),
        groups: federated_claims.groups.clone(),
        roles: federated_claims.roles.clone(),
        source_subject: claims.sub.clone(),
        attribute_sources,
        trust_material_ref: matched_provider
            .and_then(|provider| provider.provenance.trust_material_ref.clone()),
    }
}

fn enterprise_provider_kind_name(kind: &EnterpriseProviderKind) -> &'static str {
    match kind {
        EnterpriseProviderKind::OidcJwks => "oidc_jwks",
        EnterpriseProviderKind::OauthIntrospection => "oauth_introspection",
        EnterpriseProviderKind::Scim => "scim",
        EnterpriseProviderKind::Saml => "saml",
    }
}

fn enterprise_federation_method(kind: &EnterpriseProviderKind) -> EnterpriseFederationMethod {
    match kind {
        EnterpriseProviderKind::OidcJwks => EnterpriseFederationMethod::Jwt,
        EnterpriseProviderKind::OauthIntrospection => EnterpriseFederationMethod::Introspection,
        EnterpriseProviderKind::Scim => EnterpriseFederationMethod::Scim,
        EnterpriseProviderKind::Saml => EnterpriseFederationMethod::Saml,
    }
}

fn bearer_principal_source_field(
    claims: &JwtClaims,
    provider_profile: JwtProviderProfile,
) -> Option<&'static str> {
    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if claims.oid.is_some() {
                Some("oid")
            } else if claims.sub.is_some() {
                Some("sub")
            } else if claims.azp.is_some() {
                Some("azp")
            } else if claims.appid.is_some() {
                Some("appid")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if claims.sub.is_some() {
                Some("sub")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
    }
}

fn bearer_client_id_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.client_id.is_some() {
        Some("client_id")
    } else if claims.azp.is_some() {
        Some("azp")
    } else if claims.appid.is_some() {
        Some("appid")
    } else {
        None
    }
}

fn bearer_tenant_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.tid.is_some() {
        Some("tid")
    } else if claims.tenant_id.is_some() {
        Some("tenant_id")
    } else {
        None
    }
}

fn bearer_organization_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.org_id.is_some() {
        Some("org_id")
    } else if claims.organization_id.is_some() {
        Some("organization_id")
    } else {
        None
    }
}

fn normalize_claim_list(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn deserialize_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringVecOrString {
        String(String),
        Strings(Vec<String>),
    }

    let raw = Option::<StringVecOrString>::deserialize(deserializer)?;
    Ok(match raw {
        None => Vec::new(),
        Some(StringVecOrString::String(value)) => vec![value],
        Some(StringVecOrString::Strings(values)) => values,
    })
}

fn derive_federated_agent_keypair(
    seed_path: &FsPath,
    federated_principal: &str,
) -> Result<Keypair, CliError> {
    let master_key = load_or_create_authority_keypair(seed_path)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([0u8]);
    hasher.update(master_key.seed_bytes());
    hasher.update([0u8]);
    hasher.update(federated_principal.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    Ok(Keypair::from_seed(&seed))
}
