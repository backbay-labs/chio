pub const CHIO_PUBLIC_ISSUER_DISCOVERY_SCHEMA: &str = "chio.public-issuer-discovery.v1";
pub const CHIO_PUBLIC_VERIFIER_DISCOVERY_SCHEMA: &str = "chio.public-verifier-discovery.v1";
pub const CHIO_PUBLIC_DISCOVERY_TRANSPARENCY_SCHEMA: &str = "chio.public-discovery-transparency.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicDiscoveryImportGuardrails {
    pub informational_only: bool,
    pub requires_explicit_policy_import: bool,
    pub requires_manual_review: bool,
}

impl Default for PublicDiscoveryImportGuardrails {
    fn default() -> Self {
        Self {
            informational_only: true,
            requires_explicit_policy_import: true,
            requires_manual_review: true,
        }
    }
}

impl PublicDiscoveryImportGuardrails {
    fn validate(&self) -> Result<(), CredentialError> {
        if !self.informational_only {
            return Err(CredentialError::InvalidPublicDiscoveryDocument(
                "public discovery must remain informational only".to_string(),
            ));
        }
        if !self.requires_explicit_policy_import {
            return Err(CredentialError::InvalidPublicDiscoveryDocument(
                "public discovery must require explicit local policy import".to_string(),
            ));
        }
        if !self.requires_manual_review {
            return Err(CredentialError::InvalidPublicDiscoveryDocument(
                "public discovery must require manual review before activation".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicIssuerDiscoveryBody {
    pub schema: String,
    pub discovery_id: String,
    pub issuer: String,
    pub signer_public_key: PublicKey,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub metadata_url: String,
    pub metadata_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_configuration_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub passport_status_distribution: PassportStatusDistribution,
    #[serde(default)]
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicIssuerDiscovery {
    pub body: SignedPublicIssuerDiscoveryBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicVerifierDiscoveryBody {
    pub schema: String,
    pub discovery_id: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub metadata_url: String,
    pub metadata_sha256: String,
    pub jwks_uri: String,
    pub request_uri_prefix: String,
    #[serde(default)]
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicVerifierDiscovery {
    pub body: SignedPublicVerifierDiscoveryBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PublicDiscoveryEntryKind {
    Issuer,
    Verifier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicDiscoveryTransparencyEntry {
    pub kind: PublicDiscoveryEntryKind,
    pub discovery_id: String,
    pub metadata_url: String,
    pub document_sha256: String,
    pub published_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicDiscoveryTransparencyBody {
    pub schema: String,
    pub transparency_id: String,
    pub publisher: String,
    pub signer_public_key: PublicKey,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<PublicDiscoveryTransparencyEntry>,
    #[serde(default)]
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicDiscoveryTransparency {
    pub body: SignedPublicDiscoveryTransparencyBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublicIssuerDiscoveryInput {
    pub discovery_id: String,
    pub issuer: String,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub metadata_url: String,
    pub metadata_sha256: String,
    pub jwks_uri: Option<String>,
    pub credential_configuration_ids: Vec<String>,
    pub passport_status_distribution: PassportStatusDistribution,
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

pub fn create_signed_public_issuer_discovery(
    signer_keypair: &Keypair,
    input: SignedPublicIssuerDiscoveryInput,
) -> Result<SignedPublicIssuerDiscovery, CredentialError> {
    let SignedPublicIssuerDiscoveryInput {
        discovery_id,
        issuer,
        version,
        published_at,
        expires_at,
        metadata_url,
        metadata_sha256,
        jwks_uri,
        credential_configuration_ids,
        passport_status_distribution,
        import_guardrails,
    } = input;
    let body = SignedPublicIssuerDiscoveryBody {
        schema: CHIO_PUBLIC_ISSUER_DISCOVERY_SCHEMA.to_string(),
        discovery_id,
        issuer,
        signer_public_key: signer_keypair.public_key(),
        version,
        published_at,
        expires_at,
        metadata_url,
        metadata_sha256,
        jwks_uri,
        credential_configuration_ids,
        passport_status_distribution,
        import_guardrails,
    };
    verify_signed_public_issuer_discovery_body(&body)?;
    let (signature, _) = signer_keypair.sign_canonical(&body)?;
    let document = SignedPublicIssuerDiscovery { body, signature };
    verify_signed_public_issuer_discovery(&document)?;
    Ok(document)
}

pub fn verify_signed_public_issuer_discovery(
    document: &SignedPublicIssuerDiscovery,
) -> Result<(), CredentialError> {
    verify_signed_public_issuer_discovery_body(&document.body)?;
    if !document
        .body
        .signer_public_key
        .verify_canonical(&document.body, &document.signature)?
    {
        return Err(CredentialError::InvalidPublicDiscoverySignature);
    }
    Ok(())
}

pub fn ensure_signed_public_issuer_discovery_active(
    document: &SignedPublicIssuerDiscovery,
    now: u64,
) -> Result<(), CredentialError> {
    ensure_signed_public_discovery_active(document.body.published_at, document.body.expires_at, now)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublicVerifierDiscoveryInput {
    pub discovery_id: String,
    pub verifier: String,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub metadata_url: String,
    pub metadata_sha256: String,
    pub jwks_uri: String,
    pub request_uri_prefix: String,
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

pub fn create_signed_public_verifier_discovery(
    signer_keypair: &Keypair,
    input: SignedPublicVerifierDiscoveryInput,
) -> Result<SignedPublicVerifierDiscovery, CredentialError> {
    let SignedPublicVerifierDiscoveryInput {
        discovery_id,
        verifier,
        version,
        published_at,
        expires_at,
        metadata_url,
        metadata_sha256,
        jwks_uri,
        request_uri_prefix,
        import_guardrails,
    } = input;
    let body = SignedPublicVerifierDiscoveryBody {
        schema: CHIO_PUBLIC_VERIFIER_DISCOVERY_SCHEMA.to_string(),
        discovery_id,
        verifier,
        signer_public_key: signer_keypair.public_key(),
        version,
        published_at,
        expires_at,
        metadata_url,
        metadata_sha256,
        jwks_uri,
        request_uri_prefix,
        import_guardrails,
    };
    verify_signed_public_verifier_discovery_body(&body)?;
    let (signature, _) = signer_keypair.sign_canonical(&body)?;
    let document = SignedPublicVerifierDiscovery { body, signature };
    verify_signed_public_verifier_discovery(&document)?;
    Ok(document)
}

pub fn verify_signed_public_verifier_discovery(
    document: &SignedPublicVerifierDiscovery,
) -> Result<(), CredentialError> {
    verify_signed_public_verifier_discovery_body(&document.body)?;
    if !document
        .body
        .signer_public_key
        .verify_canonical(&document.body, &document.signature)?
    {
        return Err(CredentialError::InvalidPublicDiscoverySignature);
    }
    Ok(())
}

pub fn ensure_signed_public_verifier_discovery_active(
    document: &SignedPublicVerifierDiscovery,
    now: u64,
) -> Result<(), CredentialError> {
    ensure_signed_public_discovery_active(document.body.published_at, document.body.expires_at, now)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublicDiscoveryTransparencyInput {
    pub transparency_id: String,
    pub publisher: String,
    pub version: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub entries: Vec<PublicDiscoveryTransparencyEntry>,
    pub import_guardrails: PublicDiscoveryImportGuardrails,
}

pub fn create_signed_public_discovery_transparency(
    signer_keypair: &Keypair,
    input: SignedPublicDiscoveryTransparencyInput,
) -> Result<SignedPublicDiscoveryTransparency, CredentialError> {
    let SignedPublicDiscoveryTransparencyInput {
        transparency_id,
        publisher,
        version,
        published_at,
        expires_at,
        entries,
        import_guardrails,
    } = input;
    let body = SignedPublicDiscoveryTransparencyBody {
        schema: CHIO_PUBLIC_DISCOVERY_TRANSPARENCY_SCHEMA.to_string(),
        transparency_id,
        publisher,
        signer_public_key: signer_keypair.public_key(),
        version,
        published_at,
        expires_at,
        entries,
        import_guardrails,
    };
    verify_signed_public_discovery_transparency_body(&body)?;
    let (signature, _) = signer_keypair.sign_canonical(&body)?;
    let document = SignedPublicDiscoveryTransparency { body, signature };
    verify_signed_public_discovery_transparency(&document)?;
    Ok(document)
}

pub fn verify_signed_public_discovery_transparency(
    document: &SignedPublicDiscoveryTransparency,
) -> Result<(), CredentialError> {
    verify_signed_public_discovery_transparency_body(&document.body)?;
    if !document
        .body
        .signer_public_key
        .verify_canonical(&document.body, &document.signature)?
    {
        return Err(CredentialError::InvalidPublicDiscoverySignature);
    }
    Ok(())
}

pub fn ensure_signed_public_discovery_transparency_active(
    document: &SignedPublicDiscoveryTransparency,
    now: u64,
) -> Result<(), CredentialError> {
    ensure_signed_public_discovery_active(document.body.published_at, document.body.expires_at, now)
}

fn verify_signed_public_issuer_discovery_body(
    body: &SignedPublicIssuerDiscoveryBody,
) -> Result<(), CredentialError> {
    if body.schema != CHIO_PUBLIC_ISSUER_DISCOVERY_SCHEMA {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "issuer discovery schema must be {CHIO_PUBLIC_ISSUER_DISCOVERY_SCHEMA}"
        )));
    }
    if body.discovery_id.trim().is_empty() {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "issuer discovery must include a non-empty discovery_id".to_string(),
        ));
    }
    if body.version == 0 {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "issuer discovery must include a non-zero version".to_string(),
        ));
    }
    validate_discovery_window(body.published_at, body.expires_at)?;
    let issuer = normalize_credential_issuer(&body.issuer)?;
    validate_endpoint_prefix(&issuer, "metadata_url", &body.metadata_url)?;
    if let Some(jwks_uri) = body.jwks_uri.as_ref() {
        validate_endpoint_prefix(&issuer, "jwks_uri", jwks_uri)?;
    }
    validate_non_empty_sha256(&body.metadata_sha256, "metadata_sha256")?;
    validate_discovery_sorted_unique_strings(
        &body.credential_configuration_ids,
        "credential_configuration_ids",
        &body.discovery_id,
    )?;
    body.passport_status_distribution.validate()?;
    body.import_guardrails.validate()?;
    Ok(())
}

fn verify_signed_public_verifier_discovery_body(
    body: &SignedPublicVerifierDiscoveryBody,
) -> Result<(), CredentialError> {
    if body.schema != CHIO_PUBLIC_VERIFIER_DISCOVERY_SCHEMA {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "verifier discovery schema must be {CHIO_PUBLIC_VERIFIER_DISCOVERY_SCHEMA}"
        )));
    }
    if body.discovery_id.trim().is_empty() {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "verifier discovery must include a non-empty discovery_id".to_string(),
        ));
    }
    if body.version == 0 {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "verifier discovery must include a non-zero version".to_string(),
        ));
    }
    validate_discovery_window(body.published_at, body.expires_at)?;
    let verifier = normalize_credential_issuer(&body.verifier)?;
    validate_endpoint_prefix(&verifier, "metadata_url", &body.metadata_url)?;
    validate_endpoint_prefix(&verifier, "jwks_uri", &body.jwks_uri)?;
    validate_endpoint_prefix(&verifier, "request_uri_prefix", &body.request_uri_prefix)?;
    validate_non_empty_sha256(&body.metadata_sha256, "metadata_sha256")?;
    body.import_guardrails.validate()?;
    Ok(())
}

fn verify_signed_public_discovery_transparency_body(
    body: &SignedPublicDiscoveryTransparencyBody,
) -> Result<(), CredentialError> {
    if body.schema != CHIO_PUBLIC_DISCOVERY_TRANSPARENCY_SCHEMA {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "public discovery transparency schema must be {CHIO_PUBLIC_DISCOVERY_TRANSPARENCY_SCHEMA}"
        )));
    }
    if body.transparency_id.trim().is_empty() {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "public discovery transparency must include a non-empty transparency_id".to_string(),
        ));
    }
    if body.version == 0 {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "public discovery transparency must include a non-zero version".to_string(),
        ));
    }
    validate_discovery_window(body.published_at, body.expires_at)?;
    let publisher = normalize_credential_issuer(&body.publisher)?;
    if body.entries.is_empty() {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "public discovery transparency must include at least one entry".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in &body.entries {
        if entry.discovery_id.trim().is_empty() {
            return Err(CredentialError::InvalidPublicDiscoveryDocument(
                "public discovery transparency entries must include a non-empty discovery_id"
                    .to_string(),
            ));
        }
        validate_endpoint_prefix(&publisher, "metadata_url", &entry.metadata_url)?;
        validate_non_empty_sha256(&entry.document_sha256, "document_sha256")?;
        validate_discovery_window(entry.published_at, entry.expires_at)?;
        if !seen.insert((entry.kind, entry.discovery_id.clone())) {
            return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
                "public discovery transparency repeats entry `{:?}:{}`",
                entry.kind, entry.discovery_id
            )));
        }
    }
    body.import_guardrails.validate()?;
    Ok(())
}

fn ensure_signed_public_discovery_active(
    published_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), CredentialError> {
    if now < published_at {
        return Err(CredentialError::PublicDiscoveryNotYetValid);
    }
    if now > expires_at {
        return Err(CredentialError::PublicDiscoveryExpired);
    }
    Ok(())
}

fn validate_discovery_window(published_at: u64, expires_at: u64) -> Result<(), CredentialError> {
    if published_at > expires_at {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(
            "public discovery published_at must be before or equal to expires_at".to_string(),
        ));
    }
    Ok(())
}

fn validate_non_empty_sha256(value: &str, field: &str) -> Result<(), CredentialError> {
    if value.trim().is_empty() {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_discovery_sorted_unique_strings(
    values: &[String],
    field: &str,
    id: &str,
) -> Result<(), CredentialError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "{field} for `{id}` cannot contain empty values"
        )));
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != values {
        return Err(CredentialError::InvalidPublicDiscoveryDocument(format!(
            "{field} for `{id}` must be stored in sorted unique order"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn signed_public_issuer_discovery_roundtrip_is_active() {
        let signer = Keypair::generate();
        let document = create_signed_public_issuer_discovery(
            &signer,
            SignedPublicIssuerDiscoveryInput {
                discovery_id: "issuer-discovery-1".to_string(),
                issuer: "https://issuer.example.com".to_string(),
                version: 1,
                published_at: 100,
                expires_at: 300,
                metadata_url: "https://issuer.example.com/.well-known/openid-credential-issuer"
                    .to_string(),
                metadata_sha256: "abc123".to_string(),
                jwks_uri: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
                credential_configuration_ids: vec![
                    "chio_agent_passport".to_string(),
                    "chio_agent_passport_sd_jwt_vc".to_string(),
                ],
                passport_status_distribution: PassportStatusDistribution {
                    resolve_urls: vec![
                        "https://issuer.example.com/v1/public/passport/statuses/resolve"
                            .to_string(),
                    ],
                    cache_ttl_secs: Some(300),
                },
                import_guardrails: PublicDiscoveryImportGuardrails::default(),
            },
        )
        .expect("issuer discovery");

        verify_signed_public_issuer_discovery(&document).expect("verify");
        ensure_signed_public_issuer_discovery_active(&document, 150).expect("active");
    }

    #[test]
    fn signed_public_verifier_discovery_rejects_missing_guardrails() {
        let signer = Keypair::generate();
        let error = create_signed_public_verifier_discovery(
            &signer,
            SignedPublicVerifierDiscoveryInput {
                discovery_id: "verifier-discovery-1".to_string(),
                verifier: "https://verifier.example.com".to_string(),
                version: 1,
                published_at: 100,
                expires_at: 300,
                metadata_url: "https://verifier.example.com/.well-known/chio-oid4vp-verifier"
                    .to_string(),
                metadata_sha256: "def456".to_string(),
                jwks_uri: "https://verifier.example.com/.well-known/jwks.json".to_string(),
                request_uri_prefix:
                    "https://verifier.example.com/v1/public/passport/oid4vp/requests/".to_string(),
                import_guardrails: PublicDiscoveryImportGuardrails {
                    informational_only: false,
                    ..PublicDiscoveryImportGuardrails::default()
                },
            },
        )
        .expect_err("missing informational guardrail should fail");

        assert!(error.to_string().contains("informational only"));
    }

    #[test]
    fn signed_public_discovery_transparency_rejects_duplicate_entries() {
        let signer = Keypair::generate();
        let error = create_signed_public_discovery_transparency(
            &signer,
            SignedPublicDiscoveryTransparencyInput {
                transparency_id: "transparency-1".to_string(),
                publisher: "https://trust.example.com".to_string(),
                version: 1,
                published_at: 100,
                expires_at: 300,
                entries: vec![
                    PublicDiscoveryTransparencyEntry {
                        kind: PublicDiscoveryEntryKind::Issuer,
                        discovery_id: "issuer-discovery-1".to_string(),
                        metadata_url:
                            "https://trust.example.com/.well-known/openid-credential-issuer"
                                .to_string(),
                        document_sha256: "aaa".to_string(),
                        published_at: 100,
                        expires_at: 300,
                    },
                    PublicDiscoveryTransparencyEntry {
                        kind: PublicDiscoveryEntryKind::Issuer,
                        discovery_id: "issuer-discovery-1".to_string(),
                        metadata_url:
                            "https://trust.example.com/.well-known/openid-credential-issuer"
                                .to_string(),
                        document_sha256: "bbb".to_string(),
                        published_at: 100,
                        expires_at: 300,
                    },
                ],
                import_guardrails: PublicDiscoveryImportGuardrails::default(),
            },
        )
        .expect_err("duplicate transparency entries should fail");

        assert!(error.to_string().contains("repeats entry"));
    }
}
