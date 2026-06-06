use super::*;

pub(super) const COSE_HEADER_ALGORITHM_KEY: i64 = 1;
pub(super) const COSE_ES384_ALGORITHM: i64 = -35;

#[derive(Debug, Deserialize)]
struct AwsNitroCoseSign1(Vec<u8>, BTreeMap<i64, CborValue>, Vec<u8>, Vec<u8>);

#[derive(Debug, Deserialize)]
pub(super) struct AwsNitroAttestationDocument {
    pub(super) module_id: String,
    pub(super) timestamp: u64,
    pub(super) digest: String,
    pub(super) pcrs: BTreeMap<u8, Vec<u8>>,
    pub(super) certificate: Vec<u8>,
    #[serde(default)]
    pub(super) cabundle: Vec<Vec<u8>>,
    #[serde(default)]
    pub(super) public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub(super) user_data: Option<Vec<u8>>,
    #[serde(default)]
    pub(super) nonce: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OidcJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum OidcJwtDecodeError {
    #[error("invalid JWT: {0}")]
    InvalidJwt(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub(super) enum OidcRsaKeyResolveError {
    #[error("signing key is not trusted")]
    UntrustedSigningKey,

    #[error("JWT signing key does not support algorithm `{0}`")]
    KeyAlgorithmMismatch(String),

    #[error("failed to decode JWK component `{component}`: {error}")]
    InvalidJwkComponent {
        component: &'static str,
        error: String,
    },

    #[error("failed to parse RSA key: {0}")]
    InvalidRsaKey(String),

    #[error("failed to parse certificate chain: {0}")]
    InvalidCertificate(String),
}

#[derive(Debug, Deserialize)]
struct AzureMaaJwtClaims {
    iss: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(default)]
    jti: Option<String>,
    #[serde(rename = "x-ms-ver")]
    version: String,
    #[serde(rename = "x-ms-attestation-type")]
    attestation_type: String,
    #[serde(default, rename = "x-ms-policy-hash")]
    policy_hash: Option<String>,
    #[serde(default, rename = "x-ms-runtime")]
    runtime: Option<Value>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct GoogleConfidentialVmJwtClaims {
    iss: String,
    sub: String,
    aud: Value,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(default, rename = "secboot")]
    secure_boot: Option<bool>,
    #[serde(default, rename = "hwmodel")]
    hardware_model: Option<String>,
    #[serde(default, rename = "swname")]
    software_name: Option<String>,
    #[serde(default, rename = "eat_nonce")]
    nonce: Option<String>,
    #[serde(default)]
    google_service_accounts: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AzureMaaJwtAlgorithm {
    Rs256,
    Ps256,
}

impl AzureMaaJwtAlgorithm {
    pub(super) fn parse(value: &str) -> Result<Self, AzureMaaVerificationError> {
        match value {
            "RS256" => Ok(Self::Rs256),
            "PS256" => Ok(Self::Ps256),
            other => Err(AzureMaaVerificationError::UnsupportedAlgorithm(
                other.to_string(),
            )),
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct AzureMaaResolvedJwk {
    pub(super) key: RsaPublicKey,
    pub(super) alg_hint: Option<String>,
}

impl AzureMaaResolvedJwk {
    pub(super) fn supports_alg(&self, alg: AzureMaaJwtAlgorithm) -> bool {
        self.alg_hint
            .as_deref()
            .is_none_or(|hint| hint == alg.as_str())
    }

    fn verify(&self, alg: AzureMaaJwtAlgorithm, signed_input: &[u8], signature: &[u8]) -> bool {
        match alg {
            AzureMaaJwtAlgorithm::Rs256 => RsaPkcs1v15Signature::try_from(signature)
                .ok()
                .and_then(|signature| {
                    RsaPkcs1v15VerifyingKey::<Sha256>::new(self.key.clone())
                        .verify(signed_input, &signature)
                        .ok()
                })
                .is_some(),
            AzureMaaJwtAlgorithm::Ps256 => RsaPssSignature::try_from(signature)
                .ok()
                .and_then(|signature| {
                    RsaPssVerifyingKey::<Sha256>::new(self.key.clone())
                        .verify(signed_input, &signature)
                        .ok()
                })
                .is_some(),
        }
    }
}

impl From<OidcJwtDecodeError> for AzureMaaVerificationError {
    fn from(value: OidcJwtDecodeError) -> Self {
        match value {
            OidcJwtDecodeError::InvalidJwt(message) => Self::InvalidJwt(message),
        }
    }
}

impl From<OidcRsaKeyResolveError> for AzureMaaVerificationError {
    fn from(value: OidcRsaKeyResolveError) -> Self {
        match value {
            OidcRsaKeyResolveError::UntrustedSigningKey => Self::UntrustedSigningKey,
            OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg) => Self::KeyAlgorithmMismatch(alg),
            OidcRsaKeyResolveError::InvalidJwkComponent { component, error } => {
                Self::InvalidJwkComponent { component, error }
            }
            OidcRsaKeyResolveError::InvalidRsaKey(error) => Self::InvalidRsaKey(error),
            OidcRsaKeyResolveError::InvalidCertificate(error) => Self::InvalidCertificate(error),
        }
    }
}

impl From<OidcJwtDecodeError> for GoogleConfidentialVmVerificationError {
    fn from(value: OidcJwtDecodeError) -> Self {
        match value {
            OidcJwtDecodeError::InvalidJwt(message) => Self::InvalidJwt(message),
        }
    }
}

impl From<OidcRsaKeyResolveError> for GoogleConfidentialVmVerificationError {
    fn from(value: OidcRsaKeyResolveError) -> Self {
        match value {
            OidcRsaKeyResolveError::UntrustedSigningKey => Self::UntrustedSigningKey,
            OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg) => Self::KeyAlgorithmMismatch(alg),
            OidcRsaKeyResolveError::InvalidJwkComponent { component, error } => {
                Self::InvalidJwkComponent { component, error }
            }
            OidcRsaKeyResolveError::InvalidRsaKey(error) => Self::InvalidRsaKey(error),
            OidcRsaKeyResolveError::InvalidCertificate(error) => Self::InvalidCertificate(error),
        }
    }
}

pub fn fetch_azure_maa_openid_metadata(
    metadata_url: &str,
) -> Result<AzureMaaOpenIdMetadata, AzureMaaVerificationError> {
    let response = ureq::get(metadata_url).call().map_err(|error| {
        AzureMaaVerificationError::MetadataFetch {
            url: metadata_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<AzureMaaOpenIdMetadata>()
        .map_err(|error| AzureMaaVerificationError::MetadataParse {
            url: metadata_url.to_string(),
            error: error.to_string(),
        })
}

pub fn fetch_azure_maa_jwks(jwks_url: &str) -> Result<AzureMaaJwks, AzureMaaVerificationError> {
    let response =
        ureq::get(jwks_url)
            .call()
            .map_err(|error| AzureMaaVerificationError::MetadataFetch {
                url: jwks_url.to_string(),
                error: error.to_string(),
            })?;
    response
        .into_json::<AzureMaaJwks>()
        .map_err(|error| AzureMaaVerificationError::MetadataParse {
            url: jwks_url.to_string(),
            error: error.to_string(),
        })
}

pub fn fetch_google_confidential_vm_openid_metadata(
    metadata_url: &str,
) -> Result<GoogleConfidentialVmOpenIdMetadata, GoogleConfidentialVmVerificationError> {
    let response = ureq::get(metadata_url).call().map_err(|error| {
        GoogleConfidentialVmVerificationError::MetadataFetch {
            url: metadata_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<GoogleConfidentialVmOpenIdMetadata>()
        .map_err(
            |error| GoogleConfidentialVmVerificationError::MetadataParse {
                url: metadata_url.to_string(),
                error: error.to_string(),
            },
        )
}

pub fn fetch_google_confidential_vm_jwks(
    jwks_url: &str,
) -> Result<GoogleConfidentialVmJwks, GoogleConfidentialVmVerificationError> {
    let response = ureq::get(jwks_url).call().map_err(|error| {
        GoogleConfidentialVmVerificationError::MetadataFetch {
            url: jwks_url.to_string(),
            error: error.to_string(),
        }
    })?;
    response
        .into_json::<GoogleConfidentialVmJwks>()
        .map_err(
            |error| GoogleConfidentialVmVerificationError::MetadataParse {
                url: jwks_url.to_string(),
                error: error.to_string(),
            },
        )
}

pub fn verify_azure_maa_attestation_jwt(
    token: &str,
    policy: &AzureMaaVerificationPolicy,
    jwks: &AzureMaaJwks,
    now: u64,
) -> Result<RuntimeAttestationEvidence, AzureMaaVerificationError> {
    policy.validate()?;
    let (header, claims, signed_input, signature): (
        OidcJwtHeader,
        AzureMaaJwtClaims,
        String,
        Vec<u8>,
    ) = decode_jwt_parts(token)?;
    let algorithm = AzureMaaJwtAlgorithm::parse(&header.alg)?;
    let key = resolve_signing_key(jwks, header.kid.as_deref(), algorithm)?;
    if !key.verify(algorithm, signed_input.as_bytes(), &signature) {
        return Err(AzureMaaVerificationError::InvalidSignature);
    }

    let expected_issuer = canonicalize_issuer(&policy.issuer);
    let actual_issuer = canonicalize_issuer(&claims.iss);
    if actual_issuer != expected_issuer {
        return Err(AzureMaaVerificationError::IssuerMismatch {
            expected: expected_issuer,
            actual: actual_issuer,
        });
    }

    if now < claims.nbf || now >= claims.exp {
        return Err(AzureMaaVerificationError::TokenNotValid { now });
    }
    if claims.version.trim().is_empty() {
        return Err(AzureMaaVerificationError::MissingClaim("x-ms-ver"));
    }
    if claims.attestation_type.trim().is_empty() {
        return Err(AzureMaaVerificationError::MissingClaim(
            "x-ms-attestation-type",
        ));
    }
    if !policy.allowed_attestation_types.is_empty()
        && !policy
            .allowed_attestation_types
            .iter()
            .any(|allowed| allowed == &claims.attestation_type)
    {
        return Err(AzureMaaVerificationError::DisallowedAttestationType {
            actual: claims.attestation_type.clone(),
        });
    }

    let (runtime_identity, workload_identity) = resolve_workload_identity(
        claims.runtime.as_ref(),
        policy.workload_claim_path.as_deref(),
    )?;

    Ok(RuntimeAttestationEvidence {
        schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        verifier: expected_issuer,
        tier: policy.tier,
        issued_at: claims.iat,
        expires_at: claims.exp,
        evidence_sha256: sha256_hex(token.as_bytes()),
        runtime_identity,
        workload_identity,
        claims: Some(json!({
            "azureMaa": build_vendor_claims(&header, &claims)
        })),
    })
}

#[must_use]
pub fn appraise_azure_maa_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    let mut normalized_assertions = BTreeMap::new();
    let vendor_claims = extract_vendor_claims(evidence, "azureMaa");

    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized_assertions.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized_assertions.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    if let Some(workload_identity) = evidence.workload_identity.as_ref() {
        normalized_assertions.insert(
            "workloadIdentityScheme".to_string(),
            Value::String(format!("{:?}", workload_identity.scheme).to_lowercase()),
        );
        normalized_assertions.insert(
            "workloadIdentityUri".to_string(),
            Value::String(workload_identity.uri.clone()),
        );
    }

    let reason_codes = if evidence.schema == AZURE_MAA_ATTESTATION_SCHEMA {
        vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
    } else {
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    };

    if evidence.schema == AZURE_MAA_ATTESTATION_SCHEMA {
        RuntimeAttestationAppraisal::accepted(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    } else {
        RuntimeAttestationAppraisal::rejected(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    }
}

pub fn verify_google_confidential_vm_attestation_jwt(
    token: &str,
    policy: &GoogleConfidentialVmVerificationPolicy,
    jwks: &GoogleConfidentialVmJwks,
    now: u64,
) -> Result<RuntimeAttestationEvidence, GoogleConfidentialVmVerificationError> {
    policy.validate()?;
    let (header, claims, signed_input, signature): (
        OidcJwtHeader,
        GoogleConfidentialVmJwtClaims,
        String,
        Vec<u8>,
    ) = decode_jwt_parts(token)?;
    let algorithm = match header.alg.as_str() {
        "RS256" => AzureMaaJwtAlgorithm::Rs256,
        other => {
            return Err(GoogleConfidentialVmVerificationError::UnsupportedAlgorithm(
                other.to_string(),
            ))
        }
    };
    let key = resolve_signing_key(jwks, header.kid.as_deref(), algorithm)?;
    if !key.verify(algorithm, signed_input.as_bytes(), &signature) {
        return Err(GoogleConfidentialVmVerificationError::InvalidSignature);
    }

    let expected_issuer = canonicalize_issuer(&policy.issuer);
    let actual_issuer = canonicalize_issuer(&claims.iss);
    if actual_issuer != expected_issuer {
        return Err(GoogleConfidentialVmVerificationError::IssuerMismatch {
            expected: expected_issuer,
            actual: actual_issuer,
        });
    }
    if now < claims.nbf || now >= claims.exp {
        return Err(GoogleConfidentialVmVerificationError::TokenNotValid { now });
    }
    if claims.sub.trim().is_empty() {
        return Err(GoogleConfidentialVmVerificationError::MissingClaim("sub"));
    }
    let audiences = google_token_audiences(&claims.aud)?;
    if !policy.allowed_audiences.is_empty()
        && !audiences.iter().any(|audience| {
            policy
                .allowed_audiences
                .iter()
                .any(|allowed| allowed == audience)
        })
    {
        return Err(GoogleConfidentialVmVerificationError::AudienceMismatch);
    }
    let hardware_model = claims
        .hardware_model
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(GoogleConfidentialVmVerificationError::MissingClaim(
            "hwmodel",
        ))?;
    if !policy.allowed_hardware_models.is_empty()
        && !policy
            .allowed_hardware_models
            .iter()
            .any(|allowed| allowed == hardware_model)
    {
        return Err(
            GoogleConfidentialVmVerificationError::DisallowedHardwareModel {
                actual: hardware_model.to_string(),
            },
        );
    }
    if policy.require_secure_boot && claims.secure_boot != Some(true) {
        return Err(GoogleConfidentialVmVerificationError::InsecureBoot);
    }
    if !policy.allowed_service_accounts.is_empty() {
        let actual = claims
            .google_service_accounts
            .iter()
            .find(|account| {
                policy
                    .allowed_service_accounts
                    .iter()
                    .any(|allowed| allowed == *account)
            })
            .cloned();
        if actual.is_none() {
            return Err(
                GoogleConfidentialVmVerificationError::DisallowedServiceAccount {
                    actual: claims
                        .google_service_accounts
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "<none>".to_string()),
                },
            );
        }
    }

    Ok(RuntimeAttestationEvidence {
        schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
        verifier: expected_issuer,
        tier: policy.tier,
        issued_at: claims.iat,
        expires_at: claims.exp,
        evidence_sha256: sha256_hex(token.as_bytes()),
        runtime_identity: Some(claims.sub.clone()),
        workload_identity: None,
        claims: Some(json!({
            "googleAttestation": build_google_confidential_vm_vendor_claims(&header, &claims, audiences)
        })),
    })
}

#[must_use]
pub fn appraise_google_confidential_vm_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    derive_runtime_attestation_appraisal(evidence).unwrap_or_else(|_| {
        RuntimeAttestationAppraisal::rejected(
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
            AttestationVerifierFamily::GoogleAttestation,
            evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence],
        )
    })
}

pub fn verify_aws_nitro_attestation_document(
    document: &[u8],
    policy: &AwsNitroVerificationPolicy,
    now: u64,
) -> Result<RuntimeAttestationEvidence, AwsNitroVerificationError> {
    policy.validate()?;

    let AwsNitroCoseSign1(protected, _unprotected, payload, signature) =
        cbor_from_reader(Cursor::new(document))
            .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid COSE_Sign1 encoding"))?;
    let protected_headers = decode_cose_protected_headers(&protected)?;
    let algorithm = protected_headers
        .get(&COSE_HEADER_ALGORITHM_KEY)
        .and_then(cbor_integer_to_i64)
        .ok_or(AwsNitroVerificationError::MissingField("protected.alg"))?;
    if algorithm != COSE_ES384_ALGORITHM {
        return Err(AwsNitroVerificationError::UnsupportedAlgorithm(algorithm));
    }

    let payload_doc: AwsNitroAttestationDocument = cbor_from_reader(Cursor::new(&payload))
        .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid attestation payload"))?;
    validate_aws_nitro_document(&payload_doc, policy, now)?;

    let signing_cert = decode_certificate_der(&payload_doc.certificate)?;
    validate_certificate_chain(
        &signing_cert,
        &payload_doc.cabundle,
        &policy.trusted_root_certificates_pem,
        now,
    )?;

    let sig_structure = build_cose_sign1_sig_structure(&protected, &payload)?;
    verify_p384_cose_signature(&signing_cert, &signature, &sig_structure)?;

    Ok(RuntimeAttestationEvidence {
        schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
        verifier: "aws-nitro".to_string(),
        tier: policy.tier,
        issued_at: payload_doc.timestamp / 1000,
        expires_at: payload_doc.timestamp / 1000 + policy.max_document_age_seconds,
        evidence_sha256: sha256_hex(document),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(json!({
            "awsNitro": build_aws_nitro_vendor_claims(&payload_doc, &signing_cert)
        })),
    })
}

#[must_use]
pub fn appraise_aws_nitro_evidence(
    evidence: &RuntimeAttestationEvidence,
) -> RuntimeAttestationAppraisal {
    let vendor_claims = extract_vendor_claims(evidence, "awsNitro");
    let mut normalized_assertions = BTreeMap::new();
    if let Some(module_id) = vendor_claims.get("moduleId") {
        normalized_assertions.insert("moduleId".to_string(), module_id.clone());
    }
    if let Some(digest) = vendor_claims.get("digest") {
        normalized_assertions.insert("digest".to_string(), digest.clone());
    }
    if let Some(pcrs) = vendor_claims.get("pcrs") {
        normalized_assertions.insert("pcrs".to_string(), pcrs.clone());
    }

    let reason_codes = if evidence.schema == AWS_NITRO_ATTESTATION_SCHEMA {
        vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
    } else {
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    };

    if evidence.schema == AWS_NITRO_ATTESTATION_SCHEMA {
        RuntimeAttestationAppraisal::accepted(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    } else {
        RuntimeAttestationAppraisal::rejected(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            normalized_assertions,
            vendor_claims,
            reason_codes,
        )
    }
}

pub(super) fn extract_vendor_claims(
    evidence: &RuntimeAttestationEvidence,
    vendor_key: &str,
) -> BTreeMap<String, Value> {
    evidence
        .claims
        .as_ref()
        .and_then(|claims| claims.get(vendor_key))
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn decode_cose_protected_headers(
    protected: &[u8],
) -> Result<BTreeMap<i64, CborValue>, AwsNitroVerificationError> {
    if protected.is_empty() {
        return Ok(BTreeMap::new());
    }
    cbor_from_reader(Cursor::new(protected))
        .map_err(|_| AwsNitroVerificationError::InvalidCose("invalid protected header map"))
}

pub(super) fn cbor_integer_to_i64(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Integer(value) => cbor_integer_to_i64_inner(*value),
        _ => None,
    }
}

fn cbor_integer_to_i64_inner(value: CborInteger) -> Option<i64> {
    i128::from(value).try_into().ok()
}

pub(super) fn validate_aws_nitro_document(
    document: &AwsNitroAttestationDocument,
    policy: &AwsNitroVerificationPolicy,
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    if document.module_id.trim().is_empty() {
        return Err(AwsNitroVerificationError::MissingField("module_id"));
    }
    if document.certificate.is_empty() {
        return Err(AwsNitroVerificationError::MissingField("certificate"));
    }
    match document.digest.as_str() {
        "SHA384" => {}
        other => {
            return Err(AwsNitroVerificationError::UnsupportedDigest(
                other.to_string(),
            ))
        }
    }

    let issued_at = document.timestamp / 1000;
    if now < issued_at {
        return Err(AwsNitroVerificationError::FutureDocument {
            now,
            timestamp: document.timestamp,
        });
    }
    if now - issued_at > policy.max_document_age_seconds {
        return Err(AwsNitroVerificationError::StaleDocument {
            now,
            timestamp: document.timestamp,
            max_age_seconds: policy.max_document_age_seconds,
        });
    }

    if document.pcrs.is_empty() {
        return Err(AwsNitroVerificationError::MissingField("pcrs"));
    }
    let mut all_zero = true;
    for pcr in document.pcrs.values() {
        if pcr.len() != 48 {
            return Err(AwsNitroVerificationError::InvalidField("pcrs"));
        }
        if pcr.iter().any(|byte| *byte != 0) {
            all_zero = false;
        }
    }
    if all_zero && !policy.allow_debug_mode {
        return Err(AwsNitroVerificationError::DebugModeEvidence);
    }

    for (index, expected_hex) in &policy.expected_pcrs {
        let actual = document
            .pcrs
            .get(index)
            .ok_or(AwsNitroVerificationError::MissingPcr { index: *index })?;
        let expected = hex::decode(expected_hex)
            .map_err(|_| AwsNitroVerificationError::InvalidField("expected_pcrs"))?;
        if *actual != expected {
            return Err(AwsNitroVerificationError::PcrMismatch { index: *index });
        }
    }

    if let Some(expected_nonce_hex) = policy.expected_nonce_hex.as_deref() {
        let actual = document
            .nonce
            .as_ref()
            .ok_or(AwsNitroVerificationError::MissingField("nonce"))?;
        let expected = hex::decode(expected_nonce_hex)
            .map_err(|_| AwsNitroVerificationError::InvalidField("expected_nonce_hex"))?;
        if *actual != expected {
            return Err(AwsNitroVerificationError::NonceMismatch);
        }
    }

    Ok(())
}

pub(super) fn build_cose_sign1_sig_structure(
    protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, AwsNitroVerificationError> {
    let structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut bytes = Vec::new();
    cbor_into_writer(&structure, &mut bytes)
        .map_err(|_| AwsNitroVerificationError::InvalidCose("failed to encode Sig_structure"))?;
    Ok(bytes)
}

fn verify_p384_cose_signature(
    signing_cert: &Certificate,
    signature: &[u8],
    sig_structure: &[u8],
) -> Result<(), AwsNitroVerificationError> {
    let verifying_key = p384_verifying_key_from_cert(signing_cert)?;
    let parsed = parse_p384_signature(signature)?;
    verifying_key
        .verify(sig_structure, &parsed)
        .map_err(|_| AwsNitroVerificationError::InvalidSignature)
}

fn validate_certificate_chain(
    signing_cert: &Certificate,
    cabundle: &[Vec<u8>],
    trusted_roots_pem: &[String],
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    ensure_certificate_valid_at(signing_cert, now)?;
    let chain = cabundle
        .iter()
        .map(|cert| decode_certificate_der(cert))
        .collect::<Result<Vec<_>, _>>()?;

    let mut current = signing_cert;
    for issuer in chain.iter().rev() {
        ensure_certificate_valid_at(issuer, now)?;
        verify_certificate_issued_by(current, issuer)?;
        current = issuer;
    }

    let trusted_roots = trusted_roots_pem
        .iter()
        .map(|pem| {
            Certificate::from_pem(pem)
                .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let anchored = trusted_roots.iter().any(|root| {
        certificates_match(current, root) || verify_certificate_issued_by(current, root).is_ok()
    });
    if !anchored {
        return Err(AwsNitroVerificationError::InvalidCertificateChain(
            "certificate chain did not anchor in a trusted Nitro root".to_string(),
        ));
    }
    Ok(())
}

fn decode_certificate_der(bytes: &[u8]) -> Result<Certificate, AwsNitroVerificationError> {
    Certificate::from_der(bytes)
        .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))
}

fn ensure_certificate_valid_at(
    certificate: &Certificate,
    now: u64,
) -> Result<(), AwsNitroVerificationError> {
    let now_duration = Duration::from_secs(now);
    let validity = certificate.tbs_certificate.validity;
    if validity.not_before.to_unix_duration() > now_duration
        || validity.not_after.to_unix_duration() < now_duration
    {
        return Err(AwsNitroVerificationError::CertificateNotValid { now });
    }
    Ok(())
}

fn verify_certificate_issued_by(
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<(), AwsNitroVerificationError> {
    if certificate.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(AwsNitroVerificationError::InvalidCertificateChain(
            "certificate issuer did not match issuer subject".to_string(),
        ));
    }
    let issuer_key = p384_verifying_key_from_cert(issuer)?;
    let signature = parse_p384_signature(certificate.signature.raw_bytes())?;
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|error| AwsNitroVerificationError::InvalidCertificate(error.to_string()))?;
    issuer_key.verify(&tbs, &signature).map_err(|_| {
        AwsNitroVerificationError::InvalidCertificateChain(
            "certificate signature did not verify".to_string(),
        )
    })
}

fn certificates_match(left: &Certificate, right: &Certificate) -> bool {
    left.tbs_certificate.subject == right.tbs_certificate.subject
        && left
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            == right
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
}

fn p384_verifying_key_from_cert(
    certificate: &Certificate,
) -> Result<P384VerifyingKey, AwsNitroVerificationError> {
    P384VerifyingKey::from_sec1_bytes(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .map_err(|error| AwsNitroVerificationError::InvalidPublicKey(error.to_string()))
}

fn parse_p384_signature(signature: &[u8]) -> Result<P384Signature, AwsNitroVerificationError> {
    P384Signature::from_slice(signature)
        .or_else(|_| P384Signature::from_der(signature))
        .map_err(|_| AwsNitroVerificationError::InvalidSignature)
}

fn build_aws_nitro_vendor_claims(
    document: &AwsNitroAttestationDocument,
    signing_cert: &Certificate,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert(
        "moduleId".to_string(),
        Value::String(document.module_id.clone()),
    );
    vendor.insert("timestampMs".to_string(), Value::from(document.timestamp));
    vendor.insert("digest".to_string(), Value::String(document.digest.clone()));
    vendor.insert(
        "pcrs".to_string(),
        Value::Object(
            document
                .pcrs
                .iter()
                .map(|(index, value)| (index.to_string(), Value::String(hex::encode(value))))
                .collect(),
        ),
    );
    vendor.insert(
        "certificateSha256".to_string(),
        Value::String(sha256_hex(
            &signing_cert
                .to_der()
                .unwrap_or_else(|_| document.certificate.clone()),
        )),
    );
    if let Some(public_key) = document.public_key.as_ref() {
        vendor.insert(
            "publicKeySha256".to_string(),
            Value::String(sha256_hex(public_key)),
        );
    }
    if let Some(user_data) = document.user_data.as_ref() {
        vendor.insert(
            "userDataSha256".to_string(),
            Value::String(sha256_hex(user_data)),
        );
    }
    if let Some(nonce) = document.nonce.as_ref() {
        vendor.insert("nonce".to_string(), Value::String(hex::encode(nonce)));
    }
    vendor
}

fn build_vendor_claims(
    header: &OidcJwtHeader,
    claims: &AzureMaaJwtClaims,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert("version".to_string(), Value::String(claims.version.clone()));
    vendor.insert(
        "attestationType".to_string(),
        Value::String(claims.attestation_type.clone()),
    );
    vendor.insert("issuedAt".to_string(), Value::from(claims.iat));
    vendor.insert("notBefore".to_string(), Value::from(claims.nbf));
    vendor.insert("expiresAt".to_string(), Value::from(claims.exp));
    if let Some(policy_hash) = claims.policy_hash.as_ref() {
        vendor.insert("policyHash".to_string(), Value::String(policy_hash.clone()));
    }
    if let Some(token_id) = claims.jti.as_ref() {
        vendor.insert("tokenId".to_string(), Value::String(token_id.clone()));
    }
    if let Some(kid) = header.kid.as_ref() {
        vendor.insert("signingKeyId".to_string(), Value::String(kid.clone()));
    }
    if let Some(runtime) = claims.runtime.as_ref() {
        vendor.insert("runtime".to_string(), runtime.clone());
    }
    for (key, value) in &claims.extra {
        vendor.insert(key.clone(), value.clone());
    }
    vendor
}

fn build_google_confidential_vm_vendor_claims(
    header: &OidcJwtHeader,
    claims: &GoogleConfidentialVmJwtClaims,
    audiences: Vec<String>,
) -> serde_json::Map<String, Value> {
    let mut vendor = Map::new();
    vendor.insert(
        "attestationType".to_string(),
        Value::String("confidential_vm".to_string()),
    );
    vendor.insert("issuedAt".to_string(), Value::from(claims.iat));
    vendor.insert("notBefore".to_string(), Value::from(claims.nbf));
    vendor.insert("expiresAt".to_string(), Value::from(claims.exp));
    vendor.insert("subject".to_string(), Value::String(claims.sub.clone()));
    vendor.insert(
        "audiences".to_string(),
        Value::Array(audiences.into_iter().map(Value::String).collect()),
    );
    if let Some(hardware_model) = claims.hardware_model.as_ref() {
        vendor.insert(
            "hardwareModel".to_string(),
            Value::String(hardware_model.clone()),
        );
    }
    if let Some(software_name) = claims.software_name.as_ref() {
        vendor.insert(
            "softwareName".to_string(),
            Value::String(software_name.clone()),
        );
    }
    if let Some(secure_boot) = claims.secure_boot {
        vendor.insert(
            "secureBoot".to_string(),
            Value::String(if secure_boot {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            }),
        );
    }
    if let Some(nonce) = claims.nonce.as_ref() {
        vendor.insert("nonce".to_string(), Value::String(nonce.clone()));
    }
    if !claims.google_service_accounts.is_empty() {
        vendor.insert(
            "serviceAccounts".to_string(),
            Value::Array(
                claims
                    .google_service_accounts
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(kid) = header.kid.as_ref() {
        vendor.insert("signingKeyId".to_string(), Value::String(kid.clone()));
    }
    for (key, value) in &claims.extra {
        vendor.insert(key.clone(), value.clone());
    }
    vendor
}

pub(super) fn resolve_workload_identity(
    runtime: Option<&Value>,
    workload_claim_path: Option<&str>,
) -> Result<(Option<String>, Option<WorkloadIdentity>), AzureMaaVerificationError> {
    let Some(path) = workload_claim_path else {
        return Ok((None, None));
    };
    let Some(runtime) = runtime else {
        return Err(AzureMaaVerificationError::InvalidWorkloadClaim(
            path.to_string(),
        ));
    };
    let mut current = runtime
        .get("claims")
        .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    for segment in path.split('.') {
        current = current
            .get(segment)
            .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    }
    let workload_uri = current
        .as_str()
        .ok_or_else(|| AzureMaaVerificationError::InvalidWorkloadClaim(path.to_string()))?;
    let workload_identity =
        WorkloadIdentity::parse_spiffe_uri_with_kind(workload_uri, WorkloadCredentialKind::Uri)
            .map_err(|error| {
                AzureMaaVerificationError::InvalidWorkloadIdentity(error.to_string())
            })?;
    Ok((Some(workload_uri.to_string()), Some(workload_identity)))
}

pub(super) fn google_token_audiences(
    aud: &Value,
) -> Result<Vec<String>, GoogleConfidentialVmVerificationError> {
    match aud {
        Value::String(value) if !value.trim().is_empty() => Ok(vec![value.clone()]),
        Value::Array(values) => {
            let audiences = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if audiences.is_empty() {
                Err(GoogleConfidentialVmVerificationError::MissingClaim("aud"))
            } else {
                Ok(audiences)
            }
        }
        _ => Err(GoogleConfidentialVmVerificationError::MissingClaim("aud")),
    }
}

pub(super) fn canonicalize_issuer(value: &str) -> String {
    let trimmed = value.trim();
    match url::Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

pub(super) fn decode_jwt_parts<T: DeserializeOwned>(
    token: &str,
) -> Result<(OidcJwtHeader, T, String, Vec<u8>), OidcJwtDecodeError> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing header"))?;
    let payload_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing payload"))?;
    let signature_b64 = parts
        .next()
        .ok_or(OidcJwtDecodeError::InvalidJwt("missing signature"))?;
    if parts.next().is_some() {
        return Err(OidcJwtDecodeError::InvalidJwt("too many segments"));
    }

    let header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid header encoding"))?,
    )
    .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid header json"))?;
    let claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid payload encoding"))?,
    )
    .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid payload json"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| OidcJwtDecodeError::InvalidJwt("invalid signature encoding"))?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{payload_b64}"),
        signature,
    ))
}

pub(super) fn resolve_signing_key(
    jwks: &AzureMaaJwks,
    kid: Option<&str>,
    alg: AzureMaaJwtAlgorithm,
) -> Result<AzureMaaResolvedJwk, OidcRsaKeyResolveError> {
    let mut keys_by_kid = HashMap::new();
    let mut anonymous = Vec::new();
    for jwk in &jwks.keys {
        if jwk.key_use.as_deref().is_some_and(|value| value != "sig") {
            continue;
        }
        let resolved = resolve_jwk_public_key(jwk)?;
        if let Some(kid) = jwk.kid.as_ref() {
            keys_by_kid.insert(kid.clone(), resolved);
        } else {
            anonymous.push(resolved);
        }
    }

    if let Some(kid) = kid {
        let key = keys_by_kid
            .get(kid)
            .ok_or(OidcRsaKeyResolveError::UntrustedSigningKey)?;
        if !key.supports_alg(alg) {
            return Err(OidcRsaKeyResolveError::KeyAlgorithmMismatch(
                alg.as_str().to_string(),
            ));
        }
        return Ok(key.clone());
    }

    let mut compatible = keys_by_kid
        .values()
        .chain(anonymous.iter())
        .filter(|key| key.supports_alg(alg));
    let Some(first) = compatible.next() else {
        return Err(OidcRsaKeyResolveError::UntrustedSigningKey);
    };
    if compatible.next().is_some() {
        return Err(OidcRsaKeyResolveError::UntrustedSigningKey);
    }
    Ok(first.clone())
}

pub(super) fn resolve_jwk_public_key(
    jwk: &AzureMaaJwk,
) -> Result<AzureMaaResolvedJwk, OidcRsaKeyResolveError> {
    if jwk.kty != "RSA" {
        return Err(OidcRsaKeyResolveError::InvalidRsaKey(format!(
            "unsupported kty `{}`",
            jwk.kty
        )));
    }
    let key = if let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) {
        let modulus = BigUint::from_bytes_be(&decode_urlsafe_component(n, "n")?);
        let exponent = BigUint::from_bytes_be(&decode_urlsafe_component(e, "e")?);
        RsaPublicKey::new(modulus, exponent)
            .map_err(|error| OidcRsaKeyResolveError::InvalidRsaKey(error.to_string()))?
    } else {
        let first_cert = jwk.x5c.first().ok_or_else(|| {
            OidcRsaKeyResolveError::InvalidRsaKey("RSA JWK must include n/e or x5c".to_string())
        })?;
        let cert_der = STANDARD
            .decode(first_cert)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        let cert = Certificate::from_der(&cert_der)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?;
        RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|error| OidcRsaKeyResolveError::InvalidCertificate(error.to_string()))?
    };

    Ok(AzureMaaResolvedJwk {
        key,
        alg_hint: jwk.alg.clone(),
    })
}

pub(super) fn decode_urlsafe_component(
    value: &str,
    component: &'static str,
) -> Result<Vec<u8>, OidcRsaKeyResolveError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| OidcRsaKeyResolveError::InvalidJwkComponent {
            component,
            error: error.to_string(),
        })
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
