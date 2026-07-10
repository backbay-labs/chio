use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::Digest;

pub const CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID: &str =
    "chio_agent_passport_sd_jwt_vc";
pub const CHIO_PASSPORT_SD_JWT_VC_FORMAT: &str = "application/dc+sd-jwt";
pub const CHIO_PASSPORT_SD_JWT_VC_TYPE: &str =
    "https://chio.world/credentials/types/chio-passport-sd-jwt-vc/v1";
pub const CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH: &str =
    "/.well-known/chio-passport-sd-jwt-vc";
pub const OID4VCI_JWKS_PATH: &str = "/.well-known/jwks.json";
const SD_JWT_VC_TYP: &str = "dc+sd-jwt";
const SD_JWT_VC_HASH_ALG: &str = "sha-256";
const CHIO_PASSPORT_SD_JWT_KEY_ID: &str = "chio-passport-sd-jwt-key-1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortableEd25519Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl PortableEd25519Jwk {
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
        }
    }

    pub fn to_public_key(&self) -> Result<PublicKey, CredentialError> {
        if self.kty != "OKP" {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "portable JWK kty must be `OKP`".to_string(),
            ));
        }
        if self.crv != "Ed25519" {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "portable JWK crv must be `Ed25519`".to_string(),
            ));
        }
        let bytes = URL_SAFE_NO_PAD.decode(self.x.as_bytes()).map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable JWK x is not valid base64url: {error}"
            ))
        })?;
        if bytes.len() != 32 {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable JWK x must decode to 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        PublicKey::from_bytes(&array).map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable JWK x is not a valid Ed25519 public key: {error}"
            ))
        })
    }

    pub fn thumbprint(&self) -> Result<String, CredentialError> {
        let thumbprint_value = json!({
            "crv": self.crv,
            "kty": self.kty,
            "x": self.x,
        });
        let bytes = canonical_json_bytes(&thumbprint_value)?;
        Ok(URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortableJwkSet {
    pub keys: Vec<PortableEd25519JwkSetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortableEd25519JwkSetEntry {
    #[serde(flatten)]
    pub jwk: PortableEd25519Jwk,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
}

pub fn build_portable_jwks(
    identity: &str,
    public_keys: &[PublicKey],
) -> Result<PortableJwkSet, CredentialError> {
    let identity = normalize_credential_issuer(identity)?;
    let mut keys = Vec::new();
    for public_key in public_keys {
        let jwk = PortableEd25519Jwk::from_public_key(public_key);
        keys.push(PortableEd25519JwkSetEntry {
            kid: format!("{identity}#{}", jwk.thumbprint()?),
            jwk,
            use_: "sig".to_string(),
            alg: "EdDSA".to_string(),
        });
    }
    Ok(PortableJwkSet { keys })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPassportSdJwtVcTypeMetadata {
    pub vct: String,
    pub format: String,
    pub subject_binding: String,
    pub issuer_identity: String,
    #[serde(default)]
    pub portable_claim_catalog: ChioPortableClaimCatalog,
    #[serde(default)]
    pub portable_identity_binding: ChioPortableIdentityBinding,
    pub type_metadata_url: String,
    pub jwks_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub always_disclosed_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectively_disclosable_claims: Vec<String>,
    pub status_reference_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPassportPortableProjection {
    pub passport_id: String,
    pub subject_did: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_dids: Vec<String>,
    pub credential_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merkle_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPassportSdJwtVcEnvelope {
    pub compact: String,
    pub passport_id: String,
    pub subject_did: String,
    pub issuer: String,
    pub issuer_jwk: PortableEd25519Jwk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Oid4vciIssuedCredential {
    AgentPassport(AgentPassport),
    Compact(String),
}

impl Oid4vciIssuedCredential {
    pub fn native_passport(&self) -> Option<&AgentPassport> {
        match self {
            Self::AgentPassport(passport) => Some(passport),
            Self::Compact(_) => None,
        }
    }

    pub fn is_compact(&self) -> bool {
        matches!(self, Self::Compact(_))
    }

    pub fn write_output_bytes(&self) -> Result<Vec<u8>, CredentialError> {
        match self {
            Self::AgentPassport(passport) => serde_json::to_vec_pretty(passport).map_err(|error| {
                CredentialError::InvalidOid4vciCredentialResponse(error.to_string())
            }),
            Self::Compact(value) => Ok(value.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPassportSdJwtVcVerification {
    pub passport_id: String,
    pub subject_did: String,
    pub issuer: String,
    pub subject_thumbprint: String,
    pub holder_jwk: PortableEd25519Jwk,
    pub credential_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_status: Option<Oid4vciChioPassportStatusReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioPassportSdJwtVcUnverified {
    pub issuer: String,
    pub passport_id: String,
    pub subject_did: String,
    pub subject_thumbprint: String,
    pub holder_jwk: PortableEd25519Jwk,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_status: Option<Oid4vciChioPassportStatusReference>,
}

pub fn build_portable_issuer_jwks(
    credential_issuer: &str,
    public_key: &PublicKey,
) -> Result<PortableJwkSet, CredentialError> {
    let mut jwks = build_portable_jwks(credential_issuer, std::slice::from_ref(public_key))?;
    if let Some(entry) = jwks.keys.first_mut() {
        entry.kid = format!("{credential_issuer}#{CHIO_PASSPORT_SD_JWT_KEY_ID}");
    }
    Ok(jwks)
}

pub fn build_chio_passport_sd_jwt_type_metadata(
    credential_issuer: &str,
) -> Result<ChioPassportSdJwtVcTypeMetadata, CredentialError> {
    let credential_issuer = normalize_credential_issuer(credential_issuer)?;
    let portable_claim_catalog = ChioPortableClaimCatalog::default();
    let portable_identity_binding = ChioPortableIdentityBinding::default();
    Ok(ChioPassportSdJwtVcTypeMetadata {
        vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
        format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
        subject_binding: portable_identity_binding.subject_binding.clone(),
        issuer_identity: portable_identity_binding.issuer_identity.clone(),
        portable_claim_catalog: portable_claim_catalog.clone(),
        portable_identity_binding: portable_identity_binding.clone(),
        type_metadata_url: format!("{credential_issuer}{CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH}"),
        jwks_url: format!("{credential_issuer}{OID4VCI_JWKS_PATH}"),
        always_disclosed_claims: portable_claim_catalog.always_disclosed_claims,
        selectively_disclosable_claims: portable_claim_catalog.selectively_disclosable_claims,
        status_reference_kind: portable_claim_catalog.status_reference_kind,
    })
}

pub fn build_chio_passport_portable_projection(
    passport: &AgentPassport,
    now: u64,
) -> Result<ChioPassportPortableProjection, CredentialError> {
    let verification = verify_agent_passport(passport, now)?;
    let issuer_dids = verification.issuers;
    Ok(ChioPassportPortableProjection {
        passport_id: verification.passport_id,
        subject_did: verification.subject,
        issuer_dids,
        credential_count: passport.credentials.len(),
        merkle_roots: passport.merkle_roots.clone(),
        enterprise_identity_provenance: passport.enterprise_identity_provenance.clone(),
    })
}

pub fn issue_chio_passport_sd_jwt_vc(
    passport: &AgentPassport,
    credential_issuer: &str,
    issuer_keypair: &Keypair,
    now: u64,
    passport_status: Option<Oid4vciChioPassportStatusReference>,
) -> Result<ChioPassportSdJwtVcEnvelope, CredentialError> {
    let credential_issuer = normalize_credential_issuer(credential_issuer)?;
    let projection = build_chio_passport_portable_projection(passport, now)?;
    let subject_did = DidChio::from_str(&projection.subject_did).map_err(CredentialError::Did)?;
    let holder_jwk = PortableEd25519Jwk::from_public_key(subject_did.public_key());
    let holder_thumbprint = holder_jwk.thumbprint()?;
    let header = json!({
        "alg": "EdDSA",
        "typ": SD_JWT_VC_TYP,
        "kid": format!("{credential_issuer}#{CHIO_PASSPORT_SD_JWT_KEY_ID}")
    });

    let mut payload = Map::new();
    payload.insert("iss".to_string(), Value::String(credential_issuer.clone()));
    payload.insert("sub".to_string(), Value::String(holder_thumbprint.clone()));
    payload.insert("iat".to_string(), Value::Number(now.into()));
    payload.insert("nbf".to_string(), Value::Number(now.into()));
    payload.insert(
        "exp".to_string(),
        Value::Number(unix_from_rfc3339(&passport.valid_until)?.into()),
    );
    payload.insert(
        "vct".to_string(),
        Value::String(CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string()),
    );
    payload.insert("_sd_alg".to_string(), Value::String(SD_JWT_VC_HASH_ALG.to_string()));
    payload.insert(
        "cnf".to_string(),
        json!({
            "jwk": holder_jwk,
        }),
    );
    payload.insert(
        "chio_passport_id".to_string(),
        Value::String(projection.passport_id.clone()),
    );
    payload.insert(
        "chio_subject_did".to_string(),
        Value::String(projection.subject_did.clone()),
    );
    payload.insert(
        "chio_credential_count".to_string(),
        Value::Number(u64::try_from(projection.credential_count).unwrap_or(u64::MAX).into()),
    );
    if let Some(status) = passport_status {
        payload.insert(
            "chio_passport_status".to_string(),
            serde_json::to_value(status).map_err(|error| {
                CredentialError::InvalidOid4vciCredentialResponse(error.to_string())
            })?,
        );
    }

    let disclosures = ChioPortableClaimCatalog::default()
        .selectively_disclosable_claims
        .into_iter()
        .map(|claim| {
            let value = match claim.as_str() {
                "chio_issuer_dids" => serde_json::to_value(&projection.issuer_dids),
                "chio_merkle_roots" => serde_json::to_value(&projection.merkle_roots),
                "chio_enterprise_identity_provenance" => {
                    serde_json::to_value(&projection.enterprise_identity_provenance)
                }
                other => {
                    return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                        "portable claim catalog includes unsupported disclosure claim `{other}`"
                    )));
                }
            }
            .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))?;
            Ok(disclosure_entry(&claim, value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    payload.insert(
        "_sd".to_string(),
        Value::Array(
            disclosures
                .iter()
                .map(|entry| Value::String(entry.digest.clone()))
                .collect(),
        ),
    );

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|error| {
        CredentialError::InvalidOid4vciCredentialResponse(error.to_string())
    })?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Value::Object(payload)).map_err(
        |error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()),
    )?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_b64 = URL_SAFE_NO_PAD.encode(issuer_keypair.sign(signing_input.as_bytes()).to_bytes());
    let compact_jwt = format!("{signing_input}.{signature_b64}");
    let compact = format!(
        "{}~{}~{}~{}~",
        compact_jwt, disclosures[0].encoded, disclosures[1].encoded, disclosures[2].encoded
    );

    Ok(ChioPassportSdJwtVcEnvelope {
        compact,
        passport_id: projection.passport_id,
        subject_did: projection.subject_did,
        issuer: credential_issuer,
        issuer_jwk: PortableEd25519Jwk::from_public_key(&issuer_keypair.public_key()),
    })
}

pub fn verify_chio_passport_sd_jwt_vc(
    compact: &str,
    issuer_public_key: &PublicKey,
    now: u64,
) -> Result<ChioPassportSdJwtVcVerification, CredentialError> {
    let segments = compact.split('~').collect::<Vec<_>>();
    if segments.len() < 2 {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential must include a compact JWT plus disclosures".to_string(),
        ));
    }
    let compact_jwt = segments[0];
    let disclosures = segments
        .iter()
        .skip(1)
        .filter(|value| !value.is_empty())
        .copied()
        .collect::<Vec<_>>();
    let jwt_parts = compact_jwt.split('.').collect::<Vec<_>>();
    if jwt_parts.len() != 3 {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential JWT must contain exactly three compact segments".to_string(),
        ));
    }
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[2].as_bytes())
        .map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable credential signature is not valid base64url: {error}"
            ))
        })?;
    if signature_bytes.len() != 64 {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable credential signature must decode to 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&signature_array);
    if !issuer_public_key.verify(signing_input.as_bytes(), &signature) {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential signature verification failed".to_string(),
        ));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[1].as_bytes())
        .map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable credential payload is not valid base64url: {error}"
            ))
        })?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|error| {
        CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable credential payload is not valid JSON: {error}"
        ))
    })?;
    let payload_object = payload.as_object().ok_or_else(|| {
        CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential payload must be a JSON object".to_string(),
        )
    })?;
    let issuer = payload_object
        .get("iss")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include a non-empty `iss`".to_string(),
            )
        })?;
    let issued_at = payload_object
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `iat`".to_string(),
            )
        })?;
    let expires_at = payload_object
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `exp`".to_string(),
            )
        })?;
    if issued_at > expires_at {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential iat must be before or equal to exp".to_string(),
        ));
    }
    if now >= expires_at {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential has expired".to_string(),
        ));
    }
    let vct = payload_object
        .get("vct")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if vct != CHIO_PASSPORT_SD_JWT_VC_TYPE {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable credential vct `{vct}` does not match Chio passport profile"
        )));
    }
    let subject_did = payload_object
        .get("chio_subject_did")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `chio_subject_did`".to_string(),
            )
        })?;
    DidChio::from_str(subject_did).map_err(CredentialError::Did)?;
    let passport_id = payload_object
        .get("chio_passport_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `chio_passport_id`".to_string(),
            )
        })?;
    let credential_count = payload_object
        .get("chio_credential_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let subject_thumbprint = payload_object
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include a non-empty `sub`".to_string(),
            )
        })?;
    let holder_jwk_value = payload_object
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|value| value.get("jwk"))
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `cnf.jwk`".to_string(),
            )
        })?;
    let holder_jwk: PortableEd25519Jwk =
        serde_json::from_value(holder_jwk_value.clone()).map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable credential cnf.jwk is invalid: {error}"
            ))
        })?;
    let computed_thumbprint = holder_jwk.thumbprint()?;
    if computed_thumbprint != subject_thumbprint {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential `sub` does not match cnf.jwk thumbprint".to_string(),
        ));
    }
    let disclosure_digests = payload_object
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `_sd`".to_string(),
            )
        })?;
    let expected_digests = disclosure_digests
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                CredentialError::InvalidOid4vciCredentialResponse(
                    "portable credential `_sd` entries must be strings".to_string(),
                )
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual_digests = disclosures
        .iter()
        .map(|disclosure| sd_jwt_disclosure_digest(disclosure))
        .collect::<BTreeSet<_>>();
    if !actual_digests.is_subset(&expected_digests) {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential disclosures do not match `_sd` digests".to_string(),
        ));
    }
    let portable_claim_catalog = ChioPortableClaimCatalog::default();
    let mut disclosure_claims = Vec::new();
    for disclosure in disclosures {
        let (_, key, _) = parse_sd_jwt_disclosure(disclosure)?;
        if portable_claim_catalog.supports_selective_disclosure(&key) {
            disclosure_claims.push(key);
        } else {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable credential disclosure `{key}` is not part of the supported Chio profile"
            )));
        }
    }
    let passport_status = payload_object
        .get("chio_passport_status")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            CredentialError::InvalidOid4vciCredentialResponse(format!(
                "portable credential chio_passport_status is invalid: {error}"
            ))
        })?;

    Ok(ChioPassportSdJwtVcVerification {
        passport_id: passport_id.to_string(),
        subject_did: subject_did.to_string(),
        issuer: issuer.to_string(),
        subject_thumbprint: subject_thumbprint.to_string(),
        holder_jwk,
        credential_count: usize::try_from(credential_count).unwrap_or(usize::MAX),
        disclosure_claims,
        passport_status,
    })
}

#[derive(Debug, Clone)]
struct SdJwtDisclosureEntry {
    encoded: String,
    digest: String,
}

fn disclosure_entry(key: &str, value: Value) -> SdJwtDisclosureEntry {
    let encoded = {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let payload = json!([
            URL_SAFE_NO_PAD.encode(salt),
            key,
            value,
        ]);
        let bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) => bytes,
            Err(_) => unreachable!("sd-jwt disclosure payload is always serializable"),
        };
        URL_SAFE_NO_PAD.encode(bytes)
    };
    let digest = sd_jwt_disclosure_digest(&encoded);
    SdJwtDisclosureEntry { encoded, digest }
}

fn sd_jwt_disclosure_digest(disclosure: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(disclosure.as_bytes()))
}

fn parse_sd_jwt_disclosure(disclosure: &str) -> Result<(String, String, Value), CredentialError> {
    let bytes = URL_SAFE_NO_PAD.decode(disclosure.as_bytes()).map_err(|error| {
        CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable credential disclosure is not valid base64url: {error}"
        ))
    })?;
    let array: Vec<Value> = serde_json::from_slice(&bytes).map_err(|error| {
        CredentialError::InvalidOid4vciCredentialResponse(format!(
            "portable credential disclosure is not valid JSON: {error}"
        ))
    })?;
    if array.len() != 3 {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential disclosures must be [salt, key, value] arrays".to_string(),
        ));
    }
    let salt = array[0].as_str().unwrap_or_default().to_string();
    let key = array[1].as_str().unwrap_or_default().to_string();
    if salt.trim().is_empty() || key.trim().is_empty() {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential disclosures must include non-empty salt and key".to_string(),
        ));
    }
    Ok((salt, key, array[2].clone()))
}
