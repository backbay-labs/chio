pub const OID4VP_RESPONSE_TYPE_VP_TOKEN: &str = "vp_token";
pub const OID4VP_RESPONSE_MODE_DIRECT_POST_JWT: &str = "direct_post.jwt";
pub const OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI: &str = "redirect_uri";
pub const OID4VP_REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";
pub const OID4VP_RESPONSE_OBJECT_TYP: &str = "oauth-authz-resp+jwt";
pub const OID4VP_OPENID4VP_SCHEME: &str = "openid4vp://authorize";
pub const OID4VP_VERIFIER_METADATA_PATH: &str = "/.well-known/chio-oid4vp-verifier";
pub const CHIO_WALLET_EXCHANGE_DESCRIPTOR_PROFILE: &str = "chio.wallet-exchange.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpDcqlQuery {
    pub credentials: Vec<Oid4vpRequestedCredential>,
}

impl Oid4vpDcqlQuery {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.credentials.len() != 1 {
            return Err(CredentialError::InvalidOid4vpRequest(
                "Chio OID4VP currently supports exactly one requested credential".to_string(),
            ));
        }
        self.credentials[0].validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpRequestedCredential {
    pub id: String,
    pub format: String,
    pub vct: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_allowlist: Vec<String>,
}

impl Oid4vpRequestedCredential {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.id.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP requested credential must include a non-empty id".to_string(),
            ));
        }
        if self.format != CHIO_PASSPORT_SD_JWT_VC_FORMAT {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "Chio OID4VP only supports `{CHIO_PASSPORT_SD_JWT_VC_FORMAT}`, got `{}`",
                self.format
            )));
        }
        if self.vct != CHIO_PASSPORT_SD_JWT_VC_TYPE {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "Chio OID4VP only supports `{CHIO_PASSPORT_SD_JWT_VC_TYPE}`, got `{}`",
                self.vct
            )));
        }
        let mut seen = BTreeSet::new();
        for claim in &self.claims {
            if !is_supported_chio_sd_jwt_claim(claim) {
                return Err(CredentialError::InvalidOid4vpRequest(format!(
                    "Chio OID4VP does not support disclosure claim `{claim}`"
                )));
            }
            if !seen.insert(claim.clone()) {
                return Err(CredentialError::InvalidOid4vpRequest(format!(
                    "OID4VP requested credential repeats disclosure claim `{claim}`"
                )));
            }
        }
        for issuer in &self.issuer_allowlist {
            normalize_credential_issuer(issuer).map_err(|error| {
                CredentialError::InvalidOid4vpRequest(format!(
                    "OID4VP issuer allowlist entry `{issuer}` is invalid: {error}"
                ))
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpRequestObject {
    pub client_id: String,
    pub client_id_scheme: String,
    pub response_uri: String,
    pub response_mode: String,
    pub response_type: String,
    pub nonce: String,
    pub state: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub request_uri: String,
    pub dcql_query: Oid4vpDcqlQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

impl Oid4vpRequestObject {
    pub fn validate(&self, now: u64) -> Result<(), CredentialError> {
        let client_id = normalize_credential_issuer(&self.client_id).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(format!("OID4VP client_id is invalid: {error}"))
        })?;
        if self.client_id_scheme != OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "Chio OID4VP only supports client_id_scheme `{OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI}`"
            )));
        }
        if self.response_mode != OID4VP_RESPONSE_MODE_DIRECT_POST_JWT {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "Chio OID4VP only supports response_mode `{OID4VP_RESPONSE_MODE_DIRECT_POST_JWT}`"
            )));
        }
        if self.response_type != OID4VP_RESPONSE_TYPE_VP_TOKEN {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "Chio OID4VP only supports response_type `{OID4VP_RESPONSE_TYPE_VP_TOKEN}`"
            )));
        }
        if self.nonce.trim().is_empty() || self.state.trim().is_empty() || self.jti.trim().is_empty()
        {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP request object requires non-empty nonce, state, and jti".to_string(),
            ));
        }
        if self.iat > self.exp {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP request object iat must be before or equal to exp".to_string(),
            ));
        }
        if now > self.exp {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP request object has expired".to_string(),
            ));
        }
        validate_endpoint_prefix(&client_id, "response_uri", &self.response_uri).map_err(
            |error| CredentialError::InvalidOid4vpRequest(error.to_string()),
        )?;
        validate_endpoint_prefix(&client_id, "request_uri", &self.request_uri).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(error.to_string())
        })?;
        if let Some(assertion) = self.identity_assertion.as_ref() {
            assertion
                .validate_at(now)
                .map_err(CredentialError::InvalidOid4vpRequest)?;
            if assertion.verifier_id != self.client_id {
                return Err(CredentialError::InvalidOid4vpRequest(
                    "OID4VP identity assertion verifier_id did not match client_id".to_string(),
                ));
            }
            match assertion.bound_request_id.as_deref() {
                Some(bound_request_id) if bound_request_id == self.jti => {}
                Some(_) => {
                    return Err(CredentialError::InvalidOid4vpRequest(
                        "OID4VP identity assertion bound_request_id did not match jti"
                            .to_string(),
                    ))
                }
                None => {
                    return Err(CredentialError::InvalidOid4vpRequest(
                        "OID4VP identity assertion requires bound_request_id".to_string(),
                    ))
                }
            }
            if assertion.expires_at > self.exp {
                return Err(CredentialError::InvalidOid4vpRequest(
                    "OID4VP identity assertion must not outlive the request".to_string(),
                ));
            }
        }
        self.dcql_query.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpRequestTransport {
    pub request_id: String,
    pub request_uri: String,
    pub request_jwt: String,
    pub same_device_url: String,
    pub cross_device_url: String,
    pub response_uri: String,
    pub nonce: String,
    pub state: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum WalletExchangeTransportMode {
    SameDevice,
    CrossDevice,
    Relay,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WalletExchangeTransactionStatus {
    Issued,
    Consumed,
    Expired,
}

impl WalletExchangeTransactionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeReplayAnchors {
    pub request_id: String,
    pub nonce: String,
    pub state: String,
    pub request_object_hash: String,
}

impl WalletExchangeReplayAnchors {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.request_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || self.state.trim().is_empty()
            || self.request_object_hash.trim().is_empty()
        {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange replay anchors require non-empty request_id, nonce, state, and request_object_hash"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeDescriptor {
    pub exchange_id: String,
    pub profile: String,
    pub verifier_id: String,
    pub client_id: String,
    pub descriptor_url: String,
    pub request_uri: String,
    pub response_uri: String,
    pub same_device_url: String,
    pub cross_device_url: String,
    pub relay_url: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub transport_modes: Vec<WalletExchangeTransportMode>,
    pub replay_anchors: WalletExchangeReplayAnchors,
}

impl WalletExchangeDescriptor {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.exchange_id.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor requires a non-empty exchange_id".to_string(),
            ));
        }
        if self.profile != CHIO_WALLET_EXCHANGE_DESCRIPTOR_PROFILE {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "wallet exchange descriptor only supports profile `{CHIO_WALLET_EXCHANGE_DESCRIPTOR_PROFILE}`"
            )));
        }
        let verifier_id = normalize_credential_issuer(&self.verifier_id).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(format!(
                "wallet exchange descriptor verifier_id is invalid: {error}"
            ))
        })?;
        let client_id = normalize_credential_issuer(&self.client_id).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(format!(
                "wallet exchange descriptor client_id is invalid: {error}"
            ))
        })?;
        if verifier_id != client_id {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor must keep verifier_id and client_id aligned"
                    .to_string(),
            ));
        }
        if self.issued_at > self.expires_at {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor issued_at must be before or equal to expires_at"
                    .to_string(),
            ));
        }
        validate_endpoint_prefix(&verifier_id, "descriptor_url", &self.descriptor_url)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "request_uri", &self.request_uri)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "response_uri", &self.response_uri)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "cross_device_url", &self.cross_device_url)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "relay_url", &self.relay_url)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        if !self
            .same_device_url
            .starts_with(&format!("{OID4VP_OPENID4VP_SCHEME}?request_uri="))
        {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor same_device_url must be derived from request_uri"
                    .to_string(),
            ));
        }
        let mut deduped = self.transport_modes.clone();
        deduped.sort();
        deduped.dedup();
        if deduped != self.transport_modes {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor transport_modes must be sorted and unique".to_string(),
            ));
        }
        let expected_modes = vec![
            WalletExchangeTransportMode::SameDevice,
            WalletExchangeTransportMode::CrossDevice,
            WalletExchangeTransportMode::Relay,
        ];
        if self.transport_modes != expected_modes {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange descriptor must advertise same-device, cross-device, and relay transport modes"
                    .to_string(),
            ));
        }
        self.replay_anchors.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeTransactionState {
    pub exchange_id: String,
    pub request_id: String,
    pub status: WalletExchangeTransactionStatus,
    pub issued_at: u64,
    pub expires_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
}

impl WalletExchangeTransactionState {
    pub fn issued(exchange_id: &str, request_id: &str, issued_at: u64, expires_at: u64) -> Self {
        Self {
            exchange_id: exchange_id.to_string(),
            request_id: request_id.to_string(),
            status: WalletExchangeTransactionStatus::Issued,
            issued_at,
            expires_at,
            updated_at: issued_at,
            consumed_at: None,
        }
    }

    pub fn consumed(
        exchange_id: &str,
        request_id: &str,
        issued_at: u64,
        expires_at: u64,
        consumed_at: u64,
    ) -> Self {
        Self {
            exchange_id: exchange_id.to_string(),
            request_id: request_id.to_string(),
            status: WalletExchangeTransactionStatus::Consumed,
            issued_at,
            expires_at,
            updated_at: consumed_at,
            consumed_at: Some(consumed_at),
        }
    }

    pub fn expired(exchange_id: &str, request_id: &str, issued_at: u64, expires_at: u64) -> Self {
        Self {
            exchange_id: exchange_id.to_string(),
            request_id: request_id.to_string(),
            status: WalletExchangeTransactionStatus::Expired,
            issued_at,
            expires_at,
            updated_at: expires_at,
            consumed_at: None,
        }
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.exchange_id.trim().is_empty() || self.request_id.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange transaction state requires non-empty exchange_id and request_id"
                    .to_string(),
            ));
        }
        if self.issued_at > self.expires_at {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange transaction state issued_at must be before or equal to expires_at"
                    .to_string(),
            ));
        }
        if self.updated_at < self.issued_at {
            return Err(CredentialError::InvalidOid4vpRequest(
                "wallet exchange transaction state updated_at cannot be earlier than issued_at"
                    .to_string(),
            ));
        }
        match self.status {
            WalletExchangeTransactionStatus::Issued => {
                if self.consumed_at.is_some() || self.updated_at != self.issued_at {
                    return Err(CredentialError::InvalidOid4vpRequest(
                        "issued wallet exchange transaction state cannot include consumed_at and must keep updated_at equal to issued_at"
                            .to_string(),
                    ));
                }
            }
            WalletExchangeTransactionStatus::Consumed => {
                let consumed_at = self.consumed_at.ok_or_else(|| {
                    CredentialError::InvalidOid4vpRequest(
                        "consumed wallet exchange transaction state must include consumed_at"
                            .to_string(),
                    )
                })?;
                if consumed_at != self.updated_at || consumed_at < self.issued_at {
                    return Err(CredentialError::InvalidOid4vpRequest(
                        "consumed wallet exchange transaction state must keep consumed_at equal to updated_at and not earlier than issued_at"
                            .to_string(),
                    ));
                }
            }
            WalletExchangeTransactionStatus::Expired => {
                if self.consumed_at.is_some() || self.updated_at < self.expires_at {
                    return Err(CredentialError::InvalidOid4vpRequest(
                        "expired wallet exchange transaction state cannot include consumed_at and must keep updated_at at or after expires_at"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpVerifierMetadata {
    pub verifier_id: String,
    pub client_id: String,
    pub client_id_scheme: String,
    pub request_uri_prefix: String,
    pub response_uri: String,
    pub same_device_launch_prefix: String,
    pub jwks_uri: String,
    pub request_object_signing_alg_values_supported: Vec<String>,
    pub response_mode: String,
    pub response_type: String,
    pub credential_format: String,
    pub credential_vct: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_rotated_at: Option<u64>,
    pub trusted_key_count: usize,
}

impl Oid4vpVerifierMetadata {
    pub fn validate(&self) -> Result<(), CredentialError> {
        let verifier_id = normalize_credential_issuer(&self.verifier_id).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata verifier_id is invalid: {error}"
            ))
        })?;
        let client_id = normalize_credential_issuer(&self.client_id).map_err(|error| {
            CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata client_id is invalid: {error}"
            ))
        })?;
        if verifier_id != client_id {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP verifier metadata must keep verifier_id and client_id aligned".to_string(),
            ));
        }
        if self.client_id_scheme != OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata only supports client_id_scheme `{OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI}`"
            )));
        }
        validate_endpoint_prefix(&verifier_id, "request_uri_prefix", &self.request_uri_prefix)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "response_uri", &self.response_uri)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        validate_endpoint_prefix(&verifier_id, "jwks_uri", &self.jwks_uri)
            .map_err(|error| CredentialError::InvalidOid4vpRequest(error.to_string()))?;
        if self.same_device_launch_prefix != format!("{OID4VP_OPENID4VP_SCHEME}?request_uri=") {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP verifier metadata same_device_launch_prefix did not match the supported Chio profile"
                    .to_string(),
            ));
        }
        if !self
            .request_object_signing_alg_values_supported
            .iter()
            .any(|alg| alg == "EdDSA")
        {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP verifier metadata must advertise EdDSA request signing".to_string(),
            ));
        }
        if self.response_mode != OID4VP_RESPONSE_MODE_DIRECT_POST_JWT {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata only supports response_mode `{OID4VP_RESPONSE_MODE_DIRECT_POST_JWT}`"
            )));
        }
        if self.response_type != OID4VP_RESPONSE_TYPE_VP_TOKEN {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata only supports response_type `{OID4VP_RESPONSE_TYPE_VP_TOKEN}`"
            )));
        }
        if self.credential_format != CHIO_PASSPORT_SD_JWT_VC_FORMAT {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata only supports credential format `{CHIO_PASSPORT_SD_JWT_VC_FORMAT}`"
            )));
        }
        if self.credential_vct != CHIO_PASSPORT_SD_JWT_VC_TYPE {
            return Err(CredentialError::InvalidOid4vpRequest(format!(
                "OID4VP verifier metadata only supports credential type `{CHIO_PASSPORT_SD_JWT_VC_TYPE}`"
            )));
        }
        if self.trusted_key_count == 0 {
            return Err(CredentialError::InvalidOid4vpRequest(
                "OID4VP verifier metadata must advertise at least one trusted signing key"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpPresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<Oid4vpDescriptorMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpDescriptorMap {
    pub id: String,
    pub format: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpDirectPostResponseClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
    pub state: String,
    pub vp_token: String,
    pub presentation_submission: Oid4vpPresentationSubmission,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vpPresentationVerification {
    pub request_id: String,
    pub client_id: String,
    pub response_uri: String,
    pub verified_at: u64,
    pub passport_id: String,
    pub subject_did: String,
    pub issuer: String,
    pub credential_count: usize,
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_status: Option<Oid4vciChioPassportStatusReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_transaction: Option<WalletExchangeTransactionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

pub fn sign_oid4vp_request_object(
    request: &Oid4vpRequestObject,
    signing_key: &Keypair,
) -> Result<String, CredentialError> {
    request.validate(request.iat)?;
    sign_jwt_value(
        OID4VP_REQUEST_OBJECT_TYP,
        &serde_json::to_value(request).map_err(|error| CredentialError::Core(error.into()))?,
        signing_key,
    )
}

pub fn verify_signed_oid4vp_request_object(
    compact: &str,
    verifier_public_key: &PublicKey,
    now: u64,
) -> Result<Oid4vpRequestObject, CredentialError> {
    let (header, payload, signing_input, signature) = decode_compact_jwt_without_signature(
        compact,
        "OID4VP request",
        CredentialError::InvalidOid4vpRequest,
    )?;
    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if typ != OID4VP_REQUEST_OBJECT_TYP {
        return Err(CredentialError::InvalidOid4vpRequest(format!(
            "OID4VP request JWT typ must be `{OID4VP_REQUEST_OBJECT_TYP}`"
        )));
    }
    if !verifier_public_key.verify(signing_input.as_bytes(), &signature) {
        return Err(CredentialError::InvalidOid4vpRequest(
            "OID4VP request JWT signature verification failed".to_string(),
        ));
    }
    let request: Oid4vpRequestObject = serde_json::from_value(payload).map_err(|error| {
        CredentialError::InvalidOid4vpRequest(format!(
            "OID4VP request payload is not valid JSON: {error}"
        ))
    })?;
    request.validate(now)?;
    Ok(request)
}

pub fn verify_signed_oid4vp_request_object_with_any_key(
    compact: &str,
    verifier_public_keys: &[PublicKey],
    now: u64,
) -> Result<Oid4vpRequestObject, CredentialError> {
    let mut last_error = None;
    for public_key in verifier_public_keys {
        match verify_signed_oid4vp_request_object(compact, public_key, now) {
            Ok(request) => return Ok(request),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        CredentialError::InvalidOid4vpRequest(
            "OID4VP request verification requires at least one trusted verifier key".to_string(),
        )
    }))
}

pub fn build_oid4vp_request_transport(
    request: &Oid4vpRequestObject,
    signing_key: &Keypair,
) -> Result<Oid4vpRequestTransport, CredentialError> {
    let request_jwt = sign_oid4vp_request_object(request, signing_key)?;
    let launch_url = format!("{OID4VP_OPENID4VP_SCHEME}?request_uri={}", request.request_uri);
    Ok(Oid4vpRequestTransport {
        request_id: request.jti.clone(),
        request_uri: request.request_uri.clone(),
        request_jwt,
        same_device_url: launch_url.clone(),
        cross_device_url: launch_url,
        response_uri: request.response_uri.clone(),
        nonce: request.nonce.clone(),
        state: request.state.clone(),
        expires_at: request.exp,
    })
}

pub fn build_wallet_exchange_descriptor_for_oid4vp(
    request: &Oid4vpRequestObject,
    request_jwt: &str,
    descriptor_url: &str,
    same_device_url: &str,
    cross_device_url: &str,
    relay_url: Option<&str>,
) -> Result<WalletExchangeDescriptor, CredentialError> {
    let descriptor = WalletExchangeDescriptor {
        exchange_id: request.jti.clone(),
        profile: CHIO_WALLET_EXCHANGE_DESCRIPTOR_PROFILE.to_string(),
        verifier_id: request.client_id.clone(),
        client_id: request.client_id.clone(),
        descriptor_url: descriptor_url.to_string(),
        request_uri: request.request_uri.clone(),
        response_uri: request.response_uri.clone(),
        same_device_url: same_device_url.to_string(),
        cross_device_url: cross_device_url.to_string(),
        relay_url: relay_url.unwrap_or(cross_device_url).to_string(),
        issued_at: request.iat,
        expires_at: request.exp,
        transport_modes: vec![
            WalletExchangeTransportMode::SameDevice,
            WalletExchangeTransportMode::CrossDevice,
            WalletExchangeTransportMode::Relay,
        ],
        replay_anchors: WalletExchangeReplayAnchors {
            request_id: request.jti.clone(),
            nonce: request.nonce.clone(),
            state: request.state.clone(),
            request_object_hash: sha256_hex(request_jwt.as_bytes()),
        },
    };
    descriptor.validate()?;
    Ok(descriptor)
}

pub fn inspect_chio_passport_sd_jwt_vc_unverified(
    compact: &str,
) -> Result<ChioPassportSdJwtVcUnverified, CredentialError> {
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
    let (_, payload, _, _) = decode_compact_jwt_without_signature(
        compact_jwt,
        "portable credential",
        CredentialError::InvalidOid4vciCredentialResponse,
    )?;
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
    let passport_id = payload_object
        .get("chio_passport_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `chio_passport_id`".to_string(),
            )
        })?;
    let subject_did = payload_object
        .get("chio_subject_did")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential must include `chio_subject_did`".to_string(),
            )
        })?;
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
    let disclosure_claims = disclosures
        .iter()
        .map(|disclosure| {
            let (_, key, _) = parse_sd_jwt_disclosure(disclosure)?;
            Ok(key)
        })
        .collect::<Result<Vec<_>, CredentialError>>()?;

    Ok(ChioPassportSdJwtVcUnverified {
        issuer: issuer.to_string(),
        passport_id: passport_id.to_string(),
        subject_did: subject_did.to_string(),
        subject_thumbprint: subject_thumbprint.to_string(),
        holder_jwk,
        passport_status,
        disclosure_claims,
    })
}

pub fn respond_to_oid4vp_request(
    holder_keypair: &Keypair,
    portable_credential: &str,
    request: &Oid4vpRequestObject,
    now: u64,
) -> Result<String, CredentialError> {
    request.validate(now)?;
    let requested = &request.dcql_query.credentials[0];
    let inspected = inspect_chio_passport_sd_jwt_vc_unverified(portable_credential)?;
    let holder_did = DidChio::from_public_key(holder_keypair.public_key())?;
    if holder_did.to_string() != inspected.subject_did {
        return Err(CredentialError::InvalidOid4vpResponse(
            "holder key does not match the portable credential subject".to_string(),
        ));
    }
    let holder_thumbprint = PortableEd25519Jwk::from_public_key(&holder_keypair.public_key())
        .thumbprint()?;
    if holder_thumbprint != inspected.subject_thumbprint {
        return Err(CredentialError::InvalidOid4vpResponse(
            "holder key does not match the portable credential cnf.jwk thumbprint".to_string(),
        ));
    }
    let filtered_vp_token = filter_portable_disclosures(portable_credential, &requested.claims)?;
    let response = Oid4vpDirectPostResponseClaims {
        iss: inspected.subject_thumbprint.clone(),
        sub: inspected.subject_thumbprint,
        aud: request.response_uri.clone(),
        iat: now,
        exp: request.exp.min(now.saturating_add(300)),
        nonce: request.nonce.clone(),
        state: request.state.clone(),
        vp_token: filtered_vp_token,
        presentation_submission: Oid4vpPresentationSubmission {
            id: request.jti.clone(),
            definition_id: "chio-passport-sd-jwt-vc".to_string(),
            descriptor_map: vec![Oid4vpDescriptorMap {
                id: requested.id.clone(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                path: "$.vp_token".to_string(),
            }],
        },
    };
    sign_jwt_value(
        OID4VP_RESPONSE_OBJECT_TYP,
        &serde_json::to_value(response).map_err(|error| CredentialError::Core(error.into()))?,
        holder_keypair,
    )
}

pub fn inspect_oid4vp_direct_post_response(
    compact: &str,
) -> Result<Oid4vpDirectPostResponseClaims, CredentialError> {
    let (_, payload, _, _) = decode_compact_jwt_without_signature(
        compact,
        "OID4VP response",
        CredentialError::InvalidOid4vpResponse,
    )?;
    serde_json::from_value(payload).map_err(|error| {
        CredentialError::InvalidOid4vpResponse(format!(
            "OID4VP response payload is not valid JSON: {error}"
        ))
    })
}

pub fn verify_oid4vp_direct_post_response(
    compact: &str,
    expected_request: &Oid4vpRequestObject,
    issuer_public_key: &PublicKey,
    now: u64,
) -> Result<Oid4vpPresentationVerification, CredentialError> {
    expected_request.validate(now)?;
    let (header, payload, signing_input, signature) =
        decode_compact_jwt(compact, "OID4VP response")?;
    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if typ != OID4VP_RESPONSE_OBJECT_TYP {
        return Err(CredentialError::InvalidOid4vpResponse(format!(
            "OID4VP response JWT typ must be `{OID4VP_RESPONSE_OBJECT_TYP}`"
        )));
    }
    let response: Oid4vpDirectPostResponseClaims =
        serde_json::from_value(payload.clone()).map_err(|error| {
            CredentialError::InvalidOid4vpResponse(format!(
                "OID4VP response payload is not valid JSON: {error}"
            ))
        })?;
    if response.iat > response.exp {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response iat must be before or equal to exp".to_string(),
        ));
    }
    if now > response.exp {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response has expired".to_string(),
        ));
    }
    if response.aud != expected_request.response_uri {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response audience did not match the expected response_uri".to_string(),
        ));
    }
    if response.nonce != expected_request.nonce {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response nonce did not match the request".to_string(),
        ));
    }
    if response.state != expected_request.state {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response state did not match the request".to_string(),
        ));
    }
    let expected_credential = &expected_request.dcql_query.credentials[0];
    if response.presentation_submission.id != expected_request.jti {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP presentation_submission.id did not match the request".to_string(),
        ));
    }
    if response.presentation_submission.descriptor_map.len() != 1 {
        return Err(CredentialError::InvalidOid4vpResponse(
            "Chio OID4VP currently requires exactly one descriptor_map entry".to_string(),
        ));
    }
    let descriptor = &response.presentation_submission.descriptor_map[0];
    if descriptor.id != expected_credential.id
        || descriptor.format != CHIO_PASSPORT_SD_JWT_VC_FORMAT
        || descriptor.path != "$.vp_token"
    {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP descriptor_map did not match the supported Chio profile".to_string(),
        ));
    }

    let credential_verification =
        verify_chio_passport_sd_jwt_vc(&response.vp_token, issuer_public_key, now)?;
    if !expected_credential.issuer_allowlist.is_empty()
        && !expected_credential
            .issuer_allowlist
            .iter()
            .any(|issuer| issuer == &credential_verification.issuer)
    {
        return Err(CredentialError::InvalidOid4vpResponse(format!(
            "portable credential issuer `{}` is outside the OID4VP request allowlist",
            credential_verification.issuer
        )));
    }
    let expected_claims = expected_credential
        .claims
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_claims = credential_verification
        .disclosure_claims
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_claims != expected_claims {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP disclosed claims did not match the verifier request".to_string(),
        ));
    }
    if response.iss != credential_verification.subject_thumbprint
        || response.sub != credential_verification.subject_thumbprint
    {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response iss/sub did not match the presented holder binding".to_string(),
        ));
    }
    let holder_public_key = credential_verification.holder_jwk.to_public_key()?;
    if !holder_public_key.verify(signing_input.as_bytes(), &signature) {
        return Err(CredentialError::InvalidOid4vpResponse(
            "OID4VP response JWT signature verification failed".to_string(),
        ));
    }

    Ok(Oid4vpPresentationVerification {
        request_id: expected_request.jti.clone(),
        client_id: expected_request.client_id.clone(),
        response_uri: expected_request.response_uri.clone(),
        verified_at: now,
        passport_id: credential_verification.passport_id,
        subject_did: credential_verification.subject_did,
        issuer: credential_verification.issuer,
        credential_count: credential_verification.credential_count,
        disclosure_claims: credential_verification.disclosure_claims,
        passport_status: credential_verification.passport_status,
        exchange_transaction: None,
        identity_assertion: expected_request.identity_assertion.clone(),
    })
}

pub fn verify_oid4vp_direct_post_response_with_any_issuer_key(
    compact: &str,
    expected_request: &Oid4vpRequestObject,
    issuer_public_keys: &[PublicKey],
    now: u64,
) -> Result<Oid4vpPresentationVerification, CredentialError> {
    let mut last_error = None;
    for public_key in issuer_public_keys {
        match verify_oid4vp_direct_post_response(compact, expected_request, public_key, now) {
            Ok(verification) => return Ok(verification),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        CredentialError::InvalidOid4vpResponse(
            "OID4VP response verification requires at least one issuer verification key"
                .to_string(),
        )
    }))
}

fn is_supported_chio_sd_jwt_claim(claim: &str) -> bool {
    ChioPortableClaimCatalog::default().supports_selective_disclosure(claim)
}

fn filter_portable_disclosures(
    compact: &str,
    requested_claims: &[String],
) -> Result<String, CredentialError> {
    let segments = compact.split('~').collect::<Vec<_>>();
    if segments.is_empty() {
        return Err(CredentialError::InvalidOid4vciCredentialResponse(
            "portable credential must include a compact JWT".to_string(),
        ));
    }
    let compact_jwt = segments[0];
    let requested = requested_claims.iter().collect::<BTreeSet<_>>();
    let mut filtered = Vec::new();
    for disclosure in segments.iter().skip(1).filter(|value| !value.is_empty()) {
        let (_, key, _) = parse_sd_jwt_disclosure(disclosure)?;
        if requested.contains(&key) {
            filtered.push(*disclosure);
        }
    }
    if filtered.is_empty() {
        Ok(format!("{compact_jwt}~"))
    } else {
        Ok(format!("{compact_jwt}~{}~", filtered.join("~")))
    }
}

fn sign_jwt_value(
    typ: &str,
    payload: &Value,
    signing_key: &Keypair,
) -> Result<String, CredentialError> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": typ,
    });
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|error| CredentialError::Core(error.into()))?,
    );
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(payload).map_err(|error| CredentialError::Core(error.into()))?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn decode_compact_jwt(
    compact: &str,
    label: &str,
) -> Result<(Value, Value, String, Signature), CredentialError> {
    decode_compact_jwt_without_signature(
        compact,
        label,
        CredentialError::InvalidOid4vpResponse,
    )
}

fn decode_compact_jwt_without_signature<F>(
    compact: &str,
    label: &str,
    error_mapper: F,
) -> Result<(Value, Value, String, Signature), CredentialError>
where
    F: Fn(String) -> CredentialError,
{
    let parts = compact.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(error_mapper(format!(
            "{label} JWT must contain exactly three compact segments"
        )));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|error| error_mapper(format!("{label} JWT header is not valid base64url: {error}")))?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|error| error_mapper(format!("{label} JWT payload is not valid base64url: {error}")))?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|error| error_mapper(format!("{label} JWT signature is not valid base64url: {error}")))?;
    if signature_bytes.len() != 64 {
        return Err(error_mapper(format!(
            "{label} JWT signature must decode to 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let header = serde_json::from_slice(&header_bytes)
        .map_err(|error| error_mapper(format!("{label} JWT header is not valid JSON: {error}")))?;
    let payload = serde_json::from_slice(&payload_bytes).map_err(|error| {
        error_mapper(format!("{label} JWT payload is not valid JSON: {error}"))
    })?;
    Ok((header, payload, signing_input, Signature::from_bytes(&signature_array)))
}
