pub const OID4VCI_PRE_AUTHORIZED_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID: &str = "chio_agent_passport";
pub const CHIO_PASSPORT_OID4VCI_FORMAT: &str = "chio-agent-passport+json";
pub const OID4VCI_ISSUER_METADATA_PATH: &str = "/.well-known/openid-credential-issuer";
pub const OID4VCI_PASSPORT_OFFERS_PATH: &str = "/v1/passport/issuance/offers";
pub const OID4VCI_PASSPORT_TOKEN_PATH: &str = "/v1/passport/issuance/token";
pub const OID4VCI_PASSPORT_CREDENTIAL_PATH: &str = "/v1/passport/issuance/credential";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioCredentialProfile {
    pub artifact_type: String,
    pub subject_did_method: String,
    pub issuer_did_method: String,
    pub signature_suite: String,
}

impl Oid4vciChioCredentialProfile {
    fn validate(&self) -> Result<(), CredentialError> {
        if self.artifact_type.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio credential profile must include a non-empty artifact_type".to_string(),
            ));
        }
        if self.subject_did_method.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio credential profile must include a non-empty subject_did_method".to_string(),
            ));
        }
        if self.issuer_did_method.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio credential profile must include a non-empty issuer_did_method".to_string(),
            ));
        }
        if self.signature_suite.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio credential profile must include a non-empty signature_suite".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioPortableCredentialProfile {
    pub credential_kind: String,
    pub type_metadata_url: String,
    pub subject_binding: String,
    pub issuer_identity: String,
    pub proof_family: String,
    pub supports_selective_disclosure: bool,
    #[serde(default)]
    pub portable_claim_catalog: ChioPortableClaimCatalog,
    #[serde(default)]
    pub portable_identity_binding: ChioPortableIdentityBinding,
}

impl Oid4vciChioPortableCredentialProfile {
    fn validate(&self, credential_issuer: &str) -> Result<(), CredentialError> {
        if self.credential_kind.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile must include a non-empty credential_kind".to_string(),
            ));
        }
        if self.subject_binding.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile must include a non-empty subject_binding".to_string(),
            ));
        }
        if self.issuer_identity.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile must include a non-empty issuer_identity".to_string(),
            ));
        }
        if self.proof_family.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile must include a non-empty proof_family".to_string(),
            ));
        }
        validate_endpoint_prefix(
            credential_issuer,
            "type_metadata_url",
            &self.type_metadata_url,
        )?;
        self.portable_claim_catalog
            .validate()
            .map_err(CredentialError::InvalidOid4vciIssuerMetadata)?;
        self.portable_identity_binding
            .validate()
            .map_err(CredentialError::InvalidOid4vciIssuerMetadata)?;
        if self.portable_identity_binding.subject_binding != self.subject_binding {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile subject_binding must match portable_identity_binding.subject_binding".to_string(),
            ));
        }
        if self.portable_identity_binding.issuer_identity != self.issuer_identity {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "portable credential profile issuer_identity must match portable_identity_binding.issuer_identity".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioIssuerProfile {
    pub credential_kind: String,
    pub subject_did_method: String,
    pub issuer_did_method: String,
    pub signature_suite: String,
    pub operator_offer_endpoint: String,
    #[serde(default, skip_serializing_if = "PassportStatusDistribution::is_empty")]
    pub passport_status_distribution: PassportStatusDistribution,
}

impl Oid4vciChioIssuerProfile {
    fn validate(&self, credential_issuer: &str) -> Result<(), CredentialError> {
        if self.credential_kind.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio issuer profile must include a non-empty credential_kind".to_string(),
            ));
        }
        if self.subject_did_method.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio issuer profile must include a non-empty subject_did_method".to_string(),
            ));
        }
        if self.issuer_did_method.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio issuer profile must include a non-empty issuer_did_method".to_string(),
            ));
        }
        if self.signature_suite.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "Chio issuer profile must include a non-empty signature_suite".to_string(),
            ));
        }
        validate_endpoint_prefix(
            credential_issuer,
            "operator_offer_endpoint",
            &self.operator_offer_endpoint,
        )?;
        self.passport_status_distribution.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciCredentialConfiguration {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio_profile: Option<Oid4vciChioCredentialProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable_profile: Option<Oid4vciChioPortableCredentialProfile>,
}

impl Oid4vciCredentialConfiguration {
    fn validate(&self, credential_issuer: &str) -> Result<(), CredentialError> {
        if self.format.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "credential configuration must include a non-empty format".to_string(),
            ));
        }
        if let Some(profile) = self.chio_profile.as_ref() {
            profile.validate()?;
        }
        if let Some(profile) = self.portable_profile.as_ref() {
            profile.validate(credential_issuer)?;
            if self.format != CHIO_PASSPORT_SD_JWT_VC_FORMAT
                && self.format != CHIO_PASSPORT_JWT_VC_JSON_FORMAT
            {
                return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                    "portable credential configurations must use application/dc+sd-jwt or jwt_vc_json".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciCredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub credential_configurations_supported:
        BTreeMap<String, Oid4vciCredentialConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio_profile: Option<Oid4vciChioIssuerProfile>,
}

impl Oid4vciCredentialIssuerMetadata {
    pub fn validate(&self) -> Result<(), CredentialError> {
        let credential_issuer = normalize_credential_issuer(&self.credential_issuer)?;
        validate_endpoint_prefix(
            &credential_issuer,
            "credential_endpoint",
            &self.credential_endpoint,
        )?;
        validate_endpoint_prefix(&credential_issuer, "token_endpoint", &self.token_endpoint)?;
        if self.credential_configurations_supported.is_empty() {
            return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                "credential issuer metadata must publish at least one credential configuration"
                    .to_string(),
            ));
        }
        for (configuration_id, configuration) in &self.credential_configurations_supported {
            if configuration_id.trim().is_empty() {
                return Err(CredentialError::InvalidOid4vciIssuerMetadata(
                    "credential configuration IDs must be non-empty".to_string(),
                ));
            }
            configuration.validate(&credential_issuer)?;
        }
        if let Some(jwks_uri) = self.jwks_uri.as_ref() {
            validate_endpoint_prefix(&credential_issuer, "jwks_uri", jwks_uri)?;
        }
        if let Some(profile) = self.chio_profile.as_ref() {
            profile.validate(&credential_issuer)?;
        }
        Ok(())
    }

    pub fn credential_configuration(
        &self,
        credential_configuration_id: &str,
    ) -> Result<&Oid4vciCredentialConfiguration, CredentialError> {
        self.validate()?;
        self.credential_configurations_supported
            .get(credential_configuration_id)
            .ok_or_else(|| {
                CredentialError::InvalidOid4vciCredentialRequest(format!(
                    "unsupported credential_configuration_id `{credential_configuration_id}`"
                ))
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciTxCode {
    pub input_mode: String,
    pub length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciPreAuthorizedGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<Oid4vciTxCode>,
}

impl Oid4vciPreAuthorizedGrant {
    fn validate(&self) -> Result<(), CredentialError> {
        if self.pre_authorized_code.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "pre-authorized grants must include a non-empty pre-authorized_code".to_string(),
            ));
        }
        if let Some(tx_code) = self.tx_code.as_ref() {
            if tx_code.input_mode.trim().is_empty() {
                return Err(CredentialError::InvalidOid4vciCredentialOffer(
                    "tx_code input_mode must be non-empty when present".to_string(),
                ));
            }
            if tx_code.length == 0 {
                return Err(CredentialError::InvalidOid4vciCredentialOffer(
                    "tx_code length must be greater than zero when present".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Oid4vciOfferGrants {
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<Oid4vciPreAuthorizedGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioOfferContext {
    pub passport_id: String,
    pub subject: String,
    pub expires_at: String,
}

impl Oid4vciChioOfferContext {
    fn validate(&self) -> Result<(), CredentialError> {
        if self.passport_id.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "Chio offer context must include a non-empty passport_id".to_string(),
            ));
        }
        if self.subject.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "Chio offer context must include a non-empty subject".to_string(),
            ));
        }
        DidChio::from_str(&self.subject)?;
        unix_from_rfc3339(&self.expires_at)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciCredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Oid4vciOfferGrants,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio_offer_context: Option<Oid4vciChioOfferContext>,
}

impl Oid4vciCredentialOffer {
    pub fn validate(&self) -> Result<(), CredentialError> {
        normalize_credential_issuer(&self.credential_issuer)?;
        if self.credential_configuration_ids.is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "credential offer must include at least one credential_configuration_id".to_string(),
            ));
        }
        let mut deduped = self.credential_configuration_ids.clone();
        deduped.sort();
        deduped.dedup();
        if deduped != self.credential_configuration_ids {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "credential offer credential_configuration_ids must be sorted and unique"
                    .to_string(),
            ));
        }
        let Some(grant) = self.grants.pre_authorized_code.as_ref() else {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "credential offer must include a pre-authorized code grant".to_string(),
            ));
        };
        grant.validate()?;
        if let Some(context) = self.chio_offer_context.as_ref() {
            context.validate()?;
        }
        Ok(())
    }

    pub fn validate_against_metadata(
        &self,
        metadata: &Oid4vciCredentialIssuerMetadata,
    ) -> Result<(), CredentialError> {
        self.validate()?;
        metadata.validate()?;
        if normalize_credential_issuer(&self.credential_issuer)?
            != normalize_credential_issuer(&metadata.credential_issuer)?
        {
            return Err(CredentialError::InvalidOid4vciCredentialOffer(
                "credential offer issuer does not match issuer metadata".to_string(),
            ));
        }
        for credential_configuration_id in &self.credential_configuration_ids {
            metadata.credential_configuration(credential_configuration_id)?;
        }
        Ok(())
    }

    pub fn primary_configuration_id(&self) -> Result<&str, CredentialError> {
        self.credential_configuration_ids
            .first()
            .map(String::as_str)
            .ok_or_else(|| {
                CredentialError::InvalidOid4vciCredentialOffer(
                    "credential offer must include at least one credential_configuration_id"
                        .to_string(),
                )
            })
    }

    pub fn pre_authorized_code(&self) -> Result<&str, CredentialError> {
        self.grants
            .pre_authorized_code
            .as_ref()
            .map(|grant| grant.pre_authorized_code.as_str())
            .ok_or_else(|| {
                CredentialError::InvalidOid4vciCredentialOffer(
                    "credential offer is missing a pre-authorized code grant".to_string(),
                )
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciTokenRequest {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

impl Oid4vciTokenRequest {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.grant_type != OID4VCI_PRE_AUTHORIZED_GRANT_TYPE {
            return Err(CredentialError::InvalidOid4vciTokenRequest(format!(
                "unsupported grant_type `{}`; expected `{}`",
                self.grant_type, OID4VCI_PRE_AUTHORIZED_GRANT_TYPE
            )));
        }
        if self.pre_authorized_code.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciTokenRequest(
                "token request must include a non-empty pre-authorized_code".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

impl Oid4vciTokenResponse {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.access_token.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciTokenResponse(
                "token response must include a non-empty access_token".to_string(),
            ));
        }
        if !self.token_type.eq_ignore_ascii_case("bearer") {
            return Err(CredentialError::InvalidOid4vciTokenResponse(
                "token response token_type must be `Bearer`".to_string(),
            ));
        }
        if self.expires_in == 0 {
            return Err(CredentialError::InvalidOid4vciTokenResponse(
                "token response expires_in must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciCredentialRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub subject: String,
}

impl Oid4vciCredentialRequest {
    pub fn validate(&self) -> Result<(), CredentialError> {
        if self.subject.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialRequest(
                "credential request must include a non-empty subject".to_string(),
            ));
        }
        DidChio::from_str(&self.subject)?;
        if self.credential_configuration_id.is_none() && self.format.is_none() {
            return Err(CredentialError::InvalidOid4vciCredentialRequest(
                "credential request must include credential_configuration_id or format"
                    .to_string(),
            ));
        }
        if let Some(credential_configuration_id) = self.credential_configuration_id.as_ref() {
            if credential_configuration_id.trim().is_empty() {
                return Err(CredentialError::InvalidOid4vciCredentialRequest(
                    "credential_configuration_id must be non-empty when present".to_string(),
                ));
            }
        }
        if let Some(format) = self.format.as_ref() {
            if format.trim().is_empty() {
                return Err(CredentialError::InvalidOid4vciCredentialRequest(
                    "format must be non-empty when present".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_against_metadata(
        &self,
        metadata: &Oid4vciCredentialIssuerMetadata,
    ) -> Result<String, CredentialError> {
        self.validate()?;
        metadata.validate()?;

        if let Some(credential_configuration_id) = self.credential_configuration_id.as_ref() {
            let configuration = metadata.credential_configuration(credential_configuration_id)?;
            if let Some(format) = self.format.as_ref() {
                if configuration.format != *format {
                    return Err(CredentialError::InvalidOid4vciCredentialRequest(format!(
                        "format `{format}` does not match credential_configuration_id `{credential_configuration_id}`"
                    )));
                }
            }
            return Ok(credential_configuration_id.clone());
        }

        let Some(format) = self.format.as_ref() else {
            return Err(CredentialError::InvalidOid4vciCredentialRequest(
                "credential request must include format when credential_configuration_id is absent"
                    .to_string(),
            ));
        };
        let mut matches = metadata
            .credential_configurations_supported
            .iter()
            .filter(|(_, configuration)| configuration.format == *format)
            .map(|(configuration_id, _)| configuration_id.clone())
            .collect::<Vec<_>>();
        matches.sort();
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => Err(CredentialError::InvalidOid4vciCredentialRequest(format!(
                "no credential configuration supports format `{format}`"
            ))),
            _ => Err(CredentialError::InvalidOid4vciCredentialRequest(format!(
                "format `{format}` is ambiguous; credential_configuration_id is required"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioCredentialContext {
    pub passport_id: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_status: Option<Oid4vciChioPassportStatusReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_jwk: Option<PortableEd25519Jwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciChioPassportStatusReference {
    pub passport_id: String,
    pub distribution: PassportStatusDistribution,
}

impl Oid4vciChioPassportStatusReference {
    fn validate(&self) -> Result<(), CredentialError> {
        if self.passport_id.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "Chio passport status reference must include a non-empty passport_id".to_string(),
            ));
        }
        if self.distribution.is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "Chio passport status reference must include a non-empty distribution"
                    .to_string(),
            ));
        }
        self.distribution
            .validate()
            .map_err(|error| CredentialError::InvalidOid4vciCredentialResponse(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Oid4vciCredentialResponse {
    pub format: String,
    pub credential: Oid4vciIssuedCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio_credential_context: Option<Oid4vciChioCredentialContext>,
}

struct PortableCompactCredentialArgs<'a> {
    format: String,
    compact: String,
    passport_id: String,
    subject: String,
    passport_status: Option<Oid4vciChioPassportStatusReference>,
    issuer_jwk: PortableEd25519Jwk,
    allowed_formats: &'a [&'a str],
    error_message: &'a str,
}

impl Oid4vciCredentialResponse {
    pub fn new(format: impl Into<String>, credential: AgentPassport) -> Result<Self, CredentialError> {
        Self::new_with_status_reference(format, credential, None)
    }

    pub fn new_with_status_reference(
        format: impl Into<String>,
        credential: AgentPassport,
        passport_status: Option<Oid4vciChioPassportStatusReference>,
    ) -> Result<Self, CredentialError> {
        let passport_id = passport_artifact_id(&credential)?;
        Ok(Self {
            format: format.into(),
            chio_credential_context: Some(Oid4vciChioCredentialContext {
                passport_id,
                subject: credential.subject.clone(),
                passport_status,
                issuer_jwk: None,
            }),
            credential: Oid4vciIssuedCredential::AgentPassport(credential),
        })
    }

    pub fn new_portable_sd_jwt(
        format: impl Into<String>,
        compact: impl Into<String>,
        passport_id: impl Into<String>,
        subject: impl Into<String>,
        passport_status: Option<Oid4vciChioPassportStatusReference>,
        issuer_jwk: PortableEd25519Jwk,
    ) -> Result<Self, CredentialError> {
        Self::new_portable_compact(PortableCompactCredentialArgs {
            format: format.into(),
            compact: compact.into(),
            passport_id: passport_id.into(),
            subject: subject.into(),
            passport_status,
            issuer_jwk,
            allowed_formats: &[CHIO_PASSPORT_SD_JWT_VC_FORMAT],
            error_message: "portable Chio passport credentials must use application/dc+sd-jwt",
        })
    }

    pub fn new_portable_jwt_vc_json(
        format: impl Into<String>,
        compact: impl Into<String>,
        passport_id: impl Into<String>,
        subject: impl Into<String>,
        passport_status: Option<Oid4vciChioPassportStatusReference>,
        issuer_jwk: PortableEd25519Jwk,
    ) -> Result<Self, CredentialError> {
        Self::new_portable_compact(PortableCompactCredentialArgs {
            format: format.into(),
            compact: compact.into(),
            passport_id: passport_id.into(),
            subject: subject.into(),
            passport_status,
            issuer_jwk,
            allowed_formats: &[CHIO_PASSPORT_JWT_VC_JSON_FORMAT],
            error_message: "portable Chio passport credentials must use jwt_vc_json",
        })
    }

    fn new_portable_compact(args: PortableCompactCredentialArgs<'_>) -> Result<Self, CredentialError> {
        let PortableCompactCredentialArgs {
            format,
            compact,
            passport_id,
            subject,
            passport_status,
            issuer_jwk,
            allowed_formats,
            error_message,
        } = args;
        if !allowed_formats.iter().any(|supported| *supported == format) {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                error_message.to_string(),
            ));
        }
        if passport_id.trim().is_empty() || subject.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "portable credential context must include non-empty passport_id and subject"
                    .to_string(),
            ));
        }
        Ok(Self {
            format,
            chio_credential_context: Some(Oid4vciChioCredentialContext {
                passport_id,
                subject,
                passport_status,
                issuer_jwk: Some(issuer_jwk),
            }),
            credential: Oid4vciIssuedCredential::Compact(compact),
        })
    }

    pub fn validate(
        &self,
        now: u64,
        expected_format: Option<&str>,
        expected_subject: Option<&str>,
    ) -> Result<(), CredentialError> {
        if self.format.trim().is_empty() {
            return Err(CredentialError::InvalidOid4vciCredentialResponse(
                "credential response must include a non-empty format".to_string(),
            ));
        }
        if let Some(expected_format) = expected_format {
            if self.format != expected_format {
                return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                    "credential response format `{}` does not match expected `{expected_format}`",
                    self.format
                )));
            }
        }
        let (passport_id, subject) = match &self.credential {
            Oid4vciIssuedCredential::AgentPassport(passport) => {
                let verification = verify_agent_passport(passport, now)?;
                (verification.passport_id, verification.subject)
            }
            Oid4vciIssuedCredential::Compact(compact) => {
                let context = self.chio_credential_context.as_ref().ok_or_else(|| {
                    CredentialError::InvalidOid4vciCredentialResponse(
                        "portable credential response must include chio_credential_context"
                            .to_string(),
                    )
                })?;
                let issuer_jwk = context.issuer_jwk.as_ref().ok_or_else(|| {
                    CredentialError::InvalidOid4vciCredentialResponse(
                        "portable credential response must include issuer_jwk in chio_credential_context"
                            .to_string(),
                    )
                })?;
                let verification = if self.format == CHIO_PASSPORT_SD_JWT_VC_FORMAT {
                    let verification =
                        verify_chio_passport_sd_jwt_vc(compact, &issuer_jwk.to_public_key()?, now)?;
                    (verification.passport_id, verification.subject_did)
                } else if self.format == CHIO_PASSPORT_JWT_VC_JSON_FORMAT {
                    let verification = verify_chio_passport_jwt_vc_json(
                        compact,
                        &issuer_jwk.to_public_key()?,
                        now,
                    )?;
                    (verification.passport_id, verification.subject_did)
                } else {
                    return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                        "unsupported compact portable credential format `{}`",
                        self.format
                    )));
                };
                verification
            }
        };
        if let Some(expected_subject) = expected_subject {
            if subject != expected_subject {
                return Err(CredentialError::InvalidOid4vciCredentialResponse(format!(
                    "credential response subject `{}` does not match expected `{expected_subject}`",
                    subject
                )));
            }
        }
        if let Some(context) = self.chio_credential_context.as_ref() {
            if context.passport_id != passport_id {
                return Err(CredentialError::InvalidOid4vciCredentialResponse(
                    "Chio credential context passport_id does not match the delivered passport"
                        .to_string(),
                ));
            }
            if context.subject != subject {
                return Err(CredentialError::InvalidOid4vciCredentialResponse(
                    "Chio credential context subject does not match the delivered passport"
                        .to_string(),
                ));
            }
            if let Some(passport_status) = context.passport_status.as_ref() {
                passport_status.validate()?;
                if passport_status.passport_id != passport_id {
                    return Err(CredentialError::InvalidOid4vciCredentialResponse(
                        "Chio passport status reference passport_id does not match the delivered passport"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn subject_hint(&self) -> Option<&str> {
        self.chio_credential_context
            .as_ref()
            .map(|context| context.subject.as_str())
    }

    pub fn passport_id_hint(&self) -> Option<&str> {
        self.chio_credential_context
            .as_ref()
            .map(|context| context.passport_id.as_str())
    }
}

pub fn default_oid4vci_passport_issuer_metadata(
    credential_issuer: &str,
) -> Result<Oid4vciCredentialIssuerMetadata, CredentialError> {
    default_oid4vci_passport_issuer_metadata_with_signing_key(
        credential_issuer,
        PassportStatusDistribution::default(),
        None,
    )
}

pub fn default_oid4vci_passport_issuer_metadata_with_status_distribution(
    credential_issuer: &str,
    passport_status_distribution: PassportStatusDistribution,
) -> Result<Oid4vciCredentialIssuerMetadata, CredentialError> {
    default_oid4vci_passport_issuer_metadata_with_signing_key(
        credential_issuer,
        passport_status_distribution,
        None,
    )
}

pub fn default_oid4vci_passport_issuer_metadata_with_signing_key(
    credential_issuer: &str,
    passport_status_distribution: PassportStatusDistribution,
    portable_signing_public_key: Option<&PublicKey>,
) -> Result<Oid4vciCredentialIssuerMetadata, CredentialError> {
    let credential_issuer = normalize_credential_issuer(credential_issuer)?;
    let mut credential_configurations_supported = BTreeMap::from([(
        CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
        Oid4vciCredentialConfiguration {
            format: CHIO_PASSPORT_OID4VCI_FORMAT.to_string(),
            scope: None,
            chio_profile: Some(Oid4vciChioCredentialProfile {
                artifact_type: "agent_passport".to_string(),
                subject_did_method: "did:chio".to_string(),
                issuer_did_method: "did:chio".to_string(),
                signature_suite: "Ed25519".to_string(),
            }),
            portable_profile: None,
        },
    )]);
    if portable_signing_public_key.is_some() {
        let portable_claim_catalog = ChioPortableClaimCatalog::default();
        let portable_identity_binding = ChioPortableIdentityBinding::default();
        credential_configurations_supported.insert(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
            Oid4vciCredentialConfiguration {
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                scope: None,
                chio_profile: None,
                portable_profile: Some(Oid4vciChioPortableCredentialProfile {
                    credential_kind: "agent_passport_sd_jwt_vc".to_string(),
                    type_metadata_url: format!(
                        "{credential_issuer}{CHIO_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH}"
                    ),
                    subject_binding: portable_identity_binding.subject_binding.clone(),
                    issuer_identity: portable_identity_binding.issuer_identity.clone(),
                    proof_family: "dc+sd-jwt".to_string(),
                    supports_selective_disclosure: true,
                    portable_claim_catalog,
                    portable_identity_binding,
                }),
            },
        );
        let portable_claim_catalog = jwt_vc_json_claim_catalog();
        let portable_identity_binding = jwt_vc_json_identity_binding();
        credential_configurations_supported.insert(
            CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID.to_string(),
            Oid4vciCredentialConfiguration {
                format: CHIO_PASSPORT_JWT_VC_JSON_FORMAT.to_string(),
                scope: None,
                chio_profile: None,
                portable_profile: Some(Oid4vciChioPortableCredentialProfile {
                    credential_kind: "agent_passport_jwt_vc_json".to_string(),
                    type_metadata_url: format!(
                        "{credential_issuer}{CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH}"
                    ),
                    subject_binding: portable_identity_binding.subject_binding.clone(),
                    issuer_identity: portable_identity_binding.issuer_identity.clone(),
                    proof_family: "vc+jwt".to_string(),
                    supports_selective_disclosure: false,
                    portable_claim_catalog,
                    portable_identity_binding,
                }),
            },
        );
    }
    let metadata = Oid4vciCredentialIssuerMetadata {
        credential_issuer: credential_issuer.clone(),
        credential_endpoint: format!("{credential_issuer}{OID4VCI_PASSPORT_CREDENTIAL_PATH}"),
        token_endpoint: format!("{credential_issuer}{OID4VCI_PASSPORT_TOKEN_PATH}"),
        jwks_uri: portable_signing_public_key
            .map(|_| format!("{credential_issuer}{OID4VCI_JWKS_PATH}")),
        credential_configurations_supported,
        chio_profile: Some(Oid4vciChioIssuerProfile {
            credential_kind: "agent_passport".to_string(),
            subject_did_method: "did:chio".to_string(),
            issuer_did_method: "did:chio".to_string(),
            signature_suite: "Ed25519".to_string(),
            operator_offer_endpoint: format!("{credential_issuer}{OID4VCI_PASSPORT_OFFERS_PATH}"),
            passport_status_distribution,
        }),
    };
    metadata.validate()?;
    Ok(metadata)
}

pub fn build_oid4vci_passport_offer(
    metadata: &Oid4vciCredentialIssuerMetadata,
    credential_configuration_id: &str,
    pre_authorized_code: &str,
    passport: &AgentPassport,
    expires_at: u64,
) -> Result<Oid4vciCredentialOffer, CredentialError> {
    let verification = verify_agent_passport(passport, expires_at)?;
    let offer = Oid4vciCredentialOffer {
        credential_issuer: metadata.credential_issuer.clone(),
        credential_configuration_ids: vec![credential_configuration_id.to_string()],
        grants: Oid4vciOfferGrants {
            pre_authorized_code: Some(Oid4vciPreAuthorizedGrant {
                pre_authorized_code: pre_authorized_code.to_string(),
                tx_code: None,
            }),
        },
        chio_offer_context: Some(Oid4vciChioOfferContext {
            passport_id: verification.passport_id,
            subject: verification.subject,
            expires_at: rfc3339_from_unix(expires_at)?,
        }),
    };
    offer.validate_against_metadata(metadata)?;
    Ok(offer)
}

fn normalize_credential_issuer(value: &str) -> Result<String, CredentialError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CredentialError::InvalidOid4vciIssuerMetadata(
            "credential_issuer must be non-empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

fn validate_endpoint_prefix(
    credential_issuer: &str,
    field: &str,
    endpoint: &str,
) -> Result<(), CredentialError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(CredentialError::InvalidOid4vciIssuerMetadata(format!(
            "{field} must be non-empty"
        )));
    }
    if !endpoint.starts_with(credential_issuer) {
        return Err(CredentialError::InvalidOid4vciIssuerMetadata(format!(
            "{field} must be rooted at credential_issuer `{credential_issuer}`"
        )));
    }
    Ok(())
}
