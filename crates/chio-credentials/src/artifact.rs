#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("did error: {0}")]
    Did(#[from] DidError),

    #[error("core error: {0}")]
    Core(#[from] chio_core::Error),

    #[error("invalid unix timestamp: {0}")]
    InvalidUnixTimestamp(u64),

    #[error("invalid RFC3339 timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("credential proof type must be {PROOF_TYPE}")]
    InvalidProofType,

    #[error("credential proof purpose must be {PROOF_PURPOSE}")]
    InvalidProofPurpose,

    #[error("credential verification method does not match issuer DID")]
    IssuerVerificationMethodMismatch,

    #[error("credential subject DID does not match the embedded scorecard subject")]
    SubjectDidMismatch,

    #[error("credential has expired")]
    CredentialExpired,

    #[error("credential issuance date must be before or equal to expiration date")]
    InvalidCredentialValidityWindow,

    #[error("credential signature verification failed")]
    InvalidCredentialSignature,

    #[error("passport must contain at least one credential")]
    EmptyPassport,

    #[error("passport schema must be {PASSPORT_SCHEMA}")]
    InvalidPassportSchema,

    #[error("passport subject does not match credential subject {0}")]
    PassportSubjectMismatch(String),

    #[error("passport validUntil extends beyond at least one contained credential")]
    PassportValidityMismatch,

    #[error("enterprise identity provenance field {field} must be non-empty")]
    MissingEnterpriseIdentityProvenanceField { field: &'static str },

    #[error("passport enterprise identity provenance does not match embedded credential provenance")]
    PassportEnterpriseIdentityProvenanceMismatch,

    #[error("verifier policy threshold for {field} must be within [0.0, 1.0], got {value}")]
    InvalidVerifierThreshold { field: &'static str, value: f64 },

    #[error("signed verifier policy schema must be {PASSPORT_VERIFIER_POLICY_SCHEMA}")]
    InvalidSignedVerifierPolicySchema,

    #[error("signed verifier policy created_at must be before or equal to expires_at")]
    InvalidSignedVerifierPolicyValidityWindow,

    #[error("signed verifier policy must include a non-empty policy_id")]
    MissingSignedVerifierPolicyId,

    #[error("signed verifier policy must include a non-empty verifier")]
    MissingSignedVerifierVerifier,

    #[error("signed verifier policy signature verification failed")]
    InvalidSignedVerifierPolicySignature,

    #[error("signed verifier policy is not yet valid")]
    SignedVerifierPolicyNotYetValid,

    #[error("signed verifier policy has expired")]
    SignedVerifierPolicyExpired,

    #[error("invalid public discovery document: {0}")]
    InvalidPublicDiscoveryDocument(String),

    #[error("public discovery signature verification failed")]
    InvalidPublicDiscoverySignature,

    #[error("public discovery document is not yet valid")]
    PublicDiscoveryNotYetValid,

    #[error("public discovery document has expired")]
    PublicDiscoveryExpired,

    #[error("challenge schema must be {PASSPORT_PRESENTATION_CHALLENGE_SCHEMA}")]
    InvalidChallengeSchema,

    #[error("challenge issuance date must be before or equal to expiration date")]
    InvalidChallengeValidityWindow,

    #[error("challenge is not yet valid")]
    ChallengeNotYetValid,

    #[error("challenge has expired")]
    ChallengeExpired,

    #[error("presentation schema must be {PASSPORT_PRESENTATION_RESPONSE_SCHEMA}")]
    InvalidPresentationSchema,

    #[error("presentation holder key does not match passport subject")]
    PresentationHolderMismatch,

    #[error("presentation proof type must be {PROOF_TYPE}")]
    InvalidPresentationProofType,

    #[error("presentation proof purpose must be {PRESENTATION_PROOF_PURPOSE}")]
    InvalidPresentationProofPurpose,

    #[error("presentation verification method does not match passport subject DID")]
    PresentationVerificationMethodMismatch,

    #[error("presentation proof timestamp must fall within the challenge validity window")]
    PresentationProofOutsideChallengeWindow,

    #[error("presentation proof timestamp is in the future")]
    PresentationProofFromFuture,

    #[error("presentation signature verification failed")]
    InvalidPresentationSignature,

    #[error("expected challenge does not match embedded challenge")]
    ChallengeMismatch,

    #[error("presentation includes issuer {0} outside the challenge allowlist")]
    PresentationIssuerNotAllowed(String),

    #[error("presentation includes {actual} credential(s), exceeding challenge maximum {max}")]
    PresentationCredentialLimitExceeded { max: usize, actual: usize },

    #[error("invalid OID4VCI issuer metadata: {0}")]
    InvalidOid4vciIssuerMetadata(String),

    #[error("invalid OID4VCI credential offer: {0}")]
    InvalidOid4vciCredentialOffer(String),

    #[error("invalid OID4VCI token request: {0}")]
    InvalidOid4vciTokenRequest(String),

    #[error("invalid OID4VCI token response: {0}")]
    InvalidOid4vciTokenResponse(String),

    #[error("invalid OID4VCI credential request: {0}")]
    InvalidOid4vciCredentialRequest(String),

    #[error("invalid OID4VCI credential response: {0}")]
    InvalidOid4vciCredentialResponse(String),

    #[error("invalid OID4VP request object: {0}")]
    InvalidOid4vpRequest(String),

    #[error("invalid OID4VP response: {0}")]
    InvalidOid4vpResponse(String),

    #[error("invalid passport lifecycle contract: {0}")]
    InvalidPassportLifecycle(String),

    #[error("invalid cross-issuer portfolio contract: {0}")]
    InvalidCrossIssuerPortfolio(String),

    #[error("invalid cross-issuer trust pack: {0}")]
    InvalidCrossIssuerTrustPack(String),

    #[error("invalid cross-issuer migration record: {0}")]
    InvalidCrossIssuerMigration(String),

    #[error("invalid portable reputation contract: {0}")]
    InvalidPortableReputation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    pub until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChioCredentialEvidence {
    pub query: AttestationWindow,
    pub receipt_count: usize,
    pub receipt_ids: Vec<String>,
    pub checkpoint_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_log_urls: Vec<String>,
    pub lineage_records: usize,
    pub uncheckpointed_receipts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<chio_core::capability::RuntimeAttestationEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseIdentityProvenance {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: EnterpriseFederationMethod,
    pub principal: String,
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subject: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
}

impl EnterpriseIdentityProvenance {
    pub fn from_context(context: &EnterpriseIdentityContext) -> Self {
        Self {
            provider_id: context.provider_id.clone(),
            provider_record_id: context.provider_record_id.clone(),
            provider_kind: context.provider_kind.clone(),
            federation_method: context.federation_method.clone(),
            principal: context.principal.clone(),
            subject_key: context.subject_key.clone(),
            client_id: context.client_id.clone(),
            object_id: context.object_id.clone(),
            tenant_id: context.tenant_id.clone(),
            organization_id: context.organization_id.clone(),
            groups: context.groups.clone(),
            roles: context.roles.clone(),
            source_subject: context.source_subject.clone(),
            attribute_sources: context.attribute_sources.clone(),
            trust_material_ref: context.trust_material_ref.clone(),
        }
    }

    fn validate(&self) -> Result<(), CredentialError> {
        if self.provider_id.trim().is_empty() {
            return Err(CredentialError::MissingEnterpriseIdentityProvenanceField {
                field: "providerId",
            });
        }
        if self.provider_kind.trim().is_empty() {
            return Err(CredentialError::MissingEnterpriseIdentityProvenanceField {
                field: "providerKind",
            });
        }
        if self.principal.trim().is_empty() {
            return Err(CredentialError::MissingEnterpriseIdentityProvenanceField {
                field: "principal",
            });
        }
        if self.subject_key.trim().is_empty() {
            return Err(CredentialError::MissingEnterpriseIdentityProvenanceField {
                field: "subjectKey",
            });
        }
        Ok(())
    }
}

impl From<&EnterpriseIdentityContext> for EnterpriseIdentityProvenance {
    fn from(context: &EnterpriseIdentityContext) -> Self {
        Self::from_context(context)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCredentialSubject {
    pub id: String,
    pub metrics: LocalReputationScorecard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedReputationCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: ReputationCredentialSubject,
    pub evidence: ChioCredentialEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity_provenance: Option<EnterpriseIdentityProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCredential {
    #[serde(flatten)]
    pub unsigned: UnsignedReputationCredential,
    pub proof: CredentialProof,
}
