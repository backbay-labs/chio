use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BoundedAdmissionText<const MAX: usize>(String);

impl<const MAX: usize> BoundedAdmissionText<MAX> {
    pub fn try_new(
        field: &'static str,
        value: impl Into<String>,
    ) -> Result<Self, AdmissionOperationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AdmissionOperationError::Empty { field });
        }
        if value.len() > MAX {
            return Err(AdmissionOperationError::TooLong {
                field,
                maximum: MAX,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(AdmissionOperationError::ControlCharacter { field });
        }
        if value.trim() != value {
            return Err(AdmissionOperationError::Padded { field });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedAdmissionText<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_new("persisted_admission_text", value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AdmissionDigest(String);

impl AdmissionDigest {
    pub fn try_new(
        field: &'static str,
        value: impl Into<String>,
    ) -> Result<Self, AdmissionOperationError> {
        let value = value.into();
        if !is_sha256_hex(&value) {
            return Err(AdmissionOperationError::InvalidDigest { field });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_derived(value: String) -> Self {
        debug_assert!(is_sha256_hex(&value));
        Self(value)
    }
}

impl<'de> Deserialize<'de> for AdmissionDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_new("persisted_admission_digest", value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissionOperationId(AdmissionDigest);

impl AdmissionOperationId {
    pub fn from_persisted(value: impl Into<String>) -> Result<Self, AdmissionOperationError> {
        AdmissionDigest::try_new("operation_id", value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn from_derived(value: String) -> Self {
        Self(AdmissionDigest::from_derived(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestNamespaceDigest(AdmissionDigest);

impl RequestNamespaceDigest {
    pub fn from_persisted(value: impl Into<String>) -> Result<Self, AdmissionOperationError> {
        AdmissionDigest::try_new("request_namespace_digest", value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn from_derived(value: String) -> Self {
        Self(AdmissionDigest::from_derived(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRequestNamespace {
    coordinator_authority_id: AdmissionIdentifier,
    authenticated_tenant_id: BoundedAdmissionText<MAX_ADMISSION_TENANT_BYTES>,
    digest: RequestNamespaceDigest,
}

impl AuthenticatedRequestNamespace {
    pub fn for_local_system(
        coordinator_authority_id: AdmissionIdentifier,
    ) -> Result<Self, AdmissionOperationError> {
        Self::bind(
            coordinator_authority_id,
            BoundedAdmissionText::try_new("authenticated_tenant_id", LOCAL_SYSTEM_TENANT_ID)?,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn from_authentication_context(
        coordinator_authority_id: AdmissionIdentifier,
        authenticated_tenant_id: impl Into<String>,
    ) -> Result<Self, AdmissionOperationError> {
        let authenticated_tenant_id = authenticated_tenant_id.into();
        if authenticated_tenant_id == LOCAL_SYSTEM_TENANT_ID {
            return Err(AdmissionOperationError::ReservedLocalSystemTenant);
        }
        Self::bind(
            coordinator_authority_id,
            BoundedAdmissionText::try_new("authenticated_tenant_id", authenticated_tenant_id)?,
        )
    }

    fn bind(
        coordinator_authority_id: AdmissionIdentifier,
        authenticated_tenant_id: BoundedAdmissionText<MAX_ADMISSION_TENANT_BYTES>,
    ) -> Result<Self, AdmissionOperationError> {
        #[derive(Serialize)]
        struct NamespaceBody<'a> {
            authenticated_tenant_id: &'a str,
            coordinator_authority_id: &'a str,
        }

        let body = NamespaceBody {
            authenticated_tenant_id: authenticated_tenant_id.as_str(),
            coordinator_authority_id: coordinator_authority_id.as_str(),
        };
        let digest = domain_separated_digest(ADMISSION_REQUEST_NAMESPACE_DOMAIN, &body)?;
        Ok(Self {
            coordinator_authority_id,
            authenticated_tenant_id,
            digest: RequestNamespaceDigest::from_derived(digest),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOperationKind {
    ToolDispatch,
    GovernedActiveResponse,
    GovernedEconomicMutation,
}

impl AdmissionOperationKind {
    pub const ALL: [Self; 3] = [
        Self::ToolDispatch,
        Self::GovernedActiveResponse,
        Self::GovernedEconomicMutation,
    ];

    pub(super) fn uses_dispatch(self) -> bool {
        matches!(self, Self::ToolDispatch | Self::GovernedActiveResponse)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    ReadOnly,
    SideEffecting,
    Monetary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionParticipantRequirements {
    pub broker_attempt: bool,
    pub budget_capture: bool,
    pub approval: bool,
    pub execution_nonce: bool,
    pub outcome_eligibility: bool,
    pub payment: bool,
    pub authorization_consumption: bool,
    pub observation_attempt_zero: bool,
    pub obligation: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub channel: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub credit_exposure: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub supplemental_authorization: bool,
}

impl AdmissionParticipantRequirements {
    pub const NONE: Self = Self {
        broker_attempt: false,
        budget_capture: false,
        approval: false,
        execution_nonce: false,
        outcome_eligibility: false,
        payment: false,
        authorization_consumption: false,
        observation_attempt_zero: false,
        obligation: false,
        channel: false,
        credit_exposure: false,
        supplemental_authorization: false,
    };

    fn validate(self) -> Result<(), AdmissionOperationError> {
        if (self.broker_attempt || self.payment || self.channel) && !self.budget_capture
            || self.channel && (self.payment || !self.obligation)
            || self.credit_exposure
                && (!self.budget_capture || !self.obligation || self.payment || self.channel)
        {
            return Err(AdmissionOperationError::InvalidParticipantRequirements);
        }
        Ok(())
    }

    pub(super) fn validate_for_kind(
        self,
        kind: AdmissionOperationKind,
    ) -> Result<(), AdmissionOperationError> {
        self.validate()?;
        let kind_valid = match kind {
            AdmissionOperationKind::ToolDispatch => {
                self.budget_capture && self.broker_attempt && !self.supplemental_authorization
            }
            AdmissionOperationKind::GovernedActiveResponse => {
                self == (Self {
                    approval: true,
                    ..Self::NONE
                })
            }
            AdmissionOperationKind::GovernedEconomicMutation => {
                self == Self::NONE
                    || self
                        == (Self {
                            supplemental_authorization: true,
                            ..Self::NONE
                        })
            }
        };
        if kind_valid {
            Ok(())
        } else {
            Err(AdmissionOperationError::InvalidParticipantRequirements)
        }
    }
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionRequestBindingV1 {
    pub(super) immutable_request_hash: AdmissionDigest,
    pub(super) action_parameter_hash: AdmissionDigest,
    pub(super) participant_requirements: AdmissionParticipantRequirements,
    pub(super) request_binding_hash: AdmissionDigest,
}

impl AdmissionRequestBindingV1 {
    pub fn new(
        immutable_request_hash: AdmissionDigest,
        participant_requirements: AdmissionParticipantRequirements,
    ) -> Result<Self, AdmissionOperationError> {
        Self::new_with_action_parameter_hash(
            immutable_request_hash.clone(),
            immutable_request_hash,
            participant_requirements,
        )
    }

    pub fn new_with_action_parameter_hash(
        immutable_request_hash: AdmissionDigest,
        action_parameter_hash: AdmissionDigest,
        participant_requirements: AdmissionParticipantRequirements,
    ) -> Result<Self, AdmissionOperationError> {
        participant_requirements.validate()?;
        let request_binding_hash = derive_request_binding_hash(
            &immutable_request_hash,
            &action_parameter_hash,
            participant_requirements,
        )?;
        Ok(Self {
            immutable_request_hash,
            action_parameter_hash,
            participant_requirements,
            request_binding_hash,
        })
    }

    fn validate(&self) -> Result<(), AdmissionOperationError> {
        self.participant_requirements.validate()?;
        if derive_request_binding_hash(
            &self.immutable_request_hash,
            &self.action_parameter_hash,
            self.participant_requirements,
        )? != self.request_binding_hash
        {
            return Err(AdmissionOperationError::RequestBindingMismatch);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AdmissionRequestBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Persisted {
            immutable_request_hash: AdmissionDigest,
            action_parameter_hash: AdmissionDigest,
            participant_requirements: AdmissionParticipantRequirements,
            request_binding_hash: AdmissionDigest,
        }
        let value = Persisted::deserialize(deserializer)?;
        let binding = Self {
            immutable_request_hash: value.immutable_request_hash,
            action_parameter_hash: value.action_parameter_hash,
            participant_requirements: value.participant_requirements,
            request_binding_hash: value.request_binding_hash,
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableAdmissionMode {
    Off,
    Monetary,
    #[default]
    SideEffecting,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionReceiptPersistence {
    Durable,
    Ephemeral,
}

impl DurableAdmissionMode {
    #[must_use]
    pub fn covers(self, effect_class: SideEffectClass) -> bool {
        match self {
            Self::Off => false,
            Self::Monetary => effect_class == SideEffectClass::Monetary,
            Self::SideEffecting => effect_class != SideEffectClass::ReadOnly,
            Self::All => true,
        }
    }

    pub fn validate_configuration(
        self,
        unsafe_development: bool,
        receipts: AdmissionReceiptPersistence,
    ) -> Result<Self, AdmissionOperationError> {
        if self == Self::Off
            && (!unsafe_development || receipts != AdmissionReceiptPersistence::Ephemeral)
        {
            return Err(AdmissionOperationError::UnsafeDurableAdmissionOff);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOperationBindingInputV1 {
    pub kind: AdmissionOperationKind,
    pub namespace: AuthenticatedRequestNamespace,
    pub request_id: AdmissionIdentifier,
    pub capability_id: AdmissionIdentifier,
    pub authorization_capability_hash: AdmissionDigest,
    pub request_binding: AdmissionRequestBindingV1,
    pub policy_hash: AdmissionDigest,
    pub effect_class: SideEffectClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedAdmissionOperationBindingV1 {
    pub kind: AdmissionOperationKind,
    pub operation_id: AdmissionOperationId,
    pub coordinator_authority_id: AdmissionIdentifier,
    pub authenticated_tenant_id: BoundedAdmissionText<MAX_ADMISSION_TENANT_BYTES>,
    pub request_namespace_digest: RequestNamespaceDigest,
    pub request_id: AdmissionIdentifier,
    pub capability_id: AdmissionIdentifier,
    pub authorization_capability_hash: AdmissionDigest,
    pub request_binding: AdmissionRequestBindingV1,
    pub policy_hash: AdmissionDigest,
    pub effect_class: SideEffectClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionOperationBindingV1 {
    pub(super) kind: AdmissionOperationKind,
    pub(super) operation_id: AdmissionOperationId,
    pub(super) coordinator_authority_id: AdmissionIdentifier,
    pub(super) authenticated_tenant_id: BoundedAdmissionText<MAX_ADMISSION_TENANT_BYTES>,
    pub(super) request_namespace_digest: RequestNamespaceDigest,
    pub(super) request_id: AdmissionIdentifier,
    pub(super) capability_id: AdmissionIdentifier,
    pub(super) authorization_capability_hash: AdmissionDigest,
    pub(super) request_binding: AdmissionRequestBindingV1,
    pub(super) policy_hash: AdmissionDigest,
    pub(super) effect_class: SideEffectClass,
}

impl AdmissionOperationBindingV1 {
    pub fn new(input: AdmissionOperationBindingInputV1) -> Result<Self, AdmissionOperationError> {
        input
            .request_binding
            .participant_requirements
            .validate_for_kind(input.kind)?;
        let operation_id = derive_operation_id(OperationIdInput {
            kind: input.kind,
            coordinator_authority_id: &input.namespace.coordinator_authority_id,
            request_namespace_digest: &input.namespace.digest,
            request_id: &input.request_id,
            capability_id: &input.capability_id,
            authorization_capability_hash: &input.authorization_capability_hash,
            request_binding_hash: &input.request_binding.request_binding_hash,
            policy_hash: &input.policy_hash,
            effect_class: input.effect_class,
        })?;
        Ok(Self {
            kind: input.kind,
            operation_id,
            coordinator_authority_id: input.namespace.coordinator_authority_id,
            authenticated_tenant_id: input.namespace.authenticated_tenant_id,
            request_namespace_digest: input.namespace.digest,
            request_id: input.request_id,
            capability_id: input.capability_id,
            authorization_capability_hash: input.authorization_capability_hash,
            request_binding: input.request_binding,
            policy_hash: input.policy_hash,
            effect_class: input.effect_class,
        })
    }

    pub fn from_persisted(
        input: PersistedAdmissionOperationBindingV1,
    ) -> Result<Self, AdmissionOperationError> {
        let namespace = AuthenticatedRequestNamespace::bind(
            input.coordinator_authority_id.clone(),
            input.authenticated_tenant_id.clone(),
        )?;
        if namespace.digest != input.request_namespace_digest {
            return Err(AdmissionOperationError::RequestNamespaceMismatch);
        }
        let binding = Self {
            kind: input.kind,
            operation_id: input.operation_id,
            coordinator_authority_id: input.coordinator_authority_id,
            authenticated_tenant_id: input.authenticated_tenant_id,
            request_namespace_digest: input.request_namespace_digest,
            request_id: input.request_id,
            capability_id: input.capability_id,
            authorization_capability_hash: input.authorization_capability_hash,
            request_binding: input.request_binding,
            policy_hash: input.policy_hash,
            effect_class: input.effect_class,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        self.request_binding.validate()?;
        self.request_binding
            .participant_requirements
            .validate_for_kind(self.kind)?;
        let namespace = AuthenticatedRequestNamespace::bind(
            self.coordinator_authority_id.clone(),
            self.authenticated_tenant_id.clone(),
        )?;
        if namespace.digest != self.request_namespace_digest {
            return Err(AdmissionOperationError::RequestNamespaceMismatch);
        }
        let expected = derive_operation_id(OperationIdInput {
            kind: self.kind,
            coordinator_authority_id: &self.coordinator_authority_id,
            request_namespace_digest: &self.request_namespace_digest,
            request_id: &self.request_id,
            capability_id: &self.capability_id,
            authorization_capability_hash: &self.authorization_capability_hash,
            request_binding_hash: &self.request_binding.request_binding_hash,
            policy_hash: &self.policy_hash,
            effect_class: self.effect_class,
        })?;
        if expected != self.operation_id {
            return Err(AdmissionOperationError::OperationIdMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn kind(&self) -> AdmissionOperationKind {
        self.kind
    }

    #[must_use]
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    #[must_use]
    pub fn coordinator_authority_id(&self) -> &AdmissionIdentifier {
        &self.coordinator_authority_id
    }

    #[must_use]
    pub fn request_namespace_digest(&self) -> &RequestNamespaceDigest {
        &self.request_namespace_digest
    }

    #[must_use]
    pub fn request_id(&self) -> &AdmissionIdentifier {
        &self.request_id
    }

    #[must_use]
    pub fn capability_id(&self) -> &AdmissionIdentifier {
        &self.capability_id
    }

    #[must_use]
    pub fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding.request_binding_hash
    }

    #[must_use]
    pub fn immutable_request_hash(&self) -> &AdmissionDigest {
        &self.request_binding.immutable_request_hash
    }

    #[must_use]
    pub fn action_parameter_hash(&self) -> &AdmissionDigest {
        &self.request_binding.action_parameter_hash
    }

    #[must_use]
    pub fn participant_requirements(&self) -> AdmissionParticipantRequirements {
        self.request_binding.participant_requirements
    }

    #[must_use]
    pub fn policy_hash(&self) -> &AdmissionDigest {
        &self.policy_hash
    }

    #[must_use]
    pub fn effect_class(&self) -> SideEffectClass {
        self.effect_class
    }

    #[must_use]
    pub fn replay_key(&self) -> AdmissionReplayKey {
        AdmissionReplayKey {
            request_namespace_digest: self.request_namespace_digest.clone(),
            request_id: self.request_id.clone(),
        }
    }

    #[must_use]
    pub fn to_persisted(&self) -> PersistedAdmissionOperationBindingV1 {
        self.into()
    }
}

impl From<&AdmissionOperationBindingV1> for PersistedAdmissionOperationBindingV1 {
    fn from(binding: &AdmissionOperationBindingV1) -> Self {
        Self {
            kind: binding.kind,
            operation_id: binding.operation_id.clone(),
            coordinator_authority_id: binding.coordinator_authority_id.clone(),
            authenticated_tenant_id: binding.authenticated_tenant_id.clone(),
            request_namespace_digest: binding.request_namespace_digest.clone(),
            request_id: binding.request_id.clone(),
            capability_id: binding.capability_id.clone(),
            authorization_capability_hash: binding.authorization_capability_hash.clone(),
            request_binding: binding.request_binding.clone(),
            policy_hash: binding.policy_hash.clone(),
            effect_class: binding.effect_class,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdmissionReplayKey {
    pub request_namespace_digest: RequestNamespaceDigest,
    pub request_id: AdmissionIdentifier,
}

pub(super) struct OperationIdInput<'a> {
    pub(super) kind: AdmissionOperationKind,
    pub(super) coordinator_authority_id: &'a AdmissionIdentifier,
    pub(super) request_namespace_digest: &'a RequestNamespaceDigest,
    pub(super) request_id: &'a AdmissionIdentifier,
    pub(super) capability_id: &'a AdmissionIdentifier,
    pub(super) authorization_capability_hash: &'a AdmissionDigest,
    pub(super) request_binding_hash: &'a AdmissionDigest,
    pub(super) policy_hash: &'a AdmissionDigest,
    pub(super) effect_class: SideEffectClass,
}

pub(super) fn derive_operation_id(
    input: OperationIdInput<'_>,
) -> Result<AdmissionOperationId, AdmissionOperationError> {
    #[derive(Serialize)]
    struct OperationIdBody<'a> {
        kind: AdmissionOperationKind,
        coordinator_authority_id: &'a str,
        request_namespace_digest: &'a str,
        request_id: &'a str,
        capability_id: &'a str,
        authorization_capability_hash: &'a str,
        request_binding_hash: &'a str,
        policy_hash: &'a str,
        effect_class: SideEffectClass,
    }

    let body = OperationIdBody {
        kind: input.kind,
        coordinator_authority_id: input.coordinator_authority_id.as_str(),
        request_namespace_digest: input.request_namespace_digest.as_str(),
        request_id: input.request_id.as_str(),
        capability_id: input.capability_id.as_str(),
        authorization_capability_hash: input.authorization_capability_hash.as_str(),
        request_binding_hash: input.request_binding_hash.as_str(),
        policy_hash: input.policy_hash.as_str(),
        effect_class: input.effect_class,
    };
    domain_separated_digest(ADMISSION_OPERATION_DOMAIN, &body)
        .map(AdmissionOperationId::from_derived)
}

fn derive_request_binding_hash(
    immutable_request_hash: &AdmissionDigest,
    action_parameter_hash: &AdmissionDigest,
    participant_requirements: AdmissionParticipantRequirements,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    #[derive(Serialize)]
    struct RequestBindingBody<'a> {
        immutable_request_hash: &'a str,
        action_parameter_hash: &'a str,
        participant_requirements: AdmissionParticipantRequirements,
    }
    domain_separated_digest(
        ADMISSION_REQUEST_BINDING_DOMAIN,
        &RequestBindingBody {
            immutable_request_hash: immutable_request_hash.as_str(),
            action_parameter_hash: action_parameter_hash.as_str(),
            participant_requirements,
        },
    )
    .map(AdmissionDigest::from_derived)
}

fn domain_separated_digest<T: Serialize>(
    domain: &[u8],
    body: &T,
) -> Result<String, AdmissionOperationError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
