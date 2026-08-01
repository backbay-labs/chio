use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::action::FrostActionPreimageV1;
use super::registry::frost_action_registration;

pub const CHIO_FROST_AUTHORIZATION_BODY_SCHEMA: &str = "chio.frost.authorization-body.v1";
pub const CHIO_FROST_AUTHORIZATION_SIGNING_PREFIX: &[u8] = b"CHIO-FROST-AUTHORIZATION-V1\0";
const CHIO_FROST_AUTHORIZATION_ID_PREFIX: &[u8] = b"chio.frost.authorization.id.v1\0";
const IJSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrostAuthorizationDomain {
    #[serde(rename = "chio.frost.settle-commitment.v1")]
    SettleCommitment,
    #[serde(rename = "chio.frost.clearing-round-finalize.v1")]
    ClearingRoundFinalize,
    #[serde(rename = "chio.frost.channel-close.v1")]
    ChannelClose,
    #[serde(rename = "chio.frost.adjudication-panel-decision.v1")]
    AdjudicationPanelDecision,
    #[serde(rename = "chio.frost.pouncer-revoke-credential.v1")]
    PouncerRevokeCredential,
    #[serde(rename = "chio.frost.governance-case-enforce-sanction.v1")]
    GovernanceCaseEnforceSanction,
    #[serde(rename = "chio.frost.credentials-passport-revoke.v1")]
    CredentialsPassportRevoke,
    #[serde(rename = "chio.frost.roster-rotate.v1")]
    RosterRotate,
}

impl FrostAuthorizationDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SettleCommitment => "chio.frost.settle-commitment.v1",
            Self::ClearingRoundFinalize => "chio.frost.clearing-round-finalize.v1",
            Self::ChannelClose => "chio.frost.channel-close.v1",
            Self::AdjudicationPanelDecision => "chio.frost.adjudication-panel-decision.v1",
            Self::PouncerRevokeCredential => "chio.frost.pouncer-revoke-credential.v1",
            Self::GovernanceCaseEnforceSanction => "chio.frost.governance-case-enforce-sanction.v1",
            Self::CredentialsPassportRevoke => "chio.frost.credentials-passport-revoke.v1",
            Self::RosterRotate => "chio.frost.roster-rotate.v1",
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FrostAuthorizationError {
    #[error("unsupported FROST authorization schema {0:?}")]
    UnsupportedSchema(String),
    #[error("invalid FROST authorization field {field}: {detail}")]
    InvalidField {
        field: &'static str,
        detail: &'static str,
    },
    #[error("FROST authorization domain is not enabled: {0}")]
    DisabledDomain(&'static str),
    #[error("FROST authorization contract mismatch: {0}")]
    ContractMismatch(&'static str),
    #[error("FROST authorization id does not match its canonical body")]
    AuthorizationIdMismatch,
    #[error("FROST action digest does not match its canonical preimage")]
    ActionDigestMismatch,
    #[error("FROST canonical JSON failed: {0}")]
    Canonical(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostAuthorizationBodyV1 {
    pub schema: String,
    pub authorization_id: String,
    pub domain: FrostAuthorizationDomain,
    pub ladder_action_class: String,
    pub ladder_contract_digest: String,
    pub quorum_n: u16,
    pub quorum_m: u16,
    pub quorum_scope: String,
    pub scope_id: String,
    pub resource_id: String,
    pub resource_version: u64,
    pub resource_fence: u64,
    pub action_digest: String,
    pub roster_digest: String,
    pub key_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostAuthorizationIdPreimage<'a> {
    schema: &'a str,
    domain: FrostAuthorizationDomain,
    ladder_action_class: &'a str,
    ladder_contract_digest: &'a str,
    quorum_n: u16,
    quorum_m: u16,
    quorum_scope: &'a str,
    scope_id: &'a str,
    resource_id: &'a str,
    resource_version: u64,
    resource_fence: u64,
    action_digest: &'a str,
    roster_digest: &'a str,
    key_epoch: u64,
    issued_at: u64,
    expires_at: u64,
}

impl FrostAuthorizationBodyV1 {
    pub fn recompute_authorization_id(&self) -> Result<String, FrostAuthorizationError> {
        let preimage = FrostAuthorizationIdPreimage {
            schema: &self.schema,
            domain: self.domain,
            ladder_action_class: &self.ladder_action_class,
            ladder_contract_digest: &self.ladder_contract_digest,
            quorum_n: self.quorum_n,
            quorum_m: self.quorum_m,
            quorum_scope: &self.quorum_scope,
            scope_id: &self.scope_id,
            resource_id: &self.resource_id,
            resource_version: self.resource_version,
            resource_fence: self.resource_fence,
            action_digest: &self.action_digest,
            roster_digest: &self.roster_digest,
            key_epoch: self.key_epoch,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        let canonical = canonical_json_bytes(&preimage)
            .map_err(|error| FrostAuthorizationError::Canonical(error.to_string()))?;
        let mut bytes =
            Vec::with_capacity(CHIO_FROST_AUTHORIZATION_ID_PREFIX.len() + canonical.len());
        bytes.extend_from_slice(CHIO_FROST_AUTHORIZATION_ID_PREFIX);
        bytes.extend_from_slice(&canonical);
        Ok(sha256_hex(&bytes))
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, FrostAuthorizationError> {
        self.validate()?;
        let canonical = canonical_json_bytes(self)
            .map_err(|error| FrostAuthorizationError::Canonical(error.to_string()))?;
        let mut bytes =
            Vec::with_capacity(CHIO_FROST_AUTHORIZATION_SIGNING_PREFIX.len() + canonical.len());
        bytes.extend_from_slice(CHIO_FROST_AUTHORIZATION_SIGNING_PREFIX);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), FrostAuthorizationError> {
        if self.schema != CHIO_FROST_AUTHORIZATION_BODY_SCHEMA {
            return Err(FrostAuthorizationError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        validate_digest(&self.authorization_id, "authorization_id")?;
        validate_identifier(&self.ladder_action_class, "ladder_action_class")?;
        validate_digest(&self.ladder_contract_digest, "ladder_contract_digest")?;
        validate_identifier(&self.quorum_scope, "quorum_scope")?;
        validate_identifier(&self.scope_id, "scope_id")?;
        validate_identifier(&self.resource_id, "resource_id")?;
        validate_digest(&self.action_digest, "action_digest")?;
        validate_digest(&self.roster_digest, "roster_digest")?;
        validate_positive_safe_integer(self.resource_version, "resource_version")?;
        validate_positive_safe_integer(self.resource_fence, "resource_fence")?;
        validate_positive_safe_integer(self.key_epoch, "key_epoch")?;
        validate_safe_integer(self.issued_at, "issued_at")?;
        validate_safe_integer(self.expires_at, "expires_at")?;
        if self.issued_at >= self.expires_at {
            return Err(FrostAuthorizationError::InvalidField {
                field: "expires_at",
                detail: "must be greater than issued_at",
            });
        }

        let registration = frost_action_registration(self.domain).ok_or(
            FrostAuthorizationError::DisabledDomain(self.domain.as_str()),
        )?;
        if self.ladder_action_class != registration.ladder_action_class {
            return Err(FrostAuthorizationError::ContractMismatch(
                "domain and ladder_action_class",
            ));
        }
        let expected_ladder_digest = registration.ladder_contract_digest()?;
        if self.ladder_contract_digest != expected_ladder_digest {
            return Err(FrostAuthorizationError::ContractMismatch(
                "ladder_contract_digest",
            ));
        }
        if self.quorum_n != registration.quorum_n
            || self.quorum_m != registration.quorum_m
            || self.quorum_scope != registration.quorum_scope
        {
            return Err(FrostAuthorizationError::ContractMismatch(
                "registered quorum",
            ));
        }
        if self.recompute_authorization_id()? != self.authorization_id {
            return Err(FrostAuthorizationError::AuthorizationIdMismatch);
        }
        Ok(())
    }

    pub fn validate_action_preimage(
        &self,
        preimage: &FrostActionPreimageV1,
    ) -> Result<(), FrostAuthorizationError> {
        self.validate()?;
        preimage.validate()?;
        if preimage.domain() != self.domain {
            return Err(FrostAuthorizationError::ContractMismatch(
                "action preimage domain",
            ));
        }
        if preimage.resource_id() != self.resource_id {
            return Err(FrostAuthorizationError::ContractMismatch(
                "action preimage resource_id",
            ));
        }
        if preimage.resource_version() != self.resource_version {
            return Err(FrostAuthorizationError::ContractMismatch(
                "action preimage resource_version",
            ));
        }
        if preimage.resource_fence() != self.resource_fence {
            return Err(FrostAuthorizationError::ContractMismatch(
                "action preimage resource_fence",
            ));
        }
        if preimage.action_digest()? != self.action_digest {
            return Err(FrostAuthorizationError::ActionDigestMismatch);
        }
        Ok(())
    }
}

pub(super) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value.is_empty()
        || value.trim() != value
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must contain only unpadded printable ASCII",
        });
    }
    Ok(())
}

pub(super) fn validate_text(
    value: &str,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value.is_empty()
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be non-empty, unpadded ASCII text without controls",
        });
    }
    Ok(())
}

pub(super) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be 64 lowercase hexadecimal characters",
        });
    }
    Ok(())
}

pub(super) fn validate_positive_safe_integer(
    value: u64,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value == 0 || value > IJSON_MAX_SAFE_INTEGER {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be a positive I-JSON safe integer",
        });
    }
    Ok(())
}

pub(super) fn validate_safe_integer(
    value: u64,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value > IJSON_MAX_SAFE_INTEGER {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be an I-JSON safe integer",
        });
    }
    Ok(())
}

pub(super) fn validate_positive_base_units(
    value: &str,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    validate_identifier(value, field)?;
    if value == "0" || value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be a canonical positive base-unit integer",
        });
    }
    Ok(())
}

pub(super) fn validate_base_units(
    value: &str,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    validate_identifier(value, field)?;
    if value.len() > 1 && value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must be a canonical base-unit integer",
        });
    }
    Ok(())
}
