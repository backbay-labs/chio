use std::collections::HashSet;

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use frost_ed25519::keys::VerifyingShare;
use frost_ed25519::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::registry::frost_action_registration;
use super::types::{
    validate_digest, validate_identifier, validate_positive_safe_integer, validate_safe_integer,
    FrostAuthorizationDomain,
};

pub const CHIO_FROST_ROSTER_SCHEMA: &str = "chio.frost.roster.v1";
pub const CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA: &str = "chio.frost.epoch-checkpoint.v1";
pub const FROST_ED25519_SHA512_SUITE_ID: &str = "FROST-ED25519-SHA512-v1";
const CHIO_FROST_ROSTER_ID_PREFIX: &[u8] = b"chio.frost.roster.id.v1\0";
const CHIO_FROST_ROSTER_DIGEST_PREFIX: &[u8] = b"chio.frost.roster.digest.v1\0";
const CHIO_FROST_ROSTER_SIGNING_PREFIX: &[u8] = b"CHIO-FROST-ROSTER-V1\0";
const CHIO_FROST_EPOCH_CHECKPOINT_DIGEST_PREFIX: &[u8] = b"chio.frost.epoch-checkpoint.digest.v1\0";
const CHIO_FROST_EPOCH_CHECKPOINT_SIGNING_PREFIX: &[u8] = b"CHIO-FROST-EPOCH-CHECKPOINT-V1\0";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FrostRosterError {
    #[error("unsupported FROST roster schema {0:?}")]
    UnsupportedSchema(String),
    #[error("invalid FROST roster field {field}: {detail}")]
    InvalidField {
        field: &'static str,
        detail: &'static str,
    },
    #[error("FROST roster contract mismatch: {0}")]
    ContractMismatch(&'static str),
    #[error("FROST roster id does not match its canonical body")]
    RosterIdMismatch,
    #[error("FROST roster digest does not match its canonical signed artifact")]
    RosterDigestMismatch,
    #[error("FROST roster canonical JSON failed: {0}")]
    Canonical(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FrostRosterResolutionError {
    #[error("FROST roster resolver unavailable: {0}")]
    Unavailable(String),
    #[error("FROST roster resolver returned invalid data: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FrostAnchorError {
    #[error("FROST external anchor unavailable: {0}")]
    Unavailable(String),
    #[error("FROST external anchor returned invalid data: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostParticipantV1 {
    pub participant_id: String,
    pub verification_share: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostRosterKeyOrigin {
    DistributedDkg,
    DealerFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostRosterV1 {
    pub schema: String,
    pub roster_id: String,
    pub roster_digest: String,
    pub authority_scope: String,
    pub scope_id: String,
    pub allowed_domains: Vec<FrostAuthorizationDomain>,
    pub key_epoch: u64,
    pub threshold: u16,
    pub participant_count: u16,
    pub participants: Vec<FrostParticipantV1>,
    pub group_public_key: String,
    pub suite_id: String,
    pub key_origin: FrostRosterKeyOrigin,
    pub ceremony_transcript_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_roster_digest: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub roster_authority_key_id: String,
    pub roster_authority_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostRosterIdPreimage<'a> {
    schema: &'a str,
    authority_scope: &'a str,
    scope_id: &'a str,
    allowed_domains: &'a [FrostAuthorizationDomain],
    key_epoch: u64,
    threshold: u16,
    participant_count: u16,
    participants: &'a [FrostParticipantV1],
    group_public_key: &'a str,
    suite_id: &'a str,
    key_origin: FrostRosterKeyOrigin,
    ceremony_transcript_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_roster_digest: Option<&'a str>,
    valid_from: u64,
    valid_until: u64,
    roster_authority_key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostRosterDigestPreimage<'a> {
    roster_id: &'a str,
    #[serde(flatten)]
    body: FrostRosterIdPreimage<'a>,
    roster_authority_signature: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostRosterSigningPreimage<'a> {
    roster_id: &'a str,
    #[serde(flatten)]
    body: FrostRosterIdPreimage<'a>,
}

impl FrostRosterV1 {
    pub fn recompute_roster_id(&self) -> Result<String, FrostRosterError> {
        canonical_digest(CHIO_FROST_ROSTER_ID_PREFIX, &self.id_preimage())
    }

    pub fn recompute_roster_digest(&self) -> Result<String, FrostRosterError> {
        canonical_digest(
            CHIO_FROST_ROSTER_DIGEST_PREFIX,
            &FrostRosterDigestPreimage {
                roster_id: &self.roster_id,
                body: self.id_preimage(),
                roster_authority_signature: &self.roster_authority_signature,
            },
        )
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, FrostRosterError> {
        canonical_prefixed_bytes(
            CHIO_FROST_ROSTER_SIGNING_PREFIX,
            &FrostRosterSigningPreimage {
                roster_id: &self.roster_id,
                body: self.id_preimage(),
            },
        )
    }

    pub fn validate(&self) -> Result<(), FrostRosterError> {
        if self.schema != CHIO_FROST_ROSTER_SCHEMA {
            return Err(FrostRosterError::UnsupportedSchema(self.schema.clone()));
        }
        roster_digest(&self.roster_id, "roster_id")?;
        roster_digest(&self.roster_digest, "roster_digest")?;
        roster_identifier(&self.authority_scope, "authority_scope")?;
        roster_identifier(&self.scope_id, "scope_id")?;
        roster_positive_safe_integer(self.key_epoch, "key_epoch")?;
        if self.threshold == 0 || self.threshold > self.participant_count {
            return Err(FrostRosterError::InvalidField {
                field: "threshold",
                detail: "must be between one and participant_count",
            });
        }
        if usize::from(self.participant_count) != self.participants.len() {
            return Err(FrostRosterError::InvalidField {
                field: "participant_count",
                detail: "must equal participants length",
            });
        }
        self.validate_domains()?;
        self.validate_participants()?;
        validate_fixed_hex(&self.group_public_key, 64, "group_public_key")?;
        VerifyingKey::deserialize(&decode_hex(&self.group_public_key, "group_public_key")?)
            .map_err(|_| FrostRosterError::InvalidField {
                field: "group_public_key",
                detail: "must encode a valid FROST Ed25519 verifying key",
            })?;
        if self.suite_id != FROST_ED25519_SHA512_SUITE_ID {
            return Err(FrostRosterError::InvalidField {
                field: "suite_id",
                detail: "must be the production FROST Ed25519 SHA-512 suite",
            });
        }
        roster_digest(
            &self.ceremony_transcript_digest,
            "ceremony_transcript_digest",
        )?;
        match (self.key_epoch, self.predecessor_roster_digest.as_deref()) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(FrostRosterError::InvalidField {
                    field: "predecessor_roster_digest",
                    detail: "must be absent for the first key epoch",
                });
            }
            (_, Some(digest)) => roster_digest(digest, "predecessor_roster_digest")?,
            (_, None) => {
                return Err(FrostRosterError::InvalidField {
                    field: "predecessor_roster_digest",
                    detail: "is required after the first key epoch",
                });
            }
        }
        roster_safe_integer(self.valid_from, "valid_from")?;
        roster_safe_integer(self.valid_until, "valid_until")?;
        if self.valid_from >= self.valid_until {
            return Err(FrostRosterError::InvalidField {
                field: "valid_until",
                detail: "must be greater than valid_from",
            });
        }
        roster_identifier(&self.roster_authority_key_id, "roster_authority_key_id")?;
        validate_fixed_hex(
            &self.roster_authority_signature,
            128,
            "roster_authority_signature",
        )?;
        if self.recompute_roster_id()? != self.roster_id {
            return Err(FrostRosterError::RosterIdMismatch);
        }
        if self.recompute_roster_digest()? != self.roster_digest {
            return Err(FrostRosterError::RosterDigestMismatch);
        }
        Ok(())
    }

    pub fn validate_for_active_resolution(&self) -> Result<(), FrostRosterError> {
        self.validate()?;
        if self.key_origin != FrostRosterKeyOrigin::DistributedDkg {
            return Err(FrostRosterError::ContractMismatch(
                "active rosters must originate from distributed DKG",
            ));
        }
        Ok(())
    }

    fn validate_domains(&self) -> Result<(), FrostRosterError> {
        if self.allowed_domains.is_empty() {
            return Err(FrostRosterError::InvalidField {
                field: "allowed_domains",
                detail: "must not be empty",
            });
        }
        if !self
            .allowed_domains
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
        {
            return Err(FrostRosterError::InvalidField {
                field: "allowed_domains",
                detail: "must be sorted and unique by canonical domain",
            });
        }
        for domain in &self.allowed_domains {
            let registration =
                frost_action_registration(*domain).ok_or(FrostRosterError::InvalidField {
                    field: "allowed_domains",
                    detail: "contains a reserved or unregistered domain",
                })?;
            if registration.quorum_n != self.threshold
                || registration.quorum_m != self.participant_count
                || registration.quorum_scope != self.authority_scope
            {
                return Err(FrostRosterError::ContractMismatch(
                    "allowed domain quorum and authority scope",
                ));
            }
        }
        Ok(())
    }

    fn validate_participants(&self) -> Result<(), FrostRosterError> {
        let mut shares = HashSet::with_capacity(self.participants.len());
        for (index, participant) in self.participants.iter().enumerate() {
            roster_identifier(&participant.participant_id, "participant_id")?;
            if index > 0
                && self.participants[index - 1].participant_id >= participant.participant_id
            {
                return Err(FrostRosterError::InvalidField {
                    field: "participants",
                    detail: "must be sorted by unique participant_id",
                });
            }
            validate_fixed_hex(&participant.verification_share, 64, "verification_share")?;
            if !shares.insert(&participant.verification_share) {
                return Err(FrostRosterError::InvalidField {
                    field: "verification_share",
                    detail: "must be unique",
                });
            }
            VerifyingShare::deserialize(&decode_hex(
                &participant.verification_share,
                "verification_share",
            )?)
            .map_err(|_| FrostRosterError::InvalidField {
                field: "verification_share",
                detail: "must encode a valid FROST Ed25519 verification share",
            })?;
        }
        Ok(())
    }

    fn id_preimage(&self) -> FrostRosterIdPreimage<'_> {
        FrostRosterIdPreimage {
            schema: &self.schema,
            authority_scope: &self.authority_scope,
            scope_id: &self.scope_id,
            allowed_domains: &self.allowed_domains,
            key_epoch: self.key_epoch,
            threshold: self.threshold,
            participant_count: self.participant_count,
            participants: &self.participants,
            group_public_key: &self.group_public_key,
            suite_id: &self.suite_id,
            key_origin: self.key_origin,
            ceremony_transcript_digest: &self.ceremony_transcript_digest,
            predecessor_roster_digest: self.predecessor_roster_digest.as_deref(),
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            roster_authority_key_id: &self.roster_authority_key_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostEpochCheckpointV1 {
    pub schema: String,
    pub anchor_id: String,
    pub checkpoint_digest: String,
    pub scope_id: String,
    pub checkpoint_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
    pub active_roster_id: String,
    pub active_roster_digest: String,
    pub key_epoch: u64,
    pub group_public_key_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_authorization_digest: Option<String>,
    pub activation_fence: u64,
    pub clock_high_water: u64,
    pub anchor_key_id: String,
    pub anchor_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostEpochCheckpointSigningPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    scope_id: &'a str,
    checkpoint_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_digest: Option<&'a str>,
    active_roster_id: &'a str,
    active_roster_digest: &'a str,
    key_epoch: u64,
    group_public_key_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation_authorization_digest: Option<&'a str>,
    activation_fence: u64,
    clock_high_water: u64,
    anchor_key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostEpochCheckpointDigestPreimage<'a> {
    #[serde(flatten)]
    body: FrostEpochCheckpointSigningPreimage<'a>,
    anchor_signature: &'a str,
}

impl FrostEpochCheckpointV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FrostRosterError> {
        canonical_prefixed_bytes(
            CHIO_FROST_EPOCH_CHECKPOINT_SIGNING_PREFIX,
            &self.signing_preimage(),
        )
    }

    pub fn recompute_checkpoint_digest(&self) -> Result<String, FrostRosterError> {
        canonical_digest(
            CHIO_FROST_EPOCH_CHECKPOINT_DIGEST_PREFIX,
            &FrostEpochCheckpointDigestPreimage {
                body: self.signing_preimage(),
                anchor_signature: &self.anchor_signature,
            },
        )
    }

    pub fn validate(&self) -> Result<(), FrostRosterError> {
        if self.schema != CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA {
            return Err(FrostRosterError::UnsupportedSchema(self.schema.clone()));
        }
        roster_identifier(&self.anchor_id, "anchor_id")?;
        roster_digest(&self.checkpoint_digest, "checkpoint_digest")?;
        roster_identifier(&self.scope_id, "scope_id")?;
        roster_positive_safe_integer(self.checkpoint_sequence, "checkpoint_sequence")?;
        match (self.checkpoint_sequence, self.predecessor_digest.as_deref()) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(FrostRosterError::InvalidField {
                    field: "predecessor_digest",
                    detail: "must be absent for the first checkpoint",
                });
            }
            (_, Some(digest)) => roster_digest(digest, "predecessor_digest")?,
            (_, None) => {
                return Err(FrostRosterError::InvalidField {
                    field: "predecessor_digest",
                    detail: "is required after the first checkpoint",
                });
            }
        }
        roster_digest(&self.active_roster_id, "active_roster_id")?;
        roster_digest(&self.active_roster_digest, "active_roster_digest")?;
        roster_positive_safe_integer(self.key_epoch, "key_epoch")?;
        roster_digest(&self.group_public_key_digest, "group_public_key_digest")?;
        match (
            self.key_epoch,
            self.rotation_authorization_digest.as_deref(),
        ) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(FrostRosterError::InvalidField {
                    field: "rotation_authorization_digest",
                    detail: "must be absent for the first key epoch",
                });
            }
            (_, Some(digest)) => roster_digest(digest, "rotation_authorization_digest")?,
            (_, None) => {
                return Err(FrostRosterError::InvalidField {
                    field: "rotation_authorization_digest",
                    detail: "is required after the first key epoch",
                });
            }
        }
        roster_positive_safe_integer(self.activation_fence, "activation_fence")?;
        roster_positive_safe_integer(self.clock_high_water, "clock_high_water")?;
        roster_identifier(&self.anchor_key_id, "anchor_key_id")?;
        validate_fixed_hex(&self.anchor_signature, 128, "anchor_signature")?;
        if self.recompute_checkpoint_digest()? != self.checkpoint_digest {
            return Err(FrostRosterError::InvalidField {
                field: "checkpoint_digest",
                detail: "does not match the canonical signed checkpoint",
            });
        }
        Ok(())
    }

    fn signing_preimage(&self) -> FrostEpochCheckpointSigningPreimage<'_> {
        FrostEpochCheckpointSigningPreimage {
            schema: &self.schema,
            anchor_id: &self.anchor_id,
            scope_id: &self.scope_id,
            checkpoint_sequence: self.checkpoint_sequence,
            predecessor_digest: self.predecessor_digest.as_deref(),
            active_roster_id: &self.active_roster_id,
            active_roster_digest: &self.active_roster_digest,
            key_epoch: self.key_epoch,
            group_public_key_digest: &self.group_public_key_digest,
            rotation_authorization_digest: self.rotation_authorization_digest.as_deref(),
            activation_fence: self.activation_fence,
            clock_high_water: self.clock_high_water,
            anchor_key_id: &self.anchor_key_id,
        }
    }
}

pub trait ActiveFrostRosterResolver: Send + Sync {
    /// Return the candidate signed roster; the caller verifies its pinned authority.
    fn resolve_active_roster(
        &self,
        scope_id: &str,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError>;

    /// Classify a concrete scope using trusted configuration.
    fn classify_scope(&self, scope_id: &str) -> Result<Option<String>, FrostRosterResolutionError>;
}

pub trait FrostHistoricalRosterResolver: Send + Sync {
    /// Return a historical candidate; the caller verifies its pinned authority.
    fn resolve_historical_roster(
        &self,
        roster_digest: &str,
        key_epoch: u64,
        issued_at: u64,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError>;
}

pub trait FrostEpochAnchor: Send + Sync {
    /// Return the current checkpoint from rollback-independent storage.
    ///
    /// The caller verifies its pinned anchor authority and exact roster binding.
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedActiveFrostRoster {
    pub(super) roster: FrostRosterV1,
}

impl VerifiedActiveFrostRoster {
    #[must_use]
    pub fn roster(&self) -> &FrostRosterV1 {
        &self.roster
    }

    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.roster.scope_id
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.roster.key_epoch
    }

    #[must_use]
    pub fn roster_digest(&self) -> &str {
        &self.roster.roster_digest
    }

    #[must_use]
    pub fn participant_verification_share(&self, participant_id: &str) -> Option<&str> {
        self.roster
            .participants
            .iter()
            .find(|participant| participant.participant_id == participant_id)
            .map(|participant| participant.verification_share.as_str())
    }
}

fn canonical_digest<T: Serialize>(prefix: &[u8], value: &T) -> Result<String, FrostRosterError> {
    Ok(sha256_hex(&canonical_prefixed_bytes(prefix, value)?))
}

fn canonical_prefixed_bytes<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<Vec<u8>, FrostRosterError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| FrostRosterError::Canonical(error.to_string()))?;
    let mut bytes = Vec::with_capacity(prefix.len() + canonical.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>, FrostRosterError> {
    hex::decode(value).map_err(|_| FrostRosterError::InvalidField {
        field,
        detail: "must be lowercase hexadecimal",
    })
}

fn validate_fixed_hex(
    value: &str,
    length: usize,
    field: &'static str,
) -> Result<(), FrostRosterError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FrostRosterError::InvalidField {
            field,
            detail: "must have the required lowercase hexadecimal encoding",
        });
    }
    Ok(())
}

fn roster_identifier(value: &str, field: &'static str) -> Result<(), FrostRosterError> {
    validate_identifier(value, field).map_err(|_| FrostRosterError::InvalidField {
        field,
        detail: "must contain only unpadded printable ASCII",
    })
}

fn roster_digest(value: &str, field: &'static str) -> Result<(), FrostRosterError> {
    validate_digest(value, field).map_err(|_| FrostRosterError::InvalidField {
        field,
        detail: "must be 64 lowercase hexadecimal characters",
    })
}

fn roster_positive_safe_integer(value: u64, field: &'static str) -> Result<(), FrostRosterError> {
    validate_positive_safe_integer(value, field).map_err(|_| FrostRosterError::InvalidField {
        field,
        detail: "must be a positive I-JSON safe integer",
    })
}

fn roster_safe_integer(value: u64, field: &'static str) -> Result<(), FrostRosterError> {
    validate_safe_integer(value, field).map_err(|_| FrostRosterError::InvalidField {
        field,
        detail: "must be an I-JSON safe integer",
    })
}
