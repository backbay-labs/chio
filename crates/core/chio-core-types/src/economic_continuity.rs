use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use crate::StoreMutationFence;

mod anchor;
pub use anchor::*;

pub const CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA: &str = "chio.economy.resource-head.v1";
pub const CHIO_ECONOMIC_STATE_BATCH_SCHEMA: &str = "chio.economy.state-batch.v1";
pub const CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA: &str = "chio.economy.effect-slot.v1";
pub const MAX_ECONOMIC_TRANSITIONS: usize = 128;
pub const MAX_ECONOMIC_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_ECONOMIC_INLINE_CONTENT_BYTES: usize = 256 * 1024;
pub const MAX_ECONOMIC_TERMINAL_CONTENT_BYTES: usize = 1024 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REQUEST_ID_BYTES: usize = 2048;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const RESOURCE_HEAD_DIGEST_DOMAIN: &str = "chio.economy.resource-head.digest.v1";
const EFFECT_SLOT_ID_DOMAIN: &str = "chio.economy.effect-slot.id.v1";
const EFFECT_SLOT_DIGEST_DOMAIN: &str = "chio.economy.effect-slot.digest.v1";
const EXPECTED_HEADS_ROOT_DOMAIN: &str = "chio.economy.expected-heads-root.v1";
const NEXT_HEADS_ROOT_DOMAIN: &str = "chio.economy.next-heads-root.v1";
const BATCH_ID_DOMAIN: &str = "chio.economy.state-batch.id.v1";
const BATCH_SIGNING_DOMAIN: &str = "CHIO-ECONOMIC-STATE-BATCH-V1";
const CHECKPOINT_DIGEST_DOMAIN: &str = "chio.economy.state-batch.checkpoint.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicContinuityError {
    UnsupportedSchema {
        field: &'static str,
        value: String,
    },
    EmptyField(&'static str),
    FieldTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidDigest(&'static str),
    InvalidValue {
        field: &'static str,
        reason: String,
    },
    BindingMismatch(&'static str),
    IllegalEffectTransition {
        from: EconomicEffectStateV1,
        to: EconomicEffectStateV1,
    },
    ReplayConflict,
    InvalidSignature,
    Canonicalization(String),
}

impl fmt::Display for EconomicContinuityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { field, value } => {
                write!(formatter, "unsupported economic {field} schema `{value}`")
            }
            Self::EmptyField(field) => write!(formatter, "economic field `{field}` is empty"),
            Self::FieldTooLarge {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "economic field `{field}` is {actual} bytes (maximum {maximum})"
            ),
            Self::InvalidDigest(field) => write!(
                formatter,
                "economic field `{field}` is not a lowercase SHA-256 digest"
            ),
            Self::InvalidValue { field, reason } => {
                write!(formatter, "economic field `{field}` is invalid: {reason}")
            }
            Self::BindingMismatch(field) => {
                write!(formatter, "economic binding mismatch on `{field}`")
            }
            Self::IllegalEffectTransition { from, to } => {
                write!(
                    formatter,
                    "illegal economic effect transition {from:?} -> {to:?}"
                )
            }
            Self::ReplayConflict => write!(
                formatter,
                "economic request replay conflicts with retained truth"
            ),
            Self::InvalidSignature => {
                write!(formatter, "economic state batch signature is invalid")
            }
            Self::Canonicalization(error) => {
                write!(formatter, "economic canonicalization failed: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EconomicContinuityError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicResourceKeyV1 {
    pub resource_family: String,
    pub scope_id: String,
    pub resource_id: String,
}

impl EconomicResourceKeyV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_identifier("resource_family", &self.resource_family)?;
        validate_identifier("scope_id", &self.scope_id)?;
        validate_identifier("resource_id", &self.resource_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "snake_case", deny_unknown_fields)]
pub enum EconomicContentV1 {
    Inline {
        value: Value,
    },
    Available {
        content_ref: String,
        content_sha256: String,
        content_size_bytes: u64,
        availability_receipt: Value,
        availability_receipt_sha256: String,
    },
}

impl EconomicContentV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        self.validate_with_limit(MAX_ECONOMIC_INLINE_CONTENT_BYTES)
    }

    pub fn digest(&self) -> Result<String, EconomicContinuityError> {
        self.validate()?;
        match self {
            Self::Inline { value } => Ok(sha256_hex(&canonical(value)?)),
            Self::Available { content_sha256, .. } => Ok(content_sha256.clone()),
        }
    }

    fn validate_with_limit(&self, maximum: usize) -> Result<(), EconomicContinuityError> {
        match self {
            Self::Inline { value } => {
                let bytes = canonical(value)?;
                if bytes.len() > maximum {
                    return Err(EconomicContinuityError::FieldTooLarge {
                        field: "inline_content",
                        actual: bytes.len(),
                        maximum,
                    });
                }
                Ok(())
            }
            Self::Available {
                content_ref,
                content_sha256,
                content_size_bytes,
                availability_receipt,
                availability_receipt_sha256,
            } => {
                validate_reference("content_ref", content_ref)?;
                validate_digest("content_sha256", content_sha256)?;
                validate_positive("content_size_bytes", *content_size_bytes)?;
                validate_digest("availability_receipt_sha256", availability_receipt_sha256)?;
                let receipt = canonical(availability_receipt)?;
                if receipt.len() > MAX_ECONOMIC_TERMINAL_CONTENT_BYTES {
                    return Err(EconomicContinuityError::FieldTooLarge {
                        field: "availability_receipt",
                        actual: receipt.len(),
                        maximum: MAX_ECONOMIC_TERMINAL_CONTENT_BYTES,
                    });
                }
                if sha256_hex(&receipt) != *availability_receipt_sha256 {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "availability_receipt_sha256",
                    ));
                }
                Ok(())
            }
        }
    }

    fn digest_with_limit(&self, maximum: usize) -> Result<String, EconomicContinuityError> {
        self.validate_with_limit(maximum)?;
        match self {
            Self::Inline { value } => Ok(sha256_hex(&canonical(value)?)),
            Self::Available { content_sha256, .. } => Ok(content_sha256.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicFrostBindingV1 {
    pub authorization_slot_id: String,
    pub authorization_id: String,
    pub action_digest: String,
    pub signed_envelope_digest: String,
}

impl EconomicFrostBindingV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_digest("authorization_slot_id", &self.authorization_slot_id)?;
        validate_digest("authorization_id", &self.authorization_id)?;
        validate_digest("frost_action_digest", &self.action_digest)?;
        validate_digest("signed_envelope_digest", &self.signed_envelope_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicTerminalResultV1 {
    pub result_id: String,
    pub result_digest: String,
    pub result: EconomicContentV1,
}

impl EconomicTerminalResultV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_identifier("terminal_result_id", &self.result_id)?;
        validate_digest("terminal_result_digest", &self.result_digest)?;
        if self
            .result
            .digest_with_limit(MAX_ECONOMIC_TERMINAL_CONTENT_BYTES)?
            != self.result_digest
        {
            return Err(EconomicContinuityError::BindingMismatch(
                "terminal_result_digest",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicResourceHeadV1 {
    pub schema: String,
    pub anchor_id: String,
    pub namespace: String,
    pub resource_key: EconomicResourceKeyV1,
    pub head_version: u64,
    pub resource_version: u64,
    pub lifecycle_fence: u64,
    pub lifecycle_state: String,
    pub state_digest: String,
    pub state: EconomicContentV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frost: Option<EconomicFrostBindingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_result: Option<EconomicTerminalResultV1>,
    pub trusted_clock_high_water: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
}

impl EconomicResourceHeadV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_schema(
            "resource_head",
            &self.schema,
            CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
        )?;
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        self.resource_key.validate()?;
        validate_positive("head_version", self.head_version)?;
        validate_positive("resource_version", self.resource_version)?;
        validate_positive("lifecycle_fence", self.lifecycle_fence)?;
        validate_identifier("lifecycle_state", &self.lifecycle_state)?;
        validate_digest("state_digest", &self.state_digest)?;
        if self.state.digest()? != self.state_digest {
            return Err(EconomicContinuityError::BindingMismatch("state_digest"));
        }
        match (
            self.operation_id.as_deref(),
            self.effect_idempotency_key.as_deref(),
        ) {
            (Some(operation_id), Some(idempotency_key)) => {
                validate_digest("operation_id", operation_id)?;
                validate_digest("effect_idempotency_key", idempotency_key)?;
            }
            (None, None) => {}
            _ => return Err(EconomicContinuityError::BindingMismatch("operation_effect")),
        }
        if let Some(frost) = &self.frost {
            frost.validate()?;
        }
        if let Some(result) = &self.terminal_result {
            result.validate()?;
        }
        validate_positive("trusted_clock_high_water", self.trusted_clock_high_water)?;
        match (self.head_version, self.predecessor_digest.as_deref()) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(invalid(
                    "predecessor_digest",
                    "a genesis head cannot have a predecessor",
                ))
            }
            (_, Some(predecessor)) => validate_digest("predecessor_digest", predecessor)?,
            (_, None) => {
                return Err(invalid(
                    "predecessor_digest",
                    "a successor head requires a predecessor",
                ))
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, EconomicContinuityError> {
        self.validate()?;
        domain_digest(RESOURCE_HEAD_DIGEST_DOMAIN, self)
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), EconomicContinuityError> {
        self.validate()?;
        next.validate()?;
        if self.anchor_id != next.anchor_id {
            return Err(EconomicContinuityError::BindingMismatch("anchor_id"));
        }
        if self.namespace != next.namespace {
            return Err(EconomicContinuityError::BindingMismatch("namespace"));
        }
        if self.resource_key != next.resource_key {
            return Err(EconomicContinuityError::BindingMismatch("resource_key"));
        }
        if self.terminal_result.is_some() {
            return Err(invalid(
                "terminal_result",
                "a terminal resource head cannot advance",
            ));
        }
        let expected_head_version = self
            .head_version
            .checked_add(1)
            .ok_or_else(|| invalid("head_version", "overflow"))?;
        if next.head_version != expected_head_version {
            return Err(invalid("head_version", "must advance by exactly one"));
        }
        if next.resource_version <= self.resource_version {
            return Err(invalid("resource_version", "must advance monotonically"));
        }
        if next.lifecycle_fence < self.lifecycle_fence {
            return Err(invalid("lifecycle_fence", "must not regress"));
        }
        if next.trusted_clock_high_water < self.trusted_clock_high_water {
            return Err(invalid("trusted_clock_high_water", "must not regress"));
        }
        if next.predecessor_digest.as_deref() != Some(self.digest()?.as_str()) {
            return Err(EconomicContinuityError::BindingMismatch(
                "predecessor_digest",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicRequestBindingV1 {
    pub request_namespace_digest: String,
    pub request_id: String,
    pub request_binding_digest: String,
}

impl EconomicRequestBindingV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_digest("request_namespace_digest", &self.request_namespace_digest)?;
        validate_text("request_id", &self.request_id, MAX_REQUEST_ID_BYTES)?;
        validate_digest("request_binding_digest", &self.request_binding_digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicAdmissionHandoffStateV1 {
    DispatchCommitted,
    MutationSubmitted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicAdmissionHandoffV1 {
    pub state: EconomicAdmissionHandoffStateV1,
    pub operation_version: u64,
    pub lifecycle_fence: u64,
    pub store_fence: StoreMutationFence,
}

impl EconomicAdmissionHandoffV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_positive("admission_operation_version", self.operation_version)?;
        validate_positive("admission_lifecycle_fence", self.lifecycle_fence)?;
        validate_text(
            "admission_store_uuid",
            &self.store_fence.store_uuid,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            "admission_store_lease_id",
            &self.store_fence.lease_id,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_positive("admission_store_owner_epoch", self.store_fence.owner_epoch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicEffectTargetV1 {
    pub target_id: String,
    pub target_key_epoch: u64,
    pub qualification_digest: String,
}

impl EconomicEffectTargetV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_identifier("target_id", &self.target_id)?;
        validate_positive("target_key_epoch", self.target_key_epoch)?;
        validate_digest("target_qualification_digest", &self.qualification_digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicEffectStateV1 {
    Ready,
    DispatchCommitted,
    Completed,
    NoEffect,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicNoEffectKindV1 {
    PreDispatch,
    VerifiedTransportNotAccepted,
    PermanentlyNotApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum EconomicEffectTerminalV1 {
    Completed {
        result_id: String,
        result_digest: String,
        result: EconomicContentV1,
    },
    NoEffect {
        kind: EconomicNoEffectKindV1,
        proof_id: String,
        proof_digest: String,
        proof: EconomicContentV1,
    },
}

impl EconomicEffectTerminalV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        match self {
            Self::Completed {
                result_id,
                result_digest,
                result,
            } => {
                validate_identifier("effect_result_id", result_id)?;
                validate_digest("effect_result_digest", result_digest)?;
                if result.digest_with_limit(MAX_ECONOMIC_TERMINAL_CONTENT_BYTES)? != *result_digest
                {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "effect_result_digest",
                    ));
                }
            }
            Self::NoEffect {
                proof_id,
                proof_digest,
                proof,
                ..
            } => {
                validate_identifier("no_effect_proof_id", proof_id)?;
                validate_digest("no_effect_proof_digest", proof_digest)?;
                if proof.digest_with_limit(MAX_ECONOMIC_TERMINAL_CONTENT_BYTES)? != *proof_digest {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "no_effect_proof_digest",
                    ));
                }
            }
        }
        Ok(())
    }

    const fn state(&self) -> EconomicEffectStateV1 {
        match self {
            Self::Completed { .. } => EconomicEffectStateV1::Completed,
            Self::NoEffect { .. } => EconomicEffectStateV1::NoEffect,
        }
    }

    const fn no_effect_kind(&self) -> Option<EconomicNoEffectKindV1> {
        match self {
            Self::Completed { .. } => None,
            Self::NoEffect { kind, .. } => Some(*kind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicEffectSlotV1 {
    pub schema: String,
    pub slot_id: String,
    pub anchor_id: String,
    pub namespace: String,
    pub resource_key: EconomicResourceKeyV1,
    pub operation_id: String,
    pub effect_kind: String,
    pub request: EconomicRequestBindingV1,
    pub admission_handoff: EconomicAdmissionHandoffV1,
    pub target: EconomicEffectTargetV1,
    pub action_digest: String,
    pub parameters_digest: String,
    pub resource_head_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frost: Option<EconomicFrostBindingV1>,
    pub idempotency_key: String,
    pub state: EconomicEffectStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<EconomicEffectTerminalV1>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicEffectSlotIdPreimage<'a> {
    anchor_id: &'a str,
    namespace: &'a str,
    resource_key: &'a EconomicResourceKeyV1,
    operation_id: &'a str,
    effect_kind: &'a str,
}

impl EconomicEffectSlotV1 {
    pub fn recompute_slot_id(&self) -> Result<String, EconomicContinuityError> {
        domain_digest(
            EFFECT_SLOT_ID_DOMAIN,
            &EconomicEffectSlotIdPreimage {
                anchor_id: &self.anchor_id,
                namespace: &self.namespace,
                resource_key: &self.resource_key,
                operation_id: &self.operation_id,
                effect_kind: &self.effect_kind,
            },
        )
    }

    pub fn resource_head_key(&self) -> EconomicResourceKeyV1 {
        EconomicResourceKeyV1 {
            resource_family: "effect_slot".to_string(),
            scope_id: self.resource_key.scope_id.clone(),
            resource_id: self.slot_id.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_schema(
            "effect_slot",
            &self.schema,
            CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        )?;
        validate_digest("effect_slot_id", &self.slot_id)?;
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        self.resource_key.validate()?;
        validate_digest("operation_id", &self.operation_id)?;
        validate_identifier("effect_kind", &self.effect_kind)?;
        self.request.validate()?;
        self.admission_handoff.validate()?;
        self.target.validate()?;
        validate_digest("action_digest", &self.action_digest)?;
        validate_digest("parameters_digest", &self.parameters_digest)?;
        validate_digest("resource_head_digest", &self.resource_head_digest)?;
        if let Some(frost) = &self.frost {
            frost.validate()?;
            if frost.action_digest != self.action_digest {
                return Err(EconomicContinuityError::BindingMismatch(
                    "frost_action_digest",
                ));
            }
        }
        validate_digest("idempotency_key", &self.idempotency_key)?;
        if self.recompute_slot_id()? != self.slot_id {
            return Err(EconomicContinuityError::BindingMismatch("effect_slot_id"));
        }
        match (&self.state, &self.terminal) {
            (
                EconomicEffectStateV1::Ready
                | EconomicEffectStateV1::DispatchCommitted
                | EconomicEffectStateV1::Unknown,
                None,
            ) => {}
            (
                EconomicEffectStateV1::Completed | EconomicEffectStateV1::NoEffect,
                Some(terminal),
            ) if terminal.state() == self.state => {
                terminal.validate()?;
            }
            _ => return Err(EconomicContinuityError::BindingMismatch("effect_terminal")),
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, EconomicContinuityError> {
        self.validate()?;
        domain_digest(EFFECT_SLOT_DIGEST_DOMAIN, self)
    }

    pub fn validate_successor(&self, next: &Self) -> Result<(), EconomicContinuityError> {
        self.validate()?;
        next.validate()?;
        if !self.same_binding(next) {
            return Err(EconomicContinuityError::BindingMismatch(
                "effect_slot_successor",
            ));
        }
        let legal = matches!(
            (self.state, next.state),
            (
                EconomicEffectStateV1::Ready,
                EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::NoEffect
            ) | (
                EconomicEffectStateV1::DispatchCommitted,
                EconomicEffectStateV1::Completed
                    | EconomicEffectStateV1::NoEffect
                    | EconomicEffectStateV1::Unknown
            ) | (
                EconomicEffectStateV1::Unknown,
                EconomicEffectStateV1::Completed | EconomicEffectStateV1::NoEffect
            )
        );
        if !legal {
            return Err(EconomicContinuityError::IllegalEffectTransition {
                from: self.state,
                to: next.state,
            });
        }
        if matches!(
            self.state,
            EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::Unknown
        ) && next
            .terminal
            .as_ref()
            .and_then(EconomicEffectTerminalV1::no_effect_kind)
            == Some(EconomicNoEffectKindV1::PreDispatch)
        {
            return Err(invalid(
                "no_effect_kind",
                "pre-dispatch proof cannot close a post-commit effect",
            ));
        }
        Ok(())
    }

    fn same_binding(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.slot_id == other.slot_id
            && self.anchor_id == other.anchor_id
            && self.namespace == other.namespace
            && self.resource_key == other.resource_key
            && self.operation_id == other.operation_id
            && self.effect_kind == other.effect_kind
            && self.request == other.request
            && self.admission_handoff == other.admission_handoff
            && self.target == other.target
            && self.action_digest == other.action_digest
            && self.parameters_digest == other.parameters_digest
            && self.resource_head_digest == other.resource_head_digest
            && self.frost == other.frost
            && self.idempotency_key == other.idempotency_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicRequestReplayV1 {
    pub request: EconomicRequestBindingV1,
    pub operation_id: String,
    pub effect_slot_ids: Vec<String>,
}

impl EconomicRequestReplayV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        self.request.validate()?;
        validate_digest("replay_operation_id", &self.operation_id)?;
        if self.effect_slot_ids.is_empty() || self.effect_slot_ids.len() > MAX_ECONOMIC_TRANSITIONS
        {
            return Err(invalid(
                "effect_slot_ids",
                format!("must contain 1..={MAX_ECONOMIC_TRANSITIONS} retained effect slots"),
            ));
        }
        validate_sorted_unique_digests("effect_slot_ids", &self.effect_slot_ids)
    }

    pub fn ensure_same_replay(&self, candidate: &Self) -> Result<(), EconomicContinuityError> {
        self.validate()?;
        candidate.validate()?;
        if self == candidate {
            Ok(())
        } else {
            Err(EconomicContinuityError::ReplayConflict)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum EconomicActionAuthorizationV1 {
    Direct,
    NOfM { frost: EconomicFrostBindingV1 },
}

impl EconomicActionAuthorizationV1 {
    fn validate(&self, action_digest: &str) -> Result<(), EconomicContinuityError> {
        match self {
            Self::Direct => Ok(()),
            Self::NOfM { frost } => {
                frost.validate()?;
                if frost.action_digest != action_digest {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "frost_action_digest",
                    ));
                }
                Ok(())
            }
        }
    }

    const fn frost(&self) -> Option<&EconomicFrostBindingV1> {
        match self {
            Self::Direct => None,
            Self::NOfM { frost } => Some(frost),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicPreparedEffectV1 {
    pub operation_id: String,
    pub action_digest: String,
    pub effect_slot_id: String,
    pub effect_slot_digest: String,
    pub authorization: EconomicActionAuthorizationV1,
}

impl EconomicPreparedEffectV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        validate_digest("prepared_effect_operation_id", &self.operation_id)?;
        validate_digest("prepared_effect_action_digest", &self.action_digest)?;
        validate_digest("prepared_effect_slot_id", &self.effect_slot_id)?;
        validate_digest("prepared_effect_slot_digest", &self.effect_slot_digest)?;
        self.authorization.validate(&self.action_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicStateTransitionV1 {
    pub resource_key: EconomicResourceKeyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head_digest: Option<String>,
    pub next_head: EconomicResourceHeadV1,
    pub transition_proof_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_effect: Option<EconomicPreparedEffectV1>,
}

impl EconomicStateTransitionV1 {
    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        self.resource_key.validate()?;
        self.next_head.validate()?;
        if self.resource_key != self.next_head.resource_key {
            return Err(EconomicContinuityError::BindingMismatch(
                "transition_resource_key",
            ));
        }
        match (
            self.expected_head_digest.as_deref(),
            self.next_head.predecessor_digest.as_deref(),
        ) {
            (None, None) if self.next_head.head_version == 1 => {}
            (Some(expected), Some(predecessor)) if expected == predecessor => {
                validate_digest("expected_head_digest", expected)?;
            }
            _ => {
                return Err(EconomicContinuityError::BindingMismatch(
                    "expected_head_digest",
                ))
            }
        }
        validate_digest("transition_proof_digest", &self.transition_proof_digest)?;
        if let Some(effect) = &self.prepared_effect {
            effect.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicStateBatchV1 {
    pub schema: String,
    pub batch_id: String,
    pub checkpoint_digest: String,
    pub anchor_id: String,
    pub namespace: String,
    pub checkpoint_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_digest: Option<String>,
    pub expected_heads_root: String,
    pub next_heads_root: String,
    pub transitions: Vec<EconomicStateTransitionV1>,
    pub effect_slots: Vec<EconomicEffectSlotV1>,
    pub request_replays: Vec<EconomicRequestReplayV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub issued_at: u64,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub anchor_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicBatchIdPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    namespace: &'a str,
    checkpoint_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_checkpoint_digest: Option<&'a str>,
    expected_heads_root: &'a str,
    next_heads_root: &'a str,
    transitions: &'a [EconomicStateTransitionV1],
    effect_slots: &'a [EconomicEffectSlotV1],
    request_replays: &'a [EconomicRequestReplayV1],
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<&'a str>,
    issued_at: u64,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicBatchSigningPreimage<'a> {
    #[serde(flatten)]
    body: EconomicBatchIdPreimage<'a>,
    batch_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EconomicCheckpointPreimage<'a> {
    batch: EconomicBatchSigningPreimage<'a>,
    anchor_signature: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedHeadRootEntry<'a> {
    resource_key: &'a EconomicResourceKeyV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_head_digest: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NextHeadRootEntry<'a> {
    resource_key: &'a EconomicResourceKeyV1,
    next_head_digest: String,
}

impl EconomicStateBatchV1 {
    pub fn seal(&mut self, keypair: &Keypair) -> Result<(), EconomicContinuityError> {
        self.validate_body(false)?;
        self.expected_heads_root = expected_heads_root(&self.transitions)?;
        self.next_heads_root = next_heads_root(&self.transitions)?;
        self.batch_id = self.recompute_batch_id()?;
        self.anchor_signature = keypair.sign(&self.signing_bytes()?).to_hex();
        self.checkpoint_digest = self.recompute_checkpoint_digest()?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), EconomicContinuityError> {
        self.validate_body(true)?;
        validate_digest("batch_id", &self.batch_id)?;
        validate_digest("checkpoint_digest", &self.checkpoint_digest)?;
        validate_fixed_hex("anchor_signature", &self.anchor_signature, 128)?;
        if expected_heads_root(&self.transitions)? != self.expected_heads_root {
            return Err(EconomicContinuityError::BindingMismatch(
                "expected_heads_root",
            ));
        }
        if next_heads_root(&self.transitions)? != self.next_heads_root {
            return Err(EconomicContinuityError::BindingMismatch("next_heads_root"));
        }
        if self.recompute_batch_id()? != self.batch_id {
            return Err(EconomicContinuityError::BindingMismatch("batch_id"));
        }
        if self.recompute_checkpoint_digest()? != self.checkpoint_digest {
            return Err(EconomicContinuityError::BindingMismatch(
                "checkpoint_digest",
            ));
        }
        let bytes = canonical(self)?;
        if bytes.len() > MAX_ECONOMIC_BATCH_BYTES {
            return Err(EconomicContinuityError::FieldTooLarge {
                field: "state_batch",
                actual: bytes.len(),
                maximum: MAX_ECONOMIC_BATCH_BYTES,
            });
        }
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<(), EconomicContinuityError> {
        self.validate()?;
        let signature = Signature::from_hex(&self.anchor_signature)
            .map_err(|_| EconomicContinuityError::InvalidSignature)?;
        if public_key.verify(&self.signing_bytes()?, &signature) {
            Ok(())
        } else {
            Err(EconomicContinuityError::InvalidSignature)
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EconomicContinuityError> {
        self.validate()?;
        canonical(self)
    }

    pub fn recompute_batch_id(&self) -> Result<String, EconomicContinuityError> {
        domain_digest(BATCH_ID_DOMAIN, &self.id_preimage())
    }

    pub fn recompute_checkpoint_digest(&self) -> Result<String, EconomicContinuityError> {
        domain_digest(
            CHECKPOINT_DIGEST_DOMAIN,
            &EconomicCheckpointPreimage {
                batch: self.signing_preimage(),
                anchor_signature: &self.anchor_signature,
            },
        )
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, EconomicContinuityError> {
        prefixed_canonical(BATCH_SIGNING_DOMAIN, &self.signing_preimage())
    }

    fn validate_body(
        &self,
        integrity_fields_required: bool,
    ) -> Result<(), EconomicContinuityError> {
        validate_schema(
            "state_batch",
            &self.schema,
            CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
        )?;
        validate_identifier("anchor_id", &self.anchor_id)?;
        validate_identifier("namespace", &self.namespace)?;
        validate_positive("checkpoint_sequence", self.checkpoint_sequence)?;
        match (
            self.checkpoint_sequence,
            self.previous_checkpoint_digest.as_deref(),
        ) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(invalid(
                    "previous_checkpoint_digest",
                    "a genesis checkpoint cannot have a predecessor",
                ))
            }
            (_, Some(previous)) => validate_digest("previous_checkpoint_digest", previous)?,
            (_, None) => {
                return Err(invalid(
                    "previous_checkpoint_digest",
                    "a successor checkpoint requires a predecessor",
                ))
            }
        }
        if integrity_fields_required {
            validate_digest("expected_heads_root", &self.expected_heads_root)?;
            validate_digest("next_heads_root", &self.next_heads_root)?;
        }
        if self.transitions.is_empty() || self.transitions.len() > MAX_ECONOMIC_TRANSITIONS {
            return Err(invalid(
                "transitions",
                format!("must contain 1..={MAX_ECONOMIC_TRANSITIONS} transitions"),
            ));
        }
        if !self
            .transitions
            .windows(2)
            .all(|pair| pair[0].resource_key < pair[1].resource_key)
        {
            return Err(invalid(
                "transitions",
                "resource keys must be sorted and unique",
            ));
        }
        for transition in &self.transitions {
            transition.validate()?;
            if transition.next_head.anchor_id != self.anchor_id {
                return Err(EconomicContinuityError::BindingMismatch("anchor_id"));
            }
            if transition.next_head.namespace != self.namespace {
                return Err(EconomicContinuityError::BindingMismatch("namespace"));
            }
        }
        if !self
            .effect_slots
            .windows(2)
            .all(|pair| pair[0].slot_id < pair[1].slot_id)
        {
            return Err(invalid(
                "effect_slots",
                "slot ids must be sorted and unique",
            ));
        }
        for slot in &self.effect_slots {
            slot.validate()?;
            if slot.state != EconomicEffectStateV1::Ready || slot.terminal.is_some() {
                return Err(EconomicContinuityError::BindingMismatch(
                    "prepared_effect_slot_state",
                ));
            }
            if slot.anchor_id != self.anchor_id || slot.namespace != self.namespace {
                return Err(EconomicContinuityError::BindingMismatch(
                    "effect_slot_anchor",
                ));
            }
        }
        if !self.request_replays.windows(2).all(|pair| {
            (
                &pair[0].request.request_namespace_digest,
                &pair[0].request.request_id,
            ) < (
                &pair[1].request.request_namespace_digest,
                &pair[1].request.request_id,
            )
        }) {
            return Err(invalid(
                "request_replays",
                "request keys must be sorted and unique",
            ));
        }
        for replay in &self.request_replays {
            replay.validate()?;
        }
        if let Some(operation_id) = self.operation_id.as_deref() {
            validate_digest("batch_operation_id", operation_id)?;
        }
        validate_positive("issued_at", self.issued_at)?;
        validate_identifier("signer_key_id", &self.signer_key_id)?;
        validate_positive("signer_key_epoch", self.signer_key_epoch)?;
        self.validate_operation_binding()?;
        self.validate_effect_bindings()?;
        Ok(())
    }

    fn validate_operation_binding(&self) -> Result<(), EconomicContinuityError> {
        if self.operation_id.is_none() {
            let mut owners = self
                .effect_slots
                .iter()
                .map(|slot| slot.operation_id.as_str())
                .collect::<Vec<_>>();
            owners.sort_unstable();
            owners.dedup();
            if owners.is_empty() {
                if self.transitions.iter().any(|transition| {
                    transition.next_head.operation_id.is_some()
                        || transition.prepared_effect.is_some()
                }) || !self.request_replays.is_empty()
                {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "batch_operation_id",
                    ));
                }
                return Ok(());
            }
            if owners.len() < 2
                || self.effect_slots.iter().any(|slot| {
                    slot.state != EconomicEffectStateV1::Ready || slot.terminal.is_some()
                })
                || self
                    .transitions
                    .iter()
                    .any(|transition| transition.next_head.terminal_result.is_some())
                || self.transitions.iter().any(|transition| {
                    transition
                        .next_head
                        .operation_id
                        .as_deref()
                        .is_some_and(|operation_id| owners.binary_search(&operation_id).is_err())
                        || transition.prepared_effect.as_ref().is_some_and(|effect| {
                            owners.binary_search(&effect.operation_id.as_str()).is_err()
                        })
                })
                || self
                    .request_replays
                    .iter()
                    .any(|replay| owners.binary_search(&replay.operation_id.as_str()).is_err())
            {
                return Err(EconomicContinuityError::BindingMismatch(
                    "batch_operation_id",
                ));
            }
            return Ok(());
        }
        for transition in &self.transitions {
            if let Some(operation_id) = transition.next_head.operation_id.as_deref() {
                if self.operation_id.as_deref() != Some(operation_id) {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "batch_operation_id",
                    ));
                }
            }
            if let Some(effect) = &transition.prepared_effect {
                if self.operation_id.as_deref() != Some(effect.operation_id.as_str()) {
                    return Err(EconomicContinuityError::BindingMismatch(
                        "prepared_effect_operation_id",
                    ));
                }
            }
        }
        for slot in &self.effect_slots {
            if self.operation_id.as_deref() != Some(slot.operation_id.as_str()) {
                return Err(EconomicContinuityError::BindingMismatch(
                    "effect_slot_operation_id",
                ));
            }
        }
        for replay in &self.request_replays {
            if self.operation_id.as_deref() != Some(replay.operation_id.as_str()) {
                return Err(EconomicContinuityError::BindingMismatch(
                    "replay_operation_id",
                ));
            }
        }
        Ok(())
    }

    fn validate_effect_bindings(&self) -> Result<(), EconomicContinuityError> {
        let prepared = self
            .transitions
            .iter()
            .filter_map(|transition| transition.prepared_effect.as_ref())
            .collect::<Vec<_>>();
        if prepared.len() != self.effect_slots.len() {
            return Err(EconomicContinuityError::BindingMismatch(
                "prepared_effect_count",
            ));
        }
        let mut prepared_slot_ids = prepared
            .iter()
            .map(|effect| effect.effect_slot_id.as_str())
            .collect::<Vec<_>>();
        prepared_slot_ids.sort_unstable();
        let effect_slot_ids = self
            .effect_slots
            .iter()
            .map(|slot| slot.slot_id.as_str())
            .collect::<Vec<_>>();
        if prepared_slot_ids != effect_slot_ids {
            return Err(EconomicContinuityError::BindingMismatch(
                "prepared_effect_slot_set",
            ));
        }
        for effect in prepared {
            let slot = self
                .effect_slots
                .iter()
                .find(|slot| slot.slot_id == effect.effect_slot_id)
                .ok_or(EconomicContinuityError::BindingMismatch(
                    "prepared_effect_slot_id",
                ))?;
            if slot.digest()? != effect.effect_slot_digest
                || slot.operation_id != effect.operation_id
                || slot.action_digest != effect.action_digest
                || slot.frost.as_ref() != effect.authorization.frost()
            {
                return Err(EconomicContinuityError::BindingMismatch(
                    "prepared_effect_slot",
                ));
            }
            let owner_transition = self
                .transitions
                .iter()
                .find(|transition| transition.prepared_effect.as_ref() == Some(effect))
                .ok_or(EconomicContinuityError::BindingMismatch(
                    "prepared_effect_owner",
                ))?;
            let binds_resource_head = owner_transition.next_head.digest()?
                == slot.resource_head_digest
                || owner_transition.expected_head_digest.as_deref()
                    == Some(slot.resource_head_digest.as_str());
            if owner_transition.resource_key != slot.resource_key
                || !binds_resource_head
                || owner_transition.next_head.operation_id.as_deref()
                    != Some(slot.operation_id.as_str())
                || owner_transition.next_head.effect_idempotency_key.as_deref()
                    != Some(slot.idempotency_key.as_str())
                || owner_transition.next_head.frost.as_ref() != slot.frost.as_ref()
            {
                return Err(EconomicContinuityError::BindingMismatch(
                    "prepared_effect_resource_head",
                ));
            }
            let slot_transition = self
                .transitions
                .iter()
                .find(|transition| transition.resource_key == slot.resource_head_key())
                .ok_or(EconomicContinuityError::BindingMismatch(
                    "effect_slot_resource_head",
                ))?;
            let EconomicContentV1::Inline { value } = &slot_transition.next_head.state else {
                return Err(EconomicContinuityError::BindingMismatch(
                    "effect_slot_retained_state",
                ));
            };
            let expected_value = serde_json::to_value(slot)
                .map_err(|error| EconomicContinuityError::Canonicalization(error.to_string()))?;
            if value != &expected_value
                || slot_transition.next_head.lifecycle_state != "ready"
                || slot_transition.next_head.operation_id.as_deref()
                    != Some(slot.operation_id.as_str())
                || slot_transition.next_head.effect_idempotency_key.as_deref()
                    != Some(slot.idempotency_key.as_str())
                || slot_transition.next_head.frost.as_ref() != slot.frost.as_ref()
            {
                return Err(EconomicContinuityError::BindingMismatch(
                    "effect_slot_resource_head",
                ));
            }
            let replays = self
                .request_replays
                .iter()
                .filter(|replay| replay.effect_slot_ids.binary_search(&slot.slot_id).is_ok())
                .collect::<Vec<_>>();
            if replays.len() != 1
                || replays[0].request != slot.request
                || replays[0].operation_id != slot.operation_id
            {
                return Err(EconomicContinuityError::BindingMismatch(
                    "effect_slot_request_replay",
                ));
            }
        }
        let mapped_slot_count = self
            .request_replays
            .iter()
            .map(|replay| replay.effect_slot_ids.len())
            .sum::<usize>();
        if mapped_slot_count != self.effect_slots.len() {
            return Err(EconomicContinuityError::BindingMismatch(
                "request_replay_slot_count",
            ));
        }
        Ok(())
    }

    fn id_preimage(&self) -> EconomicBatchIdPreimage<'_> {
        EconomicBatchIdPreimage {
            schema: &self.schema,
            anchor_id: &self.anchor_id,
            namespace: &self.namespace,
            checkpoint_sequence: self.checkpoint_sequence,
            previous_checkpoint_digest: self.previous_checkpoint_digest.as_deref(),
            expected_heads_root: &self.expected_heads_root,
            next_heads_root: &self.next_heads_root,
            transitions: &self.transitions,
            effect_slots: &self.effect_slots,
            request_replays: &self.request_replays,
            operation_id: self.operation_id.as_deref(),
            issued_at: self.issued_at,
            signer_key_id: &self.signer_key_id,
            signer_key_epoch: self.signer_key_epoch,
        }
    }

    fn signing_preimage(&self) -> EconomicBatchSigningPreimage<'_> {
        EconomicBatchSigningPreimage {
            body: self.id_preimage(),
            batch_id: &self.batch_id,
        }
    }
}

pub fn expected_heads_root(
    transitions: &[EconomicStateTransitionV1],
) -> Result<String, EconomicContinuityError> {
    let entries = transitions
        .iter()
        .map(|transition| ExpectedHeadRootEntry {
            resource_key: &transition.resource_key,
            expected_head_digest: transition.expected_head_digest.as_deref(),
        })
        .collect::<Vec<_>>();
    domain_digest(EXPECTED_HEADS_ROOT_DOMAIN, &entries)
}

pub fn next_heads_root(
    transitions: &[EconomicStateTransitionV1],
) -> Result<String, EconomicContinuityError> {
    let entries = transitions
        .iter()
        .map(|transition| {
            Ok(NextHeadRootEntry {
                resource_key: &transition.resource_key,
                next_head_digest: transition.next_head.digest()?,
            })
        })
        .collect::<Result<Vec<_>, EconomicContinuityError>>()?;
    domain_digest(NEXT_HEADS_ROOT_DOMAIN, &entries)
}

fn validate_schema(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), EconomicContinuityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(EconomicContinuityError::UnsupportedSchema {
            field,
            value: actual.to_string(),
        })
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), EconomicContinuityError> {
    validate_text(field, value, MAX_IDENTIFIER_BYTES)?;
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
    }) {
        Ok(())
    } else {
        Err(invalid(
            field,
            "must contain only portable identifier characters",
        ))
    }
}

fn validate_reference(field: &'static str, value: &str) -> Result<(), EconomicContinuityError> {
    validate_text(field, value, MAX_REQUEST_ID_BYTES)
}

fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), EconomicContinuityError> {
    if value.is_empty() {
        return Err(EconomicContinuityError::EmptyField(field));
    }
    if value.len() > maximum {
        return Err(EconomicContinuityError::FieldTooLarge {
            field,
            actual: value.len(),
            maximum,
        });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(invalid(
            field,
            "must be trimmed and contain no control characters",
        ));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), EconomicContinuityError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(EconomicContinuityError::InvalidDigest(field))
    }
}

fn validate_fixed_hex(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<(), EconomicContinuityError> {
    if value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(
            field,
            format!("must be {expected_len} lowercase hex characters"),
        ))
    }
}

fn validate_positive(field: &'static str, value: u64) -> Result<(), EconomicContinuityError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(invalid(field, "must be a positive I-JSON safe integer"))
    } else {
        Ok(())
    }
}

fn validate_sorted_unique_digests(
    field: &'static str,
    values: &[String],
) -> Result<(), EconomicContinuityError> {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid(field, "must be sorted and unique"));
    }
    for value in values {
        validate_digest(field, value)?;
    }
    Ok(())
}

fn invalid(field: &'static str, reason: impl Into<String>) -> EconomicContinuityError {
    EconomicContinuityError::InvalidValue {
        field,
        reason: reason.into(),
    }
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, EconomicContinuityError> {
    canonical_json_bytes(value)
        .map_err(|error| EconomicContinuityError::Canonicalization(error.to_string()))
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, EconomicContinuityError> {
    Ok(sha256_hex(&prefixed_canonical(domain, value)?))
}

fn prefixed_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Vec<u8>, EconomicContinuityError> {
    let canonical = canonical(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
