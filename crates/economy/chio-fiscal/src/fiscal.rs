use std::collections::HashSet;

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey, SigningAlgorithm};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fee_schedule::OpenMarketFeeScheduleArtifact;

pub const FISCAL_CHARTER_SCHEMA: &str = "chio.fiscal.charter.v1";
pub const FISCAL_SCHEDULE_SCHEMA: &str = "chio.fiscal.schedule.v1";
pub const FISCAL_CHARTER_ID_DOMAIN: &str = "chio.fiscal.charter.id.v1";
pub const FISCAL_SCHEDULE_ID_DOMAIN: &str = "chio.fiscal.schedule.id.v1";
pub const MAX_SIGNED_FISCAL_CHARTER_BYTES: usize = 1_048_576;
pub const MAX_SIGNED_FISCAL_SCHEDULE_BYTES: usize = 1_048_576;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FiscalError {
    #[error("fiscal canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("invalid fiscal field: {0}")]
    InvalidField(&'static str),
    #[error("invalid fiscal artifact: {0}")]
    InvalidArtifact(String),
    #[error("unsupported fiscal schema: {0}")]
    UnknownSchema(String),
    #[error("fiscal artifact signature is invalid")]
    InvalidSignature,
    #[error("fiscal artifact self id is invalid")]
    InvalidSelfId,
    #[error("fiscal charter binding is invalid")]
    InvalidCharterBinding,
    #[error("fiscal schedule lineage is invalid")]
    InvalidLineage,
    #[error("unsupported fiscal signer algorithm")]
    UnsupportedSignerAlgorithm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FiscalDomain {
    TierLimits,
    MarketplaceDiscountPerHundred,
    DecisionPremiumBasisPoints,
    InsurancePremiumSchedule,
    OpenMarketFeeAndBondSchedule,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalSigner {
    pub key_id: String,
    pub public_key: PublicKey,
}

impl FiscalSigner {
    pub fn new(public_key: PublicKey) -> Result<Self, FiscalError> {
        let key_id = fiscal_signer_key_id(&public_key)?;
        Ok(Self { key_id, public_key })
    }

    pub fn validate(&self) -> Result<(), FiscalError> {
        if !is_sha256_hex(&self.key_id) {
            return Err(FiscalError::InvalidField("signer_set.key_id"));
        }
        if self.key_id != fiscal_signer_key_id(&self.public_key)? {
            return Err(FiscalError::InvalidField("signer_set.key_id_binding"));
        }
        Ok(())
    }
}

pub fn fiscal_signer_key_id(public_key: &PublicKey) -> Result<String, FiscalError> {
    let raw = match public_key.algorithm() {
        SigningAlgorithm::Ed25519 => public_key.as_bytes().to_vec(),
        SigningAlgorithm::P256 => decode_prefixed_key(public_key, "p256:")?,
        SigningAlgorithm::P384 => decode_prefixed_key(public_key, "p384:")?,
        SigningAlgorithm::Hybrid => return Err(FiscalError::UnsupportedSignerAlgorithm),
    };
    Ok(sha256_hex(&raw))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FiscalParams {
    TierLimits {
        ceilings: [MonetaryAmount; 4],
    },
    MarketplaceDiscountPerHundred {
        discounts: [u32; 4],
    },
    DecisionPremiumBasisPoints {
        approve: [u32; 4],
        reduce_ceiling: [u32; 4],
    },
    InsurancePremiumSchedule {
        decline_floor: u32,
        high_risk_floor: u32,
        medium_risk_floor: u32,
        low_risk_floor: u32,
        score_adjustments_bps: [u32; 3],
        behavioral_threshold: f64,
        behavioral_penalty_per_sigma: u32,
        behavioral_penalty_cap: u32,
    },
    OpenMarketFeeAndBondSchedule {
        legacy_body: Box<OpenMarketFeeScheduleArtifact>,
    },
}

impl FiscalParams {
    #[must_use]
    pub const fn domain(&self) -> FiscalDomain {
        match self {
            Self::TierLimits { .. } => FiscalDomain::TierLimits,
            Self::MarketplaceDiscountPerHundred { .. } => {
                FiscalDomain::MarketplaceDiscountPerHundred
            }
            Self::DecisionPremiumBasisPoints { .. } => FiscalDomain::DecisionPremiumBasisPoints,
            Self::InsurancePremiumSchedule { .. } => FiscalDomain::InsurancePremiumSchedule,
            Self::OpenMarketFeeAndBondSchedule { .. } => FiscalDomain::OpenMarketFeeAndBondSchedule,
        }
    }

    pub fn validate(&self) -> Result<(), FiscalError> {
        match self {
            Self::TierLimits { ceilings } => validate_tier_limits(ceilings),
            Self::MarketplaceDiscountPerHundred { discounts } => {
                if discounts.iter().any(|value| *value > 100) {
                    return Err(FiscalError::InvalidField("params.discounts.range"));
                }
                validate_nondecreasing(discounts, "params.discounts.order")
            }
            Self::DecisionPremiumBasisPoints {
                approve,
                reduce_ceiling,
            } => {
                validate_nondecreasing(approve, "params.approve.order")?;
                validate_nondecreasing(reduce_ceiling, "params.reduce_ceiling.order")?;
                if approve
                    .iter()
                    .zip(reduce_ceiling)
                    .any(|(approve, reduce)| reduce < approve)
                {
                    return Err(FiscalError::InvalidField("params.reduce_ceiling.minimum"));
                }
                Ok(())
            }
            Self::InsurancePremiumSchedule {
                decline_floor,
                high_risk_floor,
                medium_risk_floor,
                low_risk_floor,
                score_adjustments_bps,
                behavioral_threshold,
                ..
            } => {
                if decline_floor != high_risk_floor
                    || high_risk_floor > medium_risk_floor
                    || medium_risk_floor > low_risk_floor
                    || *low_risk_floor > 1000
                {
                    return Err(FiscalError::InvalidField("params.premium_floors"));
                }
                validate_nondecreasing(
                    score_adjustments_bps,
                    "params.score_adjustments_bps.order",
                )?;
                if !behavioral_threshold.is_finite() || *behavioral_threshold < 0.0 {
                    return Err(FiscalError::InvalidField("params.behavioral_threshold"));
                }
                Ok(())
            }
            Self::OpenMarketFeeAndBondSchedule { legacy_body } => {
                legacy_body.validate().map_err(FiscalError::InvalidArtifact)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalCharter {
    pub schema: String,
    pub charter_id: String,
    pub governing_operator_id: String,
    pub governed_domains: Vec<FiscalDomain>,
    pub signer_set: Vec<FiscalSigner>,
    pub approval_threshold: u32,
    pub timelock_seconds: u64,
    pub proposal_ttl_seconds: u64,
    pub approval_ttl_seconds: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issued_by: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_charter_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalCharterIdPreimage<'a> {
    schema: &'a str,
    governing_operator_id: &'a str,
    governed_domains: &'a [FiscalDomain],
    signer_set: &'a [FiscalSigner],
    approval_threshold: u32,
    timelock_seconds: u64,
    proposal_ttl_seconds: u64,
    approval_ttl_seconds: u64,
    issued_at: u64,
    expires_at: u64,
    issued_by: &'a str,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_charter_digest: &'a Option<String>,
}

impl FiscalCharter {
    pub fn validate(&self) -> Result<(), FiscalError> {
        if self.schema != FISCAL_CHARTER_SCHEMA {
            return Err(FiscalError::UnknownSchema(self.schema.clone()));
        }
        validate_non_empty(&self.governing_operator_id, "governing_operator_id")?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        if self.governed_domains.is_empty() {
            return Err(FiscalError::InvalidField("governed_domains"));
        }
        if self
            .governed_domains
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(FiscalError::InvalidField("governed_domains.order"));
        }
        if self.signer_set.is_empty() {
            return Err(FiscalError::InvalidField("signer_set"));
        }
        let mut public_keys = HashSet::with_capacity(self.signer_set.len());
        for signer in &self.signer_set {
            signer.validate()?;
            if !public_keys.insert(signer.public_key.to_hex()) {
                return Err(FiscalError::InvalidField("signer_set.public_key_unique"));
            }
        }
        if self
            .signer_set
            .windows(2)
            .any(|pair| pair[0].key_id >= pair[1].key_id)
        {
            return Err(FiscalError::InvalidField("signer_set.order"));
        }
        let signer_count = u32::try_from(self.signer_set.len())
            .map_err(|_| FiscalError::InvalidField("signer_set.size"))?;
        if self.approval_threshold == 0 || self.approval_threshold > signer_count {
            return Err(FiscalError::InvalidField("approval_threshold"));
        }
        if self.timelock_seconds == 0
            || self.proposal_ttl_seconds == 0
            || self.approval_ttl_seconds == 0
        {
            return Err(FiscalError::InvalidField("durations"));
        }
        if self.proposal_ttl_seconds <= self.timelock_seconds {
            return Err(FiscalError::InvalidField("proposal_ttl_seconds"));
        }
        if self.expires_at <= self.issued_at {
            return Err(FiscalError::InvalidField("expires_at"));
        }
        match (self.sequence, &self.predecessor_charter_digest) {
            (1, None) => {}
            (2.., Some(digest)) if is_sha256_hex(digest) => {}
            _ => return Err(FiscalError::InvalidLineage),
        }
        if !is_sha256_hex(&self.charter_id) || self.charter_id != self.expected_id()? {
            return Err(FiscalError::InvalidSelfId);
        }
        Ok(())
    }

    pub fn expected_id(&self) -> Result<String, FiscalError> {
        let preimage = FiscalCharterIdPreimage {
            schema: &self.schema,
            governing_operator_id: &self.governing_operator_id,
            governed_domains: &self.governed_domains,
            signer_set: &self.signer_set,
            approval_threshold: self.approval_threshold,
            timelock_seconds: self.timelock_seconds,
            proposal_ttl_seconds: self.proposal_ttl_seconds,
            approval_ttl_seconds: self.approval_ttl_seconds,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            issued_by: &self.issued_by,
            sequence: self.sequence,
            predecessor_charter_digest: &self.predecessor_charter_digest,
        };
        domain_digest(FISCAL_CHARTER_ID_DOMAIN, &preimage)
    }
}

pub type SignedFiscalCharter = SignedExportEnvelope<FiscalCharter>;

#[derive(Debug, Clone)]
pub struct FiscalCharterBuilder {
    pub governing_operator_id: String,
    pub governed_domains: Vec<FiscalDomain>,
    pub signer_keys: Vec<PublicKey>,
    pub approval_threshold: u32,
    pub timelock_seconds: u64,
    pub proposal_ttl_seconds: u64,
    pub approval_ttl_seconds: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issued_by: String,
    pub sequence: u64,
    pub predecessor_charter_digest: Option<String>,
}

impl FiscalCharterBuilder {
    pub fn build_body(mut self) -> Result<FiscalCharter, FiscalError> {
        self.governed_domains.sort_unstable();
        self.governed_domains.dedup();
        let mut signer_set = self
            .signer_keys
            .into_iter()
            .map(FiscalSigner::new)
            .collect::<Result<Vec<_>, _>>()?;
        signer_set.sort_unstable_by(|left, right| left.key_id.cmp(&right.key_id));
        if signer_set
            .windows(2)
            .any(|pair| pair[0].key_id == pair[1].key_id)
        {
            return Err(FiscalError::InvalidField("signer_set.unique"));
        }
        let mut body = FiscalCharter {
            schema: FISCAL_CHARTER_SCHEMA.to_string(),
            charter_id: String::new(),
            governing_operator_id: self.governing_operator_id,
            governed_domains: self.governed_domains,
            signer_set,
            approval_threshold: self.approval_threshold,
            timelock_seconds: self.timelock_seconds,
            proposal_ttl_seconds: self.proposal_ttl_seconds,
            approval_ttl_seconds: self.approval_ttl_seconds,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            issued_by: self.issued_by,
            sequence: self.sequence,
            predecessor_charter_digest: self.predecessor_charter_digest,
        };
        body.charter_id = body.expected_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn sign(self, keypair: &Keypair) -> Result<SignedFiscalCharter, FiscalError> {
        SignedFiscalCharter::sign(self.build_body()?, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalCharter {
    signed: SignedFiscalCharter,
    digest: String,
}

impl VerifiedFiscalCharter {
    pub fn verify(signed: SignedFiscalCharter) -> Result<Self, FiscalError> {
        signed.body.validate()?;
        if !signed
            .verify_signature()
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?
        {
            return Err(FiscalError::InvalidSignature);
        }
        let bytes = canonical_json_bytes(&signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        if bytes.len() > MAX_SIGNED_FISCAL_CHARTER_BYTES {
            return Err(FiscalError::InvalidField("signed_charter.size"));
        }
        Ok(Self {
            digest: sha256_hex(&bytes),
            signed,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_FISCAL_CHARTER_BYTES {
            return Err(FiscalError::InvalidField("signed_charter.size"));
        }
        let signed: SignedFiscalCharter = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "signed fiscal charter is not canonical".to_string(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalCharter {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalCharter {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalSchedule {
    pub schema: String,
    pub schedule_id: String,
    pub charter_id: String,
    pub charter_digest: String,
    pub domain: FiscalDomain,
    pub params: FiscalParams,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_schedule_id: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_at: u64,
    pub issued_by: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalScheduleIdPreimage<'a> {
    schema: &'a str,
    charter_id: &'a str,
    charter_digest: &'a str,
    domain: FiscalDomain,
    params: &'a FiscalParams,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes_schedule_id: &'a Option<String>,
    valid_from: u64,
    valid_until: u64,
    issued_at: u64,
    issued_by: &'a str,
}

impl FiscalSchedule {
    pub fn validate_against(&self, charter: &VerifiedFiscalCharter) -> Result<(), FiscalError> {
        if self.schema != FISCAL_SCHEDULE_SCHEMA {
            return Err(FiscalError::UnknownSchema(self.schema.clone()));
        }
        if self.charter_id != charter.body().charter_id || self.charter_digest != charter.digest() {
            return Err(FiscalError::InvalidCharterBinding);
        }
        if self.domain != self.params.domain()
            || charter
                .body()
                .governed_domains
                .binary_search(&self.domain)
                .is_err()
        {
            return Err(FiscalError::InvalidField("domain"));
        }
        self.params.validate()?;
        validate_non_empty(&self.issued_by, "issued_by")?;
        if self.valid_until <= self.valid_from
            || self.issued_at > self.valid_from
            || self.issued_at < charter.body().issued_at
            || self.valid_until > charter.body().expires_at
        {
            return Err(FiscalError::InvalidField("schedule.validity"));
        }
        match (self.sequence, &self.supersedes_schedule_id) {
            (1, None) => {}
            (2.., Some(id)) if is_sha256_hex(id) => {}
            _ => return Err(FiscalError::InvalidLineage),
        }
        if let FiscalParams::OpenMarketFeeAndBondSchedule { legacy_body } = &self.params {
            if legacy_body.governing_operator_id != charter.body().governing_operator_id
                || legacy_body.issued_at != self.valid_from
                || legacy_body.expires_at != Some(self.valid_until)
            {
                return Err(FiscalError::InvalidField("params.open_market_binding"));
            }
        }
        if !is_sha256_hex(&self.schedule_id) || self.schedule_id != self.expected_id()? {
            return Err(FiscalError::InvalidSelfId);
        }
        Ok(())
    }

    pub fn expected_id(&self) -> Result<String, FiscalError> {
        let preimage = FiscalScheduleIdPreimage {
            schema: &self.schema,
            charter_id: &self.charter_id,
            charter_digest: &self.charter_digest,
            domain: self.domain,
            params: &self.params,
            sequence: self.sequence,
            supersedes_schedule_id: &self.supersedes_schedule_id,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            issued_at: self.issued_at,
            issued_by: &self.issued_by,
        };
        domain_digest(FISCAL_SCHEDULE_ID_DOMAIN, &preimage)
    }
}

pub type SignedFiscalSchedule = SignedExportEnvelope<FiscalSchedule>;

#[derive(Debug, Clone)]
pub struct FiscalScheduleBuilder {
    pub domain: FiscalDomain,
    pub params: FiscalParams,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_at: u64,
    pub issued_by: String,
}

impl FiscalScheduleBuilder {
    pub fn build_body(
        self,
        charter: &VerifiedFiscalCharter,
        predecessor: Option<&VerifiedFiscalSchedule>,
    ) -> Result<FiscalSchedule, FiscalError> {
        self.build_successor_body(charter, predecessor, false)
    }

    pub fn build_rotation_replacement(
        self,
        successor_charter: &VerifiedFiscalCharter,
        predecessor: &VerifiedFiscalSchedule,
    ) -> Result<FiscalSchedule, FiscalError> {
        self.build_successor_body(successor_charter, Some(predecessor), true)
    }

    fn build_successor_body(
        self,
        charter: &VerifiedFiscalCharter,
        predecessor: Option<&VerifiedFiscalSchedule>,
        charter_rotation: bool,
    ) -> Result<FiscalSchedule, FiscalError> {
        self.params.validate()?;
        if self.domain != self.params.domain() {
            return Err(FiscalError::InvalidField("domain"));
        }
        let (sequence, supersedes_schedule_id) = match predecessor {
            None => (1, None),
            Some(previous) => {
                if previous.body().domain != self.domain
                    || !schedule_charter_accepts_predecessor(charter, previous, charter_rotation)
                {
                    return Err(FiscalError::InvalidLineage);
                }
                (
                    previous
                        .body()
                        .sequence
                        .checked_add(1)
                        .ok_or(FiscalError::InvalidLineage)?,
                    Some(previous.body().schedule_id.clone()),
                )
            }
        };
        let mut body = FiscalSchedule {
            schema: FISCAL_SCHEDULE_SCHEMA.to_string(),
            schedule_id: String::new(),
            charter_id: charter.body().charter_id.clone(),
            charter_digest: charter.digest().to_string(),
            domain: self.domain,
            params: self.params,
            sequence,
            supersedes_schedule_id,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            issued_at: self.issued_at,
            issued_by: self.issued_by,
        };
        body.schedule_id = body.expected_id()?;
        body.validate_against(charter)?;
        Ok(body)
    }

    pub fn sign(
        self,
        charter: &VerifiedFiscalCharter,
        predecessor: Option<&VerifiedFiscalSchedule>,
        keypair: &Keypair,
    ) -> Result<SignedFiscalSchedule, FiscalError> {
        SignedFiscalSchedule::sign(self.build_body(charter, predecessor)?, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    pub fn sign_rotation_replacement(
        self,
        successor_charter: &VerifiedFiscalCharter,
        predecessor: &VerifiedFiscalSchedule,
        keypair: &Keypair,
    ) -> Result<SignedFiscalSchedule, FiscalError> {
        SignedFiscalSchedule::sign(
            self.build_rotation_replacement(successor_charter, predecessor)?,
            keypair,
        )
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalSchedule {
    signed: SignedFiscalSchedule,
}

impl VerifiedFiscalSchedule {
    pub fn verify(
        signed: SignedFiscalSchedule,
        charter: &VerifiedFiscalCharter,
        predecessor: Option<&VerifiedFiscalSchedule>,
    ) -> Result<Self, FiscalError> {
        signed.body.validate_against(charter)?;
        verify_schedule_lineage(&signed.body, charter, predecessor, false)?;
        Self::finish_verification(signed)
    }

    pub fn verify_rotation_replacement(
        signed: SignedFiscalSchedule,
        successor_charter: &VerifiedFiscalCharter,
        predecessor: &VerifiedFiscalSchedule,
    ) -> Result<Self, FiscalError> {
        signed.body.validate_against(successor_charter)?;
        verify_schedule_lineage(&signed.body, successor_charter, Some(predecessor), true)?;
        Self::finish_verification(signed)
    }

    fn finish_verification(signed: SignedFiscalSchedule) -> Result<Self, FiscalError> {
        if !signed
            .verify_signature()
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?
        {
            return Err(FiscalError::InvalidSignature);
        }
        let bytes = canonical_json_bytes(&signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        if bytes.len() > MAX_SIGNED_FISCAL_SCHEDULE_BYTES {
            return Err(FiscalError::InvalidField("signed_schedule.size"));
        }
        Ok(Self { signed })
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        charter: &VerifiedFiscalCharter,
        predecessor: Option<&VerifiedFiscalSchedule>,
    ) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_FISCAL_SCHEDULE_BYTES {
            return Err(FiscalError::InvalidField("signed_schedule.size"));
        }
        let signed: SignedFiscalSchedule = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed, charter, predecessor)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "signed fiscal schedule is not canonical".to_string(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalSchedule {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalSchedule {
        &self.signed
    }
}

fn verify_schedule_lineage(
    schedule: &FiscalSchedule,
    charter: &VerifiedFiscalCharter,
    predecessor: Option<&VerifiedFiscalSchedule>,
    charter_rotation: bool,
) -> Result<(), FiscalError> {
    match predecessor {
        None => {
            if schedule.sequence != 1 || schedule.supersedes_schedule_id.is_some() {
                return Err(FiscalError::InvalidLineage);
            }
        }
        Some(previous) => {
            let expected_sequence = previous
                .body()
                .sequence
                .checked_add(1)
                .ok_or(FiscalError::InvalidLineage)?;
            if schedule.domain != previous.body().domain
                || !schedule_charter_accepts_predecessor(charter, previous, charter_rotation)
                || schedule.sequence != expected_sequence
                || schedule.supersedes_schedule_id.as_deref()
                    != Some(previous.body().schedule_id.as_str())
            {
                return Err(FiscalError::InvalidLineage);
            }
        }
    }
    Ok(())
}

fn schedule_charter_accepts_predecessor(
    charter: &VerifiedFiscalCharter,
    predecessor: &VerifiedFiscalSchedule,
    charter_rotation: bool,
) -> bool {
    (predecessor.body().charter_id == charter.body().charter_id
        && predecessor.body().charter_digest == charter.digest())
        || (charter_rotation
            && charter.body().predecessor_charter_digest.as_deref()
                == Some(predecessor.body().charter_digest.as_str()))
}

fn validate_tier_limits(ceilings: &[MonetaryAmount; 4]) -> Result<(), FiscalError> {
    let currency = ceilings[0].currency.as_str();
    if !is_iso_currency(currency) || ceilings.iter().any(|ceiling| ceiling.currency != currency) {
        return Err(FiscalError::InvalidField("params.ceilings.currency"));
    }
    if ceilings
        .windows(2)
        .any(|pair| pair[0].units > pair[1].units)
    {
        return Err(FiscalError::InvalidField("params.ceilings.order"));
    }
    Ok(())
}

fn validate_nondecreasing<T: PartialOrd>(
    values: &[T],
    field: &'static str,
) -> Result<(), FiscalError> {
    if values.windows(2).any(|pair| pair[0] > pair[1]) {
        Err(FiscalError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_non_empty(value: &str, field: &'static str) -> Result<(), FiscalError> {
    if value.trim().is_empty() {
        Err(FiscalError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn is_iso_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, FiscalError> {
    canonical_json_bytes(&(domain, value))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| FiscalError::Canonicalization(error.to_string()))
}

fn decode_prefixed_key(public_key: &PublicKey, prefix: &str) -> Result<Vec<u8>, FiscalError> {
    public_key
        .to_hex()
        .strip_prefix(prefix)
        .ok_or(FiscalError::UnsupportedSignerAlgorithm)
        .and_then(|encoded| {
            hex::decode(encoded).map_err(|error| FiscalError::Canonicalization(error.to_string()))
        })
}
