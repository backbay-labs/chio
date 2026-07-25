use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{
    fiscal_signer_key_id, FiscalError, SignedFiscalCharter, SignedFiscalSchedule,
    VerifiedFiscalCharter, VerifiedFiscalSchedule,
};

use super::support::{
    canonical_digest, is_digest, is_iso_currency, lifecycle_digest, require_digest,
    require_positive, require_text, signed_envelope_digest, verify_envelope,
};

pub const FISCAL_GENESIS_POLICY_SCHEMA: &str = "chio.fiscal.genesis-policy.v1";
pub const FISCAL_PROPOSAL_SCHEMA: &str = "chio.fiscal.proposal.v1";
pub const FISCAL_PROPOSAL_ADMISSION_SCHEMA: &str = "chio.fiscal.proposal-admission.v1";
pub const FISCAL_GENESIS_POLICY_ID_DOMAIN: &str = "chio.fiscal.genesis-policy.id.v1";
pub const FISCAL_PROPOSAL_ID_DOMAIN: &str = "chio.fiscal.proposal.id.v1";
pub const FISCAL_PROPOSAL_ADMISSION_ID_DOMAIN: &str = "chio.fiscal.proposal-admission.id.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalGenesisPolicy {
    pub schema: String,
    pub policy_id: String,
    pub governing_operator_id: String,
    pub genesis_charter_id: String,
    pub genesis_charter_digest: String,
    pub bootstrap_authority_key: PublicKey,
    pub anchor_id: String,
    pub anchor_namespace: String,
    pub anchor_signer_key_id: String,
    pub anchor_signer_key_epoch: u64,
    pub anchor_authority_key: PublicKey,
    pub bootstrap_tier_limits: BTreeMap<String, [u64; 4]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalGenesisPolicyIdPreimage<'a> {
    schema: &'a str,
    governing_operator_id: &'a str,
    genesis_charter_id: &'a str,
    genesis_charter_digest: &'a str,
    bootstrap_authority_key: &'a PublicKey,
    anchor_id: &'a str,
    anchor_namespace: &'a str,
    anchor_signer_key_id: &'a str,
    anchor_signer_key_epoch: u64,
    anchor_authority_key: &'a PublicKey,
    bootstrap_tier_limits: &'a BTreeMap<String, [u64; 4]>,
}

impl FiscalGenesisPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        governing_operator_id: String,
        genesis_charter: &VerifiedFiscalCharter,
        bootstrap_authority_key: PublicKey,
        anchor_id: String,
        anchor_namespace: String,
        anchor_signer_key_epoch: u64,
        anchor_authority_key: PublicKey,
        bootstrap_tier_limits: BTreeMap<String, [u64; 4]>,
    ) -> Result<Self, FiscalError> {
        let mut policy = Self {
            schema: FISCAL_GENESIS_POLICY_SCHEMA.to_owned(),
            policy_id: String::new(),
            governing_operator_id,
            genesis_charter_id: genesis_charter.body().charter_id.clone(),
            genesis_charter_digest: genesis_charter.digest().to_owned(),
            bootstrap_authority_key,
            anchor_id,
            anchor_namespace,
            anchor_signer_key_id: fiscal_signer_key_id(&anchor_authority_key)?,
            anchor_signer_key_epoch,
            anchor_authority_key,
            bootstrap_tier_limits,
        };
        policy.policy_id = policy.expected_id()?;
        policy.validate(genesis_charter)?;
        Ok(policy)
    }

    pub fn validate(&self, genesis_charter: &VerifiedFiscalCharter) -> Result<(), FiscalError> {
        if self.schema != FISCAL_GENESIS_POLICY_SCHEMA {
            return Err(FiscalError::UnknownSchema(self.schema.clone()));
        }
        require_text(&self.governing_operator_id, "genesis.governing_operator_id")?;
        require_text(&self.anchor_id, "genesis.anchor_id")?;
        require_text(&self.anchor_namespace, "genesis.anchor_namespace")?;
        if genesis_charter.signed().signer_key != self.bootstrap_authority_key {
            return Err(FiscalError::InvalidField("genesis.bootstrap_authority_key"));
        }
        if self.anchor_signer_key_epoch == 0
            || self.anchor_signer_key_id != fiscal_signer_key_id(&self.anchor_authority_key)?
            || self.governing_operator_id != genesis_charter.body().governing_operator_id
            || self.genesis_charter_id != genesis_charter.body().charter_id
            || self.genesis_charter_digest != genesis_charter.digest()
        {
            return Err(FiscalError::InvalidField("genesis.binding"));
        }
        if self.bootstrap_tier_limits.is_empty() || self.bootstrap_tier_limits.len() > 64 {
            return Err(FiscalError::InvalidField("genesis.bootstrap_tier_limits"));
        }
        for (currency, limits) in &self.bootstrap_tier_limits {
            if !is_iso_currency(currency) || limits.windows(2).any(|pair| pair[0] > pair[1]) {
                return Err(FiscalError::InvalidField("genesis.bootstrap_tier_limits"));
            }
        }
        if self.policy_id != self.expected_id()? {
            return Err(FiscalError::InvalidSelfId);
        }
        Ok(())
    }

    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_GENESIS_POLICY_ID_DOMAIN,
            &FiscalGenesisPolicyIdPreimage {
                schema: &self.schema,
                governing_operator_id: &self.governing_operator_id,
                genesis_charter_id: &self.genesis_charter_id,
                genesis_charter_digest: &self.genesis_charter_digest,
                bootstrap_authority_key: &self.bootstrap_authority_key,
                anchor_id: &self.anchor_id,
                anchor_namespace: &self.anchor_namespace,
                anchor_signer_key_id: &self.anchor_signer_key_id,
                anchor_signer_key_epoch: self.anchor_signer_key_epoch,
                anchor_authority_key: &self.anchor_authority_key,
                bootstrap_tier_limits: &self.bootstrap_tier_limits,
            },
        )
    }

    pub fn digest(&self) -> Result<String, FiscalError> {
        canonical_digest(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FiscalProposalTarget {
    Schedule {
        candidate: Box<SignedFiscalSchedule>,
    },
    CharterRotation {
        successor: Box<SignedFiscalCharter>,
    },
}

impl FiscalProposalTarget {
    fn expires_at(&self) -> u64 {
        match self {
            Self::Schedule { candidate } => candidate.body.valid_until,
            Self::CharterRotation { successor } => successor.body.expires_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalProposal {
    pub schema: String,
    pub proposal_id: String,
    pub target: FiscalProposalTarget,
    pub rationale_digest: String,
    pub proposed_by: String,
    pub proposed_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalProposalIdPreimage<'a> {
    schema: &'a str,
    target: &'a FiscalProposalTarget,
    rationale_digest: &'a str,
    proposed_by: &'a str,
    proposed_at: u64,
}

impl FiscalProposal {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_PROPOSAL_ID_DOMAIN,
            &FiscalProposalIdPreimage {
                schema: &self.schema,
                target: &self.target,
                rationale_digest: &self.rationale_digest,
                proposed_by: &self.proposed_by,
                proposed_at: self.proposed_at,
            },
        )
    }
}

pub type SignedFiscalProposal = SignedExportEnvelope<FiscalProposal>;

#[derive(Debug, Clone)]
pub struct FiscalProposalBuilder {
    pub target: FiscalProposalTarget,
    pub rationale_digest: String,
    pub proposed_at: u64,
}

impl FiscalProposalBuilder {
    pub fn sign(self, keypair: &Keypair) -> Result<SignedFiscalProposal, FiscalError> {
        let mut body = FiscalProposal {
            schema: FISCAL_PROPOSAL_SCHEMA.to_owned(),
            proposal_id: String::new(),
            target: self.target,
            rationale_digest: self.rationale_digest,
            proposed_by: fiscal_signer_key_id(&keypair.public_key())?,
            proposed_at: self.proposed_at,
        };
        body.proposal_id = body.expected_id()?;
        SignedFiscalProposal::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalProposal {
    signed: SignedFiscalProposal,
    digest: String,
}

impl VerifiedFiscalProposal {
    pub fn verify(
        signed: SignedFiscalProposal,
        current_charter: &VerifiedFiscalCharter,
        predecessor_schedule: Option<&VerifiedFiscalSchedule>,
    ) -> Result<Self, FiscalError> {
        if signed.body.schema != FISCAL_PROPOSAL_SCHEMA {
            return Err(FiscalError::UnknownSchema(signed.body.schema.clone()));
        }
        require_digest(&signed.body.rationale_digest, "proposal.rationale_digest")?;
        require_positive(signed.body.proposed_at, "proposal.proposed_at")?;
        if signed.body.proposal_id != signed.body.expected_id()?
            || signed.body.proposed_by != fiscal_signer_key_id(&signed.signer_key)?
        {
            return Err(FiscalError::InvalidSelfId);
        }
        verify_envelope(&signed)?;
        match &signed.body.target {
            FiscalProposalTarget::Schedule { candidate } => {
                VerifiedFiscalSchedule::verify(
                    candidate.as_ref().clone(),
                    current_charter,
                    predecessor_schedule,
                )?;
            }
            FiscalProposalTarget::CharterRotation { successor } => {
                let successor = VerifiedFiscalCharter::verify(successor.as_ref().clone())?;
                let expected_sequence = current_charter
                    .body()
                    .sequence
                    .checked_add(1)
                    .ok_or(FiscalError::InvalidLineage)?;
                if successor.body().governing_operator_id
                    != current_charter.body().governing_operator_id
                    || successor.body().sequence != expected_sequence
                    || successor.body().predecessor_charter_digest.as_deref()
                        != Some(current_charter.digest())
                {
                    return Err(FiscalError::InvalidLineage);
                }
            }
        }
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self { signed, digest })
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalProposal {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalProposal {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalAdmissionAuthority {
    pub governing_operator_id: String,
    pub admission_authority_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub public_key: PublicKey,
}

impl FiscalAdmissionAuthority {
    pub fn new(
        governing_operator_id: String,
        admission_authority_id: String,
        signer_key_epoch: u64,
        public_key: PublicKey,
    ) -> Result<Self, FiscalError> {
        let authority = Self {
            governing_operator_id,
            admission_authority_id,
            signer_key_id: fiscal_signer_key_id(&public_key)?,
            signer_key_epoch,
            public_key,
        };
        authority.validate()?;
        Ok(authority)
    }

    fn validate(&self) -> Result<(), FiscalError> {
        require_text(
            &self.governing_operator_id,
            "admission_authority.governing_operator_id",
        )?;
        require_text(
            &self.admission_authority_id,
            "admission_authority.admission_authority_id",
        )?;
        require_positive(
            self.signer_key_epoch,
            "admission_authority.signer_key_epoch",
        )?;
        if self.signer_key_id != fiscal_signer_key_id(&self.public_key)? {
            return Err(FiscalError::InvalidField("admission_authority.key_binding"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FiscalAdmissionTrustRegistry {
    authorities: Vec<FiscalAdmissionAuthority>,
}

impl FiscalAdmissionTrustRegistry {
    pub fn new(mut authorities: Vec<FiscalAdmissionAuthority>) -> Result<Self, FiscalError> {
        for authority in &authorities {
            authority.validate()?;
        }
        authorities.sort_by(|left, right| {
            (
                &left.governing_operator_id,
                &left.admission_authority_id,
                &left.signer_key_id,
                left.signer_key_epoch,
            )
                .cmp(&(
                    &right.governing_operator_id,
                    &right.admission_authority_id,
                    &right.signer_key_id,
                    right.signer_key_epoch,
                ))
        });
        if authorities.windows(2).any(|pair| {
            pair[0].governing_operator_id == pair[1].governing_operator_id
                && pair[0].admission_authority_id == pair[1].admission_authority_id
                && pair[0].signer_key_id == pair[1].signer_key_id
                && pair[0].signer_key_epoch == pair[1].signer_key_epoch
        }) {
            return Err(FiscalError::InvalidField("admission_authority.duplicate"));
        }
        Ok(Self { authorities })
    }

    fn resolve(
        &self,
        governing_operator_id: &str,
        admission_authority_id: &str,
        signer_key_id: &str,
        signer_key_epoch: u64,
    ) -> Option<&FiscalAdmissionAuthority> {
        self.authorities.iter().find(|authority| {
            authority.governing_operator_id == governing_operator_id
                && authority.admission_authority_id == admission_authority_id
                && authority.signer_key_id == signer_key_id
                && authority.signer_key_epoch == signer_key_epoch
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalProposalAdmission {
    pub schema: String,
    pub admission_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub governing_operator_id: String,
    pub predecessor_charter_id: String,
    pub predecessor_charter_digest: String,
    pub predecessor_charter_sequence: u64,
    pub admission_sequence: u64,
    pub admitted_at: u64,
    pub proposal_expires_at: u64,
    pub admission_authority_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalProposalAdmissionIdPreimage<'a> {
    schema: &'a str,
    proposal_id: &'a str,
    proposal_digest: &'a str,
    governing_operator_id: &'a str,
    predecessor_charter_id: &'a str,
    predecessor_charter_digest: &'a str,
    predecessor_charter_sequence: u64,
    admission_sequence: u64,
    admitted_at: u64,
    proposal_expires_at: u64,
    admission_authority_id: &'a str,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

impl FiscalProposalAdmission {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_PROPOSAL_ADMISSION_ID_DOMAIN,
            &FiscalProposalAdmissionIdPreimage {
                schema: &self.schema,
                proposal_id: &self.proposal_id,
                proposal_digest: &self.proposal_digest,
                governing_operator_id: &self.governing_operator_id,
                predecessor_charter_id: &self.predecessor_charter_id,
                predecessor_charter_digest: &self.predecessor_charter_digest,
                predecessor_charter_sequence: self.predecessor_charter_sequence,
                admission_sequence: self.admission_sequence,
                admitted_at: self.admitted_at,
                proposal_expires_at: self.proposal_expires_at,
                admission_authority_id: &self.admission_authority_id,
                signer_key_id: &self.signer_key_id,
                signer_key_epoch: self.signer_key_epoch,
            },
        )
    }
}

pub type SignedFiscalProposalAdmission = SignedExportEnvelope<FiscalProposalAdmission>;

#[derive(Debug, Clone)]
pub struct FiscalProposalAdmissionBuilder {
    pub admission_sequence: u64,
    pub admitted_at: u64,
    pub admission_authority_id: String,
    pub signer_key_epoch: u64,
}

impl FiscalProposalAdmissionBuilder {
    pub fn sign(
        self,
        proposal: &VerifiedFiscalProposal,
        current_charter: &VerifiedFiscalCharter,
        keypair: &Keypair,
    ) -> Result<SignedFiscalProposalAdmission, FiscalError> {
        let proposal_expires_at = self
            .admitted_at
            .checked_add(current_charter.body().proposal_ttl_seconds)
            .ok_or(FiscalError::InvalidField("admission.proposal_expires_at"))?;
        let mut body = FiscalProposalAdmission {
            schema: FISCAL_PROPOSAL_ADMISSION_SCHEMA.to_owned(),
            admission_id: String::new(),
            proposal_id: proposal.body().proposal_id.clone(),
            proposal_digest: proposal.digest().to_owned(),
            governing_operator_id: current_charter.body().governing_operator_id.clone(),
            predecessor_charter_id: current_charter.body().charter_id.clone(),
            predecessor_charter_digest: current_charter.digest().to_owned(),
            predecessor_charter_sequence: current_charter.body().sequence,
            admission_sequence: self.admission_sequence,
            admitted_at: self.admitted_at,
            proposal_expires_at,
            admission_authority_id: self.admission_authority_id,
            signer_key_id: fiscal_signer_key_id(&keypair.public_key())?,
            signer_key_epoch: self.signer_key_epoch,
        };
        body.admission_id = body.expected_id()?;
        SignedFiscalProposalAdmission::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalProposalAdmission {
    signed: SignedFiscalProposalAdmission,
    digest: String,
}

impl VerifiedFiscalProposalAdmission {
    pub fn verify(
        signed: SignedFiscalProposalAdmission,
        proposal: &VerifiedFiscalProposal,
        current_charter: &VerifiedFiscalCharter,
        trust: &FiscalAdmissionTrustRegistry,
        verify_at: u64,
    ) -> Result<Self, FiscalError> {
        let body = &signed.body;
        if body.schema != FISCAL_PROPOSAL_ADMISSION_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        let authority = trust
            .resolve(
                &body.governing_operator_id,
                &body.admission_authority_id,
                &body.signer_key_id,
                body.signer_key_epoch,
            )
            .ok_or(FiscalError::InvalidField("admission.authority"))?;
        let expected_expiry = body
            .admitted_at
            .checked_add(current_charter.body().proposal_ttl_seconds)
            .ok_or(FiscalError::InvalidField("admission.proposal_expires_at"))?;
        let activation_not_before = body
            .admitted_at
            .checked_add(current_charter.body().timelock_seconds)
            .ok_or(FiscalError::InvalidField("admission.activation_not_before"))?;
        if body.admission_id != body.expected_id()?
            || body.proposal_id != proposal.body().proposal_id
            || body.proposal_digest != proposal.digest()
            || body.governing_operator_id != current_charter.body().governing_operator_id
            || body.predecessor_charter_id != current_charter.body().charter_id
            || body.predecessor_charter_digest != current_charter.digest()
            || body.predecessor_charter_sequence != current_charter.body().sequence
            || body.admission_sequence == 0
            || body.admitted_at < proposal.body().proposed_at
            || body.admitted_at > verify_at
            || verify_at >= current_charter.body().expires_at
            || body.proposal_expires_at != expected_expiry
            || body.proposal_expires_at > current_charter.body().expires_at
            || body.proposal_expires_at > proposal.body().target.expires_at()
            || activation_not_before >= body.proposal_expires_at
            || body.signer_key_id != fiscal_signer_key_id(&signed.signer_key)?
            || signed.signer_key != authority.public_key
        {
            return Err(FiscalError::InvalidField("admission.binding"));
        }
        verify_envelope(&signed)?;
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self { signed, digest })
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalProposalAdmission {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalProposalAdmission {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FiscalProposalAdmissionStatus {
    Admitted,
    Activated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalProposalAdmissionState {
    pub signed_admission: SignedFiscalProposalAdmission,
    pub admission_digest: String,
    pub version: u64,
    pub status: FiscalProposalAdmissionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_sequence: Option<u64>,
}

impl FiscalProposalAdmissionState {
    pub fn admitted(admission: &VerifiedFiscalProposalAdmission) -> Self {
        Self {
            signed_admission: admission.signed().clone(),
            admission_digest: admission.digest().to_owned(),
            version: 1,
            status: FiscalProposalAdmissionStatus::Admitted,
            activation_digest: None,
            activated_sequence: None,
        }
    }

    pub fn activate(
        &self,
        activation_digest: String,
        activated_sequence: u64,
    ) -> Result<Self, FiscalError> {
        if self.status != FiscalProposalAdmissionStatus::Admitted
            || self.version == u64::MAX
            || !is_digest(&activation_digest)
            || activated_sequence == 0
        {
            return Err(FiscalError::InvalidField("admission_state.transition"));
        }
        Ok(Self {
            signed_admission: self.signed_admission.clone(),
            admission_digest: self.admission_digest.clone(),
            version: self.version + 1,
            status: FiscalProposalAdmissionStatus::Activated,
            activation_digest: Some(activation_digest),
            activated_sequence: Some(activated_sequence),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct FiscalProposalAdmissionRegistry {
    states: Vec<FiscalProposalAdmissionState>,
}

impl FiscalProposalAdmissionRegistry {
    pub fn new(states: Vec<FiscalProposalAdmissionState>) -> Result<Self, FiscalError> {
        let mut ids = BTreeSet::new();
        for state in &states {
            if !ids.insert(state.signed_admission.body.admission_id.clone()) {
                return Err(FiscalError::InvalidField("admission_state.duplicate"));
            }
        }
        Ok(Self { states })
    }

    #[must_use]
    pub fn get(&self, admission_id: &str) -> Option<&FiscalProposalAdmissionState> {
        self.states
            .iter()
            .find(|state| state.signed_admission.body.admission_id == admission_id)
    }
}
