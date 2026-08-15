//! `chio.finding.admission.v1`: the venue-signed bundle that trusted
//! search, bid, and later purchase accept as the ONLY qualification of a
//! finding listing.
//!
//! Admission binds every exact constituent envelope by digest, both
//! governance-pinned pool identities, the community-fund destination, and
//! the purchase/failed-delivery authorities BEFORE any sale. Its body
//! venue identity and its envelope signer must both equal the externally
//! configured venue authority. Presence of a current verified admission
//! IS the qualified cognition-market profile; generic listing search
//! never carries it.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::profile::FindingAuthorityKeyPolicy;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_max_items, require_nonzero,
    require_window, FindingError, MAX_FINDING_ARTIFACT_ITEMS,
};

/// Venue-signed admission bundle.
pub const FINDING_ADMISSION_SCHEMA_V1: &str = chio_core_types::CHIO_FINDING_ADMISSION_V1_SCHEMA;

/// Fee event a terminal binding settles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingFeeEvent {
    Publication,
    ParticipationEpoch { epoch_index: u64 },
}

/// One settled fee terminal: the evidence pair (instruction + matched
/// observation) persists in the activation store; the admission signature
/// authenticates this binding of schedule, event, payer, amount, pool,
/// and rail destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingFeeTerminalBinding {
    pub fee_schedule_envelope_sha256: String,
    pub event: FindingFeeEvent,
    pub payer: String,
    pub amount: MonetaryAmount,
    pub pool_principal_id: String,
    pub rail_destination: String,
    pub instruction_sha256: String,
    pub observation_sha256: String,
}

impl FindingFeeTerminalBinding {
    fn validate(&self) -> Result<(), FindingError> {
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "fee_terminals[].fee_schedule_envelope_sha256",
        )?;
        if let FindingFeeEvent::ParticipationEpoch { epoch_index } = &self.event {
            crate::validate::require_i_json_u64(*epoch_index, "fee_terminals[].event.epoch_index")?;
        }
        require_bounded_id(&self.payer, "fee_terminals[].payer")?;
        require_nonzero(self.amount.units, "fee_terminals[].amount")?;
        require_currency(&self.amount.currency, "fee_terminals[].amount.currency")?;
        require_bounded_id(&self.pool_principal_id, "fee_terminals[].pool_principal_id")?;
        require_bounded_id(&self.rail_destination, "fee_terminals[].rail_destination")?;
        require_hex64(
            &self.instruction_sha256,
            "fee_terminals[].instruction_sha256",
        )?;
        require_hex64(
            &self.observation_sha256,
            "fee_terminals[].observation_sha256",
        )?;
        Ok(())
    }
}

/// A governance-pinned pool identity. The audit pool and the
/// challenge-administration pool are distinct and non-substitutable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPoolBinding {
    pub principal_id: String,
    pub rail_destination: String,
    pub currency: String,
    pub authority_epoch: u64,
}

impl FindingPoolBinding {
    fn validate(&self, label: &'static str) -> Result<(), FindingError> {
        require_bounded_id(&self.principal_id, label)?;
        require_bounded_id(&self.rail_destination, label)?;
        require_currency(&self.currency, label)?;
        require_nonzero(self.authority_epoch, label)?;
        Ok(())
    }
}

/// Venue admission body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAdmission {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `admission_id` cleared.
    pub admission_id: String,
    /// Venue authority; must sign the enclosing envelope and equal the
    /// externally configured venue key.
    pub venue: PublicKey,
    pub venue_id: String,
    pub finding_id: String,
    pub finding_artifact_sha256: String,
    pub seller_authorization_envelope_sha256: String,
    pub listing_id: String,
    pub listing_envelope_sha256: String,
    pub server_id: String,
    pub metadata_url: String,
    pub pricing_hint_envelope_sha256: String,
    /// `finding:<finding_id>` exactly.
    pub capability_scope: String,
    pub publisher_operator_id: String,
    pub payee_destination: String,
    pub fee_schedule_envelope_sha256: String,
    pub verifier_report_id: String,
    pub verifier_report_envelope_sha256: String,
    pub terms_envelope_sha256: String,
    pub profile_envelope_sha256: String,
    /// Publication plus the first participation epoch at minimum.
    pub fee_terminals: Vec<FindingFeeTerminalBinding>,
    pub backing_allocation_id: String,
    pub backing_envelope_sha256: String,
    pub audit_pool: FindingPoolBinding,
    pub challenge_administration_pool: FindingPoolBinding,
    pub community_fund_destination: String,
    pub status_feed_operator_ref: String,
    /// Purchase and failed-delivery authority roles, pinned before any
    /// sale, snapshot included.
    pub purchase_authority: FindingAuthorityKeyPolicy,
    pub failed_delivery_authority: FindingAuthorityKeyPolicy,
    pub issued_at: u64,
    /// No later than the earliest constituent expiry; the surface that
    /// resolves every constituent enforces the bound.
    pub expires_at: u64,
}

/// Venue-signed envelope for the admission.
pub type SignedFindingAdmission = SignedExportEnvelope<FindingAdmission>;

impl FindingAdmission {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_ADMISSION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.admission_id, "admission_id")?;
        require_ed25519(&self.venue, "venue")?;
        require_bounded_id(&self.venue_id, "venue_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.finding_artifact_sha256, "finding_artifact_sha256")?;
        require_hex64(
            &self.seller_authorization_envelope_sha256,
            "seller_authorization_envelope_sha256",
        )?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_hex64(&self.listing_envelope_sha256, "listing_envelope_sha256")?;
        require_bounded_id(&self.server_id, "server_id")?;
        require_bounded_id(&self.metadata_url, "metadata_url")?;
        require_hex64(
            &self.pricing_hint_envelope_sha256,
            "pricing_hint_envelope_sha256",
        )?;
        let expected_scope = format!("finding:{}", self.finding_id);
        if self.capability_scope != expected_scope {
            return Err(FindingError::InvalidField("capability_scope"));
        }
        require_bounded_id(&self.publisher_operator_id, "publisher_operator_id")?;
        require_bounded_id(&self.payee_destination, "payee_destination")?;
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "fee_schedule_envelope_sha256",
        )?;
        require_hex64(&self.verifier_report_id, "verifier_report_id")?;
        require_hex64(
            &self.verifier_report_envelope_sha256,
            "verifier_report_envelope_sha256",
        )?;
        require_hex64(&self.terms_envelope_sha256, "terms_envelope_sha256")?;
        require_hex64(&self.profile_envelope_sha256, "profile_envelope_sha256")?;
        if self.fee_terminals.is_empty() {
            return Err(FindingError::MissingEntry("fee_terminals"));
        }
        require_max_items(
            self.fee_terminals.len(),
            "fee_terminals",
            MAX_FINDING_ARTIFACT_ITEMS,
        )?;
        let mut has_publication = false;
        let mut has_first_epoch = false;
        let mut seen_events = std::collections::BTreeSet::new();
        for terminal in &self.fee_terminals {
            terminal.validate()?;
            let key = match &terminal.event {
                FindingFeeEvent::Publication => {
                    has_publication = true;
                    ("publication", 0_u64)
                }
                FindingFeeEvent::ParticipationEpoch { epoch_index } => {
                    if *epoch_index == 0 {
                        has_first_epoch = true;
                    }
                    ("participation_epoch", *epoch_index)
                }
            };
            if !seen_events.insert(key) {
                return Err(FindingError::DuplicateEntry("fee_terminals[].event"));
            }
        }
        if !has_publication || !has_first_epoch {
            return Err(FindingError::MissingEntry("fee_terminals[].event"));
        }
        require_hex64(&self.backing_allocation_id, "backing_allocation_id")?;
        require_hex64(&self.backing_envelope_sha256, "backing_envelope_sha256")?;
        self.audit_pool.validate("audit_pool")?;
        self.challenge_administration_pool
            .validate("challenge_administration_pool")?;
        if self.audit_pool.principal_id == self.challenge_administration_pool.principal_id
            || self.audit_pool.rail_destination
                == self.challenge_administration_pool.rail_destination
        {
            return Err(FindingError::DuplicateEntry("pools"));
        }
        require_bounded_id(
            &self.community_fund_destination,
            "community_fund_destination",
        )?;
        require_bounded_id(&self.status_feed_operator_ref, "status_feed_operator_ref")?;
        self.purchase_authority.validate("purchase_authority")?;
        self.failed_delivery_authority
            .validate("failed_delivery_authority")?;
        require_window(self.issued_at, self.expires_at, "issued_at", "expires_at")?;
        self.verify_admission_id()
    }

    /// Recompute and compare the content-addressed admission id.
    pub fn verify_admission_id(&self) -> Result<(), FindingError> {
        let expected = compute_admission_id(self)?;
        if expected == self.admission_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("admission_id"))
        }
    }
}

/// Content-addressed admission id: sha256 over the canonical body with
/// `admission_id` cleared.
pub fn compute_admission_id(admission: &FindingAdmission) -> Result<String, FindingError> {
    let mut body = admission.clone();
    body.admission_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed admission against the externally configured venue
/// authority: body venue, envelope signer, and pinned key must all agree,
/// and the signature must verify strictly. Constituent digest resolution,
/// collateral liveness, fee currency, and the earliest-expiry bound are
/// surface obligations on top of this.
pub fn verify_signed_admission(
    signed: &SignedFindingAdmission,
    pinned_venue_authority: &PublicKey,
    expected_venue_id: &str,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    if signed.body.venue != *pinned_venue_authority {
        return Err(FindingError::AuthorityMismatch("admission"));
    }
    if signed.body.venue_id != expected_venue_id {
        return Err(FindingError::AuthorityMismatch("admission"));
    }
    crate::envelope::verify_pinned_envelope(signed, pinned_venue_authority, "admission")
}
