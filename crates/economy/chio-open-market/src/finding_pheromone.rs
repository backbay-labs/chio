//! Fully admitted discovery pheromones for cognition-market findings.
//!
//! A deposit is only a hint. Success means the deposit passed the real
//! pheromone passport, scarcity, replay, signer, and cost admission, and that
//! the buyer independently supplied a fresh signed listing plus the complete
//! M2 admission bundle. The hint never mints a token or grants purchase
//! authority.

use chio_finding::{signed_envelope_sha256, SignedFindingAdmission, FINDING_ADMISSION_SCHEMA_V1};
use chio_listing::{
    ensure_generic_listing_signed_by_namespace_owner, normalize_namespace,
    GenericListingFreshnessState, GenericListingFreshnessWindow, GenericListingStatus, Listing,
};
use chio_pheromone::{
    scarcity_admissions_for_deposit_treaty, validate_deposit_for_admission, CostCommitmentPolicy,
    ObservationCostVerificationMode, PheromoneDeposit, PheromoneError, PheromoneSubstrate,
    PheromoneValidationContext, Severity, SubjectClassPolicy, OBSERVATION_COST_UNIT,
};
use serde::{Deserialize, Serialize};

use crate::finding_admission::{
    verify_finding_admission, FindingAdmissionContext, FindingAdmissionError,
    VerifiedFindingAdmission,
};

pub const FINDING_PHEROMONE_INDICATOR_SCHEMA_V1: &str = "chio.finding.pheromone-indicator.v1";
pub const FINDING_PHEROMONE_SUBJECT_CLASS: &str = "finding_listing_hint";
pub const FINDING_PHEROMONE_SUBJECT_NAMESPACE: &str = "dev.chio.cognition-market";
pub const FINDING_PHEROMONE_CONFIDENCE: f64 = 0.75;
pub const FINDING_PHEROMONE_DECAY_HALF_LIFE_SECS: f64 = 3_600.0;
pub const FINDING_PHEROMONE_EVAPORATION_FLOOR: f64 = 0.01;

/// Strict typed indicator carried inside the generic deposit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPheromoneIndicator {
    pub schema: String,
    pub finding_id: String,
    pub listing_id: String,
    pub listing_envelope_sha256: String,
    pub admission_envelope_sha256: String,
    pub capability_scope: String,
}

/// Receiver-owned convention inputs that are deployment-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPheromoneConvention {
    pub treaty_id: String,
    pub max_observation_cost_microunits: u64,
}

/// Discovery result whose authority comes from the separately verified M2
/// admission, never from the pheromone.
pub struct ResolvedFindingPheromoneHint {
    pub indicator: FindingPheromoneIndicator,
    pub admission: VerifiedFindingAdmission,
}

impl ResolvedFindingPheromoneHint {
    /// The pheromone itself is discovery-only. Any later bid still requires
    /// the independently verified admission and ordinary signed bid flow.
    #[must_use]
    pub fn grants_purchase_authority(&self) -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FindingPheromoneError {
    #[error("finding pheromone indicator is malformed")]
    IndicatorMalformed,
    #[error("finding pheromone convention mismatch: {0}")]
    Convention(&'static str),
    #[error("finding pheromone observation cost exceeds the receiver cap")]
    ObservationCostExceeded,
    #[error("finding pheromone deposit rejected: {0}")]
    Deposit(#[from] PheromoneError),
    #[error("current finding listing rejected: {0}")]
    Listing(String),
    #[error("current finding admission rejected: {0}")]
    Admission(#[from] FindingAdmissionError),
    #[error("finding pheromone points at a different current listing or admission")]
    CurrentBindingMismatch,
}

/// Required receiver policy for the finding hint subject class.
#[must_use]
pub fn finding_pheromone_subject_policy(treaty_id: &str) -> SubjectClassPolicy {
    SubjectClassPolicy {
        subject_class: FINDING_PHEROMONE_SUBJECT_CLASS.to_string(),
        subject_class_namespace: FINDING_PHEROMONE_SUBJECT_NAMESPACE.to_string(),
        allowed_treaties: vec![treaty_id.to_string()],
        cost_commitment: CostCommitmentPolicy::Required,
        destructive: false,
    }
}

/// Admit one hint and re-resolve its current listing and M2 admission bundle.
pub fn admit_and_resolve_finding_pheromone_hint<S: PheromoneSubstrate + ?Sized>(
    substrate: &S,
    deposit: PheromoneDeposit,
    pheromone_context: &PheromoneValidationContext,
    convention: &FindingPheromoneConvention,
    current_listing: &Listing,
    current_admission: &SignedFindingAdmission,
    admission_context: &FindingAdmissionContext<'_>,
) -> Result<ResolvedFindingPheromoneHint, FindingPheromoneError> {
    let indicator: FindingPheromoneIndicator =
        serde_json::from_value(deposit.body.indicator.clone())
            .map_err(|_| FindingPheromoneError::IndicatorMalformed)?;
    validate_indicator(&indicator)?;
    // Authenticate the cheap generic carrier boundary before resolving the
    // substantially larger signed listing and admission bundle. The final
    // substrate call repeats this validation inside its atomic commit.
    validate_deposit_for_admission(&deposit, pheromone_context)?;
    validate_convention(&deposit, pheromone_context, convention)?;
    let now = pheromone_context.now_unix_ms / 1_000;
    validate_current_listing(current_listing, now)?;
    let mut current_admission_context = admission_context.clone();
    current_admission_context.now = now;
    current_admission_context.constituent_expiry_bounds.listing =
        current_listing.listing.body.expires_at.unwrap_or(u64::MAX);
    current_admission_context
        .constituent_expiry_bounds
        .pricing_hint = current_listing.pricing.body.expires_at;
    let verified_admission =
        verify_finding_admission(current_admission, &current_admission_context)?;
    let listing_sha256 = signed_envelope_sha256(&current_listing.listing)
        .map_err(|error| FindingPheromoneError::Listing(error.to_string()))?;
    let pricing_sha256 = signed_envelope_sha256(&current_listing.pricing)
        .map_err(|error| FindingPheromoneError::Listing(error.to_string()))?;
    let admission_sha256 = signed_envelope_sha256(current_admission)
        .map_err(|error| FindingPheromoneError::Listing(error.to_string()))?;
    if indicator.finding_id != verified_admission.finding_id()
        || indicator.listing_id != current_listing.listing_id()
        || indicator.listing_id != verified_admission.listing_id()
        || indicator.listing_envelope_sha256 != listing_sha256
        || indicator.admission_envelope_sha256 != admission_sha256
        || indicator.capability_scope != verified_admission.capability_scope()
        || current_admission.body.schema != FINDING_ADMISSION_SCHEMA_V1
        || current_admission.body.listing_envelope_sha256 != listing_sha256
        || current_admission.body.pricing_hint_envelope_sha256 != pricing_sha256
    {
        return Err(FindingPheromoneError::CurrentBindingMismatch);
    }
    substrate.deposit(deposit, pheromone_context)?;
    Ok(ResolvedFindingPheromoneHint {
        indicator,
        admission: verified_admission,
    })
}

fn validate_indicator(indicator: &FindingPheromoneIndicator) -> Result<(), FindingPheromoneError> {
    if indicator.schema != FINDING_PHEROMONE_INDICATOR_SCHEMA_V1
        || !is_hex64(&indicator.finding_id)
        || indicator.listing_id.is_empty()
        || indicator.listing_id.len() > 512
        || !is_hex64(&indicator.listing_envelope_sha256)
        || !is_hex64(&indicator.admission_envelope_sha256)
        || indicator.capability_scope != format!("finding:{}", indicator.finding_id)
    {
        return Err(FindingPheromoneError::IndicatorMalformed);
    }
    Ok(())
}

fn validate_convention(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    convention: &FindingPheromoneConvention,
) -> Result<(), FindingPheromoneError> {
    if convention.treaty_id.is_empty() || convention.max_observation_cost_microunits == 0 {
        return Err(FindingPheromoneError::Convention("receiver policy"));
    }
    let body = &deposit.body;
    if body.subject_class != FINDING_PHEROMONE_SUBJECT_CLASS
        || body.subject_class_namespace != FINDING_PHEROMONE_SUBJECT_NAMESPACE
    {
        return Err(FindingPheromoneError::Convention("subject"));
    }
    if body.severity != Severity::Medium
        || body.confidence != FINDING_PHEROMONE_CONFIDENCE
        || body.decay_half_life_secs != FINDING_PHEROMONE_DECAY_HALF_LIFE_SECS
        || body.evaporation_floor != Some(FINDING_PHEROMONE_EVAPORATION_FLOOR)
    {
        return Err(FindingPheromoneError::Convention(
            "severity, confidence, or decay",
        ));
    }
    if body.nonce.is_empty()
        || body.treaty_scope.len() != 1
        || body.treaty_scope[0] != convention.treaty_id
    {
        return Err(FindingPheromoneError::Convention("nonce or listing scope"));
    }
    let expected_policy = finding_pheromone_subject_policy(&convention.treaty_id);
    let selected_policy = context.subject_classes.iter().find(|policy| {
        policy.subject_class == body.subject_class
            && policy.subject_class_namespace == body.subject_class_namespace
    });
    if selected_policy != Some(&expected_policy) {
        return Err(FindingPheromoneError::Convention("SubjectClassPolicy"));
    }
    let scarcity_admissions =
        scarcity_admissions_for_deposit_treaty(deposit, context, &convention.treaty_id)?;
    let active = scarcity_admissions.as_slice();
    let [active] = active else {
        return Err(FindingPheromoneError::Convention("active scarcity policy"));
    };
    let active_policy = context.scarcity_policies.iter().find(|policy| {
        policy.reputation_epoch == active.reputation_epoch
            && policy.window_id == active.window_id
            && policy.subject_class == active.subject_class
            && policy.subject_class_namespace == active.subject_class_namespace
            && policy
                .treaty_scope
                .iter()
                .any(|treaty| treaty == &active.treaty_id)
    });
    if !active_policy.is_some_and(|policy| {
        policy.observation_cost_verification == ObservationCostVerificationMode::Required
    }) {
        return Err(FindingPheromoneError::Convention(
            "verified observation cost policy",
        ));
    }
    let commitment = body
        .cost_commitment
        .as_ref()
        .ok_or(FindingPheromoneError::Convention("observation cost"))?;
    if commitment.statement.cost.unit != OBSERVATION_COST_UNIT {
        return Err(FindingPheromoneError::Convention("observation cost unit"));
    }
    if commitment.statement.cost.amount > convention.max_observation_cost_microunits {
        return Err(FindingPheromoneError::ObservationCostExceeded);
    }
    Ok(())
}

fn validate_current_listing(listing: &Listing, now: u64) -> Result<(), FindingPheromoneError> {
    let freshness_window = GenericListingFreshnessWindow {
        max_age_secs: listing.freshness.max_age_secs,
        valid_until: listing.freshness.valid_until,
    };
    freshness_window
        .validate(listing.freshness.generated_at)
        .map_err(FindingPheromoneError::Listing)?;
    let assessed_freshness = freshness_window.assess(listing.freshness.generated_at, now);
    if listing.freshness != assessed_freshness
        || assessed_freshness.state != GenericListingFreshnessState::Fresh
        || !listing.is_admissible_at(now)
        || listing.freshness.valid_until <= now
        || listing.listing.body.status != GenericListingStatus::Active
        || listing
            .listing
            .body
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(FindingPheromoneError::Listing(
            "listing is not current".to_string(),
        ));
    }
    ensure_generic_listing_signed_by_namespace_owner(&listing.listing, "finding listing")
        .map_err(FindingPheromoneError::Listing)?;
    listing
        .pricing
        .body
        .validate()
        .map_err(FindingPheromoneError::Listing)?;
    match listing.pricing.verify_signature() {
        Ok(true) => {}
        Ok(false) => {
            return Err(FindingPheromoneError::Listing(
                "pricing hint signature is invalid".to_string(),
            ));
        }
        Err(error) => return Err(FindingPheromoneError::Listing(error.to_string())),
    }
    if normalize_namespace(&listing.pricing.body.namespace)
        != normalize_namespace(&listing.listing.body.namespace)
        || listing.pricing.body.listing_id != listing.listing.body.listing_id
        || listing.pricing.body.provider_operator_id != listing.publisher.operator_id
        || listing.pricing.body.provider_operator_id
            != listing.listing.body.namespace_ownership.owner_id
        || listing.pricing.signer_key != listing.listing.body.namespace_ownership.signer_public_key
    {
        return Err(FindingPheromoneError::Listing(
            "pricing hint is not bound to the current listing authority".to_string(),
        ));
    }
    Ok(())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
