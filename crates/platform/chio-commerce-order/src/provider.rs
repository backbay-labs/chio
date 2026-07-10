use super::error::CommerceOrderError;
use super::ids::{
    COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID, COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID,
    COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID,
};
use super::types::{
    CommerceFederationTrustBundle, CommerceOrderContext, CommerceProviderPassport,
    CommerceReputationSnapshot,
};
use super::validation::{parse_rfc3339_utc, require_non_empty};
use chio_core_types::crypto::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::Serialize;

const MAX_PROVIDER_TRUST_EVIDENCE_AGE_SECONDS: i64 = 86_400;
const MIN_ACCEPTED_REPUTATION_SCORE_BPS: u16 = 1;

pub(super) fn validate_provider_trust_evidence(
    context: &CommerceOrderContext,
    provider_passport: &CommerceProviderPassport,
    reputation_snapshot: &CommerceReputationSnapshot,
    federation_trust_bundle: &CommerceFederationTrustBundle,
    trusted_provider_trust_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    let context_issued_at = parse_rfc3339_utc(&context.issued_at, "order context issued_at")?;
    validate_provider_passport(
        context,
        context_issued_at,
        provider_passport,
        trusted_provider_trust_signer_keys,
    )?;
    validate_reputation_snapshot(
        context,
        context_issued_at,
        reputation_snapshot,
        trusted_provider_trust_signer_keys,
    )?;
    validate_federation_trust_bundle(
        context,
        context_issued_at,
        federation_trust_bundle,
        trusted_provider_trust_signer_keys,
    )?;
    Ok(())
}

fn validate_provider_passport(
    context: &CommerceOrderContext,
    context_issued_at: DateTime<Utc>,
    passport: &CommerceProviderPassport,
    trusted_provider_trust_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    if passport.schema != COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "provider passport",
            schema: passport.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &passport.id),
        ("issued_at", &passport.issued_at),
        ("provider_subject", &passport.provider_subject),
        ("status", &passport.status),
        ("signature", &passport.signature),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ProviderTrustFailed)?;
    }
    if passport.id != context.provider_passport_ref {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "provider passport ref mismatch".to_string(),
        ));
    }
    if passport.provider_subject != context.merchant_subject {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "provider passport subject mismatch".to_string(),
        ));
    }
    if passport.status != "active" {
        return Err(CommerceOrderError::ProviderTrustFailed(format!(
            "provider passport not active: {}",
            passport.status
        )));
    }
    if passport.service_families.is_empty() {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "provider passport missing service families".to_string(),
        ));
    }
    validate_provider_trust_recency("provider passport", context_issued_at, &passport.issued_at)?;
    verify_provider_trust_signature(
        "provider passport",
        passport,
        &passport.signature,
        trusted_provider_trust_signer_keys,
    )?;
    Ok(())
}

fn validate_reputation_snapshot(
    context: &CommerceOrderContext,
    context_issued_at: DateTime<Utc>,
    reputation: &CommerceReputationSnapshot,
    trusted_provider_trust_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    if reputation.schema != COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "reputation snapshot",
            schema: reputation.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &reputation.id),
        ("issued_at", &reputation.issued_at),
        ("provider_subject", &reputation.provider_subject),
        ("status", &reputation.status),
        ("signature", &reputation.signature),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ProviderTrustFailed)?;
    }
    if reputation.id != context.reputation_snapshot_ref {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "reputation snapshot ref mismatch".to_string(),
        ));
    }
    if reputation.provider_subject != context.merchant_subject {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "reputation snapshot subject mismatch".to_string(),
        ));
    }
    if reputation.status != "accepted" {
        return Err(CommerceOrderError::ProviderTrustFailed(format!(
            "reputation snapshot not accepted: {}",
            reputation.status
        )));
    }
    if reputation.score_bps > 10_000 {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "reputation score exceeds 10000 bps".to_string(),
        ));
    }
    if reputation.score_bps < MIN_ACCEPTED_REPUTATION_SCORE_BPS {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "reputation score below minimum accepted floor".to_string(),
        ));
    }
    validate_provider_trust_recency(
        "reputation snapshot",
        context_issued_at,
        &reputation.issued_at,
    )?;
    verify_provider_trust_signature(
        "reputation snapshot",
        reputation,
        &reputation.signature,
        trusted_provider_trust_signer_keys,
    )?;
    Ok(())
}

fn validate_federation_trust_bundle(
    context: &CommerceOrderContext,
    context_issued_at: DateTime<Utc>,
    trust_bundle: &CommerceFederationTrustBundle,
    trusted_provider_trust_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    if trust_bundle.schema != COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "federation trust bundle",
            schema: trust_bundle.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &trust_bundle.id),
        ("issued_at", &trust_bundle.issued_at),
        ("provider_subject", &trust_bundle.provider_subject),
        ("trust_domain", &trust_bundle.trust_domain),
        ("status", &trust_bundle.status),
        ("trust_root_ref", &trust_bundle.trust_root_ref),
        ("signature", &trust_bundle.signature),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ProviderTrustFailed)?;
    }
    if trust_bundle.id != context.federation_trust_bundle_ref {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "federation trust bundle ref mismatch".to_string(),
        ));
    }
    if trust_bundle.provider_subject != context.merchant_subject {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "federation trust bundle subject mismatch".to_string(),
        ));
    }
    if trust_bundle.status != "trusted" {
        return Err(CommerceOrderError::ProviderTrustFailed(format!(
            "federation trust bundle not trusted: {}",
            trust_bundle.status
        )));
    }
    validate_provider_trust_recency(
        "federation trust bundle",
        context_issued_at,
        &trust_bundle.issued_at,
    )?;
    verify_provider_trust_signature(
        "federation trust bundle",
        trust_bundle,
        &trust_bundle.signature,
        trusted_provider_trust_signer_keys,
    )?;
    Ok(())
}

fn validate_provider_trust_recency(
    label: &'static str,
    context_issued_at: DateTime<Utc>,
    issued_at: &str,
) -> Result<(), CommerceOrderError> {
    let issued_at = parse_rfc3339_utc(issued_at, "provider trust issued_at")?;
    if issued_at > context_issued_at {
        return Err(CommerceOrderError::ProviderTrustFailed(format!(
            "{label} issued after order context"
        )));
    }
    let age_seconds = context_issued_at
        .signed_duration_since(issued_at)
        .num_seconds();
    if age_seconds > MAX_PROVIDER_TRUST_EVIDENCE_AGE_SECONDS {
        return Err(CommerceOrderError::ProviderTrustFailed(format!(
            "{label} stale for order context"
        )));
    }
    Ok(())
}

fn verify_provider_trust_signature<T: Serialize>(
    label: &'static str,
    artifact: &T,
    signature: &str,
    trusted_provider_trust_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    if trusted_provider_trust_signer_keys.is_empty() {
        return Err(CommerceOrderError::ProviderTrustFailed(
            "provider trust signer roots missing".to_string(),
        ));
    }
    let signature = Signature::from_hex(signature).map_err(|_| {
        CommerceOrderError::ProviderTrustFailed(format!("{label} signature invalid"))
    })?;
    let mut signature_body = serde_json::to_value(artifact).map_err(|error| {
        CommerceOrderError::ProviderTrustFailed(format!("{label} signature body invalid: {error}"))
    })?;
    let body = signature_body.as_object_mut().ok_or_else(|| {
        CommerceOrderError::ProviderTrustFailed(format!("{label} signature body invalid"))
    })?;
    body.remove("signature");
    for trusted_key in trusted_provider_trust_signer_keys {
        let verified = trusted_key
            .verify_canonical(&signature_body, &signature)
            .map_err(|_| {
                CommerceOrderError::ProviderTrustFailed(format!("{label} signature invalid"))
            })?;
        if verified {
            return Ok(());
        }
    }
    Err(CommerceOrderError::ProviderTrustFailed(format!(
        "{label} signature invalid"
    )))
}
