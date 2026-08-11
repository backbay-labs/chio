use chio_finding::FindingBondClass;
use chio_fiscal::fee_schedule::{OpenMarketBondClass, OpenMarketBondRequirement};

use super::*;

pub(super) fn verify_bond_requirement(
    finding: &Finding,
    snapshot: &FindingBondSnapshot,
    trust: &FindingVerifierTrustRoots,
) -> Result<(), String> {
    let backing = &snapshot.backing.body;
    let schedule = &snapshot.fee_schedule;
    let store_snapshot = &snapshot.store_snapshot.body;
    if store_snapshot.bond_ref != finding.bond_ref {
        return Err("collateral store snapshot resolves a different Finding bond_ref".to_string());
    }
    if trust.fee_schedule_authorities.is_empty()
        || !trust
            .fee_schedule_authorities
            .contains(&schedule.signer_key)
    {
        return Err("fee schedule signer is not deployment-pinned".to_string());
    }
    verify_pinned_envelope(schedule, &schedule.signer_key, "finding_fee_schedule")
        .map_err(|error| format!("fee schedule envelope rejected: {error}"))?;
    schedule
        .body
        .validate()
        .map_err(|error| format!("fee schedule body rejected: {error}"))?;
    let schedule_sha256 = signed_envelope_sha256(schedule)
        .map_err(|error| format!("fee schedule digest rejected: {error}"))?;
    if schedule_sha256 != backing.fee_schedule_envelope_sha256 {
        return Err("backing allocation names a different fee schedule".to_string());
    }
    if schedule.body.issued_at > backing.issued_at
        || schedule
            .body
            .expires_at
            .is_some_and(|expires_at| trust.trusted_time >= expires_at)
    {
        return Err("fee schedule is not active for the backing evaluation".to_string());
    }

    let requirement = resolve_requirement(
        &schedule.body.bond_requirements,
        &backing.fee_requirement_sha256,
    )?;
    if requirement.bond_class != OpenMarketBondClass::Listing
        || backing.bond_class != FindingBondClass::Listing
    {
        return Err("backing allocation does not satisfy the Listing bond class".to_string());
    }
    if !requirement.slashable {
        return Err("referenced Listing bond requirement is not slashable".to_string());
    }
    if requirement.required_amount.currency != backing.locked_amount.currency
        || requirement.required_amount.currency != backing.maximum_sale_exposure.currency
    {
        return Err("backing allocation currency differs from its requirement".to_string());
    }
    if requirement.required_amount.units < backing.maximum_sale_exposure.units {
        return Err("Listing requirement does not cover maximum sale exposure".to_string());
    }
    Ok(())
}

fn resolve_requirement<'a>(
    requirements: &'a [OpenMarketBondRequirement],
    required_sha256: &str,
) -> Result<&'a OpenMarketBondRequirement, String> {
    let mut resolved = None;
    for requirement in requirements {
        let bytes = canonical_json_bytes(requirement)
            .map_err(|error| format!("fee requirement canonicalization failed: {error}"))?;
        if sha256_hex(&bytes) == required_sha256 {
            if resolved.is_some() {
                return Err("fee schedule resolves the requirement digest ambiguously".to_string());
            }
            resolved = Some(requirement);
        }
    }
    resolved.ok_or_else(|| "fee schedule does not resolve the backing requirement".to_string())
}
