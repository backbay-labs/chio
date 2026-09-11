//! Construct and validate delegation with a signed witness for every hop.
//!
//! The issuer keeps its signing key; holders authorize only their own narrowed
//! child. These pure signing helpers do not replace runtime trust, revocation,
//! quota or caller-authentication checks at admission.

use alloc::{format, string::String, vec::Vec};

use crate::{
    crypto::{Keypair, PublicKey},
    delegation_receipt::{DelegationReceipt, ScopeAttenuation},
    error::{Error, Result},
};

use super::{
    attenuation::{
        compute_attenuation_witness, delegate, scope_hash, validate_attenuation_proof,
        validate_delegable_attenuation, validate_delegation_chain_with_trust_root,
        validate_steps_reflected_in_child, AttenuationProof, DelegationChildBinding,
        DelegationLink,
    },
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
    validation::MAX_BUDGET_SHARE_BPS,
};

/// Exact child requested from an issuer, authorized by the current holder.
pub struct DelegatedCapabilityRequest {
    pub id: String,
    pub subject: PublicKey,
    pub scope: ChioScope,
    pub issued_at: u64,
    pub expires_at: u64,
    pub budget_share_bps: Option<u16>,
    pub nonce: [u8; 16],
}

fn violation(reason: impl Into<String>) -> Error {
    Error::AttenuationViolation {
        reason: reason.into(),
    }
}

/// Mint one child without dropping its preceding signed scope witnesses.
///
/// `holder` must own `parent.subject`; `issuer` must own `parent.issuer`.
/// Authority rotation is deliberately not inferred from a supplied key. The
/// caller must resolve authorized rotation separately before changing issuers.
/// Every hop narrows grants, expiry and budget share. Intermediate parents
/// created by older helpers without child bindings cannot be extended.
pub fn issue_delegated_capability(
    parent: &CapabilityToken,
    request: DelegatedCapabilityRequest,
    holder: &Keypair,
    issuer: &Keypair,
) -> Result<(CapabilityToken, DelegationReceipt)> {
    if parent.issuer != issuer.public_key() || !parent.verify_signature()? {
        return Err(violation(
            "delegation issuer does not authenticate this parent",
        ));
    }
    // A normalized scope witness does not prove inheritance of first-party
    // caveat predicates. Do not silently strip those conditions while minting.
    if !parent.caveats.is_empty() {
        return Err(violation(
            "delegating a caveated parent requires a caveat-aware issuer",
        ));
    }
    if request.id.is_empty()
        || request.id.len() > 256
        || request.id == parent.id
        || parent
            .delegation_chain
            .iter()
            .any(|link| link.capability_id == request.id)
    {
        return Err(violation(
            "child capability ID is empty, oversized or already in its ancestry",
        ));
    }
    if request.issued_at < parent.issued_at
        || request.issued_at >= parent.expires_at
        || request.expires_at <= request.issued_at
        || request.expires_at > parent.expires_at
    {
        return Err(violation(
            "child capability is outside its parent's validity window",
        ));
    }
    if !parent.delegation_chain.is_empty() {
        let root = parent.delegation_chain[0]
            .scope_hash
            .as_ref()
            .ok_or_else(|| violation("parent omits its trusted root scope binding"))?;
        validate_delegation_chain_with_trust_root(&parent.delegation_chain, Some(64), root)?;
        validate_leaf_binding(parent)?;
        if parent
            .delegation_chain
            .iter()
            .any(|link| link.child_binding.is_none())
        {
            return Err(violation(
                "extending this parent requires per-hop child-scope witnesses",
            ));
        }
    }
    // Family-wide money/approval markers have additional root authentication
    // rules. Keep their current explicit gate until those validators support
    // the new witness on every hop; never weaken them through this helper.
    if !parent.delegation_chain.is_empty()
        && (parent.aggregate_invocation_budget.is_some() || parent.scope.has_cumulative_approval())
    {
        return Err(violation(
            "multi-hop aggregate or cumulative approval families require their root verifier",
        ));
    }
    let mut proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent.scope)?,
        child_scope_hash: scope_hash(&request.scope)?,
        normalized_subset_proof: compute_attenuation_witness(&parent.scope, &request.scope)?,
    };
    proof.normalized_subset_proof.aggregate_budget = parent
        .aggregate_invocation_budget
        .as_ref()
        .and_then(|budget| budget.root_binding.as_ref())
        .map(|binding| binding.delegation_marker())
        .transpose()?;
    let mut receipt = delegate(
        parent,
        &request.scope,
        holder,
        &request.subject,
        ScopeAttenuation {
            steps: Vec::new(),
            child_expires_at: Some(request.expires_at),
            budget_share_bps: request.budget_share_bps,
        },
        request.issued_at,
        request.nonce,
    )?;
    let mut link = receipt.link.body();
    link.child_binding = Some(DelegationChildBinding {
        capability_id: request.id.clone(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        budget_share_bps: request.budget_share_bps,
        attenuation_proof: proof.clone(),
    });
    receipt.link = DelegationLink::sign(link, holder)?;
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: request.id,
                issuer: issuer.public_key(),
                subject: request.subject,
                scope: request.scope,
                issued_at: request.issued_at,
                expires_at: request.expires_at,
                delegation_chain: receipt.complete_chain(),
                aggregate_invocation_budget: parent.aggregate_invocation_budget.clone(),
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: proof,
            budget_share_bps: request.budget_share_bps,
        },
        issuer,
    )?;
    validate_leaf_binding(&token)?;
    Ok((token, receipt))
}

pub(crate) fn validate_child_binding(
    link: &DelegationLink,
    binding: &DelegationChildBinding,
) -> Result<()> {
    if binding.capability_id.is_empty()
        || binding.capability_id.len() > 256
        || binding.capability_id == link.capability_id
        || binding.issued_at != link.timestamp
        || binding.expires_at <= binding.issued_at
        || binding
            .budget_share_bps
            .is_some_and(|share| share > MAX_BUDGET_SHARE_BPS)
        || link.scope_hash.as_ref() != Some(&binding.attenuation_proof.parent_scope_hash)
    {
        return Err(violation(
            "signed child binding has invalid identity, validity, budget or parent scope",
        ));
    }
    let proof = &binding.attenuation_proof;
    validate_attenuation_proof(
        &proof.parent_scope_hash,
        &proof.child_scope_hash,
        &proof.normalized_subset_proof,
    )?;
    let parent: ChioScope =
        serde_json::from_str(&proof.normalized_subset_proof.normalized_parent_scope)
            .map_err(|error| violation(format!("invalid parent scope: {error}")))?;
    let child: ChioScope =
        serde_json::from_str(&proof.normalized_subset_proof.normalized_child_scope)
            .map_err(|error| violation(format!("invalid child scope: {error}")))?;
    validate_delegable_attenuation(&parent, &child)?;
    validate_steps_reflected_in_child(&child, binding.expires_at, &link.attenuations)?;
    Ok(())
}

/// Bind the final signed child to the capability actually presented.
/// Old single-hop links without this field remain compatible. Multi-hop
/// callers additionally run `validate_delegation_chain_with_trust_root`.
pub fn validate_leaf_binding(token: &CapabilityToken) -> Result<()> {
    if let Some(link) = token.delegation_chain.last() {
        if let Some(binding) = link.child_binding.as_ref() {
            validate_child_binding(link, binding)?;
            if binding.capability_id != token.id
                || link.delegatee != token.subject
                || binding.issued_at != token.issued_at
                || binding.expires_at != token.expires_at
                || binding.budget_share_bps != token.budget_share_bps
                || binding.attenuation_proof.child_scope_hash != scope_hash(&token.scope)?
                || token.attenuation_proof.as_ref() != Some(&binding.attenuation_proof)
            {
                return Err(violation(
                    "presented capability differs from the holder's signed child binding",
                ));
            }
        }
    }
    Ok(())
}
