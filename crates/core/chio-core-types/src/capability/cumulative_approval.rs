use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{
    is_default_optional_algorithm, sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm,
    SigningBackend,
};
use crate::error::{Error, Result};
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
};

use super::attenuation::{
    scope_hash, validate_delegable_attenuation, validate_delegation_chain, ScopeHash,
};
use super::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use super::token::{CapabilityToken, CapabilityTokenBody};

pub const CUMULATIVE_APPROVAL_ROOT_SCHEMA: &str = "chio.cumulative-approval-root.v1";
pub const MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER: usize = 64;

const ROOT_COMMITMENT_DOMAIN: &[u8] = b"chio.cumulative-approval-root-commitment.v1\0";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"chio.cumulative-approval-root.v1\0";
const ROOT_BINDING_DIGEST_DOMAIN: &[u8] = b"chio.cumulative-approval-root-binding-digest.v1\0";
const ROOT_GRANT_HASH_DOMAIN: &[u8] = b"chio.cumulative-approval-root-grant.v1\0";
const FAMILY_KEY_DOMAIN: &[u8] = b"chio.cumulative-approval-family-key.v1\0";
const DIRECT_KEY_DOMAIN: &[u8] = b"chio.cumulative-approval-direct-key.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CumulativeApprovalRootBindingBody {
    pub schema: String,
    pub signer_key_epoch: u64,
    pub root_capability_id: String,
    pub root_capability_hash: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub root_scope_hash: ScopeHash,
    pub root_grant_hash: String,
    pub approval_budget_id: String,
    pub approval_budget_epoch: u64,
    pub threshold: MonetaryAmount,
    pub root_expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CumulativeApprovalRootBinding {
    pub body: CumulativeApprovalRootBindingBody,
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CumulativeApprovalBindingMarker {
    approval_budget_id: String,
    approval_budget_epoch: u64,
    currency: String,
    root_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CumulativeApprovalDelegationMarker {
    bindings: Vec<CumulativeApprovalBindingMarker>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCumulativeApprovalConstraint {
    pub grant_index: usize,
    pub authority_id: PublicKey,
    pub owner_id: String,
    pub approval_budget_id: String,
    pub approval_budget_epoch: u64,
    pub authority_threshold: MonetaryAmount,
    pub threshold: MonetaryAmount,
    pub root_grant_hash: String,
    pub delegation_root_id: Option<String>,
    pub root_binding_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CumulativeApprovalRootCommitment {
    signer_key_epoch: u64,
    root_capability_id: String,
    root_issuer: PublicKey,
    root_subject: PublicKey,
    root_scope_hash: ScopeHash,
    root_grant_hash: String,
    root_issued_at: u64,
    root_expires_at: u64,
    approval_budget_id: String,
    approval_budget_epoch: u64,
    threshold: MonetaryAmount,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CumulativeApprovalDirectOwner<'a> {
    root_capability_id: &'a str,
    root_issuer: &'a PublicKey,
    root_grant_hash: &'a str,
    approval_budget_id: &'a str,
    approval_budget_epoch: u64,
    currency: &'a str,
}

impl CumulativeApprovalRootBinding {
    pub fn sign(body: CumulativeApprovalRootBindingBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.root_issuer,
            keypair,
            "cumulative approval root binding",
            "root_issuer",
        )?;
        let signature = keypair.sign(&domain_message(ROOT_SIGNATURE_DOMAIN, &body)?);
        Ok(Self {
            body,
            algorithm: None,
            signature,
        })
    }

    pub fn sign_with_backend(
        body: CumulativeApprovalRootBindingBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        ensure_backend_matches_embedded_key(
            &body.root_issuer,
            backend,
            "cumulative approval root binding",
            "root_issuer",
        )?;
        let signature = backend.sign_bytes(&domain_message(ROOT_SIGNATURE_DOMAIN, &body)?)?;
        Ok(Self {
            body,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        if self.body.schema != CUMULATIVE_APPROVAL_ROOT_SCHEMA {
            return Err(violation(format!(
                "unsupported cumulative approval root schema {}",
                self.body.schema
            )));
        }
        if self
            .algorithm
            .is_some_and(|algorithm| algorithm != self.signature.algorithm())
        {
            return Err(violation(
                "cumulative approval root signature algorithm does not match its envelope",
            ));
        }
        Ok(self.body.root_issuer.verify(
            &domain_message(ROOT_SIGNATURE_DOMAIN, &self.body)?,
            &self.signature,
        ))
    }

    pub fn digest(&self) -> Result<String> {
        domain_hash(ROOT_BINDING_DIGEST_DOMAIN, self)
    }

    pub(crate) fn family_owner_id(&self) -> Result<String> {
        domain_hash(FAMILY_KEY_DOMAIN, &self.body)
    }

    pub(crate) fn canonical_eq(&self, other: &Self) -> bool {
        canonical_json_bytes(self)
            .and_then(|left| canonical_json_bytes(other).map(|right| left == right))
            .unwrap_or(false)
    }

    fn delegation_binding_marker(&self) -> Result<CumulativeApprovalBindingMarker> {
        if !self.verify_signature()? {
            return Err(Error::SignatureVerificationFailed);
        }
        validate_amount(&self.body.threshold)?;
        validate_approval_budget_id(&self.body.approval_budget_id)?;
        Ok(CumulativeApprovalBindingMarker {
            approval_budget_id: self.body.approval_budget_id.clone(),
            approval_budget_epoch: self.body.approval_budget_epoch,
            currency: self.body.threshold.currency.clone(),
            root_binding_digest: self.digest()?,
        })
    }
}

impl CumulativeApprovalDelegationMarker {
    pub fn bindings(&self) -> &[CumulativeApprovalBindingMarker] {
        &self.bindings
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.bindings.is_empty()
            || self.bindings.len() > MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER
        {
            return Err(violation(format!(
                "cumulative approval delegation marker must contain 1 to {} bindings",
                MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER
            )));
        }
        for binding in &self.bindings {
            validate_approval_budget_id(&binding.approval_budget_id)?;
            validate_currency(&binding.currency)?;
            if binding.root_binding_digest.len() != 64
                || !binding
                    .root_binding_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(violation(
                    "cumulative approval root binding digest must be lowercase SHA-256 hex",
                ));
            }
        }
        if self
            .bindings
            .windows(2)
            .any(|pair| pair.first() >= pair.get(1))
        {
            return Err(violation(
                "cumulative approval delegation bindings must be sorted and unique",
            ));
        }
        Ok(())
    }

    pub(crate) fn is_subset_of(&self, parent: &Self) -> bool {
        self.bindings
            .iter()
            .all(|binding| parent.bindings.binary_search(binding).is_ok())
    }
}

pub(crate) fn cumulative_approval_delegation_marker(
    scope: &ChioScope,
) -> Result<Option<CumulativeApprovalDelegationMarker>> {
    let mut bindings = Vec::new();
    for grant in &scope.grants {
        for constraint in &grant.constraints {
            if let Some(binding) = constraint.cumulative_approval_root_binding() {
                bindings.push(binding.delegation_binding_marker()?);
            }
        }
    }
    bindings.sort_unstable();
    bindings.dedup();
    if bindings.is_empty() {
        return Ok(None);
    }
    let marker = CumulativeApprovalDelegationMarker { bindings };
    marker.validate()?;
    Ok(Some(marker))
}

pub(crate) fn bind_family_roots(
    body: &mut CapabilityTokenBody,
    signer_key_epoch: u64,
    keypair: &Keypair,
) -> Result<()> {
    ensure_keypair_matches_embedded_key(&body.issuer, keypair, "capability token", "issuer")?;
    bind_family_roots_with(body, signer_key_epoch, |binding_body| {
        CumulativeApprovalRootBinding::sign(binding_body, keypair)
    })
}

pub(crate) fn bind_family_roots_with_backend(
    body: &mut CapabilityTokenBody,
    signer_key_epoch: u64,
    backend: &dyn SigningBackend,
) -> Result<()> {
    ensure_backend_matches_embedded_key(&body.issuer, backend, "capability token", "issuer")?;
    bind_family_roots_with(body, signer_key_epoch, |binding_body| {
        CumulativeApprovalRootBinding::sign_with_backend(binding_body, backend)
    })
}

fn bind_family_roots_with(
    body: &mut CapabilityTokenBody,
    signer_key_epoch: u64,
    mut sign: impl FnMut(CumulativeApprovalRootBindingBody) -> Result<CumulativeApprovalRootBinding>,
) -> Result<()> {
    if !body.delegation_chain.is_empty() {
        return Err(violation(
            "cumulative approval family root must have an empty delegation chain",
        ));
    }
    let mut targets = Vec::new();
    for (grant_index, grant) in body.scope.grants.iter().enumerate() {
        for (constraint_index, constraint) in grant.constraints.iter().enumerate() {
            if let Constraint::RequireCumulativeApprovalAbove {
                threshold,
                approval_budget_id,
                approval_budget_epoch,
                cumulative_approval_root_binding,
            } = constraint
            {
                if cumulative_approval_root_binding.is_some() {
                    return Err(violation(
                        "cumulative approval family-root issuance requires unbound constraints",
                    ));
                }
                if grant.operations.contains(&Operation::Delegate) {
                    targets.push((
                        grant_index,
                        constraint_index,
                        root_grant_hash(grant)?,
                        threshold.clone(),
                        approval_budget_id.clone(),
                        *approval_budget_epoch,
                    ));
                }
            }
        }
    }
    if targets.is_empty() {
        return Err(violation(
            "cumulative approval family-root issuance found no delegable constraint",
        ));
    }
    for (
        grant_index,
        constraint_index,
        root_grant_hash,
        threshold,
        approval_budget_id,
        approval_budget_epoch,
    ) in targets
    {
        let binding_body = root_binding_body(
            body,
            root_grant_hash,
            &threshold,
            &approval_budget_id,
            approval_budget_epoch,
            signer_key_epoch,
        )?;
        let binding = sign(binding_body)?;
        body.scope.grants[grant_index].constraints[constraint_index]
            .set_cumulative_approval_root_binding(Some(binding))?;
    }
    Ok(())
}

pub(crate) fn validate_cumulative_approval_body(body: &CapabilityTokenBody) -> Result<()> {
    validate_scope_shape(
        &body.scope,
        !body.delegation_chain.is_empty(),
        body.expires_at,
    )
}

pub(crate) fn validate_cumulative_approval_token(token: &CapabilityToken) -> Result<()> {
    validate_scope_shape(
        &token.scope,
        !token.delegation_chain.is_empty(),
        token.expires_at,
    )?;
    if token.delegation_chain.is_empty() {
        for grant in &token.scope.grants {
            let grant_hash = root_grant_hash(grant)?;
            for constraint in &grant.constraints {
                if let Constraint::RequireCumulativeApprovalAbove {
                    threshold,
                    approval_budget_id,
                    approval_budget_epoch,
                    cumulative_approval_root_binding: Some(binding),
                } = constraint
                {
                    verify_binding_matches_root(
                        binding,
                        token,
                        &grant_hash,
                        threshold,
                        approval_budget_id,
                        *approval_budget_epoch,
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub fn verify_cumulative_approval_constraints(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    direct_root: Option<&CapabilityToken>,
) -> Result<Vec<VerifiedCumulativeApprovalConstraint>> {
    if !trusted_issuers.contains(&token.issuer) {
        return Err(violation(
            "cumulative approval capability issuer is not trusted",
        ));
    }
    if !token.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    if token.delegation_chain.is_empty() {
        if direct_root.is_some() {
            return Err(violation(
                "direct cumulative approval capability received unexpected root evidence",
            ));
        }
        return verified_direct(token, trusted_issuers);
    }

    validate_delegation_chain(&token.delegation_chain, None)?;
    let root = direct_root.ok_or_else(|| {
        violation("delegated cumulative approval capability requires direct-root evidence")
    })?;
    verified_descendant(token, root, trusted_issuers)
}

fn validate_scope_shape(scope: &ChioScope, delegated: bool, expires_at: u64) -> Result<()> {
    for grant in &scope.grants {
        for constraint in &grant.constraints {
            let Constraint::RequireCumulativeApprovalAbove {
                threshold,
                approval_budget_id,
                approval_budget_epoch,
                cumulative_approval_root_binding,
            } = constraint
            else {
                continue;
            };
            validate_amount(threshold)?;
            validate_approval_budget_id(approval_budget_id)?;
            let binding_required = delegated || grant.operations.contains(&Operation::Delegate);
            match (binding_required, cumulative_approval_root_binding.as_ref()) {
                (true, None) => {
                    return Err(violation(
                        "delegable or delegated cumulative approval constraint requires a root binding",
                    ));
                }
                (false, Some(_)) => {
                    return Err(violation(
                        "nondelegable direct cumulative approval constraint must not carry a root binding",
                    ));
                }
                (_, Some(binding)) => {
                    if !binding.verify_signature()? {
                        return Err(Error::SignatureVerificationFailed);
                    }
                    let root_threshold = &binding.body.threshold;
                    if binding.body.approval_budget_id != *approval_budget_id
                        || binding.body.approval_budget_epoch != *approval_budget_epoch
                        || root_threshold.currency != threshold.currency
                        || threshold.units > root_threshold.units
                        || expires_at > binding.body.root_expires_at
                    {
                        return Err(violation(
                            "cumulative approval constraint changed fields fixed by its root binding",
                        ));
                    }
                }
                (false, None) => {}
            }
        }
    }
    Ok(())
}

fn verified_direct(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
) -> Result<Vec<VerifiedCumulativeApprovalConstraint>> {
    validate_cumulative_approval_token(token)?;
    if !trusted_issuers.contains(&token.issuer) {
        return Err(violation("cumulative approval root issuer is not trusted"));
    }
    project_verified(token)
}

fn verified_descendant(
    token: &CapabilityToken,
    root: &CapabilityToken,
    trusted_issuers: &[PublicKey],
) -> Result<Vec<VerifiedCumulativeApprovalConstraint>> {
    if !root.delegation_chain.is_empty() {
        return Err(violation(
            "cumulative approval root evidence is not a direct token",
        ));
    }
    if !root.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    let first = token
        .delegation_chain
        .first()
        .ok_or_else(|| violation("delegated capability has no first delegation link"))?;
    let final_link = token
        .delegation_chain
        .last()
        .ok_or_else(|| violation("delegated capability has no final delegation link"))?;
    if final_link.delegatee != token.subject {
        return Err(violation(
            "delegation chain final delegatee does not match capability subject",
        ));
    }
    if first.capability_id != root.id || first.delegator != root.subject {
        return Err(violation(
            "delegation chain does not originate from the authenticated root token",
        ));
    }
    if first.scope_hash.as_ref() != Some(&scope_hash(&root.scope)?) {
        return Err(violation(
            "first delegation link scope hash does not match the authenticated root token",
        ));
    }
    if first.timestamp < root.issued_at || first.timestamp >= root.expires_at {
        return Err(violation(
            "first delegation link is outside the authenticated root validity window",
        ));
    }
    if token.issued_at < final_link.timestamp {
        return Err(violation(
            "delegated capability was issued before its final delegation link",
        ));
    }
    let verified_root = verified_direct(root, trusted_issuers)?;
    if token.delegation_chain.len() > 1
        && (!verified_root.is_empty()
            || token.scope.has_cumulative_approval()
            || token
                .delegation_chain
                .iter()
                .any(|link| link.cumulative_approval.is_some()))
    {
        return Err(violation(
            "multi-hop cumulative approval family delegation requires per-hop signed child-scope witnesses",
        ));
    }
    let root_marker = cumulative_approval_delegation_marker(&root.scope)?;
    if !delegation_marker_is_subset(first.cumulative_approval.as_ref(), root_marker.as_ref()) {
        return Err(violation(
            "first delegation link carries cumulative approval bindings outside the authenticated root",
        ));
    }
    validate_cumulative_approval_token(token)?;
    let descendant_marker = cumulative_approval_delegation_marker(&token.scope)?;
    if !delegation_marker_is_subset(descendant_marker.as_ref(), root_marker.as_ref()) {
        return Err(violation(
            "descendant cumulative approval bindings do not originate from the authenticated root",
        ));
    }
    validate_delegable_attenuation(&root.scope, &token.scope)?;
    if token.expires_at > root.expires_at {
        return Err(violation(
            "delegated capability expires after its cumulative approval root",
        ));
    }
    project_verified(token)
}

fn delegation_marker_is_subset(
    child: Option<&CumulativeApprovalDelegationMarker>,
    parent: Option<&CumulativeApprovalDelegationMarker>,
) -> bool {
    match (child, parent) {
        (None, _) => true,
        (Some(child), Some(parent)) => child.is_subset_of(parent),
        (Some(_), None) => false,
    }
}

fn project_verified(token: &CapabilityToken) -> Result<Vec<VerifiedCumulativeApprovalConstraint>> {
    let mut verified = Vec::new();
    for (grant_index, grant) in token.scope.grants.iter().enumerate() {
        let direct_grant_hash = root_grant_hash(grant)?;
        for constraint in &grant.constraints {
            if let Constraint::RequireCumulativeApprovalAbove {
                threshold,
                approval_budget_id,
                approval_budget_epoch,
                cumulative_approval_root_binding,
            } = constraint
            {
                let (
                    authority_id,
                    owner_id,
                    authority_threshold,
                    root_grant_hash,
                    delegation_root_id,
                    root_binding_digest,
                ) = if let Some(binding) = cumulative_approval_root_binding {
                    (
                        binding.body.root_issuer.clone(),
                        binding.family_owner_id()?,
                        binding.body.threshold.clone(),
                        binding.body.root_grant_hash.clone(),
                        Some(binding.body.root_capability_id.clone()),
                        Some(binding.digest()?),
                    )
                } else {
                    (
                        token.issuer.clone(),
                        domain_hash(
                            DIRECT_KEY_DOMAIN,
                            &CumulativeApprovalDirectOwner {
                                root_capability_id: &token.id,
                                root_issuer: &token.issuer,
                                root_grant_hash: &direct_grant_hash,
                                approval_budget_id,
                                approval_budget_epoch: *approval_budget_epoch,
                                currency: &threshold.currency,
                            },
                        )?,
                        threshold.clone(),
                        direct_grant_hash.clone(),
                        None,
                        None,
                    )
                };
                verified.push(VerifiedCumulativeApprovalConstraint {
                    grant_index,
                    authority_id,
                    owner_id,
                    approval_budget_id: approval_budget_id.clone(),
                    approval_budget_epoch: *approval_budget_epoch,
                    authority_threshold,
                    threshold: threshold.clone(),
                    root_grant_hash,
                    delegation_root_id,
                    root_binding_digest,
                });
            }
        }
    }
    Ok(verified)
}

fn verify_binding_matches_root(
    binding: &CumulativeApprovalRootBinding,
    root: &CapabilityToken,
    root_grant_hash: &str,
    threshold: &MonetaryAmount,
    approval_budget_id: &str,
    approval_budget_epoch: u64,
) -> Result<()> {
    if !binding.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    let expected_scope_hash = unbound_scope_hash(&root.scope)?;
    let expected_hash = root_commitment_hash(
        root,
        root_grant_hash,
        threshold,
        approval_budget_id,
        approval_budget_epoch,
        binding.body.signer_key_epoch,
    )?;
    let body = &binding.body;
    if body.root_capability_id != root.id
        || body.root_capability_hash != expected_hash
        || body.root_issuer != root.issuer
        || body.root_subject != root.subject
        || body.root_scope_hash != expected_scope_hash
        || body.root_grant_hash != root_grant_hash
        || body.approval_budget_id != approval_budget_id
        || body.approval_budget_epoch != approval_budget_epoch
        || body.threshold != *threshold
        || body.root_expires_at != root.expires_at
    {
        return Err(violation(
            "cumulative approval root binding does not match the direct root token",
        ));
    }
    Ok(())
}

fn root_binding_body(
    body: &CapabilityTokenBody,
    root_grant_hash: String,
    threshold: &MonetaryAmount,
    approval_budget_id: &str,
    approval_budget_epoch: u64,
    signer_key_epoch: u64,
) -> Result<CumulativeApprovalRootBindingBody> {
    Ok(CumulativeApprovalRootBindingBody {
        schema: CUMULATIVE_APPROVAL_ROOT_SCHEMA.to_string(),
        signer_key_epoch,
        root_capability_id: body.id.clone(),
        root_capability_hash: root_commitment_hash_from_body(
            body,
            &root_grant_hash,
            threshold,
            approval_budget_id,
            approval_budget_epoch,
            signer_key_epoch,
        )?,
        root_issuer: body.issuer.clone(),
        root_subject: body.subject.clone(),
        root_scope_hash: unbound_scope_hash(&body.scope)?,
        root_grant_hash,
        approval_budget_id: approval_budget_id.to_string(),
        approval_budget_epoch,
        threshold: threshold.clone(),
        root_expires_at: body.expires_at,
    })
}

fn root_commitment_hash(
    token: &CapabilityToken,
    root_grant_hash: &str,
    threshold: &MonetaryAmount,
    approval_budget_id: &str,
    approval_budget_epoch: u64,
    signer_key_epoch: u64,
) -> Result<String> {
    root_commitment_hash_parts(
        &token.id,
        &token.issuer,
        &token.subject,
        &token.scope,
        token.issued_at,
        token.expires_at,
        root_grant_hash,
        threshold,
        approval_budget_id,
        approval_budget_epoch,
        signer_key_epoch,
    )
}

fn root_commitment_hash_from_body(
    body: &CapabilityTokenBody,
    root_grant_hash: &str,
    threshold: &MonetaryAmount,
    approval_budget_id: &str,
    approval_budget_epoch: u64,
    signer_key_epoch: u64,
) -> Result<String> {
    root_commitment_hash_parts(
        &body.id,
        &body.issuer,
        &body.subject,
        &body.scope,
        body.issued_at,
        body.expires_at,
        root_grant_hash,
        threshold,
        approval_budget_id,
        approval_budget_epoch,
        signer_key_epoch,
    )
}

#[allow(clippy::too_many_arguments)]
fn root_commitment_hash_parts(
    id: &str,
    issuer: &PublicKey,
    subject: &PublicKey,
    scope: &ChioScope,
    issued_at: u64,
    expires_at: u64,
    root_grant_hash: &str,
    threshold: &MonetaryAmount,
    approval_budget_id: &str,
    approval_budget_epoch: u64,
    signer_key_epoch: u64,
) -> Result<String> {
    domain_hash(
        ROOT_COMMITMENT_DOMAIN,
        &CumulativeApprovalRootCommitment {
            signer_key_epoch,
            root_capability_id: id.to_string(),
            root_issuer: issuer.clone(),
            root_subject: subject.clone(),
            root_scope_hash: unbound_scope_hash(scope)?,
            root_grant_hash: root_grant_hash.to_string(),
            root_issued_at: issued_at,
            root_expires_at: expires_at,
            approval_budget_id: approval_budget_id.to_string(),
            approval_budget_epoch,
            threshold: threshold.clone(),
        },
    )
}

fn root_grant_hash(grant: &ToolGrant) -> Result<String> {
    let mut unbound = grant.clone();
    for constraint in &mut unbound.constraints {
        constraint.clear_cumulative_approval_root_binding();
    }
    domain_hash(ROOT_GRANT_HASH_DOMAIN, &unbound)
}

fn unbound_scope_hash(scope: &ChioScope) -> Result<ScopeHash> {
    let mut unbound = scope.clone();
    for grant in &mut unbound.grants {
        for constraint in &mut grant.constraints {
            constraint.clear_cumulative_approval_root_binding();
        }
    }
    scope_hash(&unbound)
}

fn validate_amount(amount: &MonetaryAmount) -> Result<()> {
    validate_currency(&amount.currency)
}

fn validate_currency(currency: &str) -> Result<()> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(violation(
            "cumulative approval threshold currency must be an uppercase ISO 4217 code",
        ));
    }
    Ok(())
}

fn validate_approval_budget_id(approval_budget_id: &str) -> Result<()> {
    if approval_budget_id.is_empty() || approval_budget_id.len() > 128 {
        return Err(violation(
            "cumulative approval budget id must contain 1 to 128 bytes",
        ));
    }
    Ok(())
}

fn domain_message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let mut message = Vec::with_capacity(domain.len() + canonical.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    Ok(sha256_hex(&domain_message(domain, value)?))
}

fn violation(reason: impl Into<String>) -> Error {
    Error::AttenuationViolation {
        reason: reason.into(),
    }
}
