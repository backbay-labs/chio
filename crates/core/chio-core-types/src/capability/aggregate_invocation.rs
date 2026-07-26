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
use super::scope::ChioScope;
use super::token::{CapabilityToken, CapabilityTokenBody};

pub const AGGREGATE_BUDGET_ROOT_SCHEMA: &str = "chio.aggregate-budget-root.v1";

const ROOT_COMMITMENT_DOMAIN: &[u8] = b"chio.aggregate-budget-root-commitment.v1\0";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"chio.aggregate-budget-root.v1\0";
const ROOT_BINDING_DIGEST_DOMAIN: &[u8] = b"chio.aggregate-budget-root-binding-digest.v1\0";
const FAMILY_KEY_DOMAIN: &[u8] = b"chio.aggregate-budget-family-key.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateInvocationScope {
    Capability,
    DelegationFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateInvocationBudget {
    pub scope: AggregateInvocationScope,
    pub max_invocations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_binding: Option<AggregateBudgetRootBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBindingBody {
    pub schema: String,
    pub root_capability_id: String,
    pub root_capability_hash: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub max_invocations: u32,
    pub root_expires_at: u64,
    pub root_scope_hash: ScopeHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBinding {
    pub body: AggregateBudgetRootBindingBody,
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetDelegationMarker {
    pub root_binding_digest: String,
    pub max_invocations: u32,
}

impl AggregateBudgetDelegationMarker {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.root_binding_digest.len() != 64
            || !self
                .root_binding_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(violation(
                "aggregate budget root binding digest must be lowercase SHA-256 hex",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAggregateInvocationBudget {
    pub scope: AggregateInvocationScope,
    pub owner_id: String,
    pub max_invocations: u32,
    pub root_binding_digest: Option<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateBudgetRootCommitment {
    root_capability_id: String,
    root_issuer: PublicKey,
    root_subject: PublicKey,
    root_scope_hash: ScopeHash,
    root_issued_at: u64,
    root_expires_at: u64,
    aggregate_scope: AggregateInvocationScope,
    max_invocations: u32,
}

impl AggregateBudgetRootBinding {
    pub fn sign(body: AggregateBudgetRootBindingBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.root_issuer,
            keypair,
            "aggregate budget root binding",
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
        body: AggregateBudgetRootBindingBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        ensure_backend_matches_embedded_key(
            &body.root_issuer,
            backend,
            "aggregate budget root binding",
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
        if self.body.schema != AGGREGATE_BUDGET_ROOT_SCHEMA {
            return Err(violation(format!(
                "unsupported aggregate budget root schema {}",
                self.body.schema
            )));
        }
        if self
            .algorithm
            .is_some_and(|algorithm| algorithm != self.signature.algorithm())
        {
            return Err(violation(
                "aggregate budget root signature algorithm does not match its envelope",
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

    pub(crate) fn delegation_marker(&self) -> Result<AggregateBudgetDelegationMarker> {
        Ok(AggregateBudgetDelegationMarker {
            root_binding_digest: self.digest()?,
            max_invocations: self.body.max_invocations,
        })
    }
}

pub(crate) fn build_family_root_binding(
    body: &CapabilityTokenBody,
    max_invocations: u32,
    keypair: &Keypair,
) -> Result<AggregateBudgetRootBinding> {
    AggregateBudgetRootBinding::sign(root_binding_body(body, max_invocations)?, keypair)
}

pub(crate) fn build_family_root_binding_with_backend(
    body: &CapabilityTokenBody,
    max_invocations: u32,
    backend: &dyn SigningBackend,
) -> Result<AggregateBudgetRootBinding> {
    AggregateBudgetRootBinding::sign_with_backend(
        root_binding_body(body, max_invocations)?,
        backend,
    )
}

pub fn verify_aggregate_invocation_budget(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    direct_root: Option<&CapabilityToken>,
) -> Result<Option<VerifiedAggregateInvocationBudget>> {
    if !trusted_issuers.contains(&token.issuer) {
        return Err(violation("aggregate capability issuer is not trusted"));
    }
    if !token.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    if token.delegation_chain.is_empty() {
        if direct_root.is_some() {
            return Err(violation(
                "direct aggregate capability received unexpected root evidence",
            ));
        }
        return verify_direct(token, trusted_issuers);
    }

    validate_delegation_chain(&token.delegation_chain, None)?;
    let root = direct_root.ok_or_else(|| {
        violation("delegated capability requires an authenticated direct-root token")
    })?;
    verify_descendant(token, root, trusted_issuers)
}

pub(crate) fn validate_direct_family_binding(token: &CapabilityToken) -> Result<()> {
    let Some(budget) = token.aggregate_invocation_budget.as_ref() else {
        return Ok(());
    };
    if !token.delegation_chain.is_empty()
        || budget.scope != AggregateInvocationScope::DelegationFamily
    {
        return Ok(());
    }
    let binding = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| violation("delegation-family aggregate budget requires a root binding"))?;
    verify_binding_matches_root(binding, token, budget.max_invocations)
}

pub(crate) fn validate_aggregate_budget_shape(
    scope: &ChioScope,
    budget: Option<&AggregateInvocationBudget>,
) -> Result<()> {
    let Some(budget) = budget else {
        return Ok(());
    };
    if scope.has_cumulative_approval() {
        return Err(violation(
            "aggregate invocation and cumulative approval budgets cannot be combined without a joint root binding",
        ));
    }
    match budget.scope {
        AggregateInvocationScope::Capability => {
            if budget.root_binding.is_some() {
                return Err(violation(
                    "capability-scoped aggregate budget must not carry a root binding",
                ));
            }
            if scope.authorizes_delegation() {
                return Err(violation(
                    "capability-scoped aggregate budget cannot authorize delegation",
                ));
            }
        }
        AggregateInvocationScope::DelegationFamily => {
            if budget.root_binding.is_none() {
                return Err(violation(
                    "delegation-family aggregate budget requires a root binding",
                ));
            }
        }
    }
    Ok(())
}

fn verify_direct(
    token: &CapabilityToken,
    trusted_root_issuers: &[PublicKey],
) -> Result<Option<VerifiedAggregateInvocationBudget>> {
    validate_aggregate_budget_shape(&token.scope, token.aggregate_invocation_budget.as_ref())?;
    if !trusted_root_issuers.contains(&token.issuer) {
        return Err(violation("aggregate capability root issuer is not trusted"));
    }
    let Some(budget) = token.aggregate_invocation_budget.as_ref() else {
        return Ok(None);
    };
    match budget.scope {
        AggregateInvocationScope::Capability => Ok(Some(VerifiedAggregateInvocationBudget {
            scope: budget.scope,
            owner_id: token.id.clone(),
            max_invocations: budget.max_invocations,
            root_binding_digest: None,
        })),
        AggregateInvocationScope::DelegationFamily => {
            let binding = budget.root_binding.as_ref().ok_or_else(|| {
                violation("delegation-family aggregate budget requires a root binding")
            })?;
            verify_binding_matches_root(binding, token, budget.max_invocations)?;
            Ok(Some(VerifiedAggregateInvocationBudget {
                scope: budget.scope,
                owner_id: binding.family_owner_id()?,
                max_invocations: budget.max_invocations,
                root_binding_digest: Some(binding.digest()?),
            }))
        }
    }
}

fn verify_descendant(
    token: &CapabilityToken,
    root: &CapabilityToken,
    trusted_root_issuers: &[PublicKey],
) -> Result<Option<VerifiedAggregateInvocationBudget>> {
    if !root.delegation_chain.is_empty() {
        return Err(violation(
            "aggregate budget root evidence is not a direct token",
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
    let root_scope_hash = scope_hash(&root.scope)?;
    if first.scope_hash.as_ref() != Some(&root_scope_hash) {
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

    let verified_root = verify_direct(root, trusted_root_issuers)?;
    if token.delegation_chain.len() > 1
        && (verified_root.is_some()
            || token.aggregate_invocation_budget.is_some()
            || chain_marker(token).is_some())
    {
        return Err(violation(
            "multi-hop aggregate family delegation requires per-hop signed child-scope witnesses",
        ));
    }
    match verified_root {
        None => {
            if token.aggregate_invocation_budget.is_some() || chain_marker(token).is_some() {
                return Err(violation(
                    "delegated capability created an aggregate family below an unbound root",
                ));
            }
            if token.expires_at > root.expires_at {
                return Err(violation(
                    "delegated capability expires after its authenticated root",
                ));
            }
            validate_delegable_attenuation(&root.scope, &token.scope)?;
            Ok(None)
        }
        Some(root_budget) if root_budget.scope == AggregateInvocationScope::Capability => Err(
            violation("capability-scoped aggregate budget cannot be delegated"),
        ),
        Some(root_budget) => {
            let root_budget_wire = root.aggregate_invocation_budget.as_ref().ok_or_else(|| {
                violation("verified aggregate root projection has no signed budget")
            })?;
            let child_budget = token.aggregate_invocation_budget.as_ref().ok_or_else(|| {
                violation("delegated capability omitted its family aggregate budget")
            })?;
            let root_binding = root_budget_wire.root_binding.as_ref().ok_or_else(|| {
                violation("verified aggregate root projection has no root binding")
            })?;
            let child_binding = child_budget.root_binding.as_ref().ok_or_else(|| {
                violation("delegation-family aggregate budget requires a root binding")
            })?;
            if child_budget.scope != AggregateInvocationScope::DelegationFamily
                || child_budget.max_invocations != root_budget.max_invocations
                || canonical_json_bytes(child_binding)? != canonical_json_bytes(root_binding)?
            {
                return Err(violation(
                    "delegated capability changed its family aggregate budget",
                ));
            }
            if token.expires_at > root.expires_at {
                return Err(violation(
                    "delegated capability expires after its aggregate budget root",
                ));
            }
            validate_delegable_attenuation(&root.scope, &token.scope)?;
            verify_binding_matches_root(child_binding, root, child_budget.max_invocations)?;
            let marker = child_binding.delegation_marker()?;
            for link in &token.delegation_chain {
                if link.aggregate_budget.as_ref() != Some(&marker) {
                    return Err(violation(
                        "delegation link changed or omitted the aggregate budget marker",
                    ));
                }
            }
            if let Some(proof) = token.attenuation_proof.as_ref() {
                if proof.normalized_subset_proof.aggregate_budget.as_ref() != Some(&marker) {
                    return Err(violation(
                        "attenuation witness changed or omitted the aggregate budget marker",
                    ));
                }
            }
            Ok(Some(root_budget))
        }
    }
}

fn verify_binding_matches_root(
    binding: &AggregateBudgetRootBinding,
    root: &CapabilityToken,
    max_invocations: u32,
) -> Result<()> {
    if !binding.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    let expected_scope_hash = scope_hash(&root.scope)?;
    let expected_hash = root_commitment_hash(root, max_invocations)?;
    let body = &binding.body;
    if body.root_capability_id != root.id
        || body.root_capability_hash != expected_hash
        || body.root_issuer != root.issuer
        || body.root_subject != root.subject
        || body.max_invocations != max_invocations
        || body.root_expires_at != root.expires_at
        || body.root_scope_hash != expected_scope_hash
    {
        return Err(violation(
            "aggregate budget root binding does not match the direct root token",
        ));
    }
    Ok(())
}

fn root_binding_body(
    body: &CapabilityTokenBody,
    max_invocations: u32,
) -> Result<AggregateBudgetRootBindingBody> {
    if !body.delegation_chain.is_empty() {
        return Err(violation(
            "aggregate family root must have an empty delegation chain",
        ));
    }
    Ok(AggregateBudgetRootBindingBody {
        schema: AGGREGATE_BUDGET_ROOT_SCHEMA.to_string(),
        root_capability_id: body.id.clone(),
        root_capability_hash: root_commitment_hash_from_body(body, max_invocations)?,
        root_issuer: body.issuer.clone(),
        root_subject: body.subject.clone(),
        max_invocations,
        root_expires_at: body.expires_at,
        root_scope_hash: scope_hash(&body.scope)?,
    })
}

fn root_commitment_hash(token: &CapabilityToken, max_invocations: u32) -> Result<String> {
    root_commitment_hash_parts(
        &token.id,
        &token.issuer,
        &token.subject,
        &token.scope,
        token.issued_at,
        token.expires_at,
        max_invocations,
    )
}

fn root_commitment_hash_from_body(
    body: &CapabilityTokenBody,
    max_invocations: u32,
) -> Result<String> {
    root_commitment_hash_parts(
        &body.id,
        &body.issuer,
        &body.subject,
        &body.scope,
        body.issued_at,
        body.expires_at,
        max_invocations,
    )
}

fn root_commitment_hash_parts(
    id: &str,
    issuer: &PublicKey,
    subject: &PublicKey,
    scope: &ChioScope,
    issued_at: u64,
    expires_at: u64,
    max_invocations: u32,
) -> Result<String> {
    let commitment = AggregateBudgetRootCommitment {
        root_capability_id: id.to_string(),
        root_issuer: issuer.clone(),
        root_subject: subject.clone(),
        root_scope_hash: scope_hash(scope)?,
        root_issued_at: issued_at,
        root_expires_at: expires_at,
        aggregate_scope: AggregateInvocationScope::DelegationFamily,
        max_invocations,
    };
    domain_hash(ROOT_COMMITMENT_DOMAIN, &commitment)
}

fn chain_marker(token: &CapabilityToken) -> Option<&AggregateBudgetDelegationMarker> {
    token
        .delegation_chain
        .iter()
        .find_map(|link| link.aggregate_budget.as_ref())
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
