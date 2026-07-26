//! Pure capability verification.
//!
//! Given a `CapabilityToken`, a trusted-issuer key set, and a clock, this
//! module answers: "is the signature valid, is the issuer trusted, and is
//! the capability inside its validity window right now?". It does NOT
//! check:
//!
//! - Revocation (stateful, lives in `chio-kernel::revocation_runtime`).
//! - Delegation-chain lineage against the receipt store (IO-dependent).
//! - Scope match against a request (use [`crate::scope::resolve_capability_grants`]).
//! - DPoP subject binding (lives in `chio-kernel::dpop`).
//!
//! All four are orchestrated by `chio-kernel::ChioKernel::evaluate_tool_call_sync`,
//! which calls into this module for the pure pieces and its own async/std
//! plumbing for the rest.
//!
//! Verified-core boundary note:
//! `formal/proof-manifest.toml` includes this module in the bounded verified
//! core because it performs only issuer-trust, signature, and time-window
//! checks over an in-memory capability token. Revocation stores, delegation
//! lineage joins, and transport-bound subject proof remain excluded surfaces.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{
    aggregate_invocation::verify_aggregate_invocation_budget,
    attenuation::{
        validate_delegation_chain, validate_delegation_chain_with_trust_root, ScopeHash,
    },
    crypto_floor::{CapabilityCryptoFloor, CapabilityFloorVerifyError},
    cumulative_approval::verify_cumulative_approval_constraints,
    features::{CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, CUMULATIVE_APPROVAL_BUDGET},
    scope::ChioScope,
    token::CapabilityToken,
};
use chio_core_types::crypto::PublicKey;
use chio_core_types::error::Error as CoreError;

use crate::budget_split::{BudgetRegistry, BudgetSplitError, NoopBudgetRegistry};
use crate::clock::Clock;
use crate::formal_core::{classify_time_window, TimeWindowStatus};
use crate::normalized::{NormalizationError, NormalizedVerifiedCapability};

/// The subset of a verified capability that portable callers actually need.
///
/// This deliberately excludes mutable kernel state (budget counters,
/// revocation membership) and avoids returning a reference into the token
/// so adapters that drop the token after verification can still act on
/// the captured scope.
#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    /// The capability ID.
    pub id: String,
    /// The subject hex-encoded public key.
    pub subject_hex: String,
    /// The issuer hex-encoded public key.
    pub issuer_hex: String,
    /// The authorized scope.
    pub scope: ChioScope,
    /// `issued_at` timestamp (Unix seconds).
    pub issued_at: u64,
    /// `expires_at` timestamp (Unix seconds).
    pub expires_at: u64,
    /// The clock value used for time-bound enforcement.
    pub evaluated_at: u64,
}

impl VerifiedCapability {
    /// Project this verification result into the proof-facing normalized AST.
    pub fn normalized(&self) -> Result<NormalizedVerifiedCapability, NormalizationError> {
        NormalizedVerifiedCapability::try_from(self)
    }
}

/// Errors raised by [`verify_capability`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// Issuer public key is not in the trusted set.
    UntrustedIssuer,
    /// Canonical-JSON signature did not verify against the issuer key.
    InvalidSignature,
    /// Signature material violates the configured crypto floor.
    CryptoFloorRejected(String),
    /// Token is not yet valid (clock is before `issued_at`).
    NotYetValid,
    /// Token has expired.
    Expired,
    /// Attenuated capability token violated the chain-binding rule.
    /// `attenuation_proof.parent_scope_hash` did not match either the
    /// issuer's trust-root scope hash (direct issue) or the last
    /// delegation link's `scope_hash` (delegated chain).
    AttenuationViolation(String),
    /// Sibling-sum budget enforcement rejected this delegation.
    BudgetSplitRejected(BudgetSplitError),
    /// An internal invariant was violated (e.g. canonical-JSON failure).
    Internal(String),
}

impl From<BudgetSplitError> for CapabilityError {
    fn from(err: BudgetSplitError) -> Self {
        CapabilityError::BudgetSplitRejected(err)
    }
}

/// Verify the signature, issuer trust, and time-bounds of a capability token.
///
/// Returns a [`VerifiedCapability`] when all three checks succeed. Delegation
/// chain validation, revocation lookup, and subject-binding checks are the
/// caller's responsibility (see module docs).
///
/// This wrapper uses a [`NoopBudgetRegistry`] internally; callers that need
/// sibling-sum budget enforcement must use [`verify_capability_with_floor`]
/// directly with their own [`BudgetRegistry`] instance.
pub fn verify_capability(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
) -> Result<VerifiedCapability, CapabilityError> {
    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(
        token,
        trusted_issuers,
        clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
}

/// Verify a capability token while enforcing the configured crypto floor and
/// sibling-sum budget split.
///
/// This is the floor-aware entry point for kernels that load
/// `policy.crypto_floor`. The default [`verify_capability`] wrapper uses
/// [`CapabilityCryptoFloor::AllowClassical`] and a [`NoopBudgetRegistry`].
///
/// Sibling-sum enforcement: when the token carries a non-empty
/// `delegation_chain`, the verifier asks `budgets` to admit the new child
/// under the immediate parent (the last entry in the chain). The proposed
/// share is `token.budget_share_bps.unwrap_or(MAX_BUDGET_SHARE_BPS)`: a
/// missing field is interpreted as a request for the full parent share.
/// The parent itself must already be registered in `budgets` from
/// verifier-owned lineage or a parent snapshot. Unknown parents fail closed.
/// Per-token validation has already enforced the `<= 10_000` cap by the time
/// the token reaches this function.
pub fn verify_capability_with_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified =
        verify_capability_base(token, trusted_issuers, clock, crypto_floor, false, false)?;
    admit_delegated_budget(token, budgets)?;
    Ok(verified)
}

fn verify_capability_base(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    aggregate_budget_enabled: bool,
    cumulative_approval_enabled: bool,
) -> Result<VerifiedCapability, CapabilityError> {
    // Issuer trust check. The full kernel also trusts its own public key
    // and the set returned by the capability authority; callers must
    // provide the full trust set they care about.
    if !trusted_issuers.contains(&token.issuer) {
        return Err(CapabilityError::UntrustedIssuer);
    }
    if !aggregate_budget_enabled && token_uses_aggregate_budget(token) {
        return Err(CapabilityError::AttenuationViolation(
            "aggregate_invocation_budget was not negotiated".to_string(),
        ));
    }
    if !cumulative_approval_enabled && token.scope.has_cumulative_approval() {
        return Err(CapabilityError::AttenuationViolation(
            "cumulative_approval_budget was not negotiated".to_string(),
        ));
    }

    // Signature check.
    match token.verify_signature_with_floor(crypto_floor) {
        Ok(true) => {}
        Ok(false) => return Err(CapabilityError::InvalidSignature),
        Err(error @ CapabilityFloorVerifyError::RejectedByCryptoFloor { .. }) => {
            return Err(CapabilityError::CryptoFloorRejected(error.to_string()));
        }
        Err(error @ CapabilityFloorVerifyError::AlgorithmMismatch { .. }) => {
            return Err(CapabilityError::CryptoFloorRejected(error.to_string()));
        }
        Err(CapabilityFloorVerifyError::Crypto(error)) => {
            return Err(CapabilityError::Internal(error.to_string()));
        }
    }

    // Time-bound check.
    let now = clock.now_unix_secs();
    match classify_time_window(now, token.issued_at, token.expires_at) {
        TimeWindowStatus::Valid => {}
        TimeWindowStatus::NotYetValid => return Err(CapabilityError::NotYetValid),
        TimeWindowStatus::Expired => return Err(CapabilityError::Expired),
    }

    Ok(VerifiedCapability {
        id: token.id.clone(),
        subject_hex: token.subject.to_hex(),
        issuer_hex: token.issuer.to_hex(),
        scope: token.scope.clone(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        evaluated_at: now,
    })
}

pub(crate) fn admit_delegated_budget(
    token: &CapabilityToken,
    budgets: &mut dyn BudgetRegistry,
) -> Result<(), CapabilityError> {
    // Sibling-sum budget split. Only fires for tokens that carry a
    // delegation chain; root-issued tokens have nothing to split.
    //
    // The parent must already be registered from verifier-owned lineage
    // or a parent snapshot. Unknown parents fail closed; the verifier must
    // not fabricate a missing parent share at MAX_BUDGET_SHARE_BPS.
    //
    // This runs on the shared VERIFY surface (portable/preflight verdicts and
    // adapter one-shot evaluations produced by the pure `evaluate_*` entry
    // points). None of those callers hold a `PostAdmissionDropGuard` or reach
    // `release_admitted_capability_budget`, so this MUST NOT take a holder
    // lease: a lease acquired here would never be released and would pin the
    // child edge upward forever. `verify_child_admission` runs the same
    // fail-closed oversubscription checks and still commits a fresh child's
    // share for sibling-sum accounting, but records no releasable holder. The
    // authoritative lease is taken separately by the hosted dispatch path
    // (`ChioKernel::admit_capability_budget`), which owns the matching release.
    if let Some(parent_link) = token.delegation_chain.last() {
        let proposed_share = token
            .budget_share_bps
            .unwrap_or(crate::budget_split::MAX_BUDGET_SHARE_BPS);
        budgets.verify_child_admission(
            parent_link.capability_id.as_str(),
            token.id.clone(),
            proposed_share,
        )?;
    }

    Ok(())
}

/// Verify a capability token while enforcing the configured crypto floor.
/// The peer profile is still accepted so federation callers can keep one
/// call surface, but Chio-owned capability schemas are single-version until
/// first release.
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
) -> Result<VerifiedCapability, CapabilityError> {
    validate_peer_capabilities(peer)?;
    let aggregate_budget_enabled = peer.supports(AGGREGATE_INVOCATION_BUDGET);
    let cumulative_approval_enabled = peer.supports(CUMULATIVE_APPROVAL_BUDGET);
    let verified = verify_capability_base(
        token,
        trusted_issuers,
        clock,
        crypto_floor,
        aggregate_budget_enabled,
        cumulative_approval_enabled,
    )?;
    verify_negotiated_aggregate_budget(token, trusted_issuers, aggregate_budget_enabled, None)?;
    verify_negotiated_cumulative_approval(
        token,
        trusted_issuers,
        cumulative_approval_enabled,
        None,
    )?;
    let mut budgets = NoopBudgetRegistry;
    admit_delegated_budget(token, &mut budgets)?;
    Ok(verified)
}

/// Convenience wrapper around [`verify_capability`] that returns the
/// trusted-issuer list as a `Vec` so adapters can build it lazily.
pub fn verify_capability_with_trusted<I>(
    token: &CapabilityToken,
    trusted_issuers: I,
    clock: &dyn Clock,
) -> Result<VerifiedCapability, CapabilityError>
where
    I: IntoIterator<Item = PublicKey>,
{
    let trusted: Vec<PublicKey> = trusted_issuers.into_iter().collect();
    verify_capability(token, &trusted, clock)
}

/// Convenience wrapper around [`verify_capability_with_floor`] for callers that
/// build the trusted issuer set lazily. Uses a [`NoopBudgetRegistry`]; new
/// callers that care about sibling-sum enforcement should call
/// [`verify_capability_with_floor`] with their own registry.
pub fn verify_capability_with_trusted_and_floor<I>(
    token: &CapabilityToken,
    trusted_issuers: I,
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
) -> Result<VerifiedCapability, CapabilityError>
where
    I: IntoIterator<Item = PublicKey>,
{
    let trusted: Vec<PublicKey> = trusted_issuers.into_iter().collect();
    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(token, &trusted, clock, crypto_floor, &mut budgets)
}

/// Resolver returning the trust-root scope hash bound to a given issuer
/// public key. Kernels supply this so the verifier can bind
/// `attenuation_proof.parent_scope_hash` to the issuing CA's authority
/// hash on direct-issue attenuated tokens.
pub trait TrustRootResolver {
    /// Resolve the trust-root scope hash for `issuer`, returning `None`
    /// when the issuer has no registered authority hash. The verifier
    /// treats `None` as a fail-closed deny for attenuated tokens that require
    /// chain binding.
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash>;
}

impl<F> TrustRootResolver for F
where
    F: Fn(&PublicKey) -> Option<ScopeHash>,
{
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash> {
        (self)(issuer)
    }
}

/// Negotiated optional-feature profile and authenticated family-root evidence.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityFeatureContext<'a> {
    pub peer: &'a CapabilityNegotiation,
    pub direct_root: Option<&'a CapabilityToken>,
}

/// Chain-binding entry point. Verify a capability token while also
/// enforcing the chain-binding rule required for delegation soundness.
///
/// In addition to the checks in [`verify_capability_with_floor`], this
/// entry point checks tokens that carry an `attenuation_proof`
/// whose `parent_scope_hash` matches either:
///
/// - `trust_root_scope_hash` (when the delegation chain is empty: a
///   direct issue from the trust-root authority binds the witness to the
///   verifier-known authority hash); or
/// - `delegation_chain.last().scope_hash` (when delegation has occurred:
///   the witness binds to the predecessor's signed scope_hash).
///
/// Non-attenuated tokens are accepted unchanged.
pub fn verify_capability_with_floor_and_trust_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    trust_root_scope_hash: &ScopeHash,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified =
        verify_capability_base(token, trusted_issuers, clock, crypto_floor, false, false)?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_trust_root(token, trust_root_scope_hash)?;

    Ok(verified)
}

/// Resolver-driven variant of [`verify_capability_with_floor_and_trust_root`].
///
/// Kernels that maintain a per-issuer trust-root registry pass a
/// [`TrustRootResolver`] so the verifier can pick the correct authority
/// hash without leaking the registry shape into the verifier surface.
pub fn verify_capability_with_floor_and_resolver(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    trust_root: &dyn TrustRootResolver,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified =
        verify_capability_base(token, trusted_issuers, clock, crypto_floor, false, false)?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_resolver(token, trust_root)?;

    Ok(verified)
}

/// Full verifier entry point for current capability semantics without signed
/// optional-family root evidence.
pub fn verify_capability_full(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    verify_capability_full_with_root(
        token,
        trusted_issuers,
        clock,
        crypto_floor,
        CapabilityFeatureContext {
            peer,
            direct_root: None,
        },
        trust_root,
        budgets,
    )
}

/// Full verifier entry point with authenticated optional-family root evidence
/// for delegated tokens.
pub fn verify_capability_full_with_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    features: CapabilityFeatureContext<'_>,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    let CapabilityFeatureContext { peer, direct_root } = features;
    validate_peer_capabilities(peer)?;
    let aggregate_budget_enabled = peer.supports(AGGREGATE_INVOCATION_BUDGET);
    let cumulative_approval_enabled = peer.supports(CUMULATIVE_APPROVAL_BUDGET);
    let verified = verify_capability_base(
        token,
        trusted_issuers,
        clock,
        crypto_floor,
        aggregate_budget_enabled,
        cumulative_approval_enabled,
    )?;
    if let Some(root) = direct_root {
        verify_capability_base(
            root,
            trusted_issuers,
            clock,
            crypto_floor,
            aggregate_budget_enabled,
            cumulative_approval_enabled,
        )?;
    }
    verify_negotiated_aggregate_budget(
        token,
        trusted_issuers,
        aggregate_budget_enabled,
        direct_root,
    )?;
    verify_negotiated_cumulative_approval(
        token,
        trusted_issuers,
        cumulative_approval_enabled,
        direct_root,
    )?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_negotiation(token, peer, trust_root)?;
    admit_delegated_budget(token, budgets)?;
    Ok(verified)
}

fn validate_peer_capabilities(peer: &CapabilityNegotiation) -> Result<(), CapabilityError> {
    peer.validate().map_err(|error| {
        CapabilityError::AttenuationViolation(format!(
            "invalid capability negotiation profile: {error}"
        ))
    })
}

fn token_uses_aggregate_budget(token: &CapabilityToken) -> bool {
    token.aggregate_invocation_budget.is_some()
        || token
            .delegation_chain
            .iter()
            .any(|link| link.aggregate_budget.is_some())
        || token
            .attenuation_proof
            .as_ref()
            .is_some_and(|proof| proof.normalized_subset_proof.aggregate_budget.is_some())
}

fn verify_negotiated_aggregate_budget(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    enabled: bool,
    direct_root: Option<&CapabilityToken>,
) -> Result<(), CapabilityError> {
    if !enabled {
        if token_uses_aggregate_budget(token)
            || direct_root.is_some_and(token_uses_aggregate_budget)
        {
            return Err(CapabilityError::AttenuationViolation(
                "aggregate_invocation_budget was not negotiated".to_string(),
            ));
        }
        return Ok(());
    }

    verify_aggregate_invocation_budget(token, trusted_issuers, direct_root)
        .map(|_| ())
        .map_err(map_optional_feature_error)
}

fn verify_negotiated_cumulative_approval(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    enabled: bool,
    direct_root: Option<&CapabilityToken>,
) -> Result<(), CapabilityError> {
    if !enabled {
        if token.scope.has_cumulative_approval()
            || direct_root.is_some_and(|root| root.scope.has_cumulative_approval())
        {
            return Err(CapabilityError::AttenuationViolation(
                "cumulative_approval_budget was not negotiated".to_string(),
            ));
        }
        return Ok(());
    }

    verify_cumulative_approval_constraints(token, trusted_issuers, direct_root)
        .map(|_| ())
        .map_err(map_optional_feature_error)
}

fn map_optional_feature_error(error: CoreError) -> CapabilityError {
    match error {
        CoreError::SignatureVerificationFailed | CoreError::InvalidSignature(_) => {
            CapabilityError::InvalidSignature
        }
        CoreError::AttenuationViolation { reason }
        | CoreError::DelegationChainBroken { reason }
        | CoreError::ScopeMismatch { reason } => CapabilityError::AttenuationViolation(reason),
        other => CapabilityError::Internal(other.to_string()),
    }
}

fn verify_delegation_chain_shape(token: &CapabilityToken) -> Result<(), CapabilityError> {
    if token.delegation_chain.is_empty() {
        return Ok(());
    }
    validate_delegation_chain(&token.delegation_chain, None)
        .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    let Some(final_link) = token.delegation_chain.last() else {
        return Ok(());
    };
    let final_delegatee = &final_link.delegatee;
    if final_delegatee != &token.subject {
        return Err(CapabilityError::AttenuationViolation(
            "delegation chain final delegatee does not match capability subject".to_string(),
        ));
    }
    Ok(())
}

fn verify_chain_binding_with_trust_root(
    token: &CapabilityToken,
    trust_root_scope_hash: &ScopeHash,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        token
            .validate_chain_binding(trust_root_scope_hash)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }
    Ok(())
}

fn verify_chain_binding_with_resolver(
    token: &CapabilityToken,
    trust_root: &dyn TrustRootResolver,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        let issuer_root = trust_root
            .trust_root_scope_hash(&token.issuer)
            .ok_or_else(|| {
                CapabilityError::AttenuationViolation(
                    "chain-binding: no trust-root scope hash registered for issuer".to_string(),
                )
            })?;
        validate_delegation_chain_with_trust_root(&token.delegation_chain, None, &issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
        token
            .validate_chain_binding(&issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }
    Ok(())
}

fn verify_chain_binding_with_negotiation(
    token: &CapabilityToken,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        let chain_binding_enabled = peer
            .features
            .get(chio_core_types::capability::features::DELEGATION_CHAIN_BINDING)
            .copied()
            .unwrap_or(true);
        if !chain_binding_enabled {
            return Err(CapabilityError::AttenuationViolation(
                "chain-binding: peer disabled delegation_chain_binding; attenuated tokens are rejected".to_string(),
            ));
        }
        verify_chain_binding_with_resolver(token, trust_root)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "capability_verify_tests.rs"]
mod tests;
