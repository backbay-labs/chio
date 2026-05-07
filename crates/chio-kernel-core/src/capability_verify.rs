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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{
    CapabilityCryptoFloor, CapabilityFloorVerifyError, CapabilityNegotiation,
    CapabilitySchemaVersion, CapabilityToken, ChioScope, ScopeHash, CHIO_CAPABILITY_V2_SCHEMA,
};
use chio_core_types::crypto::PublicKey;

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
    /// W1.1: V2 capability token violated the chain-binding rule.
    /// `attenuation_proof.parent_scope_hash` did not match either the
    /// issuer's trust-root scope hash (direct issue) or the last
    /// delegation link's `scope_hash` (delegated chain).
    AttenuationViolation(String),
    /// Sibling-sum budget enforcement rejected this delegation.
    BudgetSplitRejected(BudgetSplitError),
    /// An internal invariant was violated (e.g. canonical-JSON failure).
    Internal(String),
    /// Token's declared schema is above the schema ceiling negotiated with
    /// the federated peer. This blocks a v1-only Mallory from forcing a
    /// v2-aware Alice to accept v2-only fields (downgrade-attack defense).
    SchemaExceedsNegotiatedCeiling {
        /// The schema ID declared on the inbound token.
        token_schema: String,
        /// The peer-negotiated maximum capability schema ID.
        peer_max: String,
    },
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
/// `policy.crypto_floor`. The default [`verify_capability`] wrapper preserves
/// legacy callers by using [`CapabilityCryptoFloor::AllowClassical`] and a
/// [`NoopBudgetRegistry`].
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
    // Issuer trust check. The legacy kernel also trusts its own public key
    // and the set returned by the capability authority; callers must
    // provide the full trust set they care about.
    if !trusted_issuers.contains(&token.issuer) {
        return Err(CapabilityError::UntrustedIssuer);
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

    // Sibling-sum budget split. Only fires for tokens that carry a
    // delegation chain; root-issued tokens have nothing to split.
    //
    // The parent must already be registered from verifier-owned lineage
    // or a parent snapshot. Unknown parents fail closed; the verifier must
    // not fabricate a missing parent share at MAX_BUDGET_SHARE_BPS.
    if let Some(parent_link) = token.delegation_chain.last() {
        let proposed_share = token
            .budget_share_bps
            .unwrap_or(crate::budget_split::MAX_BUDGET_SHARE_BPS);
        budgets.try_admit_child(
            parent_link.capability_id.as_str(),
            token.id.clone(),
            proposed_share,
        )?;
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

/// Verify a capability token while enforcing both the configured crypto
/// floor and the schema ceiling negotiated with the federated peer.
///
/// Closes the W1.3 downgrade attack: a v1-only Mallory must not be able
/// to force a v2-aware Alice to accept v2-only fields. The peer's
/// `max_capability_schema` (populated by
/// [`CapabilityNegotiation::negotiated_with`]) acts as a ceiling: a v2
/// token presented across a v1-negotiated link is rejected before any
/// signature, time, or floor check runs.
///
/// Symmetric direction is preserved: a v1 token presented across a
/// v2-negotiated link still verifies, because v1 remains the universal
/// floor of the schema lattice.
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
) -> Result<VerifiedCapability, CapabilityError> {
    // Schema-ceiling check: reject tokens whose declared schema is
    // strictly above the peer-negotiated ceiling. Comparison is
    // ordering-aware over `CapabilitySchemaVersion`, not string
    // equality, so a v2 token across a future v3-or-higher peer
    // ceiling is admitted. v1 tokens are always admitted regardless
    // of the peer ceiling.
    let token_version = CapabilitySchemaVersion::parse(&token.schema);
    let peer_ceiling = CapabilitySchemaVersion::parse(&peer.max_capability_schema);
    let exceeds_ceiling = match (token_version, peer_ceiling) {
        (Some(token_v), Some(peer_v)) => token_v > peer_v,
        (Some(token_v), None) => token_v > CapabilitySchemaVersion::V1,
        (None, _) => false,
    };
    if exceeds_ceiling {
        return Err(CapabilityError::SchemaExceedsNegotiatedCeiling {
            token_schema: token.schema.clone(),
            peer_max: peer.max_capability_schema.clone(),
        });
    }

    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(token, trusted_issuers, clock, crypto_floor, &mut budgets)
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
/// hash on direct-issue tokens (W1.1 chain-binding rule).
pub trait TrustRootResolver {
    /// Resolve the trust-root scope hash for `issuer`, returning `None`
    /// when the issuer has no registered authority hash. The verifier
    /// treats `None` as a fail-closed deny for v2 tokens that require
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

/// W1.1 chain-binding entry point. Verify a capability token while also
/// enforcing the v2 chain-binding rule that closes the P0 soundness gap.
///
/// In addition to the checks in [`verify_capability_with_floor`], this
/// entry point requires that v2 tokens carry an `attenuation_proof`
/// whose `parent_scope_hash` matches either:
///
/// - `trust_root_scope_hash` (when the delegation chain is empty: a
///   direct issue from the trust-root authority binds the witness to the
///   verifier-known authority hash); or
/// - `delegation_chain.last().scope_hash` (when delegation has occurred:
///   the witness binds to the predecessor's signed scope_hash).
///
/// V1 tokens are accepted unchanged. Callers that have not yet plumbed
/// trust roots through their kernel should keep using
/// [`verify_capability_with_floor`] but MUST NOT accept v2 tokens via
/// that legacy entry point in production.
pub fn verify_capability_with_floor_and_trust_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    trust_root_scope_hash: &ScopeHash,
) -> Result<VerifiedCapability, CapabilityError> {
    let mut budgets = NoopBudgetRegistry;
    let verified =
        verify_capability_with_floor(token, trusted_issuers, clock, crypto_floor, &mut budgets)?;

    if token.schema == CHIO_CAPABILITY_V2_SCHEMA {
        token
            .validate_chain_binding(trust_root_scope_hash)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }

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
    let mut budgets = NoopBudgetRegistry;
    let verified =
        verify_capability_with_floor(token, trusted_issuers, clock, crypto_floor, &mut budgets)?;

    if token.schema == CHIO_CAPABILITY_V2_SCHEMA {
        let issuer_root = trust_root
            .trust_root_scope_hash(&token.issuer)
            .ok_or_else(|| {
                CapabilityError::AttenuationViolation(
                    "v2 chain-binding: no trust-root scope hash registered for issuer".to_string(),
                )
            })?;
        token
            .validate_chain_binding(&issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }

    Ok(verified)
}

/// Wave 1.5 maximum-flexibility verifier.
///
/// Composite entry point that chains all three Wave 1 defenses in a
/// single fail-closed pass:
///
/// 1. W1.3 negotiated schema-ceiling check (rejects v2 tokens across a
///    v1-only-negotiated link before any signature work).
/// 2. Legacy issuer trust + canonical-JSON signature + crypto floor +
///    time-window checks (the historical `verify_capability_with_floor`
///    body).
/// 3. W1.1 chain-binding check (v2 tokens must bind
///    `attenuation_proof.parent_scope_hash` to either the issuer's
///    trust-root scope hash or the last delegation link's `scope_hash`).
///
/// This is the verifier entry point production kernels SHOULD call
/// going forward. The earlier partial entry points
/// (`_with_negotiated_floor`, `_with_floor_and_trust_root`,
/// `_with_floor_and_resolver`) remain available for callers that do
/// not yet plumb every dependency through their boundary, but they
/// each leave one Wave 1 defense un-wired and are therefore unsafe
/// when used in isolation in production hot paths.
pub fn verify_capability_full(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    // Step 1: W1.3 schema-ceiling check. Reject tokens whose declared
    // schema is strictly above the peer-negotiated ceiling before doing
    // any cryptographic work. The comparison is ordering-aware (a v2
    // token across a v3-or-higher peer ceiling is admitted because v2
    // <= v3) rather than bare equality, so adding a future v3 schema
    // does not regress already-deployed v2 callers.
    //
    // Unknown schema identifiers fail-closed: the negotiation surface
    // already rejects unknown values via `CapabilityNegotiation::validate`,
    // and per-token validation rejects unknown token schemas. Treating
    // an unparseable peer ceiling as `None` here keeps the ceiling at
    // its safest interpretation (deny anything we cannot order).
    let token_version = CapabilitySchemaVersion::parse(&token.schema);
    let peer_ceiling = CapabilitySchemaVersion::parse(&peer.max_capability_schema);
    let exceeds_ceiling = match (token_version, peer_ceiling) {
        (Some(token_v), Some(peer_v)) => token_v > peer_v,
        // Unknown peer ceiling -> fail-closed for any v2-or-higher token.
        // v1 tokens remain the universal floor and are always admitted.
        (Some(token_v), None) => token_v > CapabilitySchemaVersion::V1,
        // Unknown token schema -> let downstream validation handle it.
        (None, _) => false,
    };
    if exceeds_ceiling {
        return Err(CapabilityError::SchemaExceedsNegotiatedCeiling {
            token_schema: token.schema.clone(),
            peer_max: peer.max_capability_schema.clone(),
        });
    }

    // Step 2: W1.1 chain-binding check on v2 tokens. v1 tokens are admitted
    // unchanged (no attenuation_proof field exists in their schema). Run
    // chain-binding before the legacy signature/floor/issuer/budget pass so
    // a witness mismatch fails closed before any budget mutation.
    //
    // V2 tokens require chain binding. If a peer explicitly disables
    // `delegation_v2_chain_binding`, treat that peer as v1-only for this
    // verifier and reject the v2 token rather than skipping the binding
    // check.
    if token.schema == CHIO_CAPABILITY_V2_SCHEMA {
        let chain_binding_enabled = peer
            .features
            .get(chio_core_types::capability::capability_features::DELEGATION_V2_CHAIN_BINDING)
            .copied()
            .unwrap_or(true);
        if !chain_binding_enabled {
            return Err(CapabilityError::AttenuationViolation(
                "v2 chain-binding: peer disabled delegation_v2_chain_binding; v2 tokens are rejected".to_string(),
            ));
        }
        let issuer_root = trust_root
            .trust_root_scope_hash(&token.issuer)
            .ok_or_else(|| {
                CapabilityError::AttenuationViolation(
                    "v2 chain-binding: no trust-root scope hash registered for issuer".to_string(),
                )
            })?;
        token
            .validate_chain_binding(&issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }

    // Step 3: legacy signature, issuer-trust, crypto-floor, time-bound
    // verification, AND W1.2 sibling-sum budget admission. The legacy
    // function chains issuer -> signature/floor -> time-window -> budget
    // admit at the end (matching the W1.2 hook position). Returns a
    // verified capability projection on success.
    verify_capability_with_floor(token, trusted_issuers, clock, crypto_floor, budgets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::capability::{
        capability_features, compute_attenuation_witness, scope_hash, AttenuationProof,
        CapabilityTokenBody, CapabilityTokenV2Body, ChioScope, DelegationLink, DelegationLinkBody,
    };
    use chio_core_types::crypto::Keypair;

    #[test]
    fn pq_required_rejects_classical_capability() {
        let issuer = Keypair::generate();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-classical".to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign classical capability");
        let clock = crate::FixedClock::new(150);

        let mut budgets = NoopBudgetRegistry;
        let err = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::PqRequired,
            &mut budgets,
        )
        .expect_err("classical capability must fail under pq_required");

        assert!(matches!(err, CapabilityError::CryptoFloorRejected(_)));
    }

    #[test]
    fn allow_classical_accepts_classical_capability() {
        let issuer = Keypair::generate();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-classical".to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign classical capability");
        let clock = crate::FixedClock::new(150);

        let mut budgets = NoopBudgetRegistry;
        let verified = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &mut budgets,
        )
        .expect("classical capability is accepted under allow_classical");

        assert_eq!(verified.id, "cap-classical");
    }

    fn make_v2_token(id: &str, issuer: &Keypair, subject: &Keypair) -> CapabilityToken {
        let scope = ChioScope::default();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&scope).expect("parent scope hash"),
            child_scope_hash: scope_hash(&scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(&scope, &scope)
                .expect("attenuation witness"),
        };
        CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body: CapabilityTokenBody {
                    id: id.to_string(),
                    issuer: issuer.public_key(),
                    subject: subject.public_key(),
                    scope,
                    issued_at: 100,
                    expires_at: 200,
                    delegation_chain: Vec::new(),
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            issuer,
        )
        .expect("sign v2 token")
    }

    #[test]
    fn full_verifier_rejects_v2_when_chain_binding_feature_is_disabled() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_v2_token("cap-v2-disabled-chain-binding", &issuer, &subject);
        let clock = crate::FixedClock::new(150);
        let mut peer = CapabilityNegotiation::t1_default();
        peer.features.insert(
            capability_features::DELEGATION_V2_CHAIN_BINDING.to_string(),
            false,
        );
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("v2 token must fail when chain binding is disabled");

        assert!(matches!(err, CapabilityError::AttenuationViolation(_)));
    }

    #[test]
    fn delegated_budget_unknown_parent_fails_closed() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "missing-parent".to_string(),
                delegator: issuer.public_key(),
                delegatee: issuer.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
            },
            &issuer,
        )
        .expect("sign child token");
        let clock = crate::FixedClock::new(150);
        let mut budgets = crate::InMemoryBudgetRegistry::new();

        let err = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &mut budgets,
        )
        .expect_err("unknown budget parent must fail closed");

        assert!(matches!(
            err,
            CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
        ));
    }
}
