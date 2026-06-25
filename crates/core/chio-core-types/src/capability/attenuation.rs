use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use crate::error::{Error, Result};
use crate::signer_binding::ensure_keypair_matches_embedded_key;

use super::caveat::GrantSubsetRelation;
use super::scope::{ChioScope, Constraint, MonetaryAmount, Operation};
use super::token::CapabilityToken;
use super::validation::{validate_parent_relative_budget_share_bps, MAX_BUDGET_SHARE_BPS};

/// Hash of a canonicalized scope, encoded as lowercase SHA-256 hex.
pub type ScopeHash = String;

/// On-wire attenuation witness. The normalized scope encodings are included
/// so verifiers can hash and check the already-normalized relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationWitness {
    pub normalized_parent_scope: String,
    pub normalized_child_scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subset_relations: Vec<GrantSubsetRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted_predicates: Vec<String>,
}

/// Wire proof carried by `CapabilityToken.attenuation_proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationProof {
    pub parent_scope_hash: ScopeHash,
    pub child_scope_hash: ScopeHash,
    pub normalized_subset_proof: AttenuationWitness,
}

/// A link in the delegation chain, recording that `delegator` granted a
/// narrowed capability to `delegatee`.
///
/// Delegation chain-binding: `scope_hash` records the hash of the canonical scope
/// that the delegator authorized at this step. When set, it ties the
/// delegation chain to the underlying capability lineage so a verifier
/// can check `proof.parent_scope_hash == chain.last().scope_hash` and
/// reject inflated parent-scope claims (the parent-scope-inflation
/// soundness bug).
///
/// Links omit `scope_hash`; verifiers must reject attenuated tokens
/// whose chain links lack this field via
/// [`validate_delegation_chain_with_trust_root`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Capability ID of the ancestor token delegated at this step.
    pub capability_id: String,
    /// Public key of the agent that delegated.
    pub delegator: PublicKey,
    /// Public key of the agent that received the delegation.
    pub delegatee: PublicKey,
    /// How the scope was narrowed in this delegation step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    /// Unix timestamp of the delegation.
    pub timestamp: u64,
    /// Delegation chain-binding: SHA-256 hash of the canonical scope authorized
    /// at this hop. Absent on older links; verifiers can enforce presence via
    /// feature gate. Verifiers gated behind the `delegation_chain_binding`
    /// feature flag enforce that this matches the parent_scope_hash carried by
    /// the next hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
    /// Ed25519 signature by the delegator over the canonical form of the
    /// other fields in this link.
    pub signature: Signature,
}

/// The body of a delegation link, used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLinkBody {
    pub capability_id: String,
    pub delegator: PublicKey,
    pub delegatee: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    pub timestamp: u64,
    /// Delegation chain-binding: see [`DelegationLink::scope_hash`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
}

impl DelegationLink {
    /// Sign a delegation link body.
    pub fn sign(body: DelegationLinkBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.delegator,
            keypair,
            "delegation link",
            "delegator",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            capability_id: body.capability_id,
            delegator: body.delegator,
            delegatee: body.delegatee,
            attenuations: body.attenuations,
            timestamp: body.timestamp,
            scope_hash: body.scope_hash,
            signature,
        })
    }

    /// Extract the signable body.
    #[must_use]
    pub fn body(&self) -> DelegationLinkBody {
        DelegationLinkBody {
            capability_id: self.capability_id.clone(),
            delegator: self.delegator.clone(),
            delegatee: self.delegatee.clone(),
            attenuations: self.attenuations.clone(),
            timestamp: self.timestamp,
            scope_hash: self.scope_hash.clone(),
        }
    }

    /// Verify this link's signature against the delegator's key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.delegator.verify_canonical(&body, &self.signature)
    }
}

/// Describes how a scope was narrowed during delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attenuation {
    /// A tool was removed from the scope.
    RemoveTool {
        server_id: String,
        tool_name: String,
    },
    /// An operation was removed from a tool grant.
    RemoveOperation {
        server_id: String,
        tool_name: String,
        operation: Operation,
    },
    /// A constraint was added to a tool grant.
    AddConstraint {
        server_id: String,
        tool_name: String,
        constraint: Constraint,
    },
    /// The invocation budget was reduced.
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    /// The expiration was shortened.
    ShortenExpiry { new_expires_at: u64 },
    /// The per-invocation cost cap was tightened during delegation.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },
    /// The total cost budget was reduced during delegation.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}

/// Validate an entire delegation chain.
///
/// Checks that:
/// 1. Each link's signature is valid.
/// 2. Adjacent links are connected (link[i].delegatee == link[i+1].delegator).
/// 3. Timestamps are non-decreasing.
/// 4. The chain length does not exceed `max_depth` (if provided).
///
/// Note: this compatibility entry point does NOT enforce chain-binding
/// (the `parent_scope_hash` invariant). Callers verifying attenuated
/// tokens must use [`validate_delegation_chain_with_trust_root`] to close
/// the parent-scope-inflation soundness gap.
pub fn validate_delegation_chain(chain: &[DelegationLink], max_depth: Option<u32>) -> Result<()> {
    if let Some(max) = max_depth {
        let len = u32::try_from(chain.len()).unwrap_or(u32::MAX);
        if len > max {
            return Err(Error::DelegationDepthExceeded { depth: len, max });
        }
    }

    for (i, link) in chain.iter().enumerate() {
        let sig_valid = link.verify_signature()?;
        if !sig_valid {
            return Err(Error::DelegationChainBroken {
                reason: format!("signature invalid at link index {i}"),
            });
        }

        if i > 0 {
            let prev = &chain[i - 1];
            if prev.delegatee != link.delegator {
                return Err(Error::DelegationChainBroken {
                    reason: format!("link {i} delegator does not match link {} delegatee", i - 1),
                });
            }
            if link.timestamp < prev.timestamp {
                return Err(Error::DelegationChainBroken {
                    reason: format!(
                        "link {i} timestamp ({}) precedes link {} timestamp ({})",
                        link.timestamp,
                        i - 1,
                        prev.timestamp
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Validate a delegation chain under the chain-binding rule.
///
/// Defends against parent-scope inflation: an issuer with true authority
/// `scope_X` must not be able to mint an attenuated token claiming
/// `parent_scope = scope_BIGGER` with an internally-consistent
/// `attenuation_proof`, which is possible whenever nothing ties
/// `parent_scope_hash` to the issuer's actual upstream parent capability.
/// This verifier requires:
///
/// 1. Every link in the chain populates `scope_hash` (chains lacking
///    chain-binding are rejected fail-closed).
/// 2. The first hop's `scope_hash` equals `trust_root_scope_hash`.
/// 3. Multi-hop attenuated chains are rejected until delegation links carry
///    per-hop child-scope witnesses. With only one `scope_hash` per link, a
///    verifier cannot prove that link N's advertised parent scope was actually
///    received from link N-1.
/// 4. The leaf capability token's `attenuation_proof.parent_scope_hash`
///    is checked against `chain.last().scope_hash` by
///    [`CapabilityToken::validate_chain_binding`].
///
/// Scope hashes alone cannot prove per-hop subset relations because the
/// full parent and child scopes are not carried on every delegation link.
/// Callers that need per-hop semantic attenuation must carry explicit
/// witnesses for each hop.
///
/// The signature, connectivity, and timestamp checks from the v1 entry
/// point are also enforced.
pub fn validate_delegation_chain_with_trust_root(
    chain: &[DelegationLink],
    max_depth: Option<u32>,
    trust_root_scope_hash: &ScopeHash,
) -> Result<()> {
    validate_delegation_chain(chain, max_depth)?;

    if chain.is_empty() {
        return Ok(());
    }

    if chain.len() > 1 {
        return Err(Error::DelegationChainBroken {
            reason: "multi-hop attenuated delegation chains require per-hop child-scope witnesses"
                .to_string(),
        });
    }

    for (i, link) in chain.iter().enumerate() {
        let Some(link_hash) = link.scope_hash.as_ref() else {
            return Err(Error::DelegationChainBroken {
                reason: format!(
                    "delegation chain link {i} omits scope_hash; Chio delegation requires every hop to bind its authorized scope"
                ),
            });
        };

        if i == 0 && link_hash != trust_root_scope_hash {
            return Err(Error::DelegationChainBroken {
                reason: "delegation chain link 0 scope_hash does not match trust root scope hash"
                    .to_string(),
            });
        }
    }

    Ok(())
}

/// Returns whether a parent tool grant covers an attenuation step addressed by
/// `(server_id, tool_name)`.
///
/// Wildcard parent grants are honored with the same coverage semantics as
/// [`super::scope::ToolGrant::is_subset_of`]: a parent grant whose `server_id`
/// or `tool_name` is `"*"` covers a concrete child step. A concrete-child step
/// against a `*:*` parent grant is therefore a legitimate narrowing, not a
/// widening.
fn parent_grant_covers_target(
    grant: &super::scope::ToolGrant,
    server_id: &str,
    tool_name: &str,
) -> bool {
    (grant.server_id == "*" || grant.server_id == server_id)
        && (grant.tool_name == "*" || grant.tool_name == tool_name)
}

/// Returns whether an attenuation step's `(server_id, tool_name)` target and a
/// child tool grant address the same authority, honoring wildcards on EITHER
/// side.
///
/// The reflection check must catch two symmetric under-declaration shapes:
///
/// * Wildcard STEP TARGET vs concrete child grant. A `*:*` parent delegates a
///   concrete `srv-a:tool-x` child while declaring
///   `RemoveOperation { server_id: "*", tool_name: "*" }`; the concrete child
///   grant must still be inspected so an un-reflected removal is rejected.
/// * Concrete STEP TARGET vs wildcard child grant. A `*:*` parent delegates a
///   `*:*` child while declaring a concrete `srv-a:tool-x` removal; the child
///   retains that concrete authority through its wildcard grant, so the
///   wildcard child grant must still be inspected. Otherwise `delegate` signs
///   the link, yet chio-kernel's declared-attenuation check rejects the token
///   later (mint and kernel disagree).
///
/// A one-directional matcher (matching only when one specific side is wildcard)
/// misses the other shape and lets an under-declared link through. This matcher
/// is therefore bidirectional: for each field it matches when EITHER the step
/// target OR the child grant is `"*"`, or when the two concrete values are
/// equal. That mirrors the wildcard coverage semantics of
/// [`super::scope::ToolGrant::is_subset_of`] while keeping the reflection check
/// fail-closed in both directions.
fn step_target_covers_child_grant(
    grant: &super::scope::ToolGrant,
    step_server_id: &str,
    step_tool_name: &str,
) -> bool {
    (step_server_id == "*" || grant.server_id == "*" || step_server_id == grant.server_id)
        && (step_tool_name == "*" || grant.tool_name == "*" || step_tool_name == grant.tool_name)
}

/// Iterate over every parent tool grant that covers an attenuation step's
/// `(server_id, tool_name)` address.
///
/// Steps are addressed by `(server_id, tool_name)`. A step that references a
/// grant the parent never held is itself a widening (it asserts authority over
/// a tool outside the parent's scope) and must be rejected fail-closed. Several
/// parent grants can cover the same concrete target at once: a broad `*:*`
/// grant and a later concrete `srv-a:tool-x` grant both match. Step validation
/// therefore considers *all* covering grants rather than only the first, so a
/// step that narrows against any one of them is accepted (see
/// [`step_matches_any_covering_grant`]).
fn covering_parent_grants<'a>(
    parent: &'a ChioScope,
    server_id: &'a str,
    tool_name: &'a str,
) -> impl Iterator<Item = &'a super::scope::ToolGrant> {
    parent
        .grants
        .iter()
        .filter(move |grant| parent_grant_covers_target(grant, server_id, tool_name))
}

/// Accept a step when at least one covering parent grant satisfies the
/// variant-specific narrowing `predicate`, fail-closed otherwise.
///
/// Overlapping parent grants are order-independent: a broad `*:*` grant that
/// lacks the targeted operation (or cost cap) must not mask a later concrete
/// grant that holds it. Subset validation already accepts a child grant covered
/// by *any* parent grant, so step validation mirrors that by checking every
/// covering grant and accepting if any one of them makes the step a true
/// narrowing. When no covering grant exists at all, the step targets a tool the
/// parent never held: reject as a widening.
fn step_matches_any_covering_grant<F>(
    parent_scope: &ChioScope,
    server_id: &str,
    tool_name: &str,
    predicate: F,
    reason: impl FnOnce() -> String,
) -> Result<()>
where
    F: Fn(&super::scope::ToolGrant) -> bool,
{
    let mut covered = false;
    for grant in covering_parent_grants(parent_scope, server_id, tool_name) {
        covered = true;
        if predicate(grant) {
            return Ok(());
        }
    }
    if !covered {
        return Err(Error::AttenuationViolation {
            reason: format!(
                "attenuation step targets tool {server_id}:{tool_name} not present in parent scope"
            ),
        });
    }
    Err(Error::AttenuationViolation { reason: reason() })
}

/// Validate that a single attenuation step is a TRUE narrowing of the parent.
///
/// Each step is checked reduce-only against the parent capability's scope and
/// expiry. A step that would widen the parent (raise a cap, target a tool the
/// parent never held, or extend expiry) is rejected with
/// [`Error::AttenuationViolation`]. Removing tools, removing operations, and
/// adding constraints are narrowings by construction, but the targeted grant
/// must still exist in the parent so a step cannot smuggle in fresh authority.
///
/// Steps are validated against *every* covering parent grant rather than only
/// the first match, so an overlapping `*:*` grant cannot mask a later concrete
/// grant that legitimately holds the targeted operation or cost cap.
fn validate_attenuation_step(
    parent_scope: &ChioScope,
    parent_expires_at: u64,
    step: &Attenuation,
) -> Result<()> {
    match step {
        Attenuation::RemoveTool {
            server_id,
            tool_name,
        }
        | Attenuation::AddConstraint {
            server_id,
            tool_name,
            ..
        } => {
            // Removing a tool or adding a constraint is a narrowing; some grant
            // must cover the target in the parent so the step cannot fabricate
            // authority. Any covering grant suffices.
            step_matches_any_covering_grant(
                parent_scope,
                server_id,
                tool_name,
                |_grant| true,
                || unreachable!("a covering grant always satisfies the trivial predicate"),
            )
        }
        Attenuation::RemoveOperation {
            server_id,
            tool_name,
            operation,
        } => step_matches_any_covering_grant(
            parent_scope,
            server_id,
            tool_name,
            |grant| grant.operations.contains(operation),
            || {
                format!(
                    "attenuation step removes operation {operation:?} from {server_id}:{tool_name} but no covering parent grant holds it"
                )
            },
        ),
        Attenuation::ReduceBudget {
            server_id,
            tool_name,
            max_invocations,
        } => step_matches_any_covering_grant(
            parent_scope,
            server_id,
            tool_name,
            // Parent uncapped (None) accepts any finite child cap: that narrows.
            |grant| {
                grant
                    .max_invocations
                    .is_none_or(|cap| *max_invocations <= cap)
            },
            || {
                format!(
                    "attenuation step raises max_invocations for {server_id}:{tool_name} to {max_invocations}, above every covering parent cap"
                )
            },
        ),
        Attenuation::ReduceCostPerInvocation {
            server_id,
            tool_name,
            max_cost_per_invocation,
        } => step_matches_any_covering_grant(
            parent_scope,
            server_id,
            tool_name,
            |grant| {
                cost_narrows(
                    grant.max_cost_per_invocation.as_ref(),
                    max_cost_per_invocation,
                )
            },
            || {
                format!(
                    "attenuation step does not narrow max_cost_per_invocation for {server_id}:{tool_name} against any covering parent grant (same currency, not above parent cap required)"
                )
            },
        ),
        Attenuation::ReduceTotalCost {
            server_id,
            tool_name,
            max_total_cost,
        } => step_matches_any_covering_grant(
            parent_scope,
            server_id,
            tool_name,
            |grant| cost_narrows(grant.max_total_cost.as_ref(), max_total_cost),
            || {
                format!(
                    "attenuation step does not narrow max_total_cost for {server_id}:{tool_name} against any covering parent grant (same currency, not above parent cap required)"
                )
            },
        ),
        Attenuation::ShortenExpiry { new_expires_at } => {
            if *new_expires_at > parent_expires_at {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "attenuation step extends expiry to {new_expires_at}, beyond parent expires_at {parent_expires_at}"
                    ),
                });
            }
            Ok(())
        }
    }
}

/// Shared reduce-only predicate for the two monetary-cost attenuation steps.
///
/// A cost cap narrows only when it is denominated in the same currency as the
/// parent's cap and does not exceed it. A parent with no cap (`None`) accepts
/// any child cap as a narrowing.
fn cost_narrows(parent_cap: Option<&MonetaryAmount>, child_cap: &MonetaryAmount) -> bool {
    match parent_cap {
        // Parent uncapped: introducing any finite cap is a narrowing.
        None => true,
        Some(parent_cap) => {
            child_cap.currency == parent_cap.currency && child_cap.units <= parent_cap.units
        }
    }
}

/// Validate every attenuation step against the parent capability, fail-closed.
///
/// Returns `Ok(())` only when all steps are true narrowings. The first
/// widening step short-circuits with an [`Error::AttenuationViolation`].
fn validate_attenuation_steps(
    parent_scope: &ChioScope,
    parent_expires_at: u64,
    steps: &[Attenuation],
) -> Result<()> {
    for step in steps {
        validate_attenuation_step(parent_scope, parent_expires_at, step)?;
    }
    Ok(())
}

/// Validate that every declared attenuation step is actually reflected in the
/// resulting child scope and expiry, fail-closed.
///
/// `validate_attenuation_steps` proves each step is reduce-only against the
/// parent, but a step that reduces the parent is not necessarily mirrored by
/// the child the caller is minting: a receipt could declare
/// `AddConstraint(MaxLength(8))` while the child grant carries no such
/// constraint. The kernel's declared-attenuation validation
/// (`chio-kernel`'s `validate_declared_attenuations`) later rejects such a
/// child because the signed link and the child scope disagree, so this helper
/// rejects the same inconsistencies at mint time and never emits an unusable
/// receipt. The per-variant semantics intentionally mirror the kernel:
///
/// * `RemoveTool`: no child grant may still cover the removed tool.
/// * `RemoveOperation`: no covering child grant may still hold the operation.
/// * `AddConstraint`: every covering child grant must carry the constraint.
/// * `ReduceBudget`: every covering child grant must be capped at or below the
///   declared `max_invocations` (an uncapped child contradicts the step).
/// * `ReduceCostPerInvocation` / `ReduceTotalCost`: every covering child grant
///   must be capped, same-currency, and at or below the declared ceiling.
/// * `ShortenExpiry`: the child expiry must be at or before the declared bound.
fn validate_steps_reflected_in_child(
    child_scope: &ChioScope,
    child_expires_at: u64,
    steps: &[Attenuation],
) -> Result<()> {
    for step in steps {
        match step {
            Attenuation::RemoveTool {
                server_id,
                tool_name,
            } => {
                if child_scope
                    .grants
                    .iter()
                    .any(|grant| step_target_covers_child_grant(grant, server_id, tool_name))
                {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared RemoveTool step for {server_id}:{tool_name} is not reflected in the child scope; the child still grants the removed tool"
                        ),
                    });
                }
            }
            Attenuation::RemoveOperation {
                server_id,
                tool_name,
                operation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    step_target_covers_child_grant(grant, server_id, tool_name)
                        && grant.operations.contains(operation)
                }) {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared RemoveOperation step ({operation:?}) for {server_id}:{tool_name} is not reflected in the child scope; the child still grants the operation"
                        ),
                    });
                }
            }
            Attenuation::AddConstraint {
                server_id,
                tool_name,
                constraint,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    step_target_covers_child_grant(grant, server_id, tool_name)
                        && !grant.constraints.contains(constraint)
                }) {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared AddConstraint step for {server_id}:{tool_name} is not reflected in the child scope; a covering child grant is missing the constraint"
                        ),
                    });
                }
            }
            Attenuation::ReduceBudget {
                server_id,
                tool_name,
                max_invocations,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    step_target_covers_child_grant(grant, server_id, tool_name)
                        && grant
                            .max_invocations
                            .is_none_or(|cap| cap > *max_invocations)
                }) {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared ReduceBudget step ({max_invocations}) for {server_id}:{tool_name} is not reflected in the child scope; a covering child grant exceeds the declared cap"
                        ),
                    });
                }
            }
            Attenuation::ReduceCostPerInvocation {
                server_id,
                tool_name,
                max_cost_per_invocation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    step_target_covers_child_grant(grant, server_id, tool_name)
                        && !child_cost_within(
                            grant.max_cost_per_invocation.as_ref(),
                            max_cost_per_invocation,
                        )
                }) {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared ReduceCostPerInvocation step for {server_id}:{tool_name} is not reflected in the child scope; a covering child grant exceeds the declared per-invocation ceiling"
                        ),
                    });
                }
            }
            Attenuation::ReduceTotalCost {
                server_id,
                tool_name,
                max_total_cost,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    step_target_covers_child_grant(grant, server_id, tool_name)
                        && !child_cost_within(grant.max_total_cost.as_ref(), max_total_cost)
                }) {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared ReduceTotalCost step for {server_id}:{tool_name} is not reflected in the child scope; a covering child grant exceeds the declared total-cost ceiling"
                        ),
                    });
                }
            }
            Attenuation::ShortenExpiry { new_expires_at } => {
                if child_expires_at > *new_expires_at {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "declared ShortenExpiry step ({new_expires_at}) is not reflected in the child; child expires_at {child_expires_at} is later than the declared bound"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Returns whether a child cost cap honors a declared `Reduce*Cost` ceiling.
///
/// The child grant must be explicitly capped, denominated in the declared
/// currency, and at or below the declared units. An uncapped child grant
/// (`None`) does not honor the declared reduction.
fn child_cost_within(child_cap: Option<&MonetaryAmount>, declared: &MonetaryAmount) -> bool {
    match child_cap {
        None => false,
        Some(child_cap) => {
            child_cap.currency == declared.currency && child_cap.units <= declared.units
        }
    }
}

/// Validate that a child scope is a valid attenuation of a parent scope.
///
/// Returns Ok(()) if child is a subset of parent. Returns an error otherwise.
pub fn validate_attenuation(parent: &ChioScope, child: &ChioScope) -> Result<()> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(Error::AttenuationViolation {
            reason: "child scope is not a subset of parent scope".to_string(),
        })
    }
}

/// Compute the stable SHA-256 hash of a canonicalized scope.
pub fn scope_hash(scope: &ChioScope) -> Result<ScopeHash> {
    let canonical = canonical_json_bytes(scope)?;
    Ok(sha256_hex(&canonical))
}

pub(crate) fn canonical_scope_string(scope: &ChioScope) -> Result<String> {
    let canonical = canonical_json_bytes(scope)?;
    core::str::from_utf8(&canonical)
        .map(ToString::to_string)
        .map_err(|err| Error::CanonicalJson(format!("canonical scope utf8 error: {err}")))
}

/// Compute an on-wire witness for a parent-to-child attenuation.
pub fn compute_attenuation_witness(
    parent: &ChioScope,
    child: &ChioScope,
) -> Result<AttenuationWitness> {
    validate_attenuation(parent, child)?;

    let mut subset_relations = Vec::new();
    let mut restricted_predicates = Vec::new();

    for (child_index, child_grant) in child.grants.iter().enumerate() {
        let Some(parent_index) = parent
            .grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("tool grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "tool".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
        let parent_grant = &parent.grants[parent_index];
        for constraint in &child_grant.constraints {
            if !parent_grant.constraints.contains(constraint) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:constraint:{:?}",
                    child_grant.server_id, child_grant.tool_name, constraint
                ));
            }
        }
        for operation in &parent_grant.operations {
            if !child_grant.operations.contains(operation) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:removed_operation:{:?}",
                    child_grant.server_id, child_grant.tool_name, operation
                ));
            }
        }
    }

    for (child_index, child_grant) in child.resource_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .resource_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("resource grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "resource".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    for (child_index, child_grant) in child.prompt_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .prompt_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("prompt grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "prompt".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    Ok(AttenuationWitness {
        normalized_parent_scope: canonical_scope_string(parent)?,
        normalized_child_scope: canonical_scope_string(child)?,
        subset_relations,
        restricted_predicates,
    })
}

/// Verify a previously-computed attenuation witness against scope hashes.
pub fn verify_attenuation_witness(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    validate_attenuation_proof(parent_hash, child_hash, witness)
}

/// Verify the wire `attenuation_proof` payload.
pub fn validate_attenuation_proof(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    let computed_parent_hash = sha256_hex(witness.normalized_parent_scope.as_bytes());
    if &computed_parent_hash != parent_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness parent_scope_hash mismatch".to_string(),
        });
    }
    let computed_child_hash = sha256_hex(witness.normalized_child_scope.as_bytes());
    if &computed_child_hash != child_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness child_scope_hash mismatch".to_string(),
        });
    }
    if witness
        .subset_relations
        .iter()
        .any(|relation| !relation.subset)
    {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness carries a non-subset relation".to_string(),
        });
    }
    let parent_scope: ChioScope =
        serde_json::from_str(&witness.normalized_parent_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness parent scope is invalid: {err}"),
            }
        })?;
    let child_scope: ChioScope =
        serde_json::from_str(&witness.normalized_child_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness child scope is invalid: {err}"),
            }
        })?;
    validate_attenuation(&parent_scope, &child_scope)?;
    Ok(())
}

fn validate_delegable_child_scope(parent: &ChioScope, child: &ChioScope) -> Result<()> {
    let has_delegable_parent_grant = parent
        .grants
        .iter()
        .any(|grant| grant.operations.contains(&Operation::Delegate))
        || parent
            .resource_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate))
        || parent
            .prompt_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate));
    if !has_delegable_parent_grant {
        return Err(Error::AttenuationViolation {
            reason: "parent capability scope does not authorize delegation".to_string(),
        });
    }

    for (index, child_grant) in child.grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "tool grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    for (index, child_grant) in child.resource_grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.resource_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "resource grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    for (index, child_grant) in child.prompt_grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.prompt_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "prompt grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    Ok(())
}

/// Recursive-delegation mint helper.
///
/// `delegate` wraps [`DelegationLink::sign`] with fail-closed attenuation
/// enforcement and emits a [`DelegationReceipt`] alongside the signed
/// link. Returns `Err` (denying the mint) when any of:
///
/// * The parent token's scope does not explicitly authorize
///   [`Operation::Delegate`].
/// * The proposed `child_scope` is not a subset of the parent token's
///   scope (rejected by [`validate_attenuation`]).
/// * Any `attenuation.steps` entry is not a true narrowing of the parent
///   (raises a cap, targets a tool outside the parent scope, or extends
///   expiry). Steps are validated reduce-only rather than copied verbatim, and
///   each is checked against *every* covering parent grant so an overlapping
///   `*:*` grant cannot mask a concrete grant that holds the targeted
///   operation or cost cap.
/// * Any declared step is not actually reflected in `child_scope` /
///   `child_expires_at` (for example an `AddConstraint` step whose constraint
///   the child grant omits). This mirrors chio-kernel's declared-attenuation
///   validation so the helper never emits a receipt whose signed link and child
///   scope disagree.
/// * `attenuation.budget_share_bps` exceeds the parent's share. The share is
///   parent-relative: a child can never claim a larger fraction of the budget
///   than the parent holds (an absent parent share is treated as 100%). When
///   the parent holds a share strictly below the 100% ceiling, the child MUST
///   state an explicit `budget_share_bps`: omission is rejected fail-closed
///   because downstream admission treats a missing share as the full budget (a
///   widening). A parent at the full ceiling (`None` or `Some(10_000)`) accepts
///   an omitted child share as a no-op.
/// * The requested `child_expires_at` is greater than the parent's
///   `expires_at` (rejected as an [`Error::AttenuationViolation`]).
/// * `delegator_keypair.public_key() != parent.subject` (the mint helper
///   is fail-closed: only the parent capability's bound subject may
///   delegate further).
///
/// The helper is intentionally pure with respect to the local clock:
/// callers pass `signed_at` and `nonce` explicitly so unit tests, replay
/// proofs, and proptest-driven invariants stay deterministic.
///
/// This function is gated behind the `delegation` feature flag. Callers
/// must opt in explicitly.
pub fn delegate(
    parent: &CapabilityToken,
    child_scope: &ChioScope,
    delegator_keypair: &Keypair,
    delegatee: &PublicKey,
    attenuation: crate::delegation_receipt::ScopeAttenuation,
    signed_at: u64,
    nonce: [u8; 16],
) -> Result<crate::delegation_receipt::DelegationReceipt> {
    if !parent.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    if signed_at < parent.issued_at {
        return Err(Error::CapabilityNotYetValid {
            not_before: parent.issued_at,
        });
    }
    if delegator_keypair.public_key() != parent.subject {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "delegator key {} does not match parent capability subject {}",
                delegator_keypair.public_key().to_hex(),
                parent.subject.to_hex()
            ),
        });
    }

    validate_attenuation(&parent.scope, child_scope)?;
    validate_delegable_child_scope(&parent.scope, child_scope)?;

    // Each attenuation step must be a TRUE narrowing of the parent: previously
    // the steps were copied onto the signed link verbatim, so a widening step
    // (raise a cap, target a tool outside the parent, extend expiry) could ride
    // through unchecked. Validate reduce-only, fail-closed.
    validate_attenuation_steps(&parent.scope, parent.expires_at, &attenuation.steps)?;

    // `budget_share_bps` is parent-relative: a delegated share is a fraction of
    // the parent's remaining/granted budget and can never widen it.
    //
    // Fail-closed on omission ONLY when the parent is genuinely
    // budget-attenuated (its share is below the full ceiling). Downstream
    // delegated-budget admission treats a missing child share as the full
    // ceiling (MAX_BUDGET_SHARE_BPS, 100%). A parent that itself holds the full
    // share (`None`, or an explicit `Some(10_000)`) is not narrowed by such an
    // omission: the child inherits the same 100% the parent already holds, so a
    // no-op delegation must be allowed. Require an explicit child share only
    // when the parent's effective share is strictly below the ceiling.
    match attenuation.budget_share_bps {
        Some(child_share) => {
            validate_parent_relative_budget_share_bps(parent.budget_share_bps, child_share)?;
        }
        None => {
            if let Some(parent_share) = parent.budget_share_bps {
                if parent_share < MAX_BUDGET_SHARE_BPS {
                    return Err(Error::AttenuationViolation {
                        reason: alloc::format!(
                            "parent holds a reduced budget_share_bps {parent_share}; the child must state an explicit budget_share_bps <= {parent_share} (an omitted share would widen to the full budget)"
                        ),
                    });
                }
            }
        }
    }

    let child_expires_at = attenuation.child_expires_at.unwrap_or(parent.expires_at);
    if child_expires_at > parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "child expires_at {} exceeds parent expires_at {}",
                child_expires_at,
                parent.expires_at
            ),
        });
    }

    // The declared steps must also be reflected in the child the caller is
    // minting, not merely reduce-only against the parent. Without this, the
    // mint helper could emit a receipt whose signed link declares an
    // attenuation that the child scope does not honor; chio-kernel's
    // declared-attenuation validation would later reject the resulting child
    // token. Reject the inconsistency here, fail-closed, so the helper never
    // produces an unusable receipt.
    validate_steps_reflected_in_child(child_scope, child_expires_at, &attenuation.steps)?;

    if signed_at >= parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "signed_at {} is at or beyond parent expires_at {}",
                signed_at,
                parent.expires_at
            ),
        });
    }

    // Delegation chain-binding: emit the parent authorized scope_hash on the
    // delegation link. A child token proving parent -> child attenuation binds
    // attenuation_proof.parent_scope_hash to this predecessor link.
    let parent_scope_hash = scope_hash(&parent.scope)?;
    let body = DelegationLinkBody {
        capability_id: parent.id.clone(),
        delegator: parent.subject.clone(),
        delegatee: delegatee.clone(),
        attenuations: attenuation.steps.clone(),
        timestamp: signed_at,
        scope_hash: Some(parent_scope_hash),
    };
    let link = DelegationLink::sign(body, delegator_keypair)?;

    Ok(crate::delegation_receipt::DelegationReceipt {
        parent_chain: parent.delegation_chain.clone(),
        attenuation,
        signed_at,
        nonce,
        link,
        parent_capability_id: parent.id.clone(),
    })
}
