//! Pure-compute verdict evaluation.
//!
//! [`evaluate`] walks a `(capability, request, guards)` tuple through the
//! sync checks that do not require I/O or mutable kernel state:
//!
//! 1. Issuer trust + signature + time-bound verification via
//!    [`crate::capability_verify::verify_capability`].
//! 2. Subject-binding check (agent_id == capability.subject hex).
//! 3. Portable scope match via [`crate::scope::resolve_matching_grants`].
//! 4. Guard pipeline: every registered guard is invoked in order;
//!    fail-closed on error or `Deny`.
//!
//! What it does NOT do (fenced into `chio-kernel` proper):
//!
//! - Revocation membership lookup (stateful `RevocationStore`).
//! - Budget mutation (stateful `BudgetStore`).
//! - Delegation-chain ancestor inspection against the receipt store.
//! - DPoP proof verification with nonce replay (LRU-backed).
//! - Governed-transaction policy evaluation (pulls in chio-governance).
//! - Payment authorisation (async adapter trait).
//! - Tool dispatch to wrapped servers (async transport).
//! - Receipt persistence / Merkle checkpointing (SQL / IO).
//!
//! Callers (`chio-kernel::ChioKernel::evaluate_tool_call_sync`, the browser
//! and mobile adapters) wrap this pure core in the I/O checks they need.
//!
//! Verified-core boundary note:
//! `formal/proof-manifest.toml` names this module as covered Rust surface for
//! the current bounded verified core. The covered semantics stop at pure
//! capability verification, subject binding, portable scope matching, and the
//! synchronous guard pipeline; revocation lookups, budget mutation, DPoP, and
//! tool dispatch stay outside this module and outside the present proof claim.

use alloc::string::{String, ToString};

use chio_core_types::capability::{
    crypto_floor::CapabilityCryptoFloor, features::CapabilityNegotiation, scope::ChioScope,
    token::CapabilityToken,
};
use chio_core_types::crypto::PublicKey;

use crate::budget_split::{BudgetRegistry, NoopBudgetRegistry};
use crate::capability_verify::{
    admit_delegated_budget, verify_capability_with_floor, CapabilityError, TrustRootResolver,
    VerifiedCapability,
};
use crate::clock::Clock;
use crate::guard::{Guard, GuardContext, PortableToolCallRequest};
use crate::normalized::{NormalizationError, NormalizedEvaluationVerdict};
use crate::scope::resolve_matching_grants;
use crate::Verdict;

/// Inputs to [`evaluate`]. Grouped into a struct so the call site stays
/// tidy and future fields (e.g. a policy-digest override) can be added
/// without breaking the public signature.
pub struct EvaluateInput<'a> {
    /// Tool call request being evaluated.
    pub request: &'a PortableToolCallRequest,
    /// The capability token authorising this call.
    pub capability: &'a CapabilityToken,
    /// Trusted issuer public keys (typically CA + kernel + authority).
    pub trusted_issuers: &'a [PublicKey],
    /// Clock used for time-bound enforcement.
    pub clock: &'a dyn Clock,
    /// Guard pipeline. Evaluated in order, fail-closed on deny or error.
    pub guards: &'a [&'a dyn Guard],
    /// Optional filesystem roots from the owning session, passed through to
    /// guards that enforce root-based resource protection.
    pub session_filesystem_roots: Option<&'a [String]>,
}

/// Verdict + context produced by [`evaluate`].
///
/// On `Verdict::Allow` the caller is handed the `VerifiedCapability` and
/// the matched grant index; the full kernel uses those to drive budget
/// accounting, receipt construction, and tool dispatch.
#[derive(Debug, Clone)]
pub struct EvaluationVerdict {
    /// The three-valued verdict. `PendingApproval` is never produced by
    /// the core; only Allow / Deny flow out of this module.
    pub verdict: Verdict,
    /// Human-readable deny reason when `verdict == Deny`.
    pub reason: Option<String>,
    /// Grant index that admitted the request. Populated on Allow.
    pub matched_grant_index: Option<usize>,
    /// Verified capability snapshot. Populated when signature + time
    /// checks succeeded, even if a later guard denied.
    pub verified: Option<VerifiedCapability>,
}

impl EvaluationVerdict {
    /// Is this an allow verdict?
    #[must_use]
    pub fn is_allow(&self) -> bool {
        self.verdict == Verdict::Allow
    }

    /// Is this a deny verdict?
    #[must_use]
    pub fn is_deny(&self) -> bool {
        self.verdict == Verdict::Deny
    }

    /// Project this evaluation result into the proof-facing normalized AST.
    pub fn normalized(
        &self,
        request: &PortableToolCallRequest,
    ) -> Result<NormalizedEvaluationVerdict, NormalizationError> {
        NormalizedEvaluationVerdict::try_from_evaluation(request, self)
    }
}

/// Errors the portable core can raise.
///
/// These are portable-kernel equivalents of the
/// `chio_kernel::KernelError` variants that can be produced without any
/// I/O. The caller in `chio-kernel` maps them back onto its richer
/// `KernelError` surface for backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelCoreError {
    /// Capability signature or issuer trust failed.
    InvalidCapability(CapabilityError),
    /// Subject mismatch: `request.agent_id` != `capability.subject`.
    SubjectMismatch { expected: String, actual: String },
    /// No grant in scope covers the requested tool/server.
    OutOfScope { tool: String, server: String },
    /// Portable scope matching failed closed on an unsupported constraint.
    ConstraintError { reason: String },
    /// The capability requires stateful enforcement unavailable in this runtime.
    UnsupportedCapabilityFeature { feature: String },
    /// A guard returned a fail-closed error.
    GuardError { guard: String, reason: String },
    /// A guard denied the request outright.
    GuardDenied { guard: String },
}

impl KernelCoreError {
    /// Human-readable reason for the deny verdict.
    #[must_use]
    pub fn deny_reason(&self) -> String {
        match self {
            KernelCoreError::InvalidCapability(error) => match error {
                CapabilityError::UntrustedIssuer => {
                    "capability issuer is not a trusted CA".to_string()
                }
                CapabilityError::InvalidSignature => "capability signature is invalid".to_string(),
                CapabilityError::CryptoFloorRejected(msg) => {
                    let mut out = String::from("capability rejected by crypto floor: ");
                    out.push_str(msg);
                    out
                }
                CapabilityError::NotYetValid => "capability not yet valid".to_string(),
                CapabilityError::Expired => "capability has expired".to_string(),
                CapabilityError::AttenuationViolation(msg) => {
                    let mut out = String::from("capability rejected by chain binding: ");
                    out.push_str(msg);
                    out
                }
                CapabilityError::BudgetSplitRejected(err) => {
                    let mut out = String::from("capability budget split rejected: ");
                    // alloc::fmt is available; use core formatting.
                    let formatted = alloc::format!("{err}");
                    out.push_str(&formatted);
                    out
                }
                CapabilityError::Internal(msg) => {
                    let mut out = String::from("capability verification failed: ");
                    out.push_str(msg);
                    out
                }
            },
            KernelCoreError::SubjectMismatch { expected, actual } => {
                let mut out = String::from("request agent ");
                out.push_str(actual);
                out.push_str(" does not match capability subject ");
                out.push_str(expected);
                out
            }
            KernelCoreError::OutOfScope { tool, server } => {
                let mut out = String::from("requested tool ");
                out.push_str(tool);
                out.push_str(" on server ");
                out.push_str(server);
                out.push_str(" is not in capability scope");
                out
            }
            KernelCoreError::ConstraintError { reason } => {
                let mut out = String::from("constraint evaluation failed: ");
                out.push_str(reason);
                out
            }
            KernelCoreError::UnsupportedCapabilityFeature { feature } => {
                let mut out = String::from("capability feature unsupported on this runtime: ");
                out.push_str(feature);
                out
            }
            KernelCoreError::GuardError { guard, reason } => {
                let mut out = String::from("guard \"");
                out.push_str(guard);
                out.push_str("\" error (fail-closed): ");
                out.push_str(reason);
                out
            }
            KernelCoreError::GuardDenied { guard } => {
                let mut out = String::from("guard \"");
                out.push_str(guard);
                out.push_str("\" denied the request");
                out
            }
        }
    }
}

fn out_of_scope_error(request: &PortableToolCallRequest) -> KernelCoreError {
    KernelCoreError::OutOfScope {
        tool: request.tool_name.clone(),
        server: request.server_id.clone(),
    }
}

fn resolve_matched_grant_index(
    scope: &ChioScope,
    request: &PortableToolCallRequest,
) -> Result<usize, KernelCoreError> {
    let matches = match resolve_matching_grants(
        scope,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
    ) {
        Ok(matches) => matches,
        Err(crate::ScopeMatchError::OutOfScope) => return Err(out_of_scope_error(request)),
        Err(crate::ScopeMatchError::ConstraintError(reason)) => {
            return Err(KernelCoreError::ConstraintError { reason });
        }
    };

    matches
        .first()
        .map(|matched| matched.index)
        .ok_or_else(|| out_of_scope_error(request))
}

/// Primary entry point for the portable kernel core.
///
/// Performs in order:
///
/// 1. Capability signature / issuer / time-bound verification.
/// 2. Subject binding (agent_id match).
/// 3. Portable scope match.
/// 4. Guard pipeline (fail-closed).
///
/// Returns `Ok(EvaluationVerdict)` for Allow or Deny. An `Err` is only
/// returned when the underlying `verify_canonical` machinery reports an
/// internal failure that is not a clean verify-false; semantically this
/// is still a deny at the caller's level and chio-kernel maps it onto
/// `KernelError::Internal`.
pub fn evaluate(input: EvaluateInput<'_>) -> EvaluationVerdict {
    evaluate_with_crypto_floor(input, CapabilityCryptoFloor::AllowClassical)
}

/// Evaluate with a configured capability crypto floor.
///
/// [`evaluate`] defaults to the allow-classical posture. Kernels that load
/// `policy.crypto_floor` must call this entry point so capability tokens cannot
/// bypass the PQ floor.
///
/// This entry point uses a [`NoopBudgetRegistry`]; the full
/// [`evaluate_with_crypto_floor_and_budgets`] entry point lets a hosted
/// kernel inject its own [`BudgetRegistry`] so sibling-sum oversubscription
/// is rejected at evaluation time.
///
/// This entry point does not enforce chain binding for attenuated delegated
/// tokens because it has no trust-root resolver. Production kernels that
/// accept attenuation should call [`evaluate_with_full_floor`].
pub fn evaluate_with_crypto_floor(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
) -> EvaluationVerdict {
    let mut budgets = NoopBudgetRegistry;
    evaluate_with_crypto_floor_and_budgets(input, crypto_floor, &mut budgets)
}

/// Evaluate with both a configured crypto floor and a sibling-sum budget
/// registry. Hosted kernels that track delegated children should call this
/// so an oversubscribed sibling fails closed after the request is otherwise
/// allowed.
pub fn evaluate_with_crypto_floor_and_budgets(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    // Step 1: capability verification.
    if input.capability.attenuation_proof.is_some() {
        let core_err = KernelCoreError::InvalidCapability(CapabilityError::AttenuationViolation(
            "chain-binding requires a trust-root resolver on the evaluate path".to_string(),
        ));
        return deny(core_err, None, None);
    }

    let mut verify_only_budgets = NoopBudgetRegistry;
    let verified = match verify_capability_with_floor(
        input.capability,
        input.trusted_issuers,
        input.clock,
        crypto_floor,
        &mut verify_only_budgets,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            let core_err = KernelCoreError::InvalidCapability(error);
            return deny(core_err, None, None);
        }
    };

    finish_verified_evaluation(input, verified, budgets)
}

/// Full current-semantics evaluation entry point.
///
/// Same five steps as [`evaluate_with_crypto_floor`] but uses
/// [`crate::capability_verify::verify_capability_full`] for capability
/// verification, which threads:
///
/// - the peer-negotiated feature profile, and
/// - the per-issuer trust-root resolver
///
/// in addition to the crypto floor. Production kernels (`chio-kernel`,
/// `chio-kernel-browser`, `chio-kernel-mobile`, `chio-cpp-kernel-ffi`,
/// `chio-ag-ui-proxy`) call this path so chain-binding and feature validation
/// are exercised on the hot path.
pub fn evaluate_with_full_floor(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    evaluate_with_full_floor_and_root(input, crypto_floor, peer, None, trust_root, budgets)
}

/// Full evaluation with authenticated optional-family root evidence.
pub fn evaluate_with_full_floor_and_root(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    direct_root: Option<&CapabilityToken>,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    // Step 1: capability verification with all defenses except
    // persistent sibling-sum admission. Admission mutates the supplied
    // registry, so defer it until subject, scope, and guard checks have
    // passed. Otherwise a validly signed token for the wrong request can
    // consume sibling share and starve later valid siblings.
    let mut verify_only_budgets = NoopBudgetRegistry;
    let verified = match crate::capability_verify::verify_capability_full_with_root(
        input.capability,
        input.trusted_issuers,
        input.clock,
        crypto_floor,
        crate::capability_verify::CapabilityFeatureContext { peer, direct_root },
        trust_root,
        &mut verify_only_budgets,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            let core_err = KernelCoreError::InvalidCapability(error);
            return deny(core_err, None, None);
        }
    };
    if input.capability.aggregate_invocation_budget.is_some() {
        return deny(
            KernelCoreError::UnsupportedCapabilityFeature {
                feature: "aggregate invocation enforcement".to_string(),
            },
            None,
            Some(verified),
        );
    }
    if input.capability.scope.has_cumulative_approval() {
        return deny(
            KernelCoreError::UnsupportedCapabilityFeature {
                feature: "cumulative approval enforcement".to_string(),
            },
            None,
            Some(verified),
        );
    }

    finish_verified_evaluation(input, verified, budgets)
}

fn finish_verified_evaluation(
    input: EvaluateInput<'_>,
    verified: VerifiedCapability,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    // Step 2: subject binding.
    if verified.subject_hex != input.request.agent_id {
        let core_err = KernelCoreError::SubjectMismatch {
            expected: verified.subject_hex.clone(),
            actual: input.request.agent_id.clone(),
        };
        return deny(core_err, None, Some(verified));
    }

    // Step 3: scope match.
    let matched_grant_index = match resolve_matched_grant_index(&verified.scope, input.request) {
        Ok(index) => index,
        Err(error) => return deny(error, None, Some(verified)),
    };

    // Step 4: guard pipeline.
    let ctx = GuardContext {
        request: input.request,
        scope: &verified.scope,
        agent_id: &input.request.agent_id,
        server_id: &input.request.server_id,
        session_filesystem_roots: input.session_filesystem_roots,
        matched_grant_index: Some(matched_grant_index),
    };

    for guard in input.guards {
        match guard.evaluate(&ctx) {
            Ok(Verdict::Allow) => {}
            Ok(Verdict::Deny) | Ok(Verdict::PendingApproval) => {
                // PendingApproval is reserved for the full kernel orchestration
                // layer (chio-kernel::approval::ApprovalGuard); if a sync guard
                // surfaces it here we fail closed.
                let core_err = KernelCoreError::GuardDenied {
                    guard: guard.name().to_string(),
                };
                return deny(core_err, Some(matched_grant_index), Some(verified));
            }
            Err(error) => {
                let core_err = KernelCoreError::GuardError {
                    guard: guard.name().to_string(),
                    reason: error.deny_reason(),
                };
                return deny(core_err, Some(matched_grant_index), Some(verified));
            }
        }
    }

    // Step 5: mutate delegated sibling budget only after every deny-capable
    // local check has passed.
    if let Err(error) = admit_delegated_budget(input.capability, budgets) {
        let core_err = KernelCoreError::InvalidCapability(error);
        return deny(core_err, Some(matched_grant_index), Some(verified));
    }

    EvaluationVerdict {
        verdict: Verdict::Allow,
        reason: None,
        matched_grant_index: Some(matched_grant_index),
        verified: Some(verified),
    }
}

fn deny(
    error: KernelCoreError,
    matched_grant_index: Option<usize>,
    verified: Option<VerifiedCapability>,
) -> EvaluationVerdict {
    EvaluationVerdict {
        verdict: Verdict::Deny,
        reason: Some(error.deny_reason()),
        matched_grant_index,
        verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetRegistry, InMemoryBudgetRegistry, MAX_BUDGET_SHARE_BPS};
    use alloc::vec;
    use chio_core_types::capability::{
        aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
        attenuation::{DelegationLink, DelegationLinkBody},
        features::AGGREGATE_INVOCATION_BUDGET,
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core_types::crypto::Keypair;

    fn grant(server_id: &str, tool_name: &str) -> ToolGrant {
        ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn request() -> PortableToolCallRequest {
        PortableToolCallRequest {
            request_id: "req-1".to_string(),
            tool_name: "echo".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({"msg":"hello"}),
        }
    }

    fn delegated_capability(
        issuer: &Keypair,
        subject: &Keypair,
        parent_capability_id: &str,
    ) -> CapabilityToken {
        let parent_link = match DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_capability_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: issuer.public_key(),
                attenuations: vec![],
                timestamp: 100,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            },
            issuer,
        ) {
            Ok(link) => link,
            Err(error) => panic!("failed to sign parent delegation link: {error:?}"),
        };

        match CapabilityToken::sign(
            CapabilityTokenBody {
                id: "child-capability".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![grant("srv-a", "echo")],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![parent_link],
                aggregate_invocation_budget: None,
            },
            issuer,
        ) {
            Ok(token) => token,
            Err(error) => panic!("failed to sign delegated capability: {error:?}"),
        }
    }

    #[test]
    fn resolve_matched_grant_index_uses_scope_specificity_order() {
        let scope = ChioScope {
            grants: vec![grant("*", "*"), grant("srv-a", "echo")],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        let matched_index = resolve_matched_grant_index(&scope, &request());

        assert_eq!(matched_index, Ok(1));
    }

    #[test]
    fn resolve_matched_grant_index_maps_missing_grant_to_request_identity() {
        let scope = ChioScope {
            grants: vec![grant("srv-b", "echo")],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        let error = resolve_matched_grant_index(&scope, &request());

        assert_eq!(
            error,
            Err(KernelCoreError::OutOfScope {
                tool: "echo".to_string(),
                server: "srv-a".to_string(),
            })
        );
    }

    #[test]
    fn budget_admission_waits_until_subject_scope_and_guards_allow() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let wrong_agent = Keypair::generate();
        let parent_capability_id = "parent-capability";
        let capability = delegated_capability(&issuer, &subject, parent_capability_id);
        let mut request = request();
        request.agent_id = wrong_agent.public_key().to_hex();
        let trusted = [issuer.public_key()];
        let clock = crate::FixedClock::new(150);
        let guards: [&dyn Guard; 0] = [];
        let mut budgets = InMemoryBudgetRegistry::new();
        if let Err(error) =
            budgets.register_parent(parent_capability_id.to_string(), MAX_BUDGET_SHARE_BPS)
        {
            panic!("failed to register parent budget split: {error:?}");
        }

        let verdict = evaluate_with_crypto_floor_and_budgets(
            EvaluateInput {
                request: &request,
                capability: &capability,
                trusted_issuers: &trusted,
                clock: &clock,
                guards: &guards,
                session_filesystem_roots: None,
            },
            CapabilityCryptoFloor::AllowClassical,
            &mut budgets,
        );

        assert!(verdict.is_deny());
        let split = match budgets.split(parent_capability_id) {
            Some(split) => split,
            None => panic!("registered parent budget split was missing"),
        };
        assert_eq!(split.current_total_child_bps(), 0);
        assert!(split.children.is_empty());
    }

    #[test]
    fn full_floor_budget_admission_waits_until_subject_scope_and_guards_allow() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let wrong_agent = Keypair::generate();
        let parent_capability_id = "parent-capability-full";
        let capability = delegated_capability(&issuer, &subject, parent_capability_id);
        let mut request = request();
        request.agent_id = wrong_agent.public_key().to_hex();
        let trusted = [issuer.public_key()];
        let clock = crate::FixedClock::new(150);
        let guards: [&dyn Guard; 0] = [];
        let peer = CapabilityNegotiation::t1_default();
        let trust_roots = |_issuer: &chio_core_types::crypto::PublicKey| None;
        let mut budgets = InMemoryBudgetRegistry::new();
        if let Err(error) =
            budgets.register_parent(parent_capability_id.to_string(), MAX_BUDGET_SHARE_BPS)
        {
            panic!("failed to register parent budget split: {error:?}");
        }

        let verdict = evaluate_with_full_floor(
            EvaluateInput {
                request: &request,
                capability: &capability,
                trusted_issuers: &trusted,
                clock: &clock,
                guards: &guards,
                session_filesystem_roots: None,
            },
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        );

        assert!(verdict.is_deny());
        let split = match budgets.split(parent_capability_id) {
            Some(split) => split,
            None => panic!("registered parent budget split was missing"),
        };
        assert_eq!(split.current_total_child_bps(), 0);
        assert!(split.children.is_empty());
    }

    #[test]
    fn full_floor_denies_aggregate_budget_until_enforcement_is_available() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = match CapabilityToken::sign(
            CapabilityTokenBody {
                id: "aggregate-not-enforced".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![grant("srv-a", "echo")],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![],
                aggregate_invocation_budget: Some(AggregateInvocationBudget {
                    scope: AggregateInvocationScope::Capability,
                    max_invocations: 1,
                    root_binding: None,
                }),
            },
            &issuer,
        ) {
            Ok(capability) => capability,
            Err(error) => panic!("failed to sign aggregate capability: {error}"),
        };
        let mut request = request();
        request.agent_id = subject.public_key().to_hex();
        let trusted = [issuer.public_key()];
        let clock = crate::FixedClock::new(150);
        let guards: [&dyn Guard; 0] = [];
        let mut peer = CapabilityNegotiation::v1_default();
        peer.features
            .insert(AGGREGATE_INVOCATION_BUDGET.to_string(), true);
        let trust_roots = |_issuer: &chio_core_types::crypto::PublicKey| None;
        let mut budgets = InMemoryBudgetRegistry::new();

        let verdict = evaluate_with_full_floor(
            EvaluateInput {
                request: &request,
                capability: &capability,
                trusted_issuers: &trusted,
                clock: &clock,
                guards: &guards,
                session_filesystem_roots: None,
            },
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        );

        assert!(verdict.is_deny());
        assert!(verdict.reason.as_deref().is_some_and(|reason| reason
            .contains("unsupported on this runtime: aggregate invocation enforcement")));
    }
}
