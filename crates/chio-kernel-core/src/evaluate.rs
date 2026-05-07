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
//! The caller -- today `chio-kernel::ChioKernel::evaluate_tool_call_sync` and
//! tomorrow `chio-kernel-wasm::BrowserKernel::evaluate` -- wraps this pure
//! core in the I/O checks it needs.
//!
//! Verified-core boundary note:
//! `formal/proof-manifest.toml` names this module as covered Rust surface for
//! the current bounded verified core. The covered semantics stop at pure
//! capability verification, subject binding, portable scope matching, and the
//! synchronous guard pipeline; revocation lookups, budget mutation, DPoP, and
//! tool dispatch stay outside this module and outside the present proof claim.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{
    CapabilityCryptoFloor, CapabilityNegotiation, CapabilityToken, CHIO_CAPABILITY_V2_SCHEMA,
};
use chio_core_types::crypto::PublicKey;

use crate::budget_split::{BudgetRegistry, NoopBudgetRegistry};
use crate::capability_verify::{
    verify_capability_full, verify_capability_with_floor, CapabilityError, TrustRootResolver,
    VerifiedCapability,
};
use crate::clock::Clock;
use crate::guard::{Guard, GuardContext, PortableToolCallRequest};
use crate::normalized::{NormalizationError, NormalizedEvaluationVerdict};
use crate::scope::{resolve_matching_grants, MatchedGrant};
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
/// These are portable-kernel equivalents of the legacy
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
                CapabilityError::SchemaExceedsNegotiatedCeiling {
                    token_schema,
                    peer_max,
                } => {
                    let mut out = String::from("capability token schema ");
                    out.push_str(token_schema);
                    out.push_str(" exceeds peer-negotiated ceiling ");
                    out.push_str(peer_max);
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
/// Legacy callers use [`evaluate`], which preserves the historical
/// allow-classical posture. Kernels that load `policy.crypto_floor` must call
/// this entry point so capability tokens cannot bypass the PQ floor.
///
/// This entry point uses a [`NoopBudgetRegistry`]; the full
/// [`evaluate_with_crypto_floor_and_budgets`] entry point lets a hosted
/// kernel inject its own [`BudgetRegistry`] so sibling-sum oversubscription
/// is rejected at evaluation time.
///
/// Wave 1.5 note: this entry point does NOT enforce the W1.1 chain-binding
/// rule or the W1.3 negotiated schema-ceiling rule. Production kernels MUST
/// migrate to [`evaluate_with_full_floor`], which threads a peer-negotiated
/// capability profile and a per-issuer trust-root resolver through the
/// verifier in addition to the crypto floor. Calls that hit this entry
/// point continue to work for v1 tokens but leave a v2-token soundness
/// gap and a downgrade-attack surface open.
pub fn evaluate_with_crypto_floor(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
) -> EvaluationVerdict {
    let mut budgets = NoopBudgetRegistry;
    evaluate_with_crypto_floor_and_budgets(input, crypto_floor, &mut budgets)
}

/// Evaluate with both a configured crypto floor and a sibling-sum budget
/// registry. Hosted kernels that track delegated children should call this
/// so an oversubscribed sibling fails closed at the verify step.
pub fn evaluate_with_crypto_floor_and_budgets(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    // Step 1: capability verification.
    if input.capability.schema == CHIO_CAPABILITY_V2_SCHEMA {
        let core_err = KernelCoreError::InvalidCapability(CapabilityError::AttenuationViolation(
            "v2 chain-binding requires a trust-root resolver on the evaluate path".to_string(),
        ));
        return deny(core_err, None, None);
    }

    let verified = match verify_capability_with_floor(
        input.capability,
        input.trusted_issuers,
        input.clock,
        crypto_floor,
        budgets,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            let core_err = KernelCoreError::InvalidCapability(error);
            return deny(core_err, None, None);
        }
    };

    // Step 2: subject binding.
    if verified.subject_hex != input.request.agent_id {
        let core_err = KernelCoreError::SubjectMismatch {
            expected: verified.subject_hex.clone(),
            actual: input.request.agent_id.clone(),
        };
        return deny(core_err, None, Some(verified));
    }

    // Step 3: scope match.
    let matches: Vec<MatchedGrant<'_>> = match resolve_matching_grants(
        &verified.scope,
        &input.request.tool_name,
        &input.request.server_id,
        &input.request.arguments,
    ) {
        Ok(matches) if matches.is_empty() => {
            let core_err = KernelCoreError::OutOfScope {
                tool: input.request.tool_name.clone(),
                server: input.request.server_id.clone(),
            };
            return deny(core_err, None, Some(verified));
        }
        Ok(matches) => matches,
        Err(crate::ScopeMatchError::OutOfScope) => {
            let core_err = KernelCoreError::OutOfScope {
                tool: input.request.tool_name.clone(),
                server: input.request.server_id.clone(),
            };
            return deny(core_err, None, Some(verified));
        }
        Err(crate::ScopeMatchError::ConstraintError(reason)) => {
            return deny(
                KernelCoreError::ConstraintError { reason },
                None,
                Some(verified),
            );
        }
    };
    // Safe: guarded above.
    let matched_grant_index = matches[0].index;

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
                // layer (chio-kernel::approval::ApprovalGuard); if a legacy sync
                // guard surfaces it here we fail closed.
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

    EvaluationVerdict {
        verdict: Verdict::Allow,
        reason: None,
        matched_grant_index: Some(matched_grant_index),
        verified: Some(verified),
    }
}

/// Wave 1.5 maximum-flexibility evaluation entry point.
///
/// Same five steps as [`evaluate_with_crypto_floor`] but uses
/// [`crate::capability_verify::verify_capability_full`] for capability
/// verification, which threads:
///
/// - the W1.3 peer-negotiated schema ceiling, and
/// - the W1.1 per-issuer trust-root resolver
///
/// in addition to the crypto floor. Production kernels (`chio-kernel`,
/// `chio-kernel-browser`, `chio-kernel-mobile`, `chio-cpp-kernel-ffi`,
/// `chio-ag-ui-proxy`) call this path so the W1.1 chain-binding rule and
/// the W1.3 downgrade defense are actually exercised on the hot path.
pub fn evaluate_with_full_floor(
    input: EvaluateInput<'_>,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> EvaluationVerdict {
    // Step 1: capability verification with all Wave 1 defenses except
    // persistent sibling-sum admission. Admission mutates the supplied
    // registry, so defer it until subject, scope, and guard checks have
    // passed. Otherwise a validly signed token for the wrong request can
    // consume sibling share and starve later valid siblings.
    let mut verify_only_budgets = NoopBudgetRegistry;
    let verified = match verify_capability_full(
        input.capability,
        input.trusted_issuers,
        input.clock,
        crypto_floor,
        peer,
        trust_root,
        &mut verify_only_budgets,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            let core_err = KernelCoreError::InvalidCapability(error);
            return deny(core_err, None, None);
        }
    };

    // Step 2: subject binding.
    if verified.subject_hex != input.request.agent_id {
        let core_err = KernelCoreError::SubjectMismatch {
            expected: verified.subject_hex.clone(),
            actual: input.request.agent_id.clone(),
        };
        return deny(core_err, None, Some(verified));
    }

    // Step 3: scope match.
    let matches: Vec<MatchedGrant<'_>> = match resolve_matching_grants(
        &verified.scope,
        &input.request.tool_name,
        &input.request.server_id,
        &input.request.arguments,
    ) {
        Ok(matches) if matches.is_empty() => {
            let core_err = KernelCoreError::OutOfScope {
                tool: input.request.tool_name.clone(),
                server: input.request.server_id.clone(),
            };
            return deny(core_err, None, Some(verified));
        }
        Ok(matches) => matches,
        Err(crate::ScopeMatchError::OutOfScope) => {
            let core_err = KernelCoreError::OutOfScope {
                tool: input.request.tool_name.clone(),
                server: input.request.server_id.clone(),
            };
            return deny(core_err, None, Some(verified));
        }
        Err(crate::ScopeMatchError::ConstraintError(reason)) => {
            return deny(
                KernelCoreError::ConstraintError { reason },
                None,
                Some(verified),
            );
        }
    };
    // Safe: guarded above.
    let matched_grant_index = matches[0].index;

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

    if let Some(parent_link) = input.capability.delegation_chain.last() {
        let proposed_share = input
            .capability
            .budget_share_bps
            .unwrap_or(crate::budget_split::MAX_BUDGET_SHARE_BPS);
        if let Err(error) = budgets.try_admit_child(
            parent_link.capability_id.as_str(),
            input.capability.id.clone(),
            proposed_share,
        ) {
            let core_err = KernelCoreError::InvalidCapability(
                crate::capability_verify::CapabilityError::BudgetSplitRejected(error),
            );
            return deny(core_err, Some(matched_grant_index), Some(verified));
        }
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
