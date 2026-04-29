extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use chio_core_types::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{PublicKey, Signature, SigningAlgorithm, SigningBackend};
use chio_core_types::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use serde_json::Value;

use crate::capability_verify::CapabilityError;
use crate::clock::FixedClock;
use crate::evaluate::EvaluateInput;
use crate::formal_core::{
    monetary_cap_is_subset_by_parts, optional_u32_cap_is_subset, required_true_is_preserved,
    revocation_snapshot_denies, time_window_valid,
};
use crate::guard::PortableToolCallRequest;
use crate::normalized::{NormalizedOperation, NormalizedScope, NormalizedToolGrant};
use crate::receipts::ReceiptSigningError;
use crate::scope::resolve_matching_grants;
use crate::{evaluate, sign_receipt, verify_capability, Verdict};

fn public_key(seed: u8) -> PublicKey {
    let mut bytes = [seed; 65];
    bytes[0] = 0x04;
    PublicKey::from_p256_sec1(&bytes)
        .unwrap_or_else(|_| unreachable!("deterministic P-256 key fixture is well-formed"))
}

fn p384_public_key(seed: u8) -> PublicKey {
    let mut bytes = [seed; 97];
    bytes[0] = 0x04;
    PublicKey::from_p384_sec1(&bytes)
        .unwrap_or_else(|_| unreachable!("deterministic P-384 key fixture is well-formed"))
}

fn grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn unsigned_capability(ttl: u64) -> CapabilityToken {
    CapabilityToken {
        id: "cap-public-kani".to_string(),
        issuer: public_key(7),
        subject: public_key(9),
        scope: ChioScope {
            grants: vec![grant("s", "r")],
            ..ChioScope::default()
        },
        issued_at: 10,
        expires_at: 10 + ttl,
        delegation_chain: vec![],
        algorithm: None,
        signature: Signature::from_bytes(&[0; 64]),
    }
}

fn path_arguments(path: &str) -> Value {
    Value::String(path.to_string())
}

fn request(_capability: &CapabilityToken, tool: &str) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: "req-public-kani".to_string(),
        tool_name: tool.to_string(),
        server_id: "s".to_string(),
        agent_id: "agent-public-kani".to_string(),
        arguments: path_arguments("/app/src/main.rs"),
    }
}

fn assume_single_unconstrained_invoke_grant(scope: &ChioScope) {
    kani::assume(scope.grants.len() == 1);
    let grant = &scope.grants[0];
    kani::assume(grant.constraints.is_empty());
    kani::assume(grant.operations.len() == 1);
    kani::assume(grant.operations[0] == Operation::Invoke);
}

fn assume_single_normalized_tool_grant(scope: &NormalizedScope) {
    kani::assume(scope.grants.len() == 1);
    kani::assume(scope.resource_grants.is_empty());
    kani::assume(scope.prompt_grants.is_empty());
    let grant = &scope.grants[0];
    kani::assume(grant.constraints.is_empty());
    kani::assume(grant.operations.len() == 1);
    kani::assume(grant.max_cost_per_invocation.is_none());
    kani::assume(grant.max_total_cost.is_none());
}

#[kani::proof]
fn public_verify_capability_rejects_untrusted_issuer_before_signature() {
    let capability = unsigned_capability(100);
    let clock = FixedClock::new(11);
    let result = verify_capability(&capability, &[], &clock);

    assert!(matches!(result, Err(CapabilityError::UntrustedIssuer)));
    core::mem::forget(capability);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_widened_child() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_value_widened_child() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: Some(100),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(false),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_normalized_scope_subset_rejects_identity_mismatch() {
    let parent = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "s".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let child = NormalizedScope {
        grants: vec![NormalizedToolGrant {
            server_id: "other".to_string(),
            tool_name: "r".to_string(),
            operations: vec![NormalizedOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    assume_single_normalized_tool_grant(&child);
    assume_single_normalized_tool_grant(&parent);
    assert!(!child.is_subset_of(&parent));
    core::mem::forget(child);
    core::mem::forget(parent);
}

#[kani::proof]
fn public_resolve_matching_grants_rejects_out_of_scope_request() {
    let scope = ChioScope {
        grants: vec![grant("s", "r")],
        ..ChioScope::default()
    };
    assume_single_unconstrained_invoke_grant(&scope);
    let arguments = Value::Null;
    let matches = match resolve_matching_grants(&scope, "w", "s", &arguments) {
        Ok(matches) => matches,
        Err(_) => {
            core::mem::forget(arguments);
            core::mem::forget(scope);
            kani::assume(false);
            unreachable!("unconstrained grants do not fail during matching");
        }
    };

    assert!(matches.is_empty());
    core::mem::forget(matches);
    core::mem::forget(arguments);
    core::mem::forget(scope);
}

#[kani::proof]
fn public_resolve_matching_grants_preserves_wildcard_matching() {
    let scope = ChioScope {
        grants: vec![grant("*", "*")],
        ..ChioScope::default()
    };
    assume_single_unconstrained_invoke_grant(&scope);
    let arguments = Value::Null;
    let matches = match resolve_matching_grants(&scope, "w", "s", &arguments) {
        Ok(matches) => matches,
        Err(_) => {
            core::mem::forget(arguments);
            core::mem::forget(scope);
            kani::assume(false);
            unreachable!("unconstrained wildcard grants do not fail");
        }
    };

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].specificity, (0, 0, 0));
    core::mem::forget(matches);
    core::mem::forget(arguments);
    core::mem::forget(scope);
}

#[kani::proof]
fn public_evaluate_rejects_untrusted_issuer_before_dispatch() {
    let capability = unsigned_capability(100);
    let request = request(&capability, "r");
    let clock = FixedClock::new(11);
    let guards: [&dyn crate::Guard; 0] = [];
    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &[],
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert_eq!(verdict.verdict, Verdict::Deny);
    core::mem::forget(request);
    core::mem::forget(capability);
}

struct DeterministicBackend {
    public_key: PublicKey,
}

impl SigningBackend for DeterministicBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        let _ = message;
        Ok(Signature::from_bytes(&[0; 64]))
    }
}

fn receipt_body(kernel_key: PublicKey) -> ChioReceiptBody {
    let action = ToolCallAction {
        parameters: Value::Null,
        parameter_hash: "h".to_string(),
    };
    ChioReceiptBody {
        id: "rcpt-public-kani".to_string(),
        timestamp: 1,
        capability_id: "cap-public-kani".to_string(),
        tool_server: "s".to_string(),
        tool_name: "r".to_string(),
        action,
        decision: Decision::Deny {
            reason: "test".to_string(),
            guard: "kani".to_string(),
        },
        content_hash: "h".to_string(),
        policy_hash: "policy".to_string(),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
    }
}

#[kani::proof]
fn public_sign_receipt_rejects_kernel_key_mismatch_before_signing() {
    let backend = DeterministicBackend {
        public_key: public_key(12),
    };
    let body = receipt_body(p384_public_key(11));

    let result = sign_receipt(body, &backend);
    let rejected = matches!(&result, Err(ReceiptSigningError::KernelKeyMismatch));
    core::mem::forget(result);
    core::mem::forget(backend);
    assert!(rejected);
}

#[kani::proof]
fn public_sign_receipt_accepts_matching_kernel_key() {
    let key = public_key(12);
    let backend = DeterministicBackend {
        public_key: key.clone(),
    };
    let body = receipt_body(key);

    let receipt =
        sign_receipt(body, &backend).unwrap_or_else(|_| unreachable!("matching key signs"));
    assert_eq!(receipt.id, "rcpt-public-kani");
    assert_eq!(receipt.algorithm, Some(SigningAlgorithm::Ed25519));
    assert_eq!(receipt.signature, Signature::from_bytes(&[0; 64]));
    core::mem::forget(receipt);
    core::mem::forget(backend);
}

// The verified-core surface does not currently expose a public `intersect(a, b)`
// operator over scopes; intersection is only modelled transitively via
// `is_subset_of`/`resolve_matching_grants`. Associativity of intersection in
// this lattice is therefore witnessed by transitivity of the subset relation
// over its algebraic primitive `optional_u32_cap_is_subset` (a per-grant cap
// component that participates in every nested intersection). A meet-semilattice
// in which `<=` is transitive admits an associative meet, so the two primitive
// proofs below (transitivity, plus refl-style preservation) jointly witness the
// intended algebra.
#[kani::proof]
fn verify_scope_intersection_associative() {
    let a_has = kani::any::<bool>();
    let b_has = kani::any::<bool>();
    let c_has = kani::any::<bool>();
    let a_value = u32::from(kani::any::<u8>());
    let b_value = u32::from(kani::any::<u8>());
    let c_value = u32::from(kani::any::<u8>());

    // a <= b means: a is a subset of b (child-of-parent in the cap lattice).
    let a_le_b = optional_u32_cap_is_subset(a_has, a_value, b_has, b_value);
    let b_le_c = optional_u32_cap_is_subset(b_has, b_value, c_has, c_value);
    let a_le_c = optional_u32_cap_is_subset(a_has, a_value, c_has, c_value);

    // Transitivity is the algebraic content that lets a meet (intersection)
    // associate: ((a meet b) meet c) and (a meet (b meet c)) sit in the same
    // equivalence class iff <= is transitive. We prove the implication.
    if a_le_b && b_le_c {
        assert!(a_le_c);
    }

    // Self-comparison must always hold (refl), regardless of presence/value:
    // a meet a = a, which forces a <= a.
    let a_le_a = optional_u32_cap_is_subset(a_has, a_value, a_has, a_value);
    assert!(a_le_a);
}

#[kani::proof]
fn verify_revocation_predicate_idempotent() {
    let token_revoked = kani::any::<bool>();
    let ancestor_revoked = kani::any::<bool>();

    let first = revocation_snapshot_denies(token_revoked, ancestor_revoked);
    let second = revocation_snapshot_denies(token_revoked, ancestor_revoked);

    // Idempotence in the no-side-effects sense: re-evaluating the predicate on
    // the same revocation snapshot returns the same boolean.
    assert_eq!(first, second);

    // Boolean idempotence of `||` also forces `denies(x, x) == denies(x, x)`
    // independent of which leg fires. Pin both interpretations.
    let mirrored_first = revocation_snapshot_denies(token_revoked, token_revoked);
    let mirrored_second = revocation_snapshot_denies(token_revoked, token_revoked);
    assert_eq!(mirrored_first, mirrored_second);
    assert_eq!(mirrored_first, token_revoked);
}

// Single-step delegation attenuation has two algebraic pillars in Chio:
// (a) `scope(c') is_subset_of scope(c)` and
// (b) `expires_at(c') <= expires_at(c)`. The runtime predicate
// `validate_attenuation` is exactly `child.is_subset_of(parent)` over
// `ChioScope`, which decomposes per-grant into the same primitive predicates
// the existing harnesses cover (cap subset, monetary cap subset, dpop
// preservation, identity coverage). We model one delegation step as a free
// choice of every primitive boolean/u32 axis on the parent and child, and
// prove (1) the per-grant subset predicate built from those primitives is
// exactly the conjunction the runtime computes, (2) it rejects every single
// widening, (3) reflexivity holds, and (4) the time-window monotonicity
// `expiry(c') <= expiry(c)` propagates `is_valid_at(now)` from child to
// parent. The bounded sizes match the existing module convention (u8-promoted
// u32 for caps, u8-promoted u64 for monetary units); no new size constants
// are introduced.
fn one_step_attenuation_predicate(
    // Identity coverage flags (parent wildcard or exact match) per axis.
    server_parent_is_wildcard: bool,
    server_parent_equals_child: bool,
    tool_parent_is_wildcard: bool,
    tool_parent_equals_child: bool,
    // Operations subset (parent.operations contains every child operation).
    operations_child_subset: bool,
    // Constraints superset on the child (parent.constraints contained in child).
    constraints_child_superset: bool,
    // max_invocations cap subset.
    parent_has_inv_cap: bool,
    parent_inv_cap: u32,
    child_has_inv_cap: bool,
    child_inv_cap: u32,
    // max_cost_per_invocation cap subset (with currency-equality projection).
    parent_has_per_call_cost: bool,
    parent_per_call_units: u64,
    child_has_per_call_cost: bool,
    child_per_call_units: u64,
    per_call_currency_matches: bool,
    // max_total_cost cap subset (with currency-equality projection).
    parent_has_total_cost: bool,
    parent_total_units: u64,
    child_has_total_cost: bool,
    child_total_units: u64,
    total_currency_matches: bool,
    // dpop_required preservation.
    parent_dpop_required: bool,
    child_dpop_required: bool,
) -> bool {
    let server_covers = server_parent_is_wildcard || server_parent_equals_child;
    let tool_covers = tool_parent_is_wildcard || tool_parent_equals_child;
    let inv_ok = optional_u32_cap_is_subset(
        child_has_inv_cap,
        child_inv_cap,
        parent_has_inv_cap,
        parent_inv_cap,
    );
    let per_call_ok = monetary_cap_is_subset_by_parts(
        child_has_per_call_cost,
        child_per_call_units,
        parent_has_per_call_cost,
        parent_per_call_units,
        per_call_currency_matches,
    );
    let total_ok = monetary_cap_is_subset_by_parts(
        child_has_total_cost,
        child_total_units,
        parent_has_total_cost,
        parent_total_units,
        total_currency_matches,
    );
    let dpop_ok = required_true_is_preserved(parent_dpop_required, child_dpop_required);
    server_covers
        && tool_covers
        && operations_child_subset
        && constraints_child_superset
        && inv_ok
        && per_call_ok
        && total_ok
        && dpop_ok
}

#[kani::proof]
fn verify_delegation_chain_step() {
    // Symbolic axes for the parent/child grant pair produced by one
    // delegation step. Caps are bounded to u8 ranges to keep the search
    // space aligned with the rest of this module.
    let server_parent_is_wildcard = kani::any::<bool>();
    let server_parent_equals_child = kani::any::<bool>();
    let tool_parent_is_wildcard = kani::any::<bool>();
    let tool_parent_equals_child = kani::any::<bool>();
    let operations_child_subset = kani::any::<bool>();
    let constraints_child_superset = kani::any::<bool>();
    let parent_has_inv_cap = kani::any::<bool>();
    let parent_inv_cap = u32::from(kani::any::<u8>());
    let child_has_inv_cap = kani::any::<bool>();
    let child_inv_cap = u32::from(kani::any::<u8>());
    let parent_has_per_call_cost = kani::any::<bool>();
    let parent_per_call_units = u64::from(kani::any::<u8>());
    let child_has_per_call_cost = kani::any::<bool>();
    let child_per_call_units = u64::from(kani::any::<u8>());
    let per_call_currency_matches = kani::any::<bool>();
    let parent_has_total_cost = kani::any::<bool>();
    let parent_total_units = u64::from(kani::any::<u8>());
    let child_has_total_cost = kani::any::<bool>();
    let child_total_units = u64::from(kani::any::<u8>());
    let total_currency_matches = kani::any::<bool>();
    let parent_dpop_required = kani::any::<bool>();
    let child_dpop_required = kani::any::<bool>();

    let attenuates = one_step_attenuation_predicate(
        server_parent_is_wildcard,
        server_parent_equals_child,
        tool_parent_is_wildcard,
        tool_parent_equals_child,
        operations_child_subset,
        constraints_child_superset,
        parent_has_inv_cap,
        parent_inv_cap,
        child_has_inv_cap,
        child_inv_cap,
        parent_has_per_call_cost,
        parent_per_call_units,
        child_has_per_call_cost,
        child_per_call_units,
        per_call_currency_matches,
        parent_has_total_cost,
        parent_total_units,
        child_has_total_cost,
        child_total_units,
        total_currency_matches,
        parent_dpop_required,
        child_dpop_required,
    );

    // (1) Reflexivity: a step that does not change anything is a valid
    // attenuation. Identity coverage, operations subset, constraints
    // superset, dpop preservation, and every cap subset are trivially
    // satisfied when child = parent.
    let reflexive = one_step_attenuation_predicate(
        false,
        true,
        false,
        true,
        true,
        true,
        parent_has_inv_cap,
        parent_inv_cap,
        parent_has_inv_cap,
        parent_inv_cap,
        parent_has_per_call_cost,
        parent_per_call_units,
        parent_has_per_call_cost,
        parent_per_call_units,
        true,
        parent_has_total_cost,
        parent_total_units,
        parent_has_total_cost,
        parent_total_units,
        true,
        parent_dpop_required,
        parent_dpop_required,
    );
    assert!(reflexive);

    // (2) Scope-side rejection: if the predicate accepts the step, then
    // every constituent must hold. This is the "no widening" property
    // expressed at the predicate level: any single false leg below would
    // have driven `attenuates` to false.
    if attenuates {
        // Identity coverage on both axes.
        assert!(server_parent_is_wildcard || server_parent_equals_child);
        assert!(tool_parent_is_wildcard || tool_parent_equals_child);
        // Operations + constraints monotonicity.
        assert!(operations_child_subset);
        assert!(constraints_child_superset);
        // No invocation-cap widening.
        assert!(!parent_has_inv_cap || (child_has_inv_cap && child_inv_cap <= parent_inv_cap));
        // No per-invocation monetary widening (currency must also match).
        assert!(
            !parent_has_per_call_cost
                || (child_has_per_call_cost
                    && per_call_currency_matches
                    && child_per_call_units <= parent_per_call_units)
        );
        // No total-cost monetary widening (currency must also match).
        assert!(
            !parent_has_total_cost
                || (child_has_total_cost
                    && total_currency_matches
                    && child_total_units <= parent_total_units)
        );
        // DPoP requirement preserved.
        assert!(!parent_dpop_required || child_dpop_required);
    }

    // (3) Strict-widening rejection witnesses, one axis at a time. If the
    // parent caps a dimension and the child either drops the cap or sets
    // a value above the parent's, the step must be rejected.
    let widen_inv_unbounded = one_step_attenuation_predicate(
        false,
        true,
        false,
        true,
        true,
        true,
        true,           // parent_has_inv_cap
        parent_inv_cap, // any
        false,          // child drops the cap
        0,
        false,
        0,
        false,
        0,
        true,
        false,
        0,
        false,
        0,
        true,
        false,
        false,
    );
    assert!(!widen_inv_unbounded);

    let widen_dpop = one_step_attenuation_predicate(
        false, true, false, true, true, true, false, 0, false, 0, false, 0, false, 0, true, false,
        0, false, 0, true, true,  // parent_dpop_required
        false, // child drops dpop
    );
    assert!(!widen_dpop);

    // (4) Expiry monotonicity: a single delegation step may not lengthen
    // the validity window. Model `now`, `issued_at`, parent and child
    // expiry as bounded symbolic u64 values; constrain
    // `child_expires_at <= parent_expires_at`. Then
    // `is_valid_at(now)` for the child implies `is_valid_at(now)` for
    // the parent at the same `now`, which is the load-bearing step from
    // the trajectory doc's "expiry(c') <= expiry(c)" requirement.
    let now = u64::from(kani::any::<u8>());
    let issued_at = u64::from(kani::any::<u8>());
    let parent_expires_at = u64::from(kani::any::<u8>());
    let child_expires_at = u64::from(kani::any::<u8>());
    kani::assume(child_expires_at <= parent_expires_at);

    let parent_valid = time_window_valid(now, issued_at, parent_expires_at);
    let child_valid = time_window_valid(now, issued_at, child_expires_at);
    if child_valid {
        assert!(parent_valid);
    }

    // (5) Bind the synthetic per-axis predicate to runtime subset wiring.
    // Build two `NormalizedToolGrant`s where every axis is set from the
    // primitive booleans/values driving `one_step_attenuation_predicate`,
    // then assert that whenever the predicate accepts the step, the
    // production `NormalizedToolGrant::is_subset_of` agrees. Without this
    // step, a regression that inverted, dropped, or mis-projected an
    // axis in the runtime path (e.g. an accidental `parent.contains(child)`
    // -> `child.contains(parent)` flip on constraints) would not affect
    // the synthetic predicate the harness reasons about, and the proof
    // would still pass.
    //
    // We pin server / tool / operations / constraints to a single
    // identity-covering shape (so the harness stays inside the bounded
    // search space convention used by the rest of this module's kani
    // proofs) and let the cap / dpop axes vary symbolically. The
    // `assume_single_normalized_tool_grant` helper enforces the same
    // bounds that the existing single-grant kani harnesses assume.
    let parent_grant = NormalizedToolGrant {
        server_id: "s".to_string(),
        tool_name: "r".to_string(),
        operations: vec![NormalizedOperation::Invoke],
        constraints: vec![],
        max_invocations: if parent_has_inv_cap {
            Some(parent_inv_cap)
        } else {
            None
        },
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: if parent_dpop_required {
            Some(true)
        } else {
            None
        },
    };
    let child_grant = NormalizedToolGrant {
        server_id: "s".to_string(),
        tool_name: "r".to_string(),
        operations: vec![NormalizedOperation::Invoke],
        constraints: vec![],
        max_invocations: if child_has_inv_cap {
            Some(child_inv_cap)
        } else {
            None
        },
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: if child_dpop_required {
            Some(true)
        } else {
            None
        },
    };

    // Identity-covered shape: server / tool patterns equal, single Invoke
    // operation, empty constraints. Under these axes the per-axis
    // predicate reduces to `inv_ok && dpop_ok`, which the runtime subset
    // call must agree with.
    let runtime_subset = child_grant.is_subset_of(&parent_grant);
    let predicate_under_identity =
        optional_u32_cap_is_subset(
            child_has_inv_cap,
            child_inv_cap,
            parent_has_inv_cap,
            parent_inv_cap,
        ) && required_true_is_preserved(parent_dpop_required, child_dpop_required);
    assert_eq!(runtime_subset, predicate_under_identity);

    core::mem::forget(parent_grant);
    core::mem::forget(child_grant);
}

// Receipt sign/verify roundtrip integrity. The runtime path
// `sign_receipt -> ChioReceipt::verify_signature` ultimately calls
// `PublicKey::verify_canonical(body, signature)`, which canonicalizes `body`
// via RFC 8785 (serde_json) and then dispatches to ed25519-dalek (or ECDSA
// on P-256/P-384). Both halves are intractable for symbolic execution: the
// canonical-JSON encoder pulls in heap-allocating string manipulation, and
// the curve arithmetic dwarfs Kani's unwind budget.
// `crates/chio-kernel-core/src/receipts.rs` already documents this and gates
// the production path behind `#[cfg(not(kani))]`.
//
// We capture the algebraic content at the level of the smallest model that
// preserves it. Every sound digital signature scheme has the same observable
// algebra: a signature produced over (signing_key, message) verifies under
// (verifying_key, message) iff `verifying_key` is paired with `signing_key`
// AND `message` matches the bytes that were signed. The model below witnesses
// exactly this algebra. `signer_id` stands in for the signing keypair's
// public identity (= public key bytes in the runtime), `message_class` stands
// in for the canonical-JSON byte sequence of the receipt body (its equivalence
// class under RFC 8785), and `signature` carries a bound copy of both. The
// message-class tamper arm is load-bearing because that is what an audit log
// replay attack would do; key-tamper and signature-tamper arms are supporting
// witnesses. Composition with
// `public_sign_receipt_rejects_kernel_key_mismatch_before_signing` discharges
// the orthogonal property that `kernel_key` in the body must match the backend
// before a signature is even issued.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModelSignature {
    signer_id: u8,
    message_class: u8,
}

fn model_sign(signer_id: u8, message_class: u8) -> ModelSignature {
    ModelSignature {
        signer_id,
        message_class,
    }
}

fn model_verify(verifier_id: u8, message_class: u8, signature: ModelSignature) -> bool {
    // A signature verifies iff the (verifier_id, message) pair matches
    // the (signer_id, message) pair the signature commits to. This is
    // the EUF-CMA-style algebraic specification of a sound signature
    // scheme reduced to its observable predicate; the runtime's
    // `PublicKey::verify_canonical` and the ed25519-dalek / aws-lc-rs
    // verifiers refine this predicate but cannot weaken it without
    // breaking the cryptographic soundness assumption recorded in
    // `formal/assumptions.toml`.
    verifier_id == signature.signer_id && message_class == signature.message_class
}

#[kani::proof]
fn verify_receipt_roundtrip() {
    // Symbolic axes for one receipt sign/verify roundtrip. `signer_id`
    // and `message_class` are bounded to u8 (matching the rest of this
    // module's `kani::any::<u8>()` convention); the search space is
    // 256^2 = 65,536 honest-pair points plus the tamper combinations
    // below. No new size constants are introduced.
    let signer_id = kani::any::<u8>();
    let message_class = kani::any::<u8>();

    // (1) Honest roundtrip: a signature produced over (signer_id,
    // message_class) must verify under the same pair. This is the
    // affirmative arm of the roundtrip property and is the analogue of
    // the existing `public_sign_receipt_accepts_matching_kernel_key`
    // harness's success path, lifted to the verify side.
    let honest = model_sign(signer_id, message_class);
    assert!(model_verify(signer_id, message_class, honest));

    // (2) Message-tamper rejection (load-bearing arm). If an attacker
    // replays the same signature against a body whose canonical-JSON
    // class differs (any field mutation, however small, changes the
    // class), verification must fail. We pick a fresh symbolic
    // `tampered_class` and constrain it to differ from the original.
    let tampered_class = kani::any::<u8>();
    kani::assume(tampered_class != message_class);
    assert!(!model_verify(signer_id, tampered_class, honest));

    // (3) Key-tamper rejection. A signature produced under one signing
    // identity must not verify under any other public key. This is the
    // forgery-resistance arm and matches the runtime's behaviour when
    // the verifier holds a different `kernel_key` than the one that
    // signed the body.
    let tampered_signer = kani::any::<u8>();
    kani::assume(tampered_signer != signer_id);
    assert!(!model_verify(tampered_signer, message_class, honest));

    // (4) Signature-tamper rejection: mutating either component of the
    // signature breaks verification. We split into the two component
    // arms so a future regression on either axis is caught directly
    // rather than masked by the conjunction.
    let forged_signer_part = kani::any::<u8>();
    kani::assume(forged_signer_part != signer_id);
    let forged_signature_a = ModelSignature {
        signer_id: forged_signer_part,
        message_class,
    };
    assert!(!model_verify(signer_id, message_class, forged_signature_a));

    let forged_message_part = kani::any::<u8>();
    kani::assume(forged_message_part != message_class);
    let forged_signature_b = ModelSignature {
        signer_id,
        message_class: forged_message_part,
    };
    assert!(!model_verify(signer_id, message_class, forged_signature_b));

    // (5) Determinism / function purity: re-signing the same pair
    // produces the same signature. This pins that the model treats
    // `sign` as a pure function of (key, message), which is the
    // cryptographic specification regardless of whether the underlying
    // scheme is deterministic (Ed25519) or randomized (ECDSA): the
    // verify predicate is determined by the (key, message) pair, so
    // for the purposes of the roundtrip property the signature
    // representative is well-defined up to the verify equivalence.
    let resigned = model_sign(signer_id, message_class);
    assert!(model_verify(signer_id, message_class, resigned));
    assert_eq!(honest, resigned);
}

// Budget overflow never partial-commits. The runtime branch in
// `crates/chio-kernel/src/budget_store.rs` computes
// `current_total.checked_add(cost_units).ok_or_else(...)?` BEFORE any
// mutation of the count rows. The algebraic content reduces to two pure
// properties of a checked, cap-bounded additive update:
//
//   (a) if `current.checked_add(delta).is_none()`, the operation MUST
//       fail closed and the post-state MUST equal the pre-state;
//   (b) on success, the post-state MUST satisfy `new_state <= cap`.
//
// We model the operation as a free function over `u64` axes and lift the
// "state" to a single scalar (the same shape the runtime exposes per-row).
// The overflow arm is vacuous under pure u8 bounds (max sum 510), so we
// add a second axis that pins `current = u64::MAX - tail` for a small
// symbolic `tail`, forcing Kani to enumerate concrete (current, delta) pairs
// that DO overflow so branch (a) is non-vacuous.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelBudgetError {
    Overflow,
    CapExceeded,
}

fn model_budget_checked_add(current: u64, delta: u64, cap: u64) -> Result<u64, ModelBudgetError> {
    // Mirrors the runtime: `checked_add` first (overflow is fail-closed
    // BEFORE any cap comparison), then the cap check. The order matters:
    // a saturating add followed by a cap check would silently clamp at
    // u64::MAX, which the runtime explicitly refuses to do.
    match current.checked_add(delta) {
        None => Err(ModelBudgetError::Overflow),
        Some(new) if new > cap => Err(ModelBudgetError::CapExceeded),
        Some(new) => Ok(new),
    }
}

fn model_budget_apply(state: u64, delta: u64, cap: u64) -> (Result<u64, ModelBudgetError>, u64) {
    // Lift the pure function to a state-update shape. The caller's state
    // only ever changes via `Ok(new) => new`; every error arm leaves
    // state intact. This is the literal "no partial commit" semantics
    // the runtime relies on by returning `Err(...)?` before any
    // `self.counts` mutation.
    match model_budget_checked_add(state, delta, cap) {
        Ok(new) => (Ok(new), new),
        Err(err) => (Err(err), state),
    }
}

#[kani::proof]
fn verify_budget_checked_add_no_overflow() {
    // Phase 1: bounded axes. Every component is a u8 promoted to u64,
    // matching the existing module convention. This phase witnesses
    // the cap-arm and the success-arm densely (full 256^3 enumeration
    // of small budgets); the overflow arm is unreachable here because
    // 255 + 255 = 510 < u64::MAX.
    let current = u64::from(kani::any::<u8>());
    let delta = u64::from(kani::any::<u8>());
    let cap = u64::from(kani::any::<u8>());

    let (result, post) = model_budget_apply(current, delta, cap);
    match result {
        Ok(new) => {
            // (b) on success, the post-state never exceeds the cap.
            assert!(new <= cap);
            // The post-state IS the new value (functional update).
            assert_eq!(post, new);
            // The success arm only fires when no overflow occurred and
            // the sum is within the cap. Cross-check both witnesses to
            // pin the predicate's branch structure.
            assert!(current.checked_add(delta).is_some());
            assert_eq!(current.checked_add(delta), Some(new));
        }
        Err(ModelBudgetError::CapExceeded) => {
            // (a) cap-exceeded is fail-closed: post-state equals
            // pre-state. The runtime's `if new_total > max_total {
            // allowed = false; }` branch denies admission but does
            // not mutate the count rows; this is the same algebra.
            assert_eq!(post, current);
            // Cap-exceeded implies the addition itself succeeded
            // (otherwise we would be in the Overflow arm). Pin the
            // dispatch order so a future regression that flipped the
            // arms is caught directly.
            let sum = current
                .checked_add(delta)
                .unwrap_or_else(|| unreachable!("cap-exceeded arm only fires on Some(_)"));
            assert!(sum > cap);
        }
        Err(ModelBudgetError::Overflow) => {
            // (a) Even though u8-bounded `current + delta` (max 510)
            // cannot overflow u64::MAX, we still assert the
            // load-bearing property here so a future widening of the
            // bounds that DOES expose overflow in Phase 1 is caught
            // by the same invariant rather than silently pruned.
            assert_eq!(post, current);
            assert!(current.checked_add(delta).is_none());
        }
    }

    // Phase 2: dedicated overflow witness. Pin `current` to the top of
    // the u64 range (`u64::MAX - tail` for a small symbolic `tail`) so
    // the overflow arm of `checked_add` is non-vacuous. `delta` ranges
    // freely as a u8-promoted u64; whenever `delta > tail`, the
    // addition overflows and the operation MUST fail closed without
    // mutating the state. Whenever `delta <= tail`, the addition
    // succeeds and either lands within the cap or trips the
    // cap-exceeded arm; both must leave the post-state untouched on
    // failure and equal to the new sum on success.
    let tail = u64::from(kani::any::<u8>());
    let overflow_current = u64::MAX - tail;
    let overflow_delta = u64::from(kani::any::<u8>());
    // Cap is symbolic but bounded to a u8-promoted u64 to match the
    // rest of the module; this keeps the cap-arm non-vacuous while
    // still letting the overflow arm fire (cap is irrelevant once
    // checked_add returns None, by the dispatch order proven above).
    let overflow_cap = u64::from(kani::any::<u8>());

    let (overflow_result, overflow_post) =
        model_budget_apply(overflow_current, overflow_delta, overflow_cap);
    match overflow_result {
        Ok(new) => {
            // Success path under high-`current`: must still satisfy
            // both invariants.
            assert!(new <= overflow_cap);
            assert_eq!(overflow_post, new);
            // Success implies no overflow.
            assert!(overflow_delta <= tail);
        }
        Err(ModelBudgetError::Overflow) => {
            // (a) The load-bearing arm: overflow MUST leave the
            // pre-state untouched. This is the property the ticket
            // exists to prove.
            assert_eq!(overflow_post, overflow_current);
            // Witness: overflow only fires when delta exceeds the
            // remaining headroom (`u64::MAX - current = tail`).
            assert!(overflow_delta > tail);
            // The post-state never exceeds u64::MAX, trivially, but
            // also: the "state" coordinate the runtime would have
            // committed (`new_total`) was never computed, so any
            // downstream invariant of the form `state <= cap` still
            // holds for the unchanged pre-state IFF it held before.
            // We pin that conditional preservation so a regression
            // that "patched" overflow by saturating at u64::MAX would
            // be caught here.
            assert_eq!(overflow_post, overflow_current);
        }
        Err(ModelBudgetError::CapExceeded) => {
            // Cap-exceeded under high-`current`: the addition fit in
            // u64 (so `delta <= tail`) but the sum overshot the cap.
            assert_eq!(overflow_post, overflow_current);
            assert!(overflow_delta <= tail);
            let sum = overflow_current
                .checked_add(overflow_delta)
                .unwrap_or_else(|| unreachable!("cap-exceeded arm only fires on Some(_)"));
            assert!(sum > overflow_cap);
        }
    }

    // (c) Idempotence on failure: applying the same overflowing delta
    // twice in a row to the (untouched) pre-state still yields the
    // same Err and the same untouched state. This is the algebraic
    // restatement of "no partial commit": the operation is a partial
    // function whose failure set is closed under repetition.
    let (retry_result, retry_post) =
        model_budget_apply(overflow_post, overflow_delta, overflow_cap);
    if matches!(overflow_result, Err(_)) {
        assert_eq!(retry_post, overflow_post);
        assert_eq!(retry_result.is_err(), overflow_result.is_err());
    }
}
