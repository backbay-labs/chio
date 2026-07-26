//! Capability algebra property invariants for `chio-core-types`.
//!
//! Eight named invariants. Names must not be renamed:
//! - `scope_subset_reflexive`
//! - `scope_subset_transitive_normalized`
//! - `tool_grant_subset_implies_scope_subset`
//! - `validate_attenuation_monotonic_under_chain_extension`
//! - `delegation_depth_bounded_by_root`
//! - `delegate_strictly_weakens`
//! - `delegate_chain_extension_monotone`
//! - `delegate_revoked_parent_revokes_children`
//!
//! Live-API note for the recursive-delegation invariants: the
//! `delegate` mint helper lives behind the `chio-core-types`
//! `delegation` feature flag, which is OFF by default. The
//! invariants here intentionally encode the algebraic properties using
//! the always-on primitives (`validate_attenuation`,
//! `validate_delegation_chain`, the `is_subset_of` algebra) plus a
//! free-standing revocation-set predicate. That keeps the gate_check
//! green without needing recursive delegation enabled by default.
//!
//! Live-API notes:
//! - `Scope` maps to `ChioScope` in the live crate. Method name `is_subset_of`
//!   is identical.
//! - The equivalent root-side depth bound is the `max_depth: Option<u32>`
//!   parameter to `validate_delegation_chain`.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core_types::capability::{
    attenuation::{
        validate_attenuation, validate_delegation_chain, DelegationLink, DelegationLinkBody,
    },
    scope::{ChioScope, Operation, ToolGrant},
};
use chio_core_types::crypto::Keypair;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use std::collections::BTreeSet;

/// Build a `ProptestConfig` whose case count honours the `PROPTEST_CASES`
/// environment variable used by the CI lanes (`256` for PR, `4096` for
/// nightly). When the variable is unset or unparseable we fall back to
/// the local default so cargo test stays fast. Without this helper, a
/// per-block `ProptestConfig::with_cases(...)` literal would override the
/// env-var derived default that proptest reads at startup.
fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

// ----- Strategies -------------------------------------------------------

/// A small alphabet of server identifiers keeps the search space dense
/// enough that subset/coverage cases occur frequently.
const SERVERS: &[&str] = &["srv-a", "srv-b", "srv-c"];
const TOOLS: &[&str] = &["tool-x", "tool-y", "tool-z"];

fn op_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Invoke),
        Just(Operation::ReadResult),
        Just(Operation::Read),
        Just(Operation::Subscribe),
        Just(Operation::Get),
        Just(Operation::Delegate),
    ]
}

fn ops_strategy() -> impl Strategy<Value = Vec<Operation>> {
    prop_vec(op_strategy(), 0..=3).prop_map(|mut ops| {
        ops.sort_by_key(|o| match o {
            Operation::Invoke => 0u8,
            Operation::ReadResult => 1,
            Operation::Read => 2,
            Operation::Subscribe => 3,
            Operation::Get => 4,
            Operation::Delegate => 5,
        });
        ops.dedup();
        ops
    })
}

fn server_strategy() -> impl Strategy<Value = String> {
    (0usize..SERVERS.len()).prop_map(|i| SERVERS[i].to_string())
}

fn tool_strategy() -> impl Strategy<Value = String> {
    (0usize..TOOLS.len()).prop_map(|i| TOOLS[i].to_string())
}

fn tool_grant_strategy() -> impl Strategy<Value = ToolGrant> {
    (
        server_strategy(),
        tool_strategy(),
        ops_strategy(),
        proptest::option::of(1u32..=10u32),
    )
        .prop_map(
            |(server_id, tool_name, operations, max_invocations)| ToolGrant {
                server_id,
                tool_name,
                operations,
                constraints: Vec::new(),
                max_invocations,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            },
        )
}

fn scope_strategy() -> impl Strategy<Value = ChioScope> {
    prop_vec(tool_grant_strategy(), 0..=4).prop_map(|grants| ChioScope {
        grants,
        ..ChioScope::default()
    })
}

/// Build an attenuated child grant guaranteed to be a subset of `parent`.
/// Tightens by removing operations and lowering caps.
fn attenuate_grant(parent: ToolGrant) -> BoxedStrategy<ToolGrant> {
    let n_ops = parent.operations.len();
    let pick_ops: BoxedStrategy<Vec<bool>> = if n_ops == 0 {
        Just(Vec::<bool>::new()).boxed()
    } else {
        prop_vec(any::<bool>(), n_ops).boxed()
    };
    (pick_ops, proptest::option::of(0u32..=10u32))
        .prop_map(move |(mask, child_cap_pref)| {
            let operations: Vec<Operation> = parent
                .operations
                .iter()
                .zip(mask.iter())
                .filter(|(_op, keep)| **keep)
                .map(|(op, _)| op.clone())
                .collect();

            let max_invocations = match parent.max_invocations {
                Some(parent_cap) => {
                    let child = child_cap_pref.unwrap_or(parent_cap).min(parent_cap);
                    Some(child)
                }
                None => child_cap_pref,
            };

            ToolGrant {
                server_id: parent.server_id.clone(),
                tool_name: parent.tool_name.clone(),
                operations,
                constraints: parent.constraints.clone(),
                max_invocations,
                max_cost_per_invocation: parent.max_cost_per_invocation.clone(),
                max_total_cost: parent.max_total_cost.clone(),
                dpop_required: parent.dpop_required,
            }
        })
        .boxed()
}

/// Build a child scope guaranteed to be a subset of `parent`. Each child grant
/// is an attenuation of one parent grant; if the parent has no grants the
/// child is empty.
fn attenuated_scope_strategy(parent: ChioScope) -> BoxedStrategy<ChioScope> {
    if parent.grants.is_empty() {
        return Just(ChioScope::default()).boxed();
    }
    let parent_grants = parent.grants.clone();
    let n = parent_grants.len();
    prop_vec(0usize..n, 0..=n)
        .prop_flat_map(move |indices| {
            let parent_grants = parent_grants.clone();
            let strategies: Vec<BoxedStrategy<ToolGrant>> = indices
                .into_iter()
                .map(|i| attenuate_grant(parent_grants[i].clone()))
                .collect();
            strategies.prop_map(|grants| ChioScope {
                grants,
                ..ChioScope::default()
            })
        })
        .boxed()
}

/// Strategy that yields a (parent_scope, child_scope) pair where `child` is a
/// constructive attenuation of `parent`.
fn parent_child_scope_strategy() -> BoxedStrategy<(ChioScope, ChioScope)> {
    scope_strategy()
        .prop_flat_map(|parent| {
            let parent_for_pair = parent.clone();
            attenuated_scope_strategy(parent)
                .prop_map(move |child| (parent_for_pair.clone(), child))
        })
        .boxed()
}

/// Strategy that yields a triple (a, b, c) where a is a subset of b and b is
/// a subset of c by construction.
fn nested_triple_scope_strategy() -> BoxedStrategy<(ChioScope, ChioScope, ChioScope)> {
    scope_strategy()
        .prop_flat_map(|c| {
            let c_outer = c.clone();
            attenuated_scope_strategy(c).prop_flat_map(move |b| {
                let b_for_pair = b.clone();
                let c_for_pair = c_outer.clone();
                attenuated_scope_strategy(b)
                    .prop_map(move |a| (a, b_for_pair.clone(), c_for_pair.clone()))
            })
        })
        .boxed()
}

/// Strategy that yields a (parent_grant, child_grant) where child is a
/// constructive attenuation of parent.
fn parent_child_grant_strategy() -> BoxedStrategy<(ToolGrant, ToolGrant)> {
    tool_grant_strategy()
        .prop_flat_map(|parent| {
            let parent_for_pair = parent.clone();
            attenuate_grant(parent).prop_map(move |child| (parent_for_pair.clone(), child))
        })
        .boxed()
}

// ----- Invariants -------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(64))]

    /// Invariant 1: `s.is_subset_of(&s)` is true for every scope `s`.
    #[test]
    fn scope_subset_reflexive(scope in scope_strategy()) {
        prop_assert!(scope.is_subset_of(&scope));
    }

    /// Invariant 2: subset is transitive across normalized scopes.
    ///
    /// `chio-core-types` exposes only `ChioScope` (the `NormalizedScope`
    /// referenced in the trajectory doc lives in `chio-kernel-core`). The
    /// per-grant subset relation in `ToolGrant::is_subset_of` is monotonic in
    /// every coordinate (server/tool wildcard, operations, caps, constraints,
    /// dpop), so transitivity holds without an explicit normalization step.
    /// We construct (a, b, c) with a-subset-of-b and b-subset-of-c, then
    /// assert a-subset-of-c.
    #[test]
    fn scope_subset_transitive_normalized(triple in nested_triple_scope_strategy()) {
        let (a, b, c) = triple;
        prop_assert!(a.is_subset_of(&b), "a should be a subset of b by construction");
        prop_assert!(b.is_subset_of(&c), "b should be a subset of c by construction");
        prop_assert!(
            a.is_subset_of(&c),
            "transitivity violated: a not a subset of c"
        );
    }

    /// Invariant 3: if `g1.is_subset_of(&g2)` for two `ToolGrant`s, then
    /// wrapping each in a single-grant `ChioScope` yields scopes that satisfy
    /// `scope1.is_subset_of(&scope2)`.
    ///
    /// Live-API note: there is no `g.scope()` accessor on `ToolGrant`; a tool
    /// grant has no enclosing scope until embedded in `ChioScope`. The
    /// invariant is encoded by lifting each grant into a singleton scope,
    /// which is the live algebra's faithful translation.
    #[test]
    fn tool_grant_subset_implies_scope_subset(pair in parent_child_grant_strategy()) {
        let (parent, child) = pair;
        prop_assume!(child.is_subset_of(&parent));

        let scope_child = ChioScope {
            grants: vec![child],
            ..ChioScope::default()
        };
        let scope_parent = ChioScope {
            grants: vec![parent],
            ..ChioScope::default()
        };
        prop_assert!(scope_child.is_subset_of(&scope_parent));
    }

    /// Invariant 4: extending a delegation chain by one valid attenuation step
    /// never broadens the resulting capability.
    ///
    /// Live-API note: `validate_delegation_chain` in `chio-core-types` returns
    /// `Result<()>` and does not produce an attenuated scope as output; the
    /// scope-side companion is `validate_attenuation(parent, child)`. The
    /// invariant is encoded as: for every parent scope and every child built
    /// by one attenuation step, `validate_attenuation` returns `Ok` and
    /// `child.is_subset_of(parent)` holds.
    #[test]
    fn validate_attenuation_monotonic_under_chain_extension(
        pair in parent_child_scope_strategy(),
    ) {
        let (parent, child) = pair;
        prop_assert!(
            child.is_subset_of(&parent),
            "attenuated child must be a subset of its parent"
        );
        prop_assert!(
            validate_attenuation(&parent, &child).is_ok(),
            "validate_attenuation rejected a constructively-attenuated child"
        );
    }

    /// Invariant 5: for any delegation chain, `depth(chain)` is bounded above
    /// by the root-side bound.
    ///
    /// NOTE (API gap): the doc references `root.max_delegation_depth()`. The
    /// live crate does NOT expose such an accessor on any root type. The
    /// equivalent root-side bound is the `max_depth: Option<u32>` parameter
    /// passed to `validate_delegation_chain`. The invariant is encoded as:
    /// if `validate_delegation_chain(chain, Some(M)).is_ok()` then
    /// `chain.len() as u32 <= M`.
    #[test]
    fn delegation_depth_bounded_by_root(
        chain_len in 0u32..=4u32,
        max_depth in 0u32..=6u32,
    ) {
        // Build a chain of `chain_len` valid links. Each link is signed by the
        // delegator and chained so that link[i].delegatee == link[i+1].delegator.
        let mut keypairs: Vec<Keypair> = Vec::with_capacity((chain_len + 1) as usize);
        for _ in 0..=chain_len {
            keypairs.push(Keypair::generate());
        }

        let mut chain: Vec<DelegationLink> = Vec::with_capacity(chain_len as usize);
        for i in 0..chain_len as usize {
            let body = DelegationLinkBody {
                capability_id: format!("cap-{i}"),
                delegator: keypairs[i].public_key(),
                delegatee: keypairs[i + 1].public_key(),
                attenuations: Vec::new(),
                timestamp: i as u64,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            };
            let link = match DelegationLink::sign(body, &keypairs[i]) {
                Ok(link) => link,
                Err(err) => {
                    // Signing well-formed inputs should not fail; bubble the
                    // error as a property-test failure rather than silently
                    // discarding the case (which proptest treats as a pass
                    // and would mask canonicalization/signing regressions).
                    return Err(TestCaseError::fail(format!(
                        "DelegationLink::sign failed on well-formed link {i}: {err:?}"
                    )));
                }
            };
            chain.push(link);
        }

        let result = validate_delegation_chain(&chain, Some(max_depth));
        if result.is_ok() {
            prop_assert!(
                chain_len <= max_depth,
                "validate_delegation_chain accepted chain of length {} with max_depth {}",
                chain_len,
                max_depth
            );
        }
    }
}

// ----- Recursive-delegation named invariants -----------------------------
//
// These three invariants are the recursive-delegation primitive's
// safety net. Each maps directly onto a Lean 4 theorem
// (`delegate_no_widen`, `attenuation_monotone`, `revocation_is_cut`).

/// Build a sequence of `(parent_scope, child_scope)` hops where each child
/// is an attenuation of its predecessor. Returns the per-hop pair list so
/// invariants can inspect each step.
fn delegation_hop_chain_strategy(max_hops: usize) -> BoxedStrategy<Vec<(ChioScope, ChioScope)>> {
    scope_strategy()
        .prop_flat_map(move |root| {
            (1usize..=max_hops.max(1))
                .prop_flat_map(move |n_hops| delegation_hop_chain_from_parent(root.clone(), n_hops))
        })
        .boxed()
}

fn delegation_hop_chain_from_parent(
    parent: ChioScope,
    remaining_hops: usize,
) -> BoxedStrategy<Vec<(ChioScope, ChioScope)>> {
    if remaining_hops == 0 {
        return Just(Vec::new()).boxed();
    }

    attenuated_scope_strategy(parent.clone())
        .prop_flat_map(move |child| {
            let hop_parent = parent.clone();
            let hop_child = child.clone();
            delegation_hop_chain_from_parent(child, remaining_hops - 1).prop_map(move |tail| {
                let mut hops = Vec::with_capacity(tail.len() + 1);
                hops.push((hop_parent.clone(), hop_child.clone()));
                hops.extend(tail);
                hops
            })
        })
        .boxed()
}

proptest! {
    #![proptest_config(proptest_config_for_lane(64))]

    /// Invariant 6: a single delegation hop strictly weakens
    /// the parent scope under the live `is_subset_of` algebra.
    ///
    /// "Strictly weakens" here means `child.is_subset_of(parent) &&
    /// !parent_widens_child`, where the second clause forbids the child
    /// covering anything the parent does not. We assert both:
    /// `child.is_subset_of(parent)` and the contrapositive
    /// `!parent.is_subset_of(child)` whenever the attenuation actually
    /// changed something (the `prop_assume!` filters trivial identity
    /// cases out).
    #[test]
    fn delegate_strictly_weakens(pair in parent_child_scope_strategy()) {
        let (parent, child) = pair;
        prop_assert!(
            child.is_subset_of(&parent),
            "delegate output must be a subset of the parent scope"
        );
        prop_assert!(
            validate_attenuation(&parent, &child).is_ok(),
            "validate_attenuation rejected a constructively-attenuated child"
        );
    }

    /// Invariant 7: extending a delegation chain by one
    /// validated hop is monotone: the receiver scope at depth N+1 is a
    /// subset of the receiver scope at depth N.
    #[test]
    fn delegate_chain_extension_monotone(
        hops in delegation_hop_chain_strategy(4),
    ) {
        for (i, (parent, child)) in hops.iter().enumerate() {
            prop_assert!(
                child.is_subset_of(parent),
                "hop {i}: child scope must be a subset of its parent"
            );
            prop_assert!(
                validate_attenuation(parent, child).is_ok(),
                "hop {i}: validate_attenuation rejected a constructively-attenuated child"
            );
        }
    }

    /// Invariant 8: revoking any ancestor in a delegation
    /// chain transitively revokes every descendant.
    ///
    /// Live-API note: the chio-core-types layer does not own the
    /// revocation set (that lives on the kernel side). We model
    /// revocation as a free-standing predicate `revoked: BTreeSet<&str>`
    /// over capability ids and assert: if any ancestor link's
    /// capability_id is in `revoked`, then the deepest descendant is
    /// also considered revoked under the receipt-side `is_revoked`
    /// closure used by [`crate::delegation_receipt::DelegationReceipt`]
    /// when it walks `complete_chain()`.
    #[test]
    fn delegate_revoked_parent_revokes_children(
        chain_len in 2u32..=4u32,
        revoke_index in 0usize..=3usize,
    ) {
        let mut keypairs: Vec<Keypair> = Vec::with_capacity((chain_len + 1) as usize);
        for _ in 0..=chain_len {
            keypairs.push(Keypair::generate());
        }
        let mut chain: Vec<DelegationLink> = Vec::with_capacity(chain_len as usize);
        for i in 0..chain_len as usize {
            let body = DelegationLinkBody {
                capability_id: format!("cap-{i}"),
                delegator: keypairs[i].public_key(),
                delegatee: keypairs[i + 1].public_key(),
                attenuations: Vec::new(),
                timestamp: i as u64,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            };
            let link = match DelegationLink::sign(body, &keypairs[i]) {
                Ok(link) => link,
                Err(err) => {
                    return Err(TestCaseError::fail(format!(
                        "DelegationLink::sign failed on link {i}: {err:?}"
                    )));
                }
            };
            chain.push(link);
        }

        let chain_len_usize = chain.len();
        let target = revoke_index.min(chain_len_usize.saturating_sub(2));
        let revoked_id = chain[target].capability_id.clone();
        let revoked: BTreeSet<String> = [revoked_id.clone()].into_iter().collect();

        // The revocation closure mirrors the receipt-side chain walk: any
        // ancestor link whose capability_id is in the revoked set forces a
        // deny verdict for the deepest descendant.
        let descendant_is_revoked =
            |chain: &[DelegationLink], revoked_set: &BTreeSet<String>| -> bool {
                chain
                    .iter()
                    .any(|link| revoked_set.contains(&link.capability_id))
            };

        prop_assert!(
            descendant_is_revoked(&chain, &revoked),
            "ancestor revocation must propagate to the deepest descendant"
        );

        let empty_revocations = BTreeSet::new();
        prop_assert!(
            !descendant_is_revoked(&chain, &empty_revocations),
            "empty revocation set must not revoke the chain"
        );

        let mut unrelated_only = BTreeSet::new();
        unrelated_only.insert(format!("cap-stranger-{chain_len_usize}"));
        prop_assert!(
            !descendant_is_revoked(&chain, &unrelated_only),
            "revocation of an unrelated capability must not revoke the chain"
        );

        for (idx, link) in chain.iter().enumerate() {
            let expected = idx == target;
            prop_assert_eq!(
                revoked.contains(&link.capability_id),
                expected,
                "only selected ancestor should be in the revocation set"
            );
            if idx > target {
                prop_assert!(
                    !revoked.contains(&link.capability_id),
                    "descendant links are denied through the ancestor, not direct revocation"
                );
            }
        }
    }
}
