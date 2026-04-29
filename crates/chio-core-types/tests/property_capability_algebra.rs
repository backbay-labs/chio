//! Capability algebra property invariants for `chio-core-types`.
//!
//! Five named invariants (names must not be renamed):
//! - `scope_subset_reflexive`
//! - `scope_subset_transitive_normalized`
//! - `tool_grant_subset_implies_scope_subset`
//! - `validate_attenuation_monotonic_under_chain_extension`
//! - `delegation_depth_bounded_by_root`
//!
//! Live-API notes:
//! - `Scope` maps to `ChioScope` in the live crate. Method name `is_subset_of`
//!   is identical.
//! - The equivalent root-side depth bound is the `max_depth: Option<u32>`
//!   parameter to `validate_delegation_chain`.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core_types::capability::{
    validate_attenuation, validate_delegation_chain, ChioScope, DelegationLink, DelegationLinkBody,
    Operation, ToolGrant,
};
use chio_core_types::crypto::Keypair;
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

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
