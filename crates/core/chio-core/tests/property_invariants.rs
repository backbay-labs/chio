#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::{
    capability::{
        attenuation::validate_attenuation,
        scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn tool_operations_from_mask(mask: u8) -> Vec<Operation> {
    let mut operations = Vec::new();
    if mask & 0b001 != 0 {
        operations.push(Operation::Invoke);
    }
    if mask & 0b010 != 0 {
        operations.push(Operation::ReadResult);
    }
    if mask & 0b100 != 0 {
        operations.push(Operation::Delegate);
    }
    if operations.is_empty() {
        operations.push(Operation::Invoke);
    }
    operations
}

fn first_missing_operation(mask: u8) -> Operation {
    if mask & 0b001 == 0 {
        Operation::Invoke
    } else if mask & 0b010 == 0 {
        Operation::ReadResult
    } else {
        Operation::Delegate
    }
}

fn nonempty_subset_mask(parent_mask: u8, selector: u8) -> u8 {
    let subset = parent_mask & selector;
    if subset != 0 {
        return subset;
    }
    if parent_mask & 0b001 != 0 {
        0b001
    } else if parent_mask & 0b010 != 0 {
        0b010
    } else {
        0b100
    }
}

fn make_scope(grant: ToolGrant) -> ChioScope {
    ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    }
}

fn make_grant(
    operations: Vec<Operation>,
    constraints: Vec<Constraint>,
    max_invocations: Option<u32>,
    max_cost_per_invocation: Option<u64>,
    max_total_cost: Option<u64>,
    dpop_required: Option<bool>,
) -> ToolGrant {
    ToolGrant {
        server_id: "srv-payments".to_string(),
        tool_name: "charge_card".to_string(),
        operations,
        constraints,
        max_invocations,
        max_cost_per_invocation: max_cost_per_invocation.map(usd),
        max_total_cost: max_total_cost.map(usd),
        dpop_required,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn capability_token_signature_roundtrip_holds(
        issuer_seed in any::<[u8; 32]>(),
        subject_seed in any::<[u8; 32]>(),
        id_suffix in 0u64..1_000_000,
        issued_at in 0u64..10_000_000,
        ttl in 1u64..10_000,
        max_invocations in proptest::option::of(0u32..256),
        max_cost_per_invocation in proptest::option::of(0u16..10_000),
        max_total_cost in proptest::option::of(0u16..50_000),
        dpop_required in any::<bool>(),
    ) {
        let issuer = Keypair::from_seed(&issuer_seed);
        let subject = Keypair::from_seed(&subject_seed);
        let body = CapabilityTokenBody {
            id: format!("cap-{id_suffix}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: make_scope(make_grant(
                vec![Operation::Invoke, Operation::ReadResult],
                vec![Constraint::PathPrefix("/billing".to_string())],
                max_invocations,
                max_cost_per_invocation.map(u64::from),
                max_total_cost.map(u64::from),
                dpop_required.then_some(true),
            )),
            issued_at,
            expires_at: issued_at + ttl,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        };

        let token = CapabilityToken::sign(body, &issuer).unwrap();
        prop_assert!(token.verify_signature().unwrap());

        let encoded = serde_json::to_vec(&token).unwrap();
        let restored: CapabilityToken = serde_json::from_slice(&encoded).unwrap();

        prop_assert_eq!(&token.id, &restored.id);
        prop_assert_eq!(&token.issuer, &restored.issuer);
        prop_assert_eq!(&token.subject, &restored.subject);
        prop_assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
        prop_assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capability_token_signature_breaks_after_body_mutation(
        issuer_seed in any::<[u8; 32]>(),
        subject_seed in any::<[u8; 32]>(),
        id_suffix in 0u64..1_000_000,
        issued_at in 0u64..10_000_000,
        ttl in 1u64..10_000,
    ) {
        let issuer = Keypair::from_seed(&issuer_seed);
        let subject = Keypair::from_seed(&subject_seed);
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{id_suffix}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: make_scope(make_grant(
                    vec![Operation::Invoke],
                    Vec::new(),
                    Some(4),
                    Some(500),
                    Some(2_000),
                    Some(true),
                )),
                issued_at,
                expires_at: issued_at + ttl,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        ).unwrap();

        let mut tampered = token.clone();
        tampered.expires_at += 1;

        prop_assert!(token.verify_signature().unwrap());
        prop_assert!(!tampered.verify_signature().unwrap());
    }

    #[test]
    fn derived_child_scope_is_always_a_valid_attenuation(
        parent_mask in 1u8..8,
        child_selector in any::<u8>(),
        parent_has_constraint in any::<bool>(),
        child_adds_constraint in any::<bool>(),
        parent_max_invocations in proptest::option::of(0u32..256),
        child_cap_selector in any::<u16>(),
        parent_max_cost_per_invocation in proptest::option::of(0u16..10_000),
        parent_max_total_cost in proptest::option::of(0u16..50_000),
        uncapped_child_uses_invocation_cap in any::<bool>(),
        uncapped_child_uses_cost_caps in any::<bool>(),
        parent_requires_dpop in any::<bool>(),
        uncapped_child_requires_dpop in any::<bool>(),
    ) {
        let parent_constraints = if parent_has_constraint {
            vec![Constraint::PathPrefix("/srv/tenant-a".to_string())]
        } else {
            Vec::new()
        };
        let mut child_constraints = parent_constraints.clone();
        if child_adds_constraint {
            child_constraints.push(Constraint::MaxLength(128));
        }

        let parent_operations = tool_operations_from_mask(parent_mask);
        let child_operations = tool_operations_from_mask(nonempty_subset_mask(parent_mask, child_selector));

        let child_max_invocations = match parent_max_invocations {
            Some(parent_max) => Some(u32::from(child_cap_selector) % parent_max.saturating_add(1)),
            None if uncapped_child_uses_invocation_cap => Some(u32::from(child_cap_selector)),
            None => None,
        };

        let child_max_cost_per_invocation = match parent_max_cost_per_invocation {
            Some(parent_max) => Some(u64::from(child_cap_selector) % (u64::from(parent_max) + 1)),
            None if uncapped_child_uses_cost_caps => Some(u64::from(child_cap_selector)),
            None => None,
        };

        let child_max_total_cost = match parent_max_total_cost {
            Some(parent_max) => Some(u64::from(child_cap_selector) % (u64::from(parent_max) + 1)),
            None if uncapped_child_uses_cost_caps => Some(u64::from(child_cap_selector) * 2),
            None => None,
        };

        let parent = make_grant(
            parent_operations,
            parent_constraints,
            parent_max_invocations,
            parent_max_cost_per_invocation.map(u64::from),
            parent_max_total_cost.map(u64::from),
            parent_requires_dpop.then_some(true),
        );
        let child = make_grant(
            child_operations,
            child_constraints,
            child_max_invocations,
            child_max_cost_per_invocation,
            child_max_total_cost,
            if parent_requires_dpop {
                Some(true)
            } else {
                uncapped_child_requires_dpop.then_some(true)
            },
        );

        prop_assert!(child.is_subset_of(&parent));
        prop_assert!(validate_attenuation(&make_scope(parent), &make_scope(child)).is_ok());
    }

    #[test]
    fn adding_an_operation_not_granted_by_the_parent_breaks_attenuation(
        parent_mask in 1u8..7,
    ) {
        let extra_operation = first_missing_operation(parent_mask);
        let mut child_operations = tool_operations_from_mask(parent_mask);
        child_operations.push(extra_operation);

        let parent = make_grant(
            tool_operations_from_mask(parent_mask),
            vec![Constraint::PathPrefix("/srv/tenant-a".to_string())],
            Some(8),
            Some(500),
            Some(4_000),
            Some(true),
        );
        let child = make_grant(
            child_operations,
            vec![Constraint::PathPrefix("/srv/tenant-a".to_string())],
            Some(8),
            Some(500),
            Some(4_000),
            Some(true),
        );

        prop_assert!(!child.is_subset_of(&parent));
        prop_assert!(validate_attenuation(&make_scope(parent), &make_scope(child)).is_err());
    }
}
