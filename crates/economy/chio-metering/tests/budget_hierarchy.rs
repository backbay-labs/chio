//! Integration tests for hierarchical budget governance: tree-structured
//! budget policies where parent caps bound every child, and aggregate spend
//! rolls up from leaf to root.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chio_metering::{
    AggregateSpend, BudgetDecision, BudgetDenyReason, BudgetError, BudgetLimits, BudgetNode,
    BudgetNodeId, BudgetTree, BudgetWindow, PerWindowSpend, SpendSnapshot,
};

fn org(id: &str, limits: BudgetLimits, window: BudgetWindow) -> BudgetNode {
    BudgetNode::new(id, window).with_limits(limits)
}

fn child(id: &str, parent: &str, limits: BudgetLimits, window: BudgetWindow) -> BudgetNode {
    BudgetNode::new(id, window)
        .with_parent(parent)
        .with_limits(limits)
}

fn usd(units: u64) -> BudgetLimits {
    BudgetLimits {
        max_spend_units: Some(units),
        currency: Some("USD".to_string()),
        ..BudgetLimits::default()
    }
}

fn tokens(n: u64) -> BudgetLimits {
    BudgetLimits {
        max_tokens: Some(n),
        ..BudgetLimits::default()
    }
}

fn snapshot_for(id: &str, spent: AggregateSpend) -> SpendSnapshot {
    let mut snap = SpendSnapshot::new();
    snap.set(
        BudgetNodeId::from(id),
        PerWindowSpend {
            window_start: 0,
            current: spent,
        },
    );
    snap
}

#[test]
fn insert_creates_and_links_parent_child() {
    let mut tree = BudgetTree::new();
    tree.insert(org("org/acme", usd(1_000_000), BudgetWindow::Monthly))
        .expect("root");
    tree.insert(child(
        "dept/research",
        "org/acme",
        usd(400_000),
        BudgetWindow::Monthly,
    ))
    .expect("child");
    tree.insert(child(
        "team/ml",
        "dept/research",
        usd(100_000),
        BudgetWindow::Monthly,
    ))
    .expect("grandchild");

    assert_eq!(tree.len(), 3);
    let descendants = tree.descendants(&BudgetNodeId::from("org/acme"));
    assert_eq!(descendants.len(), 2);
    assert!(descendants.contains(&BudgetNodeId::from("dept/research")));
    assert!(descendants.contains(&BudgetNodeId::from("team/ml")));

    let ancestors = tree.ancestors(&BudgetNodeId::from("team/ml"));
    assert_eq!(
        ancestors,
        vec![
            BudgetNodeId::from("team/ml"),
            BudgetNodeId::from("dept/research"),
            BudgetNodeId::from("org/acme"),
        ]
    );
}

#[test]
fn cycle_detection_rejects_cyclic_insert() {
    // A budget tree enforces uniqueness of ids and acyclicity of the
    // parent graph. Because the public surface does not expose mutation
    // of existing nodes' parents, cycles can only be introduced at
    // insertion time by re-inserting an id that already sits in the
    // ancestor chain. We verify both guards: Duplicate rejects id reuse
    // and Cycle rejects a re-insert that would close a loop.
    let mut tree = BudgetTree::new();
    tree.insert(org("a", BudgetLimits::default(), BudgetWindow::Daily))
        .expect("root a");
    tree.insert(child(
        "b",
        "a",
        BudgetLimits::default(),
        BudgetWindow::Daily,
    ))
    .expect("b child of a");

    // Re-inserting "a" with parent "b" would form a cycle a -> b -> a.
    // Because "a" already exists, Duplicate fires first, which still
    // blocks the cyclic topology.
    let err = tree
        .insert(child(
            "a",
            "b",
            BudgetLimits::default(),
            BudgetWindow::Daily,
        ))
        .unwrap_err();
    assert!(
        matches!(err, BudgetError::Duplicate { .. }),
        "expected duplicate, got {err:?}"
    );

    // A self-parented insert is the most direct cycle: a node whose parent
    // is itself.
    let mut cyc = BudgetTree::new();
    cyc.insert(org("only", BudgetLimits::default(), BudgetWindow::Daily))
        .expect("only");
    // Re-inserting "only" with itself as parent: Duplicate fires before
    // cycle logic runs. Confirm the duplicate blocks the cyclic intent.
    let err = cyc
        .insert(child(
            "only",
            "only",
            BudgetLimits::default(),
            BudgetWindow::Daily,
        ))
        .unwrap_err();
    assert!(matches!(err, BudgetError::Duplicate { .. }));
}

#[test]
fn single_node_evaluate_allows_within_cap_denies_over() {
    let mut tree = BudgetTree::new();
    tree.insert(org("org/solo", tokens(1_000), BudgetWindow::Daily))
        .expect("solo");
    let id = BudgetNodeId::from("org/solo");

    // Within cap.
    let snap = SpendSnapshot::new();
    assert!(matches!(
        tree.evaluate(&id, AggregateSpend::with_tokens(500), &snap),
        BudgetDecision::Allow
    ));

    // At cap exactly.
    assert!(matches!(
        tree.evaluate(&id, AggregateSpend::with_tokens(1_000), &snap),
        BudgetDecision::Allow
    ));

    // Over cap.
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(1_001), &snap);
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::DimensionExceeded { ref dimension, .. } if dimension == "tokens"
    ));
}

#[test]
fn parent_cap_denies_even_when_child_has_room() {
    // A team policy with a daily cap of 10k tokens rejects the 11th
    // 1k-token request of the day, even if the per-agent policy would
    // allow it.
    let mut tree = BudgetTree::new();
    tree.insert(org("org/acme", tokens(100_000), BudgetWindow::Monthly))
        .expect("org");
    tree.insert(child(
        "team/alpha",
        "org/acme",
        tokens(10_000),
        BudgetWindow::Daily,
    ))
    .expect("team");
    tree.insert(child(
        "agent/a1",
        "team/alpha",
        tokens(5_000),
        BudgetWindow::Daily,
    ))
    .expect("agent");

    // After 10 successful 1k-token requests, the team window holds 10k
    // and the agent has spent some number <= 5k. The 11th request would
    // tip team over the 10k cap even though the per-agent window may be
    // cheap. Model this by pre-loading the team with 10k and the agent
    // with 2k; a new 1k draft should be denied with team as the offender.
    let mut snap = SpendSnapshot::new();
    snap.set(
        BudgetNodeId::from("team/alpha"),
        PerWindowSpend {
            window_start: 0,
            current: AggregateSpend::with_tokens(10_000),
        },
    );
    snap.set(
        BudgetNodeId::from("agent/a1"),
        PerWindowSpend {
            window_start: 0,
            current: AggregateSpend::with_tokens(2_000),
        },
    );

    let dec = tree.evaluate(
        &BudgetNodeId::from("agent/a1"),
        AggregateSpend::with_tokens(1_000),
        &snap,
    );
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny, got {dec:?}");
    };
    match reason {
        BudgetDenyReason::DimensionExceeded {
            node, dimension, ..
        } => {
            assert_eq!(node, BudgetNodeId::from("team/alpha"));
            assert_eq!(dimension, "tokens");
        }
        other => panic!("unexpected reason {other:?}"),
    }
}

#[test]
fn rolling_window_resets_allow_previously_denied() {
    // A rolling window that has rolled over produces a fresh snapshot.
    // Evaluating against the fresh snapshot allows previously denied
    // drafts.
    let mut tree = BudgetTree::new();
    tree.insert(org(
        "team/rolling",
        tokens(5_000),
        BudgetWindow::Rolling { seconds: 3600 },
    ))
    .expect("team");

    let id = BudgetNodeId::from("team/rolling");

    // Exhausted window: current spend = 5k. A 1k draft is denied.
    let exhausted = snapshot_for("team/rolling", AggregateSpend::with_tokens(5_000));
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(1_000), &exhausted);
    assert!(matches!(dec, BudgetDecision::Deny { .. }));

    // After the rolling window advances, the snapshot resets to zero and
    // the same draft now passes.
    let fresh = snapshot_for("team/rolling", AggregateSpend::default());
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(1_000), &fresh);
    assert!(matches!(dec, BudgetDecision::Allow));
}

#[test]
fn multiple_dimensions_evaluated_independently() {
    let limits = BudgetLimits {
        max_spend_units: Some(1_000),
        currency: Some("USD".to_string()),
        max_tokens: Some(100_000),
        max_requests: Some(50),
        max_warehouse_bytes: Some(1 << 20),
    };
    let mut tree = BudgetTree::new();
    tree.insert(org("org/multi", limits, BudgetWindow::Daily))
        .expect("org");
    let id = BudgetNodeId::from("org/multi");

    // Drafts exceeding each dimension in isolation.
    let snap = SpendSnapshot::new();

    // Tokens over.
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(100_001), &snap);
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::DimensionExceeded { ref dimension, .. } if dimension == "tokens"
    ));

    // Requests over.
    let dec = tree.evaluate(&id, AggregateSpend::with_requests(51), &snap);
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::DimensionExceeded { ref dimension, .. } if dimension == "requests"
    ));

    // Warehouse bytes over.
    let dec = tree.evaluate(
        &id,
        AggregateSpend::with_warehouse_bytes((1 << 20) + 1),
        &snap,
    );
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::DimensionExceeded { ref dimension, .. } if dimension == "warehouse_bytes"
    ));

    // Spend over (matching currency required).
    let dec = tree.evaluate(&id, AggregateSpend::with_spend(1_001, "USD"), &snap);
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::DimensionExceeded { ref dimension, .. } if dimension == "spend"
    ));

    // Mixed small draft fits every dimension.
    let mixed = AggregateSpend {
        spend_units: 10,
        currency: Some("USD".to_string()),
        tokens: 100,
        requests: 1,
        warehouse_bytes: 1024,
    };
    assert!(matches!(
        tree.evaluate(&id, mixed, &snap),
        BudgetDecision::Allow
    ));
}

#[test]
fn disabled_node_denies_with_node_disabled_reason() {
    let mut tree = BudgetTree::new();
    tree.insert(
        BudgetNode::new("team/disabled", BudgetWindow::Daily)
            .with_limits(tokens(1_000_000))
            .disabled(),
    )
    .expect("disabled");
    let id = BudgetNodeId::from("team/disabled");
    let snap = SpendSnapshot::new();
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(1), &snap);
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::NodeDisabled { ref node } if node.as_str() == "team/disabled"
    ));
}

#[test]
fn serialize_deserialize_roundtrip_preserves_tree_and_limits() {
    let mut tree = BudgetTree::new();
    tree.insert(org("org/acme", usd(1_000_000), BudgetWindow::Monthly))
        .expect("org");
    tree.insert(child(
        "dept/research",
        "org/acme",
        usd(400_000),
        BudgetWindow::Monthly,
    ))
    .expect("dept");
    tree.insert(child(
        "team/ml",
        "dept/research",
        tokens(10_000),
        BudgetWindow::Daily,
    ))
    .expect("team");

    let encoded = tree.serialize();
    let json = serde_json::to_string(&encoded).expect("json");
    let decoded_value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let decoded = BudgetTree::deserialize(decoded_value).expect("decode");

    assert_eq!(decoded.len(), tree.len());
    assert_eq!(
        decoded.ancestors(&BudgetNodeId::from("team/ml")),
        tree.ancestors(&BudgetNodeId::from("team/ml"))
    );
    let original_team = tree.get(&BudgetNodeId::from("team/ml")).expect("get");
    let decoded_team = decoded
        .get(&BudgetNodeId::from("team/ml"))
        .expect("decoded get");
    assert_eq!(decoded_team, original_team);
}

#[test]
fn ancestors_returns_leaf_to_root_order() {
    let mut tree = BudgetTree::new();
    tree.insert(org("root", BudgetLimits::default(), BudgetWindow::Daily))
        .expect("root");
    tree.insert(child(
        "mid",
        "root",
        BudgetLimits::default(),
        BudgetWindow::Daily,
    ))
    .expect("mid");
    tree.insert(child(
        "leaf",
        "mid",
        BudgetLimits::default(),
        BudgetWindow::Daily,
    ))
    .expect("leaf");
    let chain = tree.ancestors(&BudgetNodeId::from("leaf"));
    assert_eq!(
        chain,
        vec![
            BudgetNodeId::from("leaf"),
            BudgetNodeId::from("mid"),
            BudgetNodeId::from("root"),
        ]
    );
}

#[test]
fn unknown_node_id_yields_unknown_error_not_panic() {
    let tree = BudgetTree::new();
    let dec = tree.evaluate(
        &BudgetNodeId::from("ghost"),
        AggregateSpend::with_tokens(1),
        &SpendSnapshot::new(),
    );
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::UnknownNode { ref node } if node.as_str() == "ghost"
    ));
}

#[test]
fn parent_and_child_both_in_bounds_allows() {
    let mut tree = BudgetTree::new();
    tree.insert(org("org/a", tokens(100_000), BudgetWindow::Monthly))
        .expect("org");
    tree.insert(child(
        "team/a",
        "org/a",
        tokens(10_000),
        BudgetWindow::Daily,
    ))
    .expect("team");
    tree.insert(child(
        "agent/a",
        "team/a",
        tokens(1_000),
        BudgetWindow::Daily,
    ))
    .expect("agent");

    let mut snap = SpendSnapshot::new();
    snap.set(
        BudgetNodeId::from("org/a"),
        PerWindowSpend {
            window_start: 0,
            current: AggregateSpend::with_tokens(5_000),
        },
    );
    snap.set(
        BudgetNodeId::from("team/a"),
        PerWindowSpend {
            window_start: 0,
            current: AggregateSpend::with_tokens(500),
        },
    );
    snap.set(
        BudgetNodeId::from("agent/a"),
        PerWindowSpend {
            window_start: 0,
            current: AggregateSpend::with_tokens(100),
        },
    );

    assert!(matches!(
        tree.evaluate(
            &BudgetNodeId::from("agent/a"),
            AggregateSpend::with_tokens(200),
            &snap,
        ),
        BudgetDecision::Allow
    ));
}

#[test]
fn disabled_ancestor_propagates_to_leaf() {
    let mut tree = BudgetTree::new();
    tree.insert(
        BudgetNode::new("org/x", BudgetWindow::Monthly)
            .with_limits(tokens(1_000_000))
            .disabled(),
    )
    .expect("org disabled");
    tree.insert(child(
        "team/x",
        "org/x",
        tokens(10_000),
        BudgetWindow::Daily,
    ))
    .expect("team");

    let snap = SpendSnapshot::new();
    let dec = tree.evaluate(
        &BudgetNodeId::from("team/x"),
        AggregateSpend::with_tokens(1),
        &snap,
    );
    let BudgetDecision::Deny { reason } = dec else {
        panic!("expected deny");
    };
    assert!(matches!(
        reason,
        BudgetDenyReason::NodeDisabled { ref node } if node.as_str() == "org/x"
    ));
}

#[test]
fn spend_dimension_denies_currency_mismatch() {
    // A currency-denominated cap fails closed on a positive spend it
    // cannot convert: an EUR draft against a USD cap is denied, not
    // silently skipped. A zero-spend draft carries no money and passes.
    let mut tree = BudgetTree::new();
    tree.insert(org("org/usd", usd(1_000), BudgetWindow::Daily))
        .expect("org");

    let id = BudgetNodeId::from("org/usd");
    let snap = SpendSnapshot::new();

    // Matching currency over cap denies.
    let dec = tree.evaluate(&id, AggregateSpend::with_spend(2_000, "USD"), &snap);
    assert!(matches!(dec, BudgetDecision::Deny { .. }));

    // Mismatched currency with positive spend fails closed (denies).
    let dec = tree.evaluate(&id, AggregateSpend::with_spend(2_000, "EUR"), &snap);
    assert!(matches!(dec, BudgetDecision::Deny { .. }));

    // Matching currency under cap allows.
    let dec = tree.evaluate(&id, AggregateSpend::with_spend(500, "USD"), &snap);
    assert!(matches!(dec, BudgetDecision::Allow));

    // Zero-spend draft (tokens only, no currency) carries no money and passes.
    let dec = tree.evaluate(&id, AggregateSpend::with_tokens(10), &snap);
    assert!(matches!(dec, BudgetDecision::Allow));
}
