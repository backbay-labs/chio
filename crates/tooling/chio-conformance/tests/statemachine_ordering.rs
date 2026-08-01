#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

#[path = "_generated/anchor_witness_state_ordering.rs"]
mod anchor_witness;
#[path = "_generated/bilateral_dsse_producer_ordering.rs"]
mod bilateral_dsse;

fn assert_complete_relation(
    states: &[&str],
    messages: &[&str],
    edges: &[(&str, &str)],
    non_edges: &[(&str, &str)],
) {
    let edge_set: BTreeSet<_> = edges.iter().copied().collect();
    let non_edge_set: BTreeSet<_> = non_edges.iter().copied().collect();
    assert_eq!(edge_set.len(), edges.len(), "duplicate generated edge");
    assert_eq!(
        non_edge_set.len(),
        non_edges.len(),
        "duplicate generated non-edge"
    );
    for state in states {
        for message in messages {
            let pair = (*state, *message);
            assert_ne!(
                edge_set.contains(&pair),
                non_edge_set.contains(&pair),
                "each state-message pair must be exactly one edge or non-edge: {pair:?}"
            );
        }
    }
}

#[test]
fn bilateral_dsse_relation_covers_every_state_message_pair() {
    let edges: Vec<_> = bilateral_dsse::TRANSITIONS
        .iter()
        .map(|edge| (edge.from, edge.message))
        .collect();
    let non_edges: Vec<_> = bilateral_dsse::NON_EDGES
        .iter()
        .map(|edge| (edge.state, edge.message))
        .collect();
    assert_complete_relation(
        bilateral_dsse::STATES,
        bilateral_dsse::MESSAGES,
        &edges,
        &non_edges,
    );
    assert_eq!(bilateral_dsse::MACHINE, "bilateral_dsse_producer");
    assert_eq!(bilateral_dsse::TERMINAL_STATES, ["EnvelopeVerified"]);
    for message in bilateral_dsse::MESSAGES {
        assert!(non_edges.contains(&("EnvelopeVerified", *message)));
    }
    assert!(non_edges.contains(&("Drafted", "request_cosignature")));
    assert!(non_edges.contains(&("Drafted", "verify_envelope")));
}

#[test]
fn anchor_witness_relation_is_limited_to_carried_metadata() {
    let edges: Vec<_> = anchor_witness::TRANSITIONS
        .iter()
        .map(|edge| (edge.from, edge.message))
        .collect();
    let non_edges: Vec<_> = anchor_witness::NON_EDGES
        .iter()
        .map(|edge| (edge.state, edge.message))
        .collect();
    assert_complete_relation(
        anchor_witness::STATES,
        anchor_witness::MESSAGES,
        &edges,
        &non_edges,
    );
    assert_eq!(anchor_witness::MACHINE, "anchor_witness_state");
    assert!(anchor_witness::TERMINAL_STATES.is_empty());
    assert_eq!(non_edges, [("Pending", "record_verification_failure")]);
    assert!(anchor_witness::SCOPE.contains("Producer-carried"));
    assert!(anchor_witness::SCOPE.contains("does not encode verifier routing"));
}
