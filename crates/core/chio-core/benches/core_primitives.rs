use chio_core::{
    canonical_json_bytes,
    capability::{
        attenuation::{
            validate_attenuation, validate_delegation_chain, DelegationLink, DelegationLinkBody,
        },
        scope::{ChioScope, Constraint, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair, MerkleTree,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;

trait BenchUnwrap<T> {
    fn bench_unwrap(self, context: &str) -> T;
}

impl<T, E> BenchUnwrap<T> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn bench_unwrap(self, context: &str) -> T {
        self.unwrap_or_else(|error| panic!("{context}: {error}"))
    }
}

fn make_payload() -> serde_json::Value {
    json!({
        "requestId": "req-bench-001",
        "toolServer": "srv-payments",
        "toolName": "charge_card",
        "parameters": {
            "merchantId": "m-2026-04",
            "amount": { "units": 1299, "currency": "USD" },
            "memo": "chio benchmark coverage",
            "items": [
                { "sku": "sku-1", "qty": 1, "price": 499 },
                { "sku": "sku-2", "qty": 2, "price": 400 },
            ],
        },
        "evidence": {
            "attestation": "verified",
            "riskScore": 3,
            "jurisdiction": "US-NY",
        },
    })
}

fn make_grant(
    server_id: &str,
    tool_name: &str,
    operations: Vec<Operation>,
    constraints: Vec<Constraint>,
    max_invocations: Option<u32>,
) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations,
        constraints,
        max_invocations,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

fn build_validation_fixture() -> (
    CapabilityToken,
    ChioScope,
    ChioScope,
    Vec<DelegationLink>,
    u64,
) {
    let root = Keypair::from_seed(&[0x11; 32]);
    let delegate_one = Keypair::from_seed(&[0x22; 32]);
    let delegate_two = Keypair::from_seed(&[0x33; 32]);

    let parent_scope = make_scope(vec![
        make_grant(
            "srv-payments",
            "charge_card",
            vec![
                Operation::Invoke,
                Operation::ReadResult,
                Operation::Delegate,
            ],
            vec![Constraint::PathPrefix("/tenant/acme".to_string())],
            Some(32),
        ),
        make_grant(
            "srv-reports",
            "read_invoice",
            vec![Operation::Invoke, Operation::ReadResult],
            Vec::new(),
            None,
        ),
    ]);

    let child_scope = make_scope(vec![make_grant(
        "srv-payments",
        "charge_card",
        vec![Operation::Invoke, Operation::ReadResult],
        vec![
            Constraint::PathPrefix("/tenant/acme".to_string()),
            Constraint::MaxLength(128),
        ],
        Some(8),
    )]);

    let link_one = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-root".to_string(),
            delegator: root.public_key(),
            delegatee: delegate_one.public_key(),
            attenuations: Vec::new(),
            timestamp: 1_710_000_000,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &root,
    )
    .bench_unwrap("sign first delegation link");
    let link_two = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: "cap-child".to_string(),
            delegator: delegate_one.public_key(),
            delegatee: delegate_two.public_key(),
            attenuations: Vec::new(),
            timestamp: 1_710_000_060,
            scope_hash: None,
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &delegate_one,
    )
    .bench_unwrap("sign second delegation link");

    let now = 1_710_000_120;
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-bench".to_string(),
            issuer: delegate_two.public_key(),
            subject: delegate_two.public_key(),
            scope: child_scope.clone(),
            issued_at: now - 60,
            expires_at: now + 600,
            delegation_chain: vec![link_one.clone(), link_two.clone()],
            aggregate_invocation_budget: None,
        },
        &delegate_two,
    )
    .bench_unwrap("sign capability token");

    (
        token,
        parent_scope,
        child_scope,
        vec![link_one, link_two],
        now,
    )
}

fn capability_validation_pass(
    token: &CapabilityToken,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
    delegation_chain: &[DelegationLink],
    now: u64,
) -> bool {
    token
        .verify_signature()
        .bench_unwrap("verify capability signature")
        && token.validate_time(now).is_ok()
        && validate_delegation_chain(delegation_chain, Some(8)).is_ok()
        && validate_attenuation(parent_scope, child_scope).is_ok()
}

fn bench_signature_verification(c: &mut Criterion) {
    let keypair = Keypair::from_seed(&[0x44; 32]);
    let payload = make_payload();
    let canonical = canonical_json_bytes(&payload).bench_unwrap("canonicalize signature payload");
    let signature = keypair.sign(&canonical);
    let public_key = keypair.public_key();

    c.bench_function("chio_core/signature_verification", |b| {
        b.iter(|| {
            black_box(public_key.verify(black_box(canonical.as_slice()), black_box(&signature)))
        })
    });
}

fn bench_canonical_json(c: &mut Criterion) {
    let payload = make_payload();

    c.bench_function("chio_core/canonical_json_bytes", |b| {
        b.iter(|| {
            black_box(
                canonical_json_bytes(black_box(&payload)).bench_unwrap("canonicalize payload"),
            )
        })
    });
}

fn bench_merkle_paths(c: &mut Criterion) {
    let leaves = (0..1024usize)
        .map(|index| {
            canonical_json_bytes(&json!({
                "seq": index,
                "receiptId": format!("rcpt-{index:04}"),
                "contentHash": format!("hash-{index:04}"),
                "decision": if index % 2 == 0 { "allow" } else { "deny" },
            }))
            .bench_unwrap("canonicalize merkle leaf")
        })
        .collect::<Vec<_>>();
    let tree = MerkleTree::from_leaves(&leaves).bench_unwrap("build merkle tree");
    let proof_index = 511usize;
    let proof = tree
        .inclusion_proof(proof_index)
        .bench_unwrap("generate merkle proof");
    let root = tree.root();

    let mut group = c.benchmark_group("chio_core/merkle");
    group.bench_function("build_tree_1024_leaves", |b| {
        b.iter(|| {
            black_box(MerkleTree::from_leaves(black_box(&leaves)).bench_unwrap("build merkle tree"))
        })
    });
    group.bench_function("generate_proof_1024_leaves", |b| {
        b.iter(|| {
            black_box(
                tree.inclusion_proof(black_box(proof_index))
                    .bench_unwrap("generate merkle proof"),
            )
        })
    });
    group.bench_function("verify_proof_1024_leaves", |b| {
        b.iter(|| {
            black_box(proof.verify(black_box(leaves[proof_index].as_slice()), black_box(&root)))
        })
    });
    group.finish();
}

fn bench_capability_validation(c: &mut Criterion) {
    let (token, parent_scope, child_scope, delegation_chain, now) = build_validation_fixture();
    assert!(capability_validation_pass(
        &token,
        &parent_scope,
        &child_scope,
        &delegation_chain,
        now,
    ));

    c.bench_function("chio_core/capability_validation_path", |b| {
        b.iter(|| {
            black_box(capability_validation_pass(
                black_box(&token),
                black_box(&parent_scope),
                black_box(&child_scope),
                black_box(&delegation_chain),
                black_box(now),
            ))
        })
    });
}

criterion_group!(
    benches,
    bench_signature_verification,
    bench_canonical_json,
    bench_merkle_paths,
    bench_capability_validation
);
criterion_main!(benches);
