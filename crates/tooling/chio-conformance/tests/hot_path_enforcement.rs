//! Layout:

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    attenuation::{
        compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
        DelegationLinkBody,
    },
    crypto_floor::CapabilityCryptoFloor,
    features,
    features::CapabilityNegotiation,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_federation::{
    bilateral::InProcessCoSigner, trust_establishment::ConformanceTier,
    trust_establishment::FederationPeer,
};
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, Verdict as HostedVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_kernel_core::{
    verify_capability_full, BudgetSplitError, CapabilityError, FixedClock, InMemoryBudgetRegistry,
    PortableToolCallRequest, Verdict as PortableVerdict,
};

fn grant(operations: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope_with(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

/// Build a fresh `ChioKernel` whose primary keypair is the supplied
/// `issuer`. Because `trusted_issuer_keys` always includes the
/// kernel's own public key, this keeps the test issuer in the trusted
/// set without needing to mutate `ca_public_keys` post-construction.
fn make_kernel(issuer: Keypair) -> ChioKernel {
    let config = KernelConfig {
        keypair: issuer,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "hot-path-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    ChioKernel::new(config)
}

struct EchoToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for EchoToolServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["tool".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn direct_attenuated_token(
    id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let witness = compute_attenuation_witness(&scope, &scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: witness,
    };
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope,
                issued_at,
                expires_at,
                delegation_chain: vec![],
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        issuer,
    )
    .expect("attenuated token signs")
}

fn peer(
    kernel_id: &str,
    keypair: &Keypair,
    capabilities: CapabilityNegotiation,
    now: u64,
) -> FederationPeer {
    FederationPeer {
        kernel_id: kernel_id.to_string(),
        public_key: keypair.public_key(),
        conformance_tier: ConformanceTier::Bronze,
        established_at: now,
        rotation_due: now + 3_600,
        capabilities,
        ladder_manifest_ref: None,
    }
}

fn portable_request(request_id: &str, capability: &CapabilityToken) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: request_id.to_string(),
        tool_name: "tool".to_string(),
        server_id: "srv".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::Value::Null,
    }
}

fn hosted_request(request_id: &str, capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "tool".to_string(),
        server_id: "srv".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::Value::Null,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn kernel_hot_path_rejects_inflated_parent_scope() {
    let scope_x = scope_with(vec![grant(vec![Operation::Invoke, Operation::Delegate])]);
    let scope_bigger = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    // child <= scope_bigger but NOT <= scope_x (requires ReadResult).
    let scope_child = scope_with(vec![grant(vec![Operation::Invoke, Operation::ReadResult])]);

    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    // Honest witness: child <= scope_bigger. Attacker supplies it; the
    // verifier without chain-binding would accept.
    let witness = compute_attenuation_witness(&scope_bigger, &scope_child).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope_bigger).unwrap(),
        child_scope_hash: scope_hash(&scope_child).unwrap(),
        normalized_subset_proof: witness,
    };

    let body = CapabilityTokenBody {
        id: "cap-attenuated-inflated-parent-hot-path".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope_child,
        issued_at: 100,
        expires_at: 200,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("inflated-parent token signs (verifier must catch this)");

    // Build a kernel whose primary keypair is the issuer (so the
    // issuer is in the trusted set) and whose registered trust-root
    // authority is scope_X (the issuer's TRUE authority).
    let kernel = make_kernel(issuer.clone())
        .with_capability_trust_roots(vec![(issuer.public_key(), scope_hash(&scope_x).unwrap())]);

    let request = portable_request("req-w1.1-inflated", &token);
    let clock = FixedClock::new(150);
    let guards: &[&dyn chio_kernel_core::Guard] = &[];

    let verdict = kernel.evaluate_portable_verdict(&token, &request, guards, &clock, None);

    assert_eq!(
        verdict.verdict,
        PortableVerdict::Deny,
        "chain-binding must DENY the inflated parent_scope_hash attack at the kernel hot path; got verdict {:?} reason {:?}",
        verdict.verdict, verdict.reason
    );
    let reason = verdict.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("chain")
            || reason.contains("parent_scope_hash")
            || reason.contains("trust-root"),
        "expected chain-binding diagnostic, got: {reason}"
    );
}

#[test]
fn kernel_hot_path_rejects_oversubscribed_siblings() {
    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let child_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    let issuer = Keypair::generate();
    let subject_a = Keypair::generate();
    let subject_b = Keypair::generate();

    let parent_id = "cap-parent-w1.2";

    let mk_chain = |delegatee: chio_core::PublicKey| {
        let body = DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee,
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
        };
        vec![DelegationLink::sign(body, &issuer).expect("delegation link signs")]
    };

    let mk_child = |id: &str, delegatee: chio_core::PublicKey, share: u16| {
        let witness = compute_attenuation_witness(&parent_scope, &child_scope).unwrap();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent_scope).unwrap(),
            child_scope_hash: scope_hash(&child_scope).unwrap(),
            normalized_subset_proof: witness,
        };
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.clone(),
            scope: child_scope.clone(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: mk_chain(delegatee),
        };
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: Some(share),
            },
            &issuer,
        )
        .expect("child token signs")
    };

    let child_a = mk_child("cap-child-a-w1.2", subject_a.public_key(), 4_000);
    let child_b = mk_child("cap-child-b-w1.2", subject_b.public_key(), 4_000);

    // Build kernel using the issuer keypair as the kernel's primary so
    // the issuer is in the trusted set, register the trust root for
    // the chain-binding rule, and seed the budget registry with the
    // parent share.
    let kernel = make_kernel(issuer.clone()).with_capability_trust_roots(vec![(
        issuer.public_key(),
        scope_hash(&parent_scope).unwrap(),
    )]);
    kernel
        .register_budget_parent(parent_id.to_string(), 5_000)
        .expect("register parent");

    let clock = FixedClock::new(150);
    let guards: &[&dyn chio_kernel_core::Guard] = &[];

    // First child: 4000 of 5000 admits.
    let req_a = portable_request("req-w1.2-child-a", &child_a);
    let verdict_a = kernel.evaluate_portable_verdict(&child_a, &req_a, guards, &clock, None);
    assert_eq!(
        verdict_a.verdict,
        PortableVerdict::Allow,
        "first child must be admitted (4000 bps fits 5000 bps parent share); got verdict {:?} reason {:?}",
        verdict_a.verdict, verdict_a.reason
    );

    // Second child: 4000 + 4000 = 8000 > 5000. Must be DENY.
    let req_b = portable_request("req-w1.2-child-b", &child_b);
    let verdict_b = kernel.evaluate_portable_verdict(&child_b, &req_b, guards, &clock, None);
    assert_eq!(
        verdict_b.verdict,
        PortableVerdict::Deny,
        "sibling-sum must DENY oversubscribed second child at the kernel hot path; got verdict {:?} reason {:?}",
        verdict_b.verdict, verdict_b.reason
    );
    let reason = verdict_b.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("budget")
            || reason.contains("oversubscrib")
            || reason.contains("budget_split"),
        "expected sibling-sum diagnostic, got: {reason}"
    );
}

#[test]
fn delegated_child_without_pre_registered_parent_fails_closed() {
    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let child_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent_id = "cap-parent-autoreg";

    let chain = {
        let body = DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
        };
        vec![DelegationLink::sign(body, &issuer).expect("delegation link signs")]
    };

    let witness = compute_attenuation_witness(&parent_scope, &child_scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&parent_scope).unwrap(),
        child_scope_hash: scope_hash(&child_scope).unwrap(),
        normalized_subset_proof: witness,
    };
    let body = CapabilityTokenBody {
        id: "cap-child-autoreg".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: child_scope,
        issued_at: 100,
        expires_at: 200,
        delegation_chain: chain,
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(4_000),
        },
        &issuer,
    )
    .expect("child token signs");

    let peer = CapabilityNegotiation::t1_default();
    let trust_resolver =
        |k: &chio_core::PublicKey| -> Option<chio_core::capability::attenuation::ScopeHash> {
            if k == &issuer.public_key() {
                Some(scope_hash(&parent_scope).unwrap())
            } else {
                None
            }
        };
    let clock = FixedClock::new(150);

    // Fresh per-request registry: no register_parent call before verify.
    // Unknown parents must stay fail-closed so the verifier does not
    // fabricate a parent share.
    let mut budgets = InMemoryBudgetRegistry::new();
    let err = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_resolver,
        &mut budgets,
    )
    .expect_err("unknown parent must fail closed on a fresh registry");
    assert!(
        matches!(
            err,
            CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
        ),
        "expected UnknownParent budget split rejection, got: {err:?}"
    );
}

#[test]
fn unregistered_parent_rejects_first_sibling_fail_closed() {
    let parent_scope = scope_with(vec![grant(vec![
        Operation::Invoke,
        Operation::Delegate,
        Operation::ReadResult,
    ])]);
    let child_scope = scope_with(vec![grant(vec![Operation::Invoke])]);

    let issuer = Keypair::generate();
    let subject_a = Keypair::generate();
    let parent_id = "cap-parent-autoreg-siblings";

    let mk_chain = |delegatee: chio_core::PublicKey| {
        let body = DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee,
            attenuations: vec![],
            timestamp: 100,
            scope_hash: Some(scope_hash(&parent_scope).unwrap()),
        };
        vec![DelegationLink::sign(body, &issuer).expect("delegation link signs")]
    };

    let mk_child = |id: &str, delegatee: chio_core::PublicKey, share: u16| {
        let witness = compute_attenuation_witness(&parent_scope, &child_scope).unwrap();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent_scope).unwrap(),
            child_scope_hash: scope_hash(&child_scope).unwrap(),
            normalized_subset_proof: witness,
        };
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: delegatee.clone(),
            scope: child_scope.clone(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: mk_chain(delegatee),
        };
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: Some(share),
            },
            &issuer,
        )
        .expect("child token signs")
    };

    // The first sibling would fit under a fabricated 10000-bps parent,
    // but no verifier-owned parent snapshot has been registered. It must
    // fail closed with UnknownParent.
    let child_a = mk_child("cap-child-a-siblings", subject_a.public_key(), 6_000);

    let peer = CapabilityNegotiation::t1_default();
    let trust_resolver =
        |k: &chio_core::PublicKey| -> Option<chio_core::capability::attenuation::ScopeHash> {
            if k == &issuer.public_key() {
                Some(scope_hash(&parent_scope).unwrap())
            } else {
                None
            }
        };
    let clock = FixedClock::new(150);

    let mut budgets = InMemoryBudgetRegistry::new();
    let err = verify_capability_full(
        &child_a,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_resolver,
        &mut budgets,
    )
    .expect_err("unknown parent must reject the first sibling");
    assert!(
        matches!(
            err,
            CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
        ),
        "expected UnknownParent, got: {err:?}"
    );
}

#[test]
fn chain_binding_disabled_rejects_attenuated_token() {
    let scope = scope_with(vec![grant(vec![Operation::Invoke])]);
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let witness = compute_attenuation_witness(&scope, &scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(&scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: witness,
    };
    let body = CapabilityTokenBody {
        id: "cap-attenuated-chain-binding-disabled".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: scope.clone(),
        issued_at: 100,
        expires_at: 200,
        delegation_chain: vec![],
    };
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body,
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: None,
        },
        &issuer,
    )
    .expect("attenuated token signs");

    // Peer profile with chain-binding explicitly disabled.
    let mut peer = CapabilityNegotiation::t1_default();
    peer.features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);

    // Empty trust resolver: no issuer has a registered authority hash.
    // The verifier should reject because the peer explicitly disabled
    // chain binding for attenuated capabilities.
    let trust_resolver =
        |_k: &chio_core::PublicKey| -> Option<chio_core::capability::attenuation::ScopeHash> {
            None
        };
    let clock = FixedClock::new(150);
    let mut budgets = InMemoryBudgetRegistry::new();

    let err = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_resolver,
        &mut budgets,
    )
    .expect_err("disabled chain-binding must reject attenuated token fail-closed");
    match err {
        CapabilityError::AttenuationViolation(message) => assert!(
            message.contains("delegation_chain_binding") || message.contains("disabled"),
            "expected disabled chain-binding diagnostic, got: {message}"
        ),
        other => panic!("expected AttenuationViolation, got: {other:?}"),
    }
}

#[test]
#[allow(deprecated)]
fn hosted_path_rejects_attenuated_when_peer_disables_chain_binding() {
    let now = now_unix_secs();
    let scope = scope_with(vec![grant(vec![Operation::Invoke])]);
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let token = direct_attenuated_token(
        "cap-hosted-chain-binding-disabled",
        &issuer,
        &subject,
        scope.clone(),
        now.saturating_sub(1),
        now + 300,
    );
    let origin_kernel_id = "kernel.no-chain-binding";
    let origin_keypair = Keypair::generate();
    let mut capabilities = CapabilityNegotiation::t1_default();
    capabilities
        .features
        .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
    let mut kernel = make_kernel(issuer.clone())
        .with_capability_trust_roots(vec![(issuer.public_key(), scope_hash(&scope).unwrap())])
        .with_federation_peers(vec![peer(
            origin_kernel_id,
            &origin_keypair,
            capabilities,
            now,
        )]);
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_keypair,
        issuer.public_key(),
    )));
    kernel.register_tool_server(Box::new(EchoToolServer));

    // The federated hosted path fails closed without durable receipt
    // persistence (ensure_federated_receipt_persistence_ready), so install a
    // receipt store before the chain-binding check can run.
    let receipt_dir = tempfile::tempdir().expect("receipt temp dir");
    kernel
        .set_receipt_store(Box::new(
            chio_store_sqlite::SqliteReceiptStore::open(receipt_dir.path().join("receipts.db"))
                .expect("open receipt store"),
        ))
        .expect("install receipt store");

    let mut request = hosted_request("req-hosted-chain-binding-disabled", &token);
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("chain-binding denial should return a signed deny response");
    assert_eq!(response.verdict, HostedVerdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("chain") || reason.contains("delegation_chain_binding"),
        "expected chain-binding denial, got: {reason}"
    );
}
