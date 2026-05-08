//! If a future PR re-introduces a kernel-side shortcut named
//! `verify_capability_full_without_budget_admit`,
//! `verify_capability_signature`, or any other partial verifier on
//! the kernel hot path -- and routes the dispatch surface
//! (`evaluate_tool_call_blocking`,
//! `evaluate_tool_call_blocking_with_metadata`,
//! `evaluate_tool_call_with_nested_flow_bridge`,
//! `evaluate_plan_step`, `validate_non_tool_capability`) through that
//! shortcut instead of the unified
//! [`chio_kernel_core::verify_capability_full`] entry, this test MUST
//! fail. The test must continue to call the kernel via its public
//! dispatch API (no monkey-patching, no mocks of the verifier itself,
//! no calls into chio-kernel-core's verifier in the assertion
//! position): if it does not, the property is tautological and the
//! shortcut is back.
//!
//! Spec anchor: `spec/PROTOCOL.md` section "Sibling-Sum / Chain-Binding"
//! (the MUST that promotes the previous SHOULD).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    compute_attenuation_witness, scope_hash, AttenuationProof, CapabilityCryptoFloor,
    CapabilityNegotiation, CapabilityToken, CapabilityTokenBody, CapabilityTokenV2Body, ChioScope,
    Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_federation::{ConformanceTier, FederationPeer, InProcessCoSigner};
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, Verdict as HostedVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_kernel_core::{verify_capability_full, FixedClock, NoopBudgetRegistry, TrustRootResolver};

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

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

fn make_kernel(issuer: Keypair) -> ChioKernel {
    let config = KernelConfig {
        keypair: issuer,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "single-entry-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    ChioKernel::new(config)
}

fn direct_v2_token(
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
    CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
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
    .expect("v2 token signs")
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
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

struct EchoToolServer;

#[async_trait::async_trait(?Send)]
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

/// The discriminating fixture.
///
/// A v2 capability with a valid signature, a valid v2 chain-binding
/// witness (parent_scope_hash bound to the issuer's trust root), a
/// valid crypto floor, and a generous time window. Presented across a
/// federation peer whose negotiated profile caps schema at v1.
///
/// Behaviour the deleted `verify_capability_signature` shortcut would
/// produce: ACCEPT. It only checked signature, crypto floor, and v2
/// chain-binding -- the peer profile is invisible to it.
///
/// Behaviour the unified `verify_capability_full` entry produces:
/// DENY with `SchemaExceedsNegotiatedCeiling`. The schema-ceiling
/// check is step 1 of the unified entry and runs before any other
/// cryptographic work.
///
/// The kernel hot path is reached through
/// `ChioKernel::evaluate_tool_call_blocking`, the production hosted
/// dispatch surface. No verifier mock, no direct call into
/// chio-kernel-core in the assertion position.
#[test]
#[allow(deprecated)]
fn b1_single_entry_verifier_has_no_bypass_on_hosted_dispatch() {
    let now = now_unix_secs();
    let scope = scope_with(vec![grant(vec![Operation::Invoke])]);
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let token = direct_v2_token(
        "cap-b1-no-bypass",
        &issuer,
        &subject,
        scope.clone(),
        now.saturating_sub(1),
        now + 300,
    );

    let origin_kernel_id = "kernel.v1-only.b1";
    let origin_keypair = Keypair::generate();
    let mut kernel = make_kernel(issuer.clone())
        .with_capability_trust_roots(vec![(issuer.public_key(), scope_hash(&scope).unwrap())])
        .with_federation_peers(vec![peer(
            origin_kernel_id,
            &origin_keypair,
            CapabilityNegotiation::v1_default(),
            now,
        )]);
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_keypair,
        issuer.public_key(),
    )));
    kernel.register_tool_server(Box::new(EchoToolServer));

    let mut request = hosted_request("req-b1-no-bypass", &token);
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    // PRODUCTION DISPATCH SURFACE. This is the public hot-path entry.
    // If a future refactor reintroduces a verifier shortcut and routes
    // this surface through it, the assertion below MUST fail.
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("hosted dispatch returns a signed deny response");

    assert_eq!(
        response.verdict,
        HostedVerdict::Deny,
        "hosted dispatch must DENY a v2 token across a v1-only peer; got verdict {:?} reason {:?}",
        response.verdict,
        response.reason
    );

    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("schema") && reason.contains("ceiling"),
        "expected schema-ceiling diagnostic from unified verifier, got: {reason}. \
         If this assertion fails with a non-ceiling diagnostic, a verifier shortcut may have \
         been reintroduced and routed through the kernel hot path. See revert procedure in \
         this file's header comment."
    );
}

/// A `TrustRootResolver` backed by a single (issuer, scope_hash) pair.
/// Used by the positive control below.
struct SingleTrustRoot {
    issuer_hex: String,
    root: chio_core::capability::ScopeHash,
}

impl TrustRootResolver for SingleTrustRoot {
    fn trust_root_scope_hash(
        &self,
        issuer: &chio_core::PublicKey,
    ) -> Option<chio_core::capability::ScopeHash> {
        if issuer.to_hex() == self.issuer_hex {
            Some(self.root.clone())
        } else {
            None
        }
    }
}

/// Positive control on the unified verifier itself.
#[test]
fn b1_positive_control_unified_verifier_accepts_same_token_under_v2_peer() {
    let now = now_unix_secs();
    let scope = scope_with(vec![grant(vec![Operation::Invoke])]);
    let issuer = Keypair::generate();
    let subject = Keypair::generate();

    let token = direct_v2_token(
        "cap-b1-positive-control",
        &issuer,
        &subject,
        scope.clone(),
        now.saturating_sub(1),
        now + 300,
    );

    let trusted_issuers = vec![issuer.public_key()];
    let clock = FixedClock::new(now + 5);
    let peer_t1 = CapabilityNegotiation::t1_default();
    let trust_root = SingleTrustRoot {
        issuer_hex: issuer.public_key().to_hex(),
        root: scope_hash(&scope).unwrap(),
    };
    let mut budgets = NoopBudgetRegistry;

    let verified = verify_capability_full(
        &token,
        &trusted_issuers,
        &clock,
        CapabilityCryptoFloor::AllowClassical,
        &peer_t1,
        &trust_root,
        &mut budgets,
    )
    .expect("token must verify under unified entry with a v2-admitting peer profile");

    assert_eq!(
        verified.id, "cap-b1-positive-control",
        "verified projection must surface the token id"
    );
}
