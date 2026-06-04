use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    ActorRef, BoundaryClass, ChioReceipt, ChioReceiptBody, Decision, ReceiptKind, RedactionMode,
    ToolCallAction, ToolOrigin, TrustLevel,
};
use chio_federation::{
    execute_local_bilateral_invocation_fixture, ActionClassKind, BilateralCoSigningProtocol,
    BilateralPredicateExtensions, CapabilityLeaseRef, DemoAllowAllRevocationOracle,
    InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry, InMemoryReceiptStore, InProcessCoSigner,
    LocalBilateralInvocationFixtureRequest, PeerPinSet, PinnedEpoch, PinnedPeer,
    PolicyEvaluationSummary, PolicyVerdict, ResolvedLease, UnknownActionClassPolicy,
    VerifierConfig,
};
use std::collections::BTreeMap;

pub const ORIGIN_KERNEL_ID: &str = "did:chio:org-a";
pub const TOOL_HOST_KERNEL_ID: &str = "did:chio:org-b";
pub const NOW_UNIX_MS: u64 = 1_734_000_000_000;
pub const LEASE_ID: &str = "lease-c2-demo";
pub const TOOL_NAME: &str = "file_read";

#[derive(Debug, Clone)]
pub struct BilateralDemoSummary {
    pub origin_kernel_id: &'static str,
    pub origin_public_key_hex: String,
    pub tool_host_kernel_id: &'static str,
    pub tool_host_public_key_hex: String,
    pub receipt_id: String,
    pub receipt_tool_name: String,
    pub dual_signed_schema: String,
    pub dsse_payload_type: String,
    pub dsse_signature_count: usize,
    pub dsse_payload: String,
    pub joint_verdict: String,
    pub resolved_lease_id: String,
    pub resolved_lease_issuer: String,
    pub resolved_lease_expires_at_unix_ms: u64,
    pub resolved_receipt_id: String,
    pub resolved_receipt_tool_name: String,
}

pub fn run_demo() -> Result<BilateralDemoSummary, Box<dyn std::error::Error>> {
    let kp_origin = Keypair::generate();
    let kp_tool_host = Keypair::generate();
    let receipt = sample_receipt(&kp_tool_host)?;

    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());

    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: LEASE_ID.to_string(),
        issuer: ORIGIN_KERNEL_ID.to_string(),
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        scope_digest_hex: None,
    });

    let governance_store = InMemoryGovernanceReceiptStore::new();
    let revocation_oracle = DemoAllowAllRevocationOracle;

    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: ORIGIN_KERNEL_ID.to_string(),
        public_key: kp_origin.public_key(),
        ladder_manifest_ref: None,
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: TOOL_HOST_KERNEL_ID.to_string(),
        public_key: kp_tool_host.public_key(),
        ladder_manifest_ref: None,
    });

    let extensions = BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: LEASE_ID.to_string(),
            issuer: ORIGIN_KERNEL_ID.to_string(),
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            scope_digest: None,
        }),
        policy_evaluation_summary: Some(PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy.org-a/file-read".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy.org-b/host".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        }),
        governance_receipt_ref: None,
        consistency_anchor: None,
        consistency_model: None,
        cross_org_visibility: None,
        treaty_binding_ref: None,
    };

    let cosigner = InProcessCoSigner::new(
        ORIGIN_KERNEL_ID,
        kp_origin.clone(),
        kp_tool_host.public_key(),
    );

    let request = LocalBilateralInvocationFixtureRequest {
        origin_kernel_id: ORIGIN_KERNEL_ID,
        origin_keypair: &kp_origin,
        tool_host_kernel_id: TOOL_HOST_KERNEL_ID,
        tool_host_keypair: &kp_tool_host,
        receipt: receipt.clone(),
        tool_name: &receipt.body().tool_name,
        timestamp_unix_ms: NOW_UNIX_MS,
        predicate_extensions: extensions,
        cosigner: &cosigner as &dyn BilateralCoSigningProtocol,
    };

    let mut action_classes = BTreeMap::new();
    action_classes.insert(receipt.body().tool_name.clone(), ActionClassKind::Routine);

    let config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: NOW_UNIX_MS,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    };

    let outcome = execute_local_bilateral_invocation_fixture(request, &config)?;

    Ok(BilateralDemoSummary {
        origin_kernel_id: ORIGIN_KERNEL_ID,
        origin_public_key_hex: kp_origin.public_key().to_hex(),
        tool_host_kernel_id: TOOL_HOST_KERNEL_ID,
        tool_host_public_key_hex: kp_tool_host.public_key().to_hex(),
        receipt_id: receipt.id.clone(),
        receipt_tool_name: receipt.body().tool_name.clone(),
        dual_signed_schema: outcome.artifacts.dual_signed_receipt.schema,
        dsse_payload_type: outcome.artifacts.dsse_envelope.payload_type,
        dsse_signature_count: outcome.artifacts.dsse_envelope.signatures.len(),
        dsse_payload: outcome.artifacts.dsse_envelope.payload,
        joint_verdict: outcome.verified.joint_verdict,
        resolved_lease_id: outcome.verified.resolved_lease.lease_id,
        resolved_lease_issuer: outcome.verified.resolved_lease.issuer,
        resolved_lease_expires_at_unix_ms: outcome.verified.resolved_lease.expires_at_unix_ms,
        resolved_receipt_id: outcome.verified.resolved_receipt.id.clone(),
        resolved_receipt_tool_name: outcome.verified.resolved_receipt.body().tool_name.clone(),
    })
}

fn sample_receipt(kp: &Keypair) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-c2-demo".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-c2-demo".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: TOOL_NAME.to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path":"/etc/hosts"}))
            .map_err(|e| -> Box<dyn std::error::Error> { format!("toolcall: {e}").into() })?,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![ActorRef {
            actor_id: "agent:org-a/bilateral-demo".to_string(),
            actor_kind: Some("agent".to_string()),
        }],
        content_hash: sha256_hex(b"{}"),
        policy_hash: "policy:demo".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
    };
    ChioReceipt::sign(body, kp)
        .map_err(|e| -> Box<dyn std::error::Error> { format!("receipt sign: {e:?}").into() })
}

pub fn display_prefix(value: &str, bytes: usize) -> &str {
    if value.len() <= bytes {
        return value;
    }
    let mut end = bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_federation::PAYLOAD_TYPE_IN_TOTO;

    #[test]
    fn run_demo_preserves_bilateral_fixture_invariants() {
        let summary = run_demo().unwrap_or_else(|error| panic!("demo should run: {error}"));

        assert_eq!(summary.origin_kernel_id, ORIGIN_KERNEL_ID);
        assert_eq!(summary.tool_host_kernel_id, TOOL_HOST_KERNEL_ID);
        assert!(!summary.receipt_id.is_empty());
        assert_eq!(summary.receipt_tool_name, TOOL_NAME);
        assert_eq!(summary.dsse_payload_type, PAYLOAD_TYPE_IN_TOTO);
        assert_eq!(summary.dsse_signature_count, 2);
        assert!(!summary.dsse_payload.is_empty());
        assert_eq!(summary.joint_verdict, "allow");
        assert_eq!(summary.resolved_lease_id, LEASE_ID);
        assert_eq!(summary.resolved_lease_issuer, ORIGIN_KERNEL_ID);
        assert_eq!(summary.resolved_receipt_id, summary.receipt_id);
        assert_eq!(
            summary.resolved_receipt_tool_name,
            summary.receipt_tool_name
        );
    }

    #[test]
    fn display_prefix_returns_short_values_without_panicking() {
        assert_eq!(display_prefix("short", 40), "short");
    }

    #[test]
    fn display_prefix_preserves_utf8_boundaries() {
        assert_eq!(display_prefix("abcdé", 5), "abcd");
    }
}
