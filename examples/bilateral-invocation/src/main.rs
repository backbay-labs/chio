//! Runs the local bilateral fixture path end-to-end:
//!
//! 1. Construct two kernel keypairs (the two `did:chio` identities).
//! 2. Build a `ChioReceipt` for the invocation Org A's agent made
//!    against a tool hosted by Org B.
//! 3. Drive `chio_federation::execute_local_bilateral_invocation_fixture`, which:
//!    - Drives the legacy `co_sign_with_origin` hop to produce the
//!      legacy `DualSignedReceipt`.
//!    - Calls `sign_dsse_envelope_full` to produce the DSSE
//!      signature-slice envelope, with the predicate extensions
//!      (`capability_lease_ref`, `policy_evaluation_summary`) the
//!      partial local verifier requires.
//!    - Runs `verify_bilateral_cosign_invocation` (the partial
//!      local verifier covering a subset of §7) against the
//!      freshly-signed envelope.
//! 4. Print the resolved verdict, the lease id, and the wire envelope
//!    bytes for inspection.
//!
//! Run with `cargo run -p bilateral-invocation`. Expected exit
//! code: `0` on success, non-zero on any verifier rejection.

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- 1. Provision two kernel handles ------------------------------
    let kp_origin = Keypair::generate();
    let kp_tool_host = Keypair::generate();
    let origin_kernel_id = "did:chio:org-a";
    let tool_host_kernel_id = "did:chio:org-b";

    println!("== bilateral cosigned invocation demo ==");
    println!(
        "  origin kernel:   {} (passport pubkey hex prefix={}…)",
        origin_kernel_id,
        &kp_origin.public_key().to_hex()[..16]
    );
    println!(
        "  tool-host kernel: {} (passport pubkey hex prefix={}…)",
        tool_host_kernel_id,
        &kp_tool_host.public_key().to_hex()[..16]
    );

    // ---- 2. Build a receipt for the invocation ------------------------
    let receipt = sample_receipt(&kp_tool_host)?;
    println!(
        "  receipt id={}, tool_name={}, decision=Allow",
        receipt.id,
        receipt.body().tool_name
    );

    // ---- 3. Stand up the verifier-side trust roots --------------------
    let now_unix_ms: u64 = 1_734_000_000_000;
    let lease_id = "lease-c2-demo";

    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());

    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: lease_id.to_string(),
        issuer: origin_kernel_id.to_string(),
        expires_at_unix_ms: now_unix_ms + 60_000,
        scope_digest_hex: None,
    });

    let governance_store = InMemoryGovernanceReceiptStore::new();
    let revocation_oracle = DemoAllowAllRevocationOracle;

    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: origin_kernel_id.to_string(),
        public_key: kp_origin.public_key(),
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: tool_host_kernel_id.to_string(),
        public_key: kp_tool_host.public_key(),
    });

    // ---- 4. Bind predicate extensions ---------------------------------
    let extensions = BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: lease_id.to_string(),
            issuer: origin_kernel_id.to_string(),
            expires_at_unix_ms: now_unix_ms + 60_000,
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
    };

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        kp_origin.clone(),
        kp_tool_host.public_key(),
    );

    // ---- 6. Drive the kernel-boundary helper -------------------------
    let request = LocalBilateralInvocationFixtureRequest {
        origin_kernel_id,
        origin_keypair: &kp_origin,
        tool_host_kernel_id,
        tool_host_keypair: &kp_tool_host,
        receipt: receipt.clone(),
        tool_name: &receipt.body().tool_name,
        timestamp_unix_ms: now_unix_ms,
        predicate_extensions: extensions,
        cosigner: &cosigner as &dyn BilateralCoSigningProtocol,
    };

    // Register the tool's action class. With the strict
    // `UnknownActionClassPolicy::Reject` default, an unknown
    // `tool_name` would be rejected at step 15 with
    // `governance.unknown_action_class`.
    let mut action_classes = BTreeMap::new();
    action_classes.insert(receipt.body().tool_name.clone(), ActionClassKind::Routine);

    let config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    };

    let outcome = execute_local_bilateral_invocation_fixture(request, &config)?;

    // ---- 7. Print results --------------------------------------------
    println!();
    println!("== Bilateral co-sign succeeded ==");
    println!(
        "  legacy DualSignedReceipt schema: {}",
        outcome.artifacts.dual_signed_receipt.schema
    );
    println!(
        "  DSSE signature-slice envelope: payloadType={}, signatures.len={}",
        outcome.artifacts.dsse_envelope.payload_type,
        outcome.artifacts.dsse_envelope.signatures.len()
    );
    println!(
        "  envelope payload (base64, prefix): {}…",
        &outcome.artifacts.dsse_envelope.payload[..40]
    );

    println!();
    println!("== Partial local verifier accepted envelope ==");
    println!("  joint_verdict: {}", outcome.verified.joint_verdict);
    println!(
        "  resolved lease: id={} issuer={} expires_at_unix_ms={}",
        outcome.verified.resolved_lease.lease_id,
        outcome.verified.resolved_lease.issuer,
        outcome.verified.resolved_lease.expires_at_unix_ms
    );
    println!(
        "  resolved receipt: id={} tool_name={}",
        outcome.verified.resolved_receipt.id,
        outcome.verified.resolved_receipt.body().tool_name
    );

    Ok(())
}

fn sample_receipt(kp: &Keypair) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-c2-demo".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-c2-demo".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path":"/etc/hosts"}))
            .map_err(|e| -> Box<dyn std::error::Error> { format!("toolcall: {e}").into() })?,
        decision: Decision::Allow,
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
