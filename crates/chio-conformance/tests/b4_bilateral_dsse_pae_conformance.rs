//! Spec MUST: full DSSE PAE conformance for bilateral invocation evidence.
//!
//! Reverts-to-fail proof: the positive test exercises the production
//! cosigner-routed DSSE PAE path (`sign_dsse_envelope_with_cosigner`), not the
//! local helper that holds both private keys. The negative test proves a bare
//! signature-slice artifact is rejected by the strict bilateral invocation
//! verifier when required predicate fields are absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_federation::demo::DemoAllowAllRevocationOracle;
use chio_federation::{
    sign_dsse_envelope, sign_dsse_envelope_with_cosigner, verify_bilateral_cosign_invocation,
    verify_dsse_envelope, ActionClassKind, BilateralPredicateExtensions, CapabilityLeaseRef,
    GovernanceReceiptStore, InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry,
    InMemoryReceiptStore, InProcessCoSigner, PeerPinSet, PinnedEpoch, PinnedPeer,
    PolicyEvaluationSummary, PolicyVerdict, ReceiptStore, ResolvedLease, RevocationOracle,
    UnknownActionClassPolicy, VerifierConfig,
};

const ORG_A: &str = "did:chio:org-a";
const ORG_B: &str = "did:chio:org-b";
const TOOL: &str = "file_read";
const LEASE_ID: &str = "lease-b4-pae";
const NOW_MS: u64 = 1_734_000_000_000;

fn sample_receipt(kp_b: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-b4-pae".to_string(),
            timestamp: NOW_MS / 1000,
            capability_id: "cap-b4-pae".to_string(),
            tool_server: "srv-orgb".to_string(),
            tool_name: TOOL.to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/kb/doc.txt",
            }))
            .unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"{}"),
            policy_hash: "policy-b4".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp_b.public_key(),
        },
        kp_b,
    )
    .unwrap()
}

fn full_extensions() -> BilateralPredicateExtensions {
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: LEASE_ID.to_string(),
            issuer: ORG_A.to_string(),
            expires_at_unix_ms: NOW_MS + 60_000,
            scope_digest: None,
        }),
        policy_evaluation_summary: Some(PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy.org-a".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy.org-b".to_string(),
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
    }
}

struct StrictFixture {
    kp_a: Keypair,
    kp_b: Keypair,
    receipt: ChioReceipt,
    receipt_store: InMemoryReceiptStore,
    lease_registry: InMemoryLeaseRegistry,
    governance_store: InMemoryGovernanceReceiptStore,
    revocation_oracle: DemoAllowAllRevocationOracle,
    peer_pin_set: PeerPinSet,
    cosigner: InProcessCoSigner,
}

fn strict_fixture() -> StrictFixture {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());

    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: LEASE_ID.to_string(),
        issuer: ORG_A.to_string(),
        expires_at_unix_ms: NOW_MS + 60_000,
        scope_digest_hex: None,
    });

    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: ORG_A.to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: ORG_B.to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });

    let cosigner = InProcessCoSigner::new(ORG_A, kp_a.clone(), kp_b.public_key());

    StrictFixture {
        kp_a,
        kp_b,
        receipt,
        receipt_store,
        lease_registry,
        governance_store: InMemoryGovernanceReceiptStore::new(),
        revocation_oracle: DemoAllowAllRevocationOracle,
        peer_pin_set,
        cosigner,
    }
}

fn verifier_config<'a>(
    fixture: &'a StrictFixture,
    receipt_store: &'a dyn ReceiptStore,
    governance_store: &'a dyn GovernanceReceiptStore,
    revocation_oracle: &'a dyn RevocationOracle,
) -> VerifierConfig<'a> {
    let mut action_classes = BTreeMap::new();
    action_classes.insert(TOOL.to_string(), ActionClassKind::Routine);
    VerifierConfig {
        peer_pin_set: &fixture.peer_pin_set,
        receipt_store,
        lease_registry: &fixture.lease_registry,
        governance_receipt_store: governance_store,
        revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: NOW_MS,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    }
}

#[test]
fn full_dsse_pae_cosigner_path_verifies_under_strict_profile() {
    let fixture = strict_fixture();
    let envelope = sign_dsse_envelope_with_cosigner(
        &fixture.receipt,
        &fixture.kp_a.public_key(),
        &fixture.kp_b,
        ORG_A,
        ORG_B,
        TOOL,
        NOW_MS,
        full_extensions(),
        &fixture.cosigner,
    )
    .expect("cosigner-routed DSSE PAE envelope must sign");

    verify_dsse_envelope(
        &envelope,
        &fixture.kp_a.public_key(),
        &fixture.kp_b.public_key(),
    )
    .expect("signature-slice verification must pass");
    verify_bilateral_cosign_invocation(
        &envelope,
        &verifier_config(
            &fixture,
            &fixture.receipt_store,
            &fixture.governance_store,
            &fixture.revocation_oracle,
        ),
    )
    .expect("strict bilateral invocation verifier must accept full predicate fields");
}

#[test]
fn bare_signature_slice_is_rejected_by_strict_profile() {
    let fixture = strict_fixture();
    let envelope = sign_dsse_envelope(
        &fixture.receipt,
        &fixture.kp_a,
        &fixture.kp_b,
        ORG_A,
        ORG_B,
        TOOL,
        NOW_MS,
    )
    .expect("bare signature-slice envelope still signs");

    let err = verify_bilateral_cosign_invocation(
        &envelope,
        &verifier_config(
            &fixture,
            &fixture.receipt_store,
            &fixture.governance_store,
            &fixture.revocation_oracle,
        ),
    )
    .expect_err("strict profile must reject missing lease and policy fields");
    assert!(
        matches!(
            err.code(),
            "capability.lease_expired_or_unknown" | "policy.verdict_disagreement"
        ),
        "unexpected strict-profile rejection code: {}",
        err.code()
    );
}
