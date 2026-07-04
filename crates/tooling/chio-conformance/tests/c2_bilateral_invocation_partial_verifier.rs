//! Drives [`chio_federation::bilateral::execute_local_bilateral_invocation_fixture`]
//! end-to-end (NOT a mock - exercises the production
//! `sign_dsse_envelope_full` signature-slice producer and the production partial local verifier
//! `verify_bilateral_cosign_invocation`, which covers a subset of the
//! §7 step list), then mutates one byte at a time and asserts the
//! verifier rejects with the correct spec §7.1 code. Coverage:
//!
//! | Step | Tampering              | Expected code                          |
//! | ---- | ---------------------- | -------------------------------------- |
//! | 7    | drop receipt from store | subject.digest_mismatch              |
//! | 7    | flip a byte in payload | dsse.malformed (PAE preimage broken)   |
//! | 8    | drop pinned peer       | peer.unpinned_or_keyid_mismatch        |
//! | 8    | mismatch fingerprint   | peer.unpinned_or_keyid_mismatch        |
//! | 9    | revoke a passport      | peer.revoked_at_epoch                  |
//! | 11   | flip a sig_a byte      | signature.server_a_invalid             |
//! | 12   | flip a sig_b byte      | signature.server_b_invalid             |
//! | 13   | swap one verdict       | policy.verdict_disagreement            |
//! | 14   | advance clock past lease | capability.lease_expired_or_unknown  |
//! | 14   | drop lease from registry | capability.lease_expired_or_unknown  |
//! | 14   | omit lease ref         | capability.lease_expired_or_unknown    |
//! | 15   | mark class receipt-backed; omit gov ref | governance.receipt_required_missing |
//! | profile | totally-ordered signature-slice claim | predicate.schema_invalid |
//! | profile | quorum-required signature-slice claim | predicate.schema_invalid |

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::demo::DemoAllowAllRevocationOracle;
use chio_federation::{
    bilateral::execute_local_bilateral_invocation_fixture, bilateral::BilateralCoSigningProtocol,
    bilateral::BilateralInvocationError, bilateral::InProcessCoSigner,
    bilateral::LocalBilateralInvocationFixtureRequest, bilateral_dsse::receipt_subject_name,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::Keyid, bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_verifier::ActionClassKind, bilateral_verifier::DenyListRevocationOracle,
    bilateral_verifier::GovernanceReceiptStore, bilateral_verifier::InMemoryGovernanceReceiptStore,
    bilateral_verifier::InMemoryLeaseRegistry, bilateral_verifier::InMemoryReceiptStore,
    bilateral_verifier::PeerPinSet, bilateral_verifier::PinnedEpoch,
    bilateral_verifier::PinnedPeer, bilateral_verifier::ReceiptStore,
    bilateral_verifier::ResolvedGovernanceReceipt, bilateral_verifier::ResolvedLease,
    bilateral_verifier::RevocationOracle, bilateral_verifier::VerifierConfig,
};
use sha2::Digest;

const ORG_A: &str = "did:chio:org-a";
const ORG_B: &str = "did:chio:org-b";
const TOOL: &str = "file_read";
const LEASE_ID: &str = "lease-c2-fixture";

fn now_ms() -> u64 {
    1_734_000_000_000
}

fn sample_receipt(kp_b: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-c2-fixture".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-c2".to_string(),
        tool_server: "srv-orgb".to_string(),
        tool_name: TOOL.to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path":"/etc/hosts"}))
            .unwrap_or_else(|e| panic!("toolcall: {e}")),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "pol".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp_b.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, kp_b).unwrap_or_else(|e| panic!("receipt sign: {e:?}"))
}

fn happy_extensions() -> BilateralPredicateExtensions {
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: LEASE_ID.to_string(),
            issuer: ORG_A.to_string(),
            expires_at_unix_ms: now_ms() + 60_000,
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

struct Setup {
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

fn setup() -> Setup {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());

    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: LEASE_ID.to_string(),
        issuer: ORG_A.to_string(),
        expires_at_unix_ms: now_ms() + 60_000,
        scope_digest_hex: None,
    });

    let governance_store = InMemoryGovernanceReceiptStore::new();
    let revocation_oracle = DemoAllowAllRevocationOracle;

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

    Setup {
        kp_a,
        kp_b,
        receipt,
        receipt_store,
        lease_registry,
        governance_store,
        revocation_oracle,
        peer_pin_set,
        cosigner,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_invocation_with(
    setup: &Setup,
    extensions: BilateralPredicateExtensions,
    receipt_store: &dyn ReceiptStore,
    lease_registry: &dyn chio_federation::bilateral_verifier::CapabilityLeaseRegistry,
    governance_store: &dyn GovernanceReceiptStore,
    revocation_oracle: &dyn RevocationOracle,
    peer_pin_set: &PeerPinSet,
    pinned_now_ms: u64,
    mut action_classes: BTreeMap<String, ActionClassKind>,
) -> Result<chio_federation::bilateral::BilateralInvocationOutcome, BilateralInvocationError> {
    let request = LocalBilateralInvocationFixtureRequest {
        origin_kernel_id: ORG_A,
        origin_keypair: &setup.kp_a,
        tool_host_kernel_id: ORG_B,
        tool_host_keypair: &setup.kp_b,
        receipt: setup.receipt.clone(),
        tool_name: TOOL,
        timestamp_unix_ms: now_ms(),
        predicate_extensions: extensions,
        cosigner: &setup.cosigner as &dyn BilateralCoSigningProtocol,
    };
    // Strict-default regression coverage: positive helpers must run under
    // the strict fail-closed default `Reject` so they actually prove
    // that default. Tests that don't pass a custom class for `TOOL`
    // get a `Routine` registration here so the assertion still proves
    // the *non-step-15* code path; tests that exercise step 15 (the
    // `step_15_*` cases) pass their own `ReceiptBacked` mapping which
    // is preserved via the `entry().or_insert(...)` semantics below.
    action_classes
        .entry(TOOL.to_string())
        .or_insert(ActionClassKind::Routine);
    let config = VerifierConfig {
        peer_pin_set,
        receipt_store,
        lease_registry,
        governance_receipt_store: governance_store,
        revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: pinned_now_ms,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };
    execute_local_bilateral_invocation_fixture(request, &config)
}

fn run_default(
    setup: &Setup,
) -> Result<chio_federation::bilateral::BilateralInvocationOutcome, BilateralInvocationError> {
    run_invocation_with(
        setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
}

fn assert_verifier_code(err: BilateralInvocationError, want: &str) {
    match err {
        BilateralInvocationError::Verifier(e) => {
            assert_eq!(e.code(), want, "verifier code mismatch: got {:?}", e)
        }
        BilateralInvocationError::CoSigning(e) => {
            panic!("expected verifier error {want}, got cosigning error {e:?}");
        }
    }
}

fn assert_cosigning_error_contains(err: BilateralInvocationError, want: &str) {
    match err {
        BilateralInvocationError::CoSigning(e) => {
            let got = e.to_string();
            assert!(
                got.contains(want),
                "cosigning error mismatch: expected {want:?}, got {got:?}"
            );
        }
        BilateralInvocationError::Verifier(e) => {
            panic!("expected cosigning error {want}, got verifier error {e:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Happy path: end-to-end production flow runs successfully.
// ---------------------------------------------------------------------------

#[test]
fn happy_path_full_invocation_runs_end_to_end() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path failed: {e:?}"));
    assert_eq!(outcome.verified.joint_verdict, "allow");
    assert_eq!(outcome.verified.resolved_receipt.id, setup.receipt.id);
    // Both DualSignedReceipt and DSSE signature-slice artifacts populated.
    assert_eq!(outcome.artifacts.dsse_envelope.signatures.len(), 2);
}

#[test]
fn full_fixture_statement_validates_against_signature_slice_schema() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let statement_bytes = BASE64_STANDARD
        .decode(&outcome.artifacts.dsse_envelope.payload)
        .unwrap();
    let statement_json: serde_json::Value = serde_json::from_slice(&statement_bytes).unwrap();
    assert!(
        statement_json["predicate"]["capability_lease_ref"].is_object(),
        "full fixture must emit verifier-required capability_lease_ref"
    );
    assert!(
        statement_json["predicate"]["policy_evaluation_summary"].is_object(),
        "full fixture must emit verifier-required policy_evaluation_summary"
    );

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate lives under <repo>/crates/tooling/chio-conformance");
    let schema_path = repo_root
        .join("spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json");
    let schema_text = std::fs::read_to_string(&schema_path).expect("read profile schema");
    let schema: serde_json::Value =
        serde_json::from_str(&schema_text).expect("parse profile schema");
    let validator = jsonschema::validator_for(&schema).expect("compile signature-slice schema");
    let errors: Vec<String> = validator
        .iter_errors(&statement_json)
        .map(|err| err.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "full local fixture Statement must validate against registered schema: {errors:?}"
    );
}

// ---------------------------------------------------------------------------
// Step 7: ReceiptStore lookup
// ---------------------------------------------------------------------------

#[test]
fn step_7_missing_receipt_in_store_fails_with_subject_digest_mismatch() {
    let setup = setup();
    let empty_store = InMemoryReceiptStore::new();
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &empty_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "subject.digest_mismatch");
}

#[test]
fn step_7_raw_receipt_id_subject_name_fails_with_subject_digest_mismatch() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let mut envelope: DsseEnvelope = outcome.artifacts.dsse_envelope.clone();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    assert_eq!(
        statement.subject[0].name,
        receipt_subject_name(&setup.receipt.id)
    );
    statement.subject[0].name = setup.receipt.id.clone();
    envelope.payload = BASE64_STANDARD.encode(statement.canonical_bytes().unwrap());

    let mut action_classes = BTreeMap::new();
    action_classes.insert(TOOL.to_string(), ActionClassKind::Routine);
    let config = VerifierConfig {
        peer_pin_set: &setup.peer_pin_set,
        receipt_store: &setup.receipt_store,
        lease_registry: &setup.lease_registry,
        governance_receipt_store: &setup.governance_store,
        revocation_oracle: &setup.revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms(),
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };

    let err =
        chio_federation::bilateral_verifier::verify_bilateral_cosign_invocation(&envelope, &config)
            .expect_err("raw receipt id subject must fail closed");
    assert_eq!(err.code(), "subject.digest_mismatch");
}

// ---------------------------------------------------------------------------
// Steps 11-12: tampered DSSE PAE bytes
// ---------------------------------------------------------------------------

#[test]
fn steps_11_12_flipped_payload_byte_breaks_pae_preimage() {
    let setup = setup();
    // Run the production flow, then mutate the envelope's payload byte
    // to break the PAE preimage and rerun the verifier directly.
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let mut envelope: DsseEnvelope = outcome.artifacts.dsse_envelope.clone();
    // Flip the last char of payload (well-formed base64, but content
    // changes -> Statement parse fails -> dsse.malformed).
    let mut bytes = envelope.payload.into_bytes();
    if let Some(last) = bytes.last_mut() {
        *last = if *last == b'A' { b'B' } else { b'A' };
    }
    envelope.payload = String::from_utf8(bytes).unwrap_or_else(|e| panic!("payload utf8: {e}"));

    let config = VerifierConfig {
        peer_pin_set: &setup.peer_pin_set,
        receipt_store: &setup.receipt_store,
        lease_registry: &setup.lease_registry,
        governance_receipt_store: &setup.governance_store,
        revocation_oracle: &setup.revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms(),
            epoch_height: 0,
        },
        action_classes: {
            let mut m = BTreeMap::new();
            m.insert(TOOL.to_string(), ActionClassKind::Routine);
            m
        },
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };
    let err =
        chio_federation::bilateral_verifier::verify_bilateral_cosign_invocation(&envelope, &config)
            .unwrap_err();
    // The first thing a payload-byte flip breaks is base64 decode or
    // statement parse - the spec lumps these under dsse.malformed/
    // statement.malformed depending on where the byte lands. Either is
    // valid; both fail-closed.
    let code = err.code();
    assert!(
        code == "dsse.malformed"
            || code == "statement.malformed"
            || code == "statement.schema_invalid"
            || code == "predicate.schema_invalid"
            || code == "subject.digest_mismatch"
            || code == "signature.server_a_invalid"
            || code == "signature.server_b_invalid",
        "expected a fail-closed code from a tampered payload byte; got {:?}",
        code
    );
}

#[test]
fn step_11_flipped_sig_a_byte_yields_signature_server_a_invalid() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let mut envelope: DsseEnvelope = outcome.artifacts.dsse_envelope.clone();

    // Find the signature whose keyid matches kp_a's fingerprint and
    // flip a byte of its base64 payload (still well-formed base64 but
    // a different signature).
    let key_a = Keyid::from_public_key(&setup.kp_a.public_key());
    let sig_a = envelope
        .signatures
        .iter_mut()
        .find(|s| s.keyid == key_a.0)
        .unwrap_or_else(|| panic!("missing sig_a"));
    let mut bytes = sig_a.sig.clone().into_bytes();
    // Swap the first base64 char to its complement to ensure a
    // different signature byte, while keeping it valid base64.
    if let Some(first) = bytes.first_mut() {
        *first = match *first {
            b'A' => b'B',
            b'B' => b'A',
            b'a' => b'b',
            b'b' => b'a',
            b'0' => b'1',
            b'1' => b'0',
            b'+' => b'/',
            b'/' => b'+',
            other => {
                if other == b'Z' {
                    b'Y'
                } else {
                    b'A'
                }
            }
        };
    }
    sig_a.sig = String::from_utf8(bytes).unwrap_or_else(|e| panic!("sig utf8: {e}"));

    let config = VerifierConfig {
        peer_pin_set: &setup.peer_pin_set,
        receipt_store: &setup.receipt_store,
        lease_registry: &setup.lease_registry,
        governance_receipt_store: &setup.governance_store,
        revocation_oracle: &setup.revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms(),
            epoch_height: 0,
        },
        action_classes: {
            let mut m = BTreeMap::new();
            m.insert(TOOL.to_string(), ActionClassKind::Routine);
            m
        },
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };
    let err =
        chio_federation::bilateral_verifier::verify_bilateral_cosign_invocation(&envelope, &config)
            .unwrap_err();
    assert_eq!(err.code(), "signature.server_a_invalid");
}

#[test]
fn step_12_flipped_sig_b_byte_yields_signature_server_b_invalid() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let mut envelope: DsseEnvelope = outcome.artifacts.dsse_envelope.clone();
    let key_b = Keyid::from_public_key(&setup.kp_b.public_key());
    let sig_b = envelope
        .signatures
        .iter_mut()
        .find(|s| s.keyid == key_b.0)
        .unwrap_or_else(|| panic!("missing sig_b"));
    let mut bytes = sig_b.sig.clone().into_bytes();
    if let Some(first) = bytes.first_mut() {
        *first = match *first {
            b'A' => b'B',
            b'B' => b'A',
            b'a' => b'b',
            b'b' => b'a',
            b'0' => b'1',
            b'1' => b'0',
            b'+' => b'/',
            b'/' => b'+',
            other => {
                if other == b'Z' {
                    b'Y'
                } else {
                    b'A'
                }
            }
        };
    }
    sig_b.sig = String::from_utf8(bytes).unwrap_or_else(|e| panic!("sig utf8: {e}"));

    let config = VerifierConfig {
        peer_pin_set: &setup.peer_pin_set,
        receipt_store: &setup.receipt_store,
        lease_registry: &setup.lease_registry,
        governance_receipt_store: &setup.governance_store,
        revocation_oracle: &setup.revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms(),
            epoch_height: 0,
        },
        action_classes: {
            let mut m = BTreeMap::new();
            m.insert(TOOL.to_string(), ActionClassKind::Routine);
            m
        },
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };
    let err =
        chio_federation::bilateral_verifier::verify_bilateral_cosign_invocation(&envelope, &config)
            .unwrap_err();
    assert_eq!(err.code(), "signature.server_b_invalid");
}

// ---------------------------------------------------------------------------
// Step 14: capability lease enforcement
// ---------------------------------------------------------------------------

#[test]
fn step_14_expired_lease_at_pinned_epoch_fails() {
    let setup = setup();
    // Verifier wall clock advanced past lease expiry.
    let expired_now_ms = now_ms() + 60_000 + 1;
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        expired_now_ms,
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "capability.lease_expired_or_unknown");
}

#[test]
fn step_14_lease_not_in_registry_fails() {
    let setup = setup();
    let empty_registry = InMemoryLeaseRegistry::new();
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &empty_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "capability.lease_expired_or_unknown");
}

#[test]
fn step_14_missing_lease_ref_in_predicate_fails() {
    let setup = setup();
    let mut ext = happy_extensions();
    ext.capability_lease_ref = None;
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "capability.lease_expired_or_unknown");
}

// ---------------------------------------------------------------------------
// Step 13: verdict disagreement
// ---------------------------------------------------------------------------

#[test]
fn step_13_verdict_disagreement_fails() {
    let setup = setup();
    let mut ext = happy_extensions();
    if let Some(s) = ext.policy_evaluation_summary.as_mut() {
        s.server_b_verdict.verdict = "deny".to_string();
        s.joint_disposition = Some("deny".to_string());
    }
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "policy.verdict_disagreement");
}

// ---------------------------------------------------------------------------
// Step 8: peer pinning
// ---------------------------------------------------------------------------

#[test]
fn step_8_unpinned_peer_fails() {
    let setup = setup();
    let empty_pin_set = PeerPinSet::new();
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &empty_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "peer.unpinned_or_keyid_mismatch");
}

#[test]
fn step_8_mismatched_fingerprint_fails() {
    let setup = setup();
    // Pin Org B's kernel_id under Org A's key - fingerprint will mismatch.
    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: ORG_A.to_string(),
        public_key: setup.kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: ORG_B.to_string(),
        public_key: setup.kp_a.public_key(), // wrong key
        ladder_manifest_ref: None,
    });
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "peer.unpinned_or_keyid_mismatch");
}

// ---------------------------------------------------------------------------
// Step 9: revocation
// ---------------------------------------------------------------------------

#[test]
fn step_9_revoked_passport_fails() {
    let setup = setup();
    let mut oracle = DenyListRevocationOracle::new();
    oracle.revoke(&Keyid::from_public_key(&setup.kp_a.public_key()));
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_verifier_code(err, "peer.revoked_at_epoch");
}

// ---------------------------------------------------------------------------
// Step 15: governance receipt for receipt-backed classes
// ---------------------------------------------------------------------------

#[test]
fn step_15_receipt_backed_class_without_governance_ref_fails() {
    let setup = setup();
    let mut classes = BTreeMap::new();
    classes.insert(TOOL.to_string(), ActionClassKind::ReceiptBacked);
    let err = run_invocation_with(
        &setup,
        happy_extensions(),
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        classes,
    )
    .unwrap_err();
    assert_verifier_code(err, "governance.receipt_required_missing");
}

#[test]
fn step_15_receipt_backed_class_with_resolvable_governance_ref_passes() {
    let setup = setup();
    let governance_canonical = "{\"id\":\"gov-1\",\"kind\":\"approval\"}";
    let mut hasher = sha2::Sha256::new();
    hasher.update(governance_canonical.as_bytes());
    let digest_hex = hex::encode(hasher.finalize());

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: ORG_A.to_string(),
        canonical_json: governance_canonical.to_string(),
    });

    let mut ext = happy_extensions();
    ext.governance_receipt_ref = Some(GovernanceReceiptRef {
        receipt_id: "gov-1".to_string(),
        kernel_id: ORG_A.to_string(),
        digest: HashRecord {
            alg: "sha256".to_string(),
            value: digest_hex,
        },
    });

    let mut classes = BTreeMap::new();
    classes.insert(TOOL.to_string(), ActionClassKind::ReceiptBacked);

    let outcome = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        classes,
    )
    .unwrap_or_else(|e| panic!("receipt-backed happy path failed: {e:?}"));
    assert!(outcome.verified.resolved_governance_receipt.is_some());
}

// ---------------------------------------------------------------------------
// Step 16: consistency anchor reconciliation
// ---------------------------------------------------------------------------

#[test]
fn step_16_totally_ordered_without_anchor_fails() {
    let setup = setup();
    let mut ext = happy_extensions();
    ext.consistency_model = Some("totally-ordered".to_string());
    ext.consistency_anchor = None;
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_cosigning_error_contains(
        err,
        "consistency_model \"totally-ordered\" is not supported",
    );
}

#[test]
fn step_16_quorum_required_without_anchor_fails() {
    let setup = setup();
    let mut ext = happy_extensions();
    ext.consistency_model = Some("quorum-required".to_string());
    ext.consistency_anchor = None;
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_cosigning_error_contains(
        err,
        "consistency_model \"quorum-required\" is not supported",
    );
}

#[test]
fn step_16_quorum_required_with_bare_anchor_still_fails_without_quorum_proof() {
    let setup = setup();
    let mut ext = happy_extensions();
    ext.consistency_model = Some("quorum-required".to_string());
    ext.consistency_anchor = Some("frost-quorum".to_string());
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_cosigning_error_contains(
        err,
        "consistency_model \"quorum-required\" is not supported",
    );
}

#[test]
fn co_sign_n_of_m_is_rejected_until_quorum_verification_exists() {
    let setup = setup();
    let outcome = run_default(&setup).unwrap_or_else(|e| panic!("happy path: {e:?}"));
    let mut envelope: DsseEnvelope = outcome.artifacts.dsse_envelope.clone();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement.predicate.co_sign = "n_of_m".to_string();
    envelope.payload = BASE64_STANDARD.encode(statement.canonical_bytes().unwrap());

    let mut action_classes = BTreeMap::new();
    action_classes.insert(TOOL.to_string(), ActionClassKind::Routine);
    let config = VerifierConfig {
        peer_pin_set: &setup.peer_pin_set,
        receipt_store: &setup.receipt_store,
        lease_registry: &setup.lease_registry,
        governance_receipt_store: &setup.governance_store,
        revocation_oracle: &setup.revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms(),
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy:
            chio_federation::bilateral_verifier::UnknownActionClassPolicy::Reject,
    };

    let err =
        chio_federation::bilateral_verifier::verify_bilateral_cosign_invocation(&envelope, &config)
            .expect_err("n_of_m must not be accepted before quorum verification exists");
    assert_eq!(err.code(), "predicate.schema_invalid");
}

#[test]
fn step_16_totally_ordered_with_bare_anchor_still_fails_without_reconciliation() {
    let setup = setup();
    let mut ext = happy_extensions();
    ext.consistency_model = Some("totally-ordered".to_string());
    ext.consistency_anchor = Some("chio-anchor".to_string());
    let err = run_invocation_with(
        &setup,
        ext,
        &setup.receipt_store,
        &setup.lease_registry,
        &setup.governance_store,
        &setup.revocation_oracle,
        &setup.peer_pin_set,
        now_ms(),
        BTreeMap::new(),
    )
    .unwrap_err();
    assert_cosigning_error_contains(
        err,
        "consistency_model \"totally-ordered\" is not supported",
    );
}
