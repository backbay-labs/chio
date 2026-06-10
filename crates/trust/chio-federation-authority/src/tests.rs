#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_attest_buyer_core::claims::VendorKeyBinding;
use chio_attest_buyer_core::disclosure::ChioDisclosurePolicy;
use chio_attest_buyer_core::issuer::TrustedBbsIssuer;
use chio_attest_buyer_core::trust_bundle::{
    ChioAuthorityStatus, ChioTrustedActionClass, ChioTrustedGovernanceAuthority,
    ChioTrustedLeaseAuthority, ChioVerifierTrustBundle, ChioVerifierTrustBundleDocument,
    WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID, WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_federation::{bilateral_dsse::Keyid, trust_establishment::LadderManifestRef};
use chio_governance::authorization::GovernanceReceiptCaseKind;
use chio_governance::lease::CapabilityLeaseActionClass;

use crate::{
    assemble_verifier_trust_bundle, issue_authority_bundle, publish_revocation_checkpoint,
    AuthorityProfileDocument, ChioIssuanceRequest, ChioIssuanceStepRequest,
    LocalAuthoritySigningKeysDocument, PeerPinsDocument, RevocationPublicationRequest,
    AUTHORITY_PROFILE_SCHEMA, ISSUANCE_BUNDLE_SCHEMA, ISSUANCE_REQUEST_SCHEMA,
    LOCAL_SIGNING_KEYS_SCHEMA, PEER_PINS_SCHEMA, REVOCATION_PUBLICATION_REQUEST_SCHEMA,
};

const NOW: u64 = 1_766_000_000_000;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn key_id(public_key: &PublicKey) -> String {
    Keyid::from_public_key(public_key).0
}

fn different_key_id(public_key: &PublicKey) -> String {
    let current = key_id(public_key);
    let replacement = if current.starts_with('f') { '0' } else { 'f' };
    format!("{replacement}{}", &current[1..])
}

#[test]
fn sha256_hex_shape_helper_accepts_exact_hex_before_lowercase_validation() {
    assert!(crate::is_sha256_hex_shape(&"a".repeat(64)));
    assert!(crate::is_sha256_hex_shape(&"A".repeat(64)));
    assert!(!crate::is_sha256_hex_shape(&"a".repeat(63)));
    assert!(!crate::is_sha256_hex_shape(&format!("{}g", "a".repeat(63))));
}

fn profile() -> AuthorityProfileDocument {
    let lease_key = key(11);
    let governance_key = key(12);
    let revocation_key = key(13);
    let runtime_policy_issuer_key = key(42);
    AuthorityProfileDocument {
        schema: AUTHORITY_PROFILE_SCHEMA.to_string(),
        trusted_bbs_issuers: vec![TrustedBbsIssuer {
            issuer_fingerprint: "a".repeat(64),
            public_key_hex: "b".repeat(96),
        }],
        lease_authorities: vec![ChioTrustedLeaseAuthority {
            issuer: "did:chio:buyer-kernel".to_string(),
            key_id: Some(key_id(&lease_key.public_key())),
            public_key: lease_key.public_key(),
            valid_from_unix_ms: Some(NOW - 60_000),
            valid_until_unix_ms: Some(NOW + 60_000),
            status: Some(ChioAuthorityStatus::Active),
            allowed_action_classes: vec![
                CapabilityLeaseActionClass::DelegatedAction,
                CapabilityLeaseActionClass::NarrowDestructive,
            ],
        }],
        governance_authorities: vec![ChioTrustedGovernanceAuthority {
            authorizing_kernel: "did:chio:buyer-governance".to_string(),
            key_id: Some(key_id(&governance_key.public_key())),
            public_key: governance_key.public_key(),
            valid_from_unix_ms: Some(NOW - 60_000),
            valid_until_unix_ms: Some(NOW + 60_000),
            status: Some(ChioAuthorityStatus::Active),
            allowed_case_kinds: vec![GovernanceReceiptCaseKind::DestructiveAuthorization],
        }],
        runtime_policy_issuer_public_keys: vec![runtime_policy_issuer_key.public_key()],
        revocation_authority: crate::ChioRevocationAuthority {
            authority_id: "did:chio:buyer-kernel".to_string(),
            key_id: key_id(&revocation_key.public_key()),
            public_key: revocation_key.public_key(),
            valid_from_unix_ms: NOW - 60_000,
            valid_until_unix_ms: NOW + 60_000,
            status: ChioAuthorityStatus::Active,
        },
    }
}

fn signing_keys() -> LocalAuthoritySigningKeysDocument {
    LocalAuthoritySigningKeysDocument {
        schema: LOCAL_SIGNING_KEYS_SCHEMA.to_string(),
        lease_authority_seeds: vec![crate::NamedSeedHex {
            id: "did:chio:buyer-kernel".to_string(),
            seed_hex: hex::encode([11u8; 32]),
        }],
        governance_authority_seeds: vec![crate::NamedSeedHex {
            id: "did:chio:buyer-governance".to_string(),
            seed_hex: hex::encode([12u8; 32]),
        }],
        revocation_authority_seed_hex: hex::encode([13u8; 32]),
    }
}

fn request() -> ChioIssuanceRequest {
    ChioIssuanceRequest {
        schema: ISSUANCE_REQUEST_SCHEMA.to_string(),
        workflow_id: "wf-001".to_string(),
        workflow_grant_id: "cap-workflow".to_string(),
        lease_authority_issuer: "did:chio:buyer-kernel".to_string(),
        governance_authority_kernel: "did:chio:buyer-governance".to_string(),
        verification_context: chio_attest_buyer_core::context::ChioVerificationContext {
            schema: chio_attest_buyer_core::context::VERIFICATION_CONTEXT_SCHEMA.to_string(),
            audience: "buyer-auditor".to_string(),
            challenge: "challenge-001".to_string(),
            proof_purpose: "workflow-disclosure".to_string(),
            issued_at_unix_ms: NOW - 1_000,
            expires_at_unix_ms: NOW + 30_000,
        },
        steps: vec![
            ChioIssuanceStepRequest {
                lease_id: "lease-read".to_string(),
                step_index: 0,
                tool_name: "read_refund_case".to_string(),
                peer_kernel_id: "did:chio:vendor-a".to_string(),
                action_class_id: "read_refund_case".to_string(),
                subject: "did:chio:vendor-a".to_string(),
                action_class: CapabilityLeaseActionClass::DelegatedAction,
                tool_args_hash: "c".repeat(64),
                destructive: false,
                lease_issued_at_unix_ms: NOW - 5_000,
                lease_expires_at_unix_ms: NOW + 20_000,
                governance_receipt_id: None,
                governance_issued_at_unix_ms: None,
                governance_expires_at_unix_ms: None,
                step_sha256: None,
            },
            ChioIssuanceStepRequest {
                lease_id: "lease-stage-refund".to_string(),
                step_index: 1,
                tool_name: "stage_refund".to_string(),
                peer_kernel_id: "did:chio:vendor-b".to_string(),
                action_class_id: "stage_refund".to_string(),
                subject: "did:chio:vendor-b".to_string(),
                action_class: CapabilityLeaseActionClass::NarrowDestructive,
                tool_args_hash: "d".repeat(64),
                destructive: true,
                lease_issued_at_unix_ms: NOW - 5_000,
                lease_expires_at_unix_ms: NOW + 20_000,
                governance_receipt_id: Some("gov-stage-refund".to_string()),
                governance_issued_at_unix_ms: Some(NOW - 4_000),
                governance_expires_at_unix_ms: Some(NOW + 10_000),
                step_sha256: Some("e".repeat(64)),
            },
        ],
    }
}

fn peer_pins() -> PeerPinsDocument {
    PeerPinsDocument {
        schema: PEER_PINS_SCHEMA.to_string(),
        peers: vec![chio_attest_buyer_core::claims::PeerLadderBinding {
            kernel_id: "did:chio:vendor-a".to_string(),
            public_key: key(21).public_key(),
            ladder_manifest_ref: LadderManifestRef {
                manifest_id: "ladder:vendor-a".to_string(),
                sha256: "f".repeat(64),
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + 60_000,
            },
        }],
        vendors: vec![VendorKeyBinding {
            vendor_id: "vendor-a".to_string(),
            public_key: key(21).public_key(),
        }],
        action_classes: vec![
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
        ],
    }
}

#[test]
fn authority_profile_requires_runtime_policy_issuer_roots() {
    let mut document = profile();
    document.runtime_policy_issuer_public_keys.clear();
    let error = document.validate().unwrap_err();
    assert!(error.to_string().contains("runtime policy issuers"));
}

#[test]
fn authority_profile_rejects_duplicate_runtime_policy_issuer_keys() {
    let mut document = profile();
    let duplicate = document.runtime_policy_issuer_public_keys[0].clone();
    document.runtime_policy_issuer_public_keys.push(duplicate);
    let error = document.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("duplicate runtime policy issuer public key"));
}

#[test]
fn authority_profile_rejects_runtime_policy_issuer_overlapping_authority_keys() {
    let mut document = profile();
    document.runtime_policy_issuer_public_keys =
        vec![document.lease_authorities[0].public_key.clone()];
    let error = document.validate().unwrap_err();
    assert!(error.to_string().contains(
        "runtime policy issuer key must be distinct from lease, governance, and revocation authority keys"
    ));
}

#[test]
fn issuer_outputs_verifier_compatible_lease_and_governance_artifacts() {
    let bundle =
        issue_authority_bundle(&profile(), &request(), &signing_keys()).expect("issue bundle");
    assert_eq!(bundle.schema, ISSUANCE_BUNDLE_SCHEMA);
    assert_eq!(bundle.capability_leases.len(), 2);
    assert_eq!(bundle.lease_scope_bindings.len(), 2);
    assert_eq!(bundle.governance_receipts.len(), 1);
    assert_eq!(
        bundle.capability_leases[0].body.scope_digest,
        bundle.lease_scope_bindings[0].scope_digest().unwrap()
    );
    assert_eq!(
        bundle.governance_receipts[0].body.authorized_lease_id,
        "lease-stage-refund"
    );
    assert_eq!(bundle.verification_context.challenge, "challenge-001");
}

#[test]
fn chio_federation_authority_outputs_chio_native_wrapper_schemas() {
    let profile = profile();
    assert_eq!(profile.schema, "chio.federation.authority-profile.v1");

    let request = request();
    assert_eq!(request.schema, "chio.federation.issuance-request.v1");
    assert_eq!(
        request.verification_context.schema,
        "chio.federation.verification-context.v1"
    );

    let keys = signing_keys();
    assert_eq!(keys.schema, "chio.federation.local-signing-keys.v1");

    let bundle = issue_authority_bundle(&profile, &request, &keys).expect("issue bundle");
    assert_eq!(bundle.schema, "chio.federation.issuance-bundle.v1");
    assert_eq!(
        bundle.verification_context.schema,
        "chio.federation.verification-context.v1"
    );
    assert!(bundle
        .lease_scope_bindings
        .iter()
        .all(|binding| binding.schema == "chio.federation.lease-scope-binding.v1"));
    assert!(bundle
        .capability_leases
        .iter()
        .all(|lease| lease.body.schema == "chio.capability-lease.v1"));
    assert!(bundle
        .governance_receipts
        .iter()
        .all(|receipt| receipt.body.schema == "chio.governance-receipt.v1"));

    let checkpoint_request = RevocationPublicationRequest {
        schema: "chio.federation.revocation-publication-request.v1".to_string(),
        checkpoint_id: "checkpoint-001".to_string(),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 60_000,
        epoch_height: 11,
        previous_epoch_height: Some(10),
        revoked_key_fingerprints: Vec::new(),
    };
    let checkpoint =
        publish_revocation_checkpoint(&profile, &checkpoint_request, &keys).expect("checkpoint");
    assert_eq!(
        checkpoint.body.schema,
        "chio.federation.revocation-checkpoint.v1"
    );

    let peer_pins = PeerPinsDocument {
        schema: "chio.federation.peer-pins.v1".to_string(),
        peers: vec![chio_attest_buyer_core::claims::PeerLadderBinding {
            kernel_id: "did:chio:vendor-a".to_string(),
            public_key: key(21).public_key(),
            ladder_manifest_ref: LadderManifestRef {
                manifest_id: "ladder:vendor-a".to_string(),
                sha256: "f".repeat(64),
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + 60_000,
            },
        }],
        vendors: vec![VendorKeyBinding {
            vendor_id: "vendor-a".to_string(),
            public_key: key(21).public_key(),
        }],
        action_classes: vec![
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
        ],
    };
    let workflow_intersection = chio_attest_buyer_core::claims::WorkflowIntersectionArtifact {
        schema: chio_attest_buyer_core::claims::WORKFLOW_INTERSECTION_SCHEMA.to_string(),
        intersection_id: "workflow-intersection:001".to_string(),
        workflow_id: "wf-001".to_string(),
        workflow_grant_id: "cap-workflow".to_string(),
        pairwise_intersection_refs: Vec::new(),
        step_class_bindings: Vec::new(),
        required_vendor_signers: Vec::new(),
        aggregate_workflow_receipt_sha256: "a".repeat(64),
    };
    let trust_bundle = assemble_verifier_trust_bundle(
        &profile,
        &peer_pins,
        &workflow_intersection,
        ChioDisclosurePolicy {
            projection_version: "chio.bbs-projection.workflow.v1".to_string(),
            ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
            message_count: 14,
            required_disclosed_indices: vec![4, 8, 9, 10],
            required_disclosed_fields: vec![
                "id".to_string(),
                "session_id".to_string(),
                "skill_id".to_string(),
                "skill_version".to_string(),
            ],
        },
        checkpoint,
    )
    .expect("trust bundle assembles");
    assert_eq!(
        trust_bundle.schema,
        "chio.federation.verifier-trust-bundle.v1"
    );
    ChioVerifierTrustBundle::from_document(trust_bundle)
        .expect("Chio-native trust bundle remains verifier compatible");
}

#[test]
fn peer_pins_reject_duplicate_peer_kernel_ids_before_bundle_assembly() {
    let mut peer_pins = peer_pins();
    peer_pins.peers.push(peer_pins.peers[0].clone());

    let error = peer_pins.validate().unwrap_err();

    assert!(error.to_string().contains("duplicate peer kernel id"));
}

#[test]
fn inactive_authority_fails_before_signing() {
    let mut profile = profile();
    profile.lease_authorities[0].status = Some(ChioAuthorityStatus::Inactive);
    let error = issue_authority_bundle(&profile, &request(), &signing_keys()).unwrap_err();
    assert!(error.to_string().contains("not active"));
}

#[test]
fn profile_requires_authority_key_ids() {
    let mut lease_profile = profile();
    lease_profile.lease_authorities[0].key_id = None;
    let error = lease_profile.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("leaseAuthorities.keyId is required"));

    let mut governance_profile = profile();
    governance_profile.governance_authorities[0].key_id = None;
    let error = governance_profile.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("governanceAuthorities.keyId is required"));
}

#[test]
fn profile_rejects_authority_key_ids_that_do_not_match_public_keys() {
    let mut lease_profile = profile();
    lease_profile.lease_authorities[0].key_id = Some(different_key_id(
        &lease_profile.lease_authorities[0].public_key,
    ));
    let error = lease_profile.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("leaseAuthorities.keyId does not match public key"));

    let mut governance_profile = profile();
    governance_profile.governance_authorities[0].key_id = Some(different_key_id(
        &governance_profile.governance_authorities[0].public_key,
    ));
    let error = governance_profile.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("governanceAuthorities.keyId does not match public key"));

    let mut revocation_profile = profile();
    revocation_profile.revocation_authority.key_id =
        different_key_id(&revocation_profile.revocation_authority.public_key);
    let error = revocation_profile.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("revocationAuthority.keyId does not match public key"));
}

#[test]
fn checkpoint_rejects_non_monotonic_epoch() {
    let request = RevocationPublicationRequest {
        schema: REVOCATION_PUBLICATION_REQUEST_SCHEMA.to_string(),
        checkpoint_id: "checkpoint-001".to_string(),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 60_000,
        epoch_height: 10,
        previous_epoch_height: Some(10),
        revoked_key_fingerprints: Vec::new(),
    };
    let error = publish_revocation_checkpoint(&profile(), &request, &signing_keys()).unwrap_err();
    assert!(error.to_string().contains("monotonic"));
}

#[test]
fn trust_bundle_assembly_requires_reference_workflow_classes() {
    let checkpoint_request = RevocationPublicationRequest {
        schema: REVOCATION_PUBLICATION_REQUEST_SCHEMA.to_string(),
        checkpoint_id: "checkpoint-001".to_string(),
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: NOW + 60_000,
        epoch_height: 11,
        previous_epoch_height: Some(10),
        revoked_key_fingerprints: Vec::new(),
    };
    let checkpoint =
        publish_revocation_checkpoint(&profile(), &checkpoint_request, &signing_keys())
            .expect("checkpoint");
    let peer_pins = PeerPinsDocument {
        schema: PEER_PINS_SCHEMA.to_string(),
        peers: vec![chio_attest_buyer_core::claims::PeerLadderBinding {
            kernel_id: "did:chio:vendor-a".to_string(),
            public_key: key(21).public_key(),
            ladder_manifest_ref: LadderManifestRef {
                manifest_id: "ladder:vendor-a".to_string(),
                sha256: "f".repeat(64),
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + 60_000,
            },
        }],
        vendors: vec![VendorKeyBinding {
            vendor_id: "vendor-a".to_string(),
            public_key: key(21).public_key(),
        }],
        action_classes: vec![
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
            ChioTrustedActionClass {
                action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                kind: chio_attest_buyer_core::trust_bundle::ChioActionClassKind::Routine,
            },
        ],
    };
    let workflow_intersection = chio_attest_buyer_core::claims::WorkflowIntersectionArtifact {
        schema: chio_attest_buyer_core::claims::WORKFLOW_INTERSECTION_SCHEMA.to_string(),
        intersection_id: "workflow-intersection:001".to_string(),
        workflow_id: "wf-001".to_string(),
        workflow_grant_id: "cap-workflow".to_string(),
        pairwise_intersection_refs: Vec::new(),
        step_class_bindings: Vec::new(),
        required_vendor_signers: Vec::new(),
        aggregate_workflow_receipt_sha256: "a".repeat(64),
    };
    let disclosure_policy = ChioDisclosurePolicy {
        projection_version: "chio.bbs-projection.workflow.v1".to_string(),
        ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
        message_count: 14,
        required_disclosed_indices: vec![4, 8, 9, 10],
        required_disclosed_fields: vec![
            "id".to_string(),
            "session_id".to_string(),
            "skill_id".to_string(),
            "skill_version".to_string(),
        ],
    };
    let document: ChioVerifierTrustBundleDocument = assemble_verifier_trust_bundle(
        &profile(),
        &peer_pins,
        &workflow_intersection,
        disclosure_policy,
        checkpoint,
    )
    .expect("trust bundle assembles");
    ChioVerifierTrustBundle::from_document(document).expect("strict trust bundle parses");

    let mut missing_class = peer_pins;
    missing_class
        .action_classes
        .retain(|class| class.action_class_id != WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID);
    let error = assemble_verifier_trust_bundle(
        &profile(),
        &missing_class,
        &workflow_intersection,
        ChioDisclosurePolicy {
            projection_version: "chio.bbs-projection.workflow.v1".to_string(),
            ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
            message_count: 14,
            required_disclosed_indices: vec![4, 8, 9, 10],
            required_disclosed_fields: vec![
                "id".to_string(),
                "session_id".to_string(),
                "skill_id".to_string(),
                "skill_version".to_string(),
            ],
        },
        publish_revocation_checkpoint(&profile(), &checkpoint_request, &signing_keys())
            .expect("checkpoint"),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains(WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID));
}
