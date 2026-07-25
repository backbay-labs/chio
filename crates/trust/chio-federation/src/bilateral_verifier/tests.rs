// ---------------------------------------------------------------------------
// Tests (happy path + a couple of fast negatives; full negative-conformance
// coverage lives in chio-conformance/tests/c2_bilateral_invocation_partial_verifier.rs)
// ---------------------------------------------------------------------------

use super::support::{canonical_json_string, receipt_canonical_digest_hex};
use super::*;
use crate::bilateral_dsse::{
    pae, receipt_subject_name, sign_chio_bilateral_dsse_envelope, sign_dsse_envelope_full,
    BilateralPredicateExtensions, CapabilityLeaseRef, GovernanceReceiptRef, HashRecord,
    PolicyEvaluationSummary, PolicyVerdict, PAYLOAD_TYPE_IN_TOTO,
};
use crate::demo::DemoAllowAllRevocationOracle;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair, SigningBackend};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};

fn sample_receipt(kp_b: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-c2-sample".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-c2".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k":"v"})).unwrap(),
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
    ChioReceipt::sign(body, kp_b).unwrap()
}

fn happy_path_extensions(now_ms: u64) -> BilateralPredicateExtensions {
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
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

fn treaty_bound_extensions(
    receipt: &ChioReceipt,
    now_ms: u64,
    governance_digest: String,
) -> BilateralPredicateExtensions {
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: "lease-c2-happy".to_string(),
            issuer: "did:chio:org-a".to_string(),
            expires_at_unix_ms: now_ms + 60_000,
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
        governance_receipt_ref: Some(GovernanceReceiptRef {
            receipt_id: "gov-1".to_string(),
            kernel_id: "did:chio:governance".to_string(),
            digest: HashRecord {
                alg: "sha256".to_string(),
                value: governance_digest,
            },
        }),
        consistency_anchor: Some("anchor-live".to_string()),
        consistency_model: Some("totally-ordered".to_string()),
        cross_org_visibility: Some("treaty_only".to_string()),
        treaty_binding_ref: Some(TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.destructive.vendor_call".to_string(),
            consistency_model: "totally-ordered".to_string(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: receipt.content_hash.clone(),
            local_receipt_sha256: "8".repeat(64),
            remote_receipt_sha256: receipt_canonical_digest_hex(receipt).unwrap(),
            lease_refs: vec!["lease-c2-happy".to_string()],
            governance_refs: vec!["gov-1".to_string()],
            signer_kernel_ids: vec!["did:chio:org-a".to_string(), "did:chio:org-b".to_string()],
        }),
    }
}

fn insert_fresh_ladder_peers(peers: &mut PeerPinSet, kp_a: &Keypair, kp_b: &Keypair, now_ms: u64) {
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-a:v1".to_string(),
            sha256: "a".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-b:v1".to_string(),
            sha256: "b".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
}

fn fixture(
    kp_a: &Keypair,
    kp_b: &Keypair,
    receipt: &ChioReceipt,
    now_ms: u64,
) -> (
    DsseEnvelope,
    InMemoryReceiptStore,
    InMemoryLeaseRegistry,
    InMemoryGovernanceReceiptStore,
    DemoAllowAllRevocationOracle,
    PeerPinSet,
) {
    let envelope = sign_dsse_envelope_full(
        receipt,
        kp_a,
        kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        happy_path_extensions(now_ms),
    )
    .unwrap();

    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());

    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: None,
    });

    let governance_store = InMemoryGovernanceReceiptStore::new();
    let revocation_oracle = DemoAllowAllRevocationOracle;

    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });

    (
        envelope,
        receipt_store,
        lease_registry,
        governance_store,
        revocation_oracle,
        peer_pin_set,
    )
}

fn config<'a>(
    peer_pin_set: &'a PeerPinSet,
    receipt_store: &'a dyn ReceiptStore,
    lease_registry: &'a dyn CapabilityLeaseRegistry,
    governance_store: &'a dyn GovernanceReceiptStore,
    revocation_oracle: &'a dyn RevocationOracle,
    now_ms: u64,
) -> VerifierConfig<'a> {
    // The happy-path test uses UnknownActionClassPolicy::Reject (the production default)
    // with `file_read` pre-registered as Routine. Negative tests that exercise
    // strict-mode rejection or receipt-backed classes mutate `action_classes` /
    // `unknown_action_class_policy` explicitly.
    let mut action_classes = BTreeMap::new();
    action_classes.insert("file_read".to_string(), ActionClassKind::Routine);
    VerifierConfig {
        peer_pin_set,
        receipt_store,
        lease_registry,
        governance_receipt_store: governance_store,
        revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: now_ms,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    }
}

fn resign_envelope(
    envelope: &mut DsseEnvelope,
    kp_a: &Keypair,
    kp_b: &Keypair,
    statement_bytes: &[u8],
) {
    envelope.payload = BASE64_STANDARD.encode(statement_bytes);
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, statement_bytes);
    let sig_a = Ed25519Backend::new(kp_a.clone())
        .sign_bytes(&pae_bytes)
        .unwrap();
    let sig_b = Ed25519Backend::new(kp_b.clone())
        .sign_bytes(&pae_bytes)
        .unwrap();
    envelope.signatures[0].sig = BASE64_STANDARD.encode(sig_a.to_bytes());
    envelope.signatures[1].sig = BASE64_STANDARD.encode(sig_b.to_bytes());
}

fn strict_chio_verifier_rejects_treaty_mutation(
    mutate: impl FnOnce(&mut DsseStatement),
) -> VerifierError {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let (_slice_envelope, receipt_store, lease_registry, mut governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    mutate(&mut statement);
    let statement_bytes = statement.canonical_bytes().unwrap();
    resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
    let mut base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    base.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
        .unwrap_err()
}

#[test]
fn happy_path_passes_partial_local_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let config = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let verified = verify_bilateral_cosign_invocation(&envelope, &config).unwrap();
    assert_eq!(verified.joint_verdict, "allow");
    assert_eq!(verified.resolved_receipt.id, receipt.id);
}

#[test]
fn verify_chio_bilateral_invocation_accepts_unanimous_deny_for_audit() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        happy_path_extensions(now_ms),
    )
    .unwrap();
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let (mut statement, _) = envelope.decode_statement().unwrap();
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .unwrap();
    summary.server_a_verdict.verdict = "deny".to_string();
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    let statement_bytes = statement.canonical_bytes().unwrap();
    resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);

    let config = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    let verified =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &config })
            .unwrap();
    assert_eq!(verified.joint_verdict, "deny");
}

#[test]
fn strict_chio_verifier_requires_fresh_ladder_refs() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        happy_path_extensions(now_ms),
    )
    .unwrap();
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    assert!(matches!(
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base }),
        Err(VerifierError::LadderManifestMissing(_))
    ));

    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-a:v1".to_string(),
            sha256: "a".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-b:v1".to_string(),
            sha256: "b".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    let verified =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap();
    assert_eq!(verified.resolved_receipt.id, receipt.id);
}

#[test]
fn strict_chio_verifier_rejects_signature_slice_profile() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-a:v1".to_string(),
            sha256: "a".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-b:v1".to_string(),
            sha256: "b".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();
    assert_eq!(err.code(), "predicate.type_unrecognised");
    assert!(err.to_string().contains("signature-slice"));
}

#[test]
fn strict_chio_verifier_accepts_strict_predicate_profile() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        happy_path_extensions(now_ms),
    )
    .unwrap();
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());
    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: None,
    });
    let governance_store = InMemoryGovernanceReceiptStore::new();
    let oracle = DemoAllowAllRevocationOracle;
    let mut peers = PeerPinSet::new();
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-a:v1".to_string(),
            sha256: "a".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-b:v1".to_string(),
            sha256: "b".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let verified =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap();
    assert_eq!(verified.resolved_receipt.id, receipt.id);
    assert_eq!(
        verified
            .statement
            .predicate
            .tool_args_hash
            .as_ref()
            .unwrap()
            .value,
        receipt.action.parameter_hash
    );
    assert!(verified
        .statement
        .predicate
        .receipt_canonical_json
        .is_none());
}

#[test]
fn strict_chio_verifier_requires_tool_args_hash() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        happy_path_extensions(now_ms),
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement.predicate.tool_args_hash = None;
    let statement_bytes = statement.canonical_bytes().unwrap();
    resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);

    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-a:v1".to_string(),
            sha256: "a".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: Some(crate::trust_establishment::LadderManifestRef {
            manifest_id: "ladder:org-b:v1".to_string(),
            sha256: "b".repeat(64),
            issued_at_unix_ms: now_ms - 60_000,
            expires_at_unix_ms: now_ms + 60_000,
        }),
    });
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("tool_args_hash"));
}

#[test]
fn strict_chio_verifier_binds_treaty_request_hash_to_tool_args() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let (_slice_envelope, receipt_store, lease_registry, mut governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement
        .predicate
        .treaty_binding_ref
        .as_mut()
        .unwrap()
        .request_sha256 = "6".repeat(64);
    let statement_bytes = statement.canonical_bytes().unwrap();
    resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
    let mut base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    base.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("request_sha256"));
}

#[test]
fn strict_chio_verifier_binds_treaty_outcome_hash_to_resolved_receipt() {
    let err = strict_chio_verifier_rejects_treaty_mutation(|statement| {
        statement
            .predicate
            .treaty_binding_ref
            .as_mut()
            .unwrap()
            .outcome_sha256 = "7".repeat(64);
    });
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("outcome_sha256"));
}

#[test]
fn strict_chio_verifier_rejects_n_of_m_without_verified_frost_authorization() {
    let err = strict_chio_verifier_rejects_treaty_mutation(|statement| {
        statement.predicate.co_sign = "n_of_m".to_string();
        statement.predicate.consistency_model = "quorum-required".to_string();
        statement.predicate.consistency_anchor = Some("frost-quorum".to_string());
        statement
            .predicate
            .treaty_binding_ref
            .as_mut()
            .unwrap()
            .consistency_model = "quorum-required".to_string();
    });
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("n_of_m"));
}

#[test]
fn strict_chio_verifier_binds_treaty_remote_receipt_hash_to_resolved_receipt() {
    let err = strict_chio_verifier_rejects_treaty_mutation(|statement| {
        statement
            .predicate
            .treaty_binding_ref
            .as_mut()
            .unwrap()
            .remote_receipt_sha256 = "9".repeat(64);
    });
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("remote_receipt_sha256"));
}

#[test]
fn strict_chio_verifier_accepts_treaty_ordered_consistency() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let (_slice_envelope, receipt_store, lease_registry, mut governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let mut base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    base.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let verified =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap();

    assert_eq!(verified.resolved_receipt.id, receipt.id);
    assert_eq!(
        verified.statement.predicate.consistency_model,
        "totally-ordered"
    );
    assert!(verified.statement.predicate.treaty_binding_ref.is_some());
}

#[test]
fn strict_chio_verifier_resolves_treaty_governance_refs_for_routine_class() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_digest = sha256_hex(br#"{"governance":"receipt"}"#);
    let (_slice_envelope, receipt_store, lease_registry, governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();

    assert_eq!(err.code(), "governance.receipt_required_missing");
    assert!(err.to_string().contains("not resolvable"));
}

#[test]
fn strict_chio_treaty_review_binds_live_material() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_digest = sha256_hex(br#"{"governance":"receipt"}"#);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let (statement, _) = envelope.decode_statement().unwrap();
    let expected_treaty_binding = statement.predicate.treaty_binding_ref.clone().unwrap();
    let expected_subject_name = receipt_subject_name(&receipt.id);
    let expected_subject_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&receipt.body()).unwrap(),
    );
    let expected_capability_lease_ref = statement.predicate.capability_lease_ref.clone().unwrap();
    let expected_governance_receipt_ref =
        statement.predicate.governance_receipt_ref.clone().unwrap();
    let mut signer_public_keys = BTreeMap::new();
    signer_public_keys.insert("did:chio:org-a".to_string(), kp_a.public_key());
    signer_public_keys.insert("did:chio:org-b".to_string(), kp_b.public_key());

    let accepted = TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: "anchor-live",
        signer_public_keys: &signer_public_keys,
    };
    verify_treaty_bound_chio_bilateral_invocation(&envelope, &accepted).unwrap();

    let mut bad_statement = statement.clone();
    bad_statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .unwrap()
        .server_b_verdict
        .verdict = "deny".to_string();
    bad_statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .unwrap()
        .joint_disposition = Some("deny".to_string());
    let bad_payload = BASE64_STANDARD.encode(bad_statement.canonical_bytes().unwrap());
    let bad_envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: bad_payload,
        signatures: envelope.signatures.clone(),
    };
    assert_eq!(
        verify_treaty_bound_chio_bilateral_invocation(&bad_envelope, &accepted)
            .unwrap_err()
            .code(),
        "policy.verdict_disagreement"
    );
    let mut deny_statement = statement.clone();
    let deny_summary = deny_statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .unwrap();
    deny_summary.server_a_verdict.verdict = "deny".to_string();
    deny_summary.server_b_verdict.verdict = "deny".to_string();
    deny_summary.joint_disposition = Some("deny".to_string());
    let deny_payload = BASE64_STANDARD.encode(deny_statement.canonical_bytes().unwrap());
    let deny_envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: deny_payload,
        signatures: envelope.signatures.clone(),
    };
    let deny_error =
        verify_treaty_bound_chio_bilateral_invocation(&deny_envelope, &accepted).unwrap_err();
    assert_eq!(deny_error.code(), "policy.verdict_disagreement");
    assert!(deny_error
        .to_string()
        .contains("requires allow verdict for admission"));

    let wrong_anchor = TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: "anchor-other",
        signer_public_keys: &signer_public_keys,
    };
    assert_eq!(
        verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_anchor)
            .unwrap_err()
            .code(),
        "predicate.schema_invalid"
    );

    let mut wrong_lease = expected_capability_lease_ref.clone();
    wrong_lease.issuer = "did:chio:attacker".to_string();
    let wrong_lease_review = TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &wrong_lease,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: "anchor-live",
        signer_public_keys: &signer_public_keys,
    };
    assert_eq!(
        verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_lease_review)
            .unwrap_err()
            .code(),
        "capability.lease_expired_or_unknown"
    );

    let mut wrong_governance = expected_governance_receipt_ref.clone();
    wrong_governance.digest.value = "0".repeat(64);
    let wrong_governance_review = TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &wrong_governance,
        expected_consistency_anchor: "anchor-live",
        signer_public_keys: &signer_public_keys,
    };
    assert_eq!(
        verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_governance_review)
            .unwrap_err()
            .code(),
        "governance.receipt_required_missing"
    );

    let wrong_subject_sha256 = "0".repeat(64);
    let wrong_subject_review = TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &wrong_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: "anchor-live",
        signer_public_keys: &signer_public_keys,
    };
    assert_eq!(
        verify_treaty_bound_chio_bilateral_invocation(&envelope, &wrong_subject_review)
            .unwrap_err()
            .code(),
        "subject.digest_mismatch"
    );
}

#[test]
fn strict_chio_verifier_binds_treaty_signers_to_authenticated_peers() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let (_slice_envelope, receipt_store, lease_registry, mut governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let mut envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        treaty_bound_extensions(&receipt, now_ms, governance_digest),
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement
        .predicate
        .treaty_binding_ref
        .as_mut()
        .unwrap()
        .signer_kernel_ids[0] = "did:chio:attacker".to_string();
    let statement_bytes = statement.canonical_bytes().unwrap();
    resign_envelope(&mut envelope, &kp_a, &kp_b, &statement_bytes);
    let mut base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    base.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("signer_kernel_ids"));
}

#[test]
fn strict_chio_verifier_rejects_treaty_without_ordered_anchor() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let (_slice_envelope, receipt_store, lease_registry, mut governance_store, oracle, mut peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    insert_fresh_ladder_peers(&mut peers, &kp_a, &kp_b, now_ms);
    let mut ext = treaty_bound_extensions(&receipt, now_ms, governance_digest);
    ext.consistency_anchor = None;
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();
    let mut base = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    base.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let err =
        verify_chio_bilateral_invocation(&envelope, &ChioBilateralVerifierConfig { base: &base })
            .unwrap_err();
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("consistency_anchor"));
}

#[test]
fn step_7_missing_receipt_fails_closed_with_subject_digest_mismatch() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, _store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let empty_store = InMemoryReceiptStore::new();
    let config = config(
        &peers,
        &empty_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
    assert_eq!(err.code(), "subject.digest_mismatch");
}

#[test]
fn parseable_dsse_with_bad_statement_json_reports_statement_malformed() {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (mut envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    envelope.payload = BASE64_STANDARD.encode(b"{not-json");
    let config = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
    assert_eq!(err.code(), "statement.malformed");
}

/// Single-subject invariant: the §7 verifier must reject a multi-subject
/// envelope structurally (mirror of the
/// `bilateral_dsse::verify_dsse_envelope` check). Splices a second
/// subject digest into a freshly-signed envelope and asserts the
/// verifier returns `statement.schema_invalid` BEFORE any per-subject
/// digest comparison.
#[test]
fn multi_subject_envelope_is_rejected_at_verifier_step_3() {
    use crate::bilateral_dsse::{StatementSubject, SubjectDigest};
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (mut envelope, receipt_store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);

    // Decode, splice a second subject, re-canonicalise, re-encode payload.
    let (mut statement, _bytes) = envelope.decode_statement().unwrap();
    statement.subject.push(StatementSubject {
        name: "rcpt-injected".to_string(),
        digest: SubjectDigest {
            sha256: "0".repeat(64),
        },
    });
    let new_statement_bytes = canonical_json_bytes(&statement).unwrap();
    envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

    let config = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
    assert_eq!(err.code(), "statement.schema_invalid");
    let msg = err.to_string();
    assert!(
        msg.contains("statement.malformed") || msg.contains("exactly 1 subject"),
        "expected multi-subject diagnostic, got: {msg}"
    );
}

#[test]
fn step_14_expired_lease_fails_closed() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);

    // Verifier wall clock advanced past the lease expiry.
    let expired_now = now_ms + 60_000 + 1;
    let config = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        expired_now,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
    assert_eq!(err.code(), "capability.lease_expired_or_unknown");
}

#[test]
fn step_13_verdict_disagreement_fails_closed() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    // Build extensions where the verdicts disagree.
    let mut ext = happy_path_extensions(now_ms);
    if let Some(s) = ext.policy_evaluation_summary.as_mut() {
        s.server_b_verdict.verdict = "deny".to_string();
        s.joint_disposition = Some("deny".to_string());
    }
    let envelope = sign_dsse_envelope_full(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();

    let mut peer_pin_set = PeerPinSet::new();
    peer_pin_set.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peer_pin_set.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());
    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: None,
    });
    let governance_store = InMemoryGovernanceReceiptStore::new();
    let oracle = DemoAllowAllRevocationOracle;

    let config = config(
        &peer_pin_set,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &config).unwrap_err();
    assert_eq!(err.code(), "policy.verdict_disagreement");
}

#[test]
fn step_15_receipt_backed_class_requires_governance_receipt() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let mut cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    // Mark this tool as receipt-backed in the verifier's local
    // ladder manifest.
    cfg.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "governance.receipt_required_missing");
}

#[test]
fn step_8_unpinned_peer_fails_closed() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, store, lease_registry, governance_store, oracle, _peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);

    // Empty pin set.
    let peers = PeerPinSet::new();
    let cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "peer.unpinned_or_keyid_mismatch");
}

#[test]
fn step_15_unknown_action_class_rejected_under_strict_policy() {
    // Fail-closed action-class invariant: a tool name not present in
    // `action_classes` must not fall back to `Routine` (fail-OPEN for
    // receipt-backed classes misspelled or omitted from the registry).
    // The strict default (Reject) returns the typed
    // `governance.unknown_action_class` diagnostic.
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let mut cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    // Strict policy: any unregistered tool is rejected. The
    // `action_classes` table is intentionally cleared so the
    // predicate's `tool_name` cannot resolve. (The shared helper
    // pre-registers `file_read` for the happy path; this negative
    // test removes that registration.)
    cfg.unknown_action_class_policy = UnknownActionClassPolicy::Reject;
    cfg.action_classes.clear();

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "governance.unknown_action_class");
    match err {
        VerifierError::UnknownActionClass { tool_name } => {
            assert_eq!(tool_name, "file_read");
        }
        other => panic!("expected UnknownActionClass, got {other:?}"),
    }
}

#[test]
fn resolved_receipt_signature_must_verify() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (envelope, _store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.content_hash = sha256_hex(b"tampered");
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(tampered_receipt);
    let cfg = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "subject.digest_mismatch");
    assert!(err.to_string().contains("signature"));
}

#[test]
fn predicate_tool_name_must_match_resolved_receipt() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let (mut statement, _) = envelope.decode_statement().unwrap();
    statement.predicate.tool_name = "file_write".to_string();
    resign_envelope(
        &mut envelope,
        &kp_a,
        &kp_b,
        &statement.canonical_bytes().unwrap(),
    );
    let cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "predicate.schema_invalid");
    assert!(err.to_string().contains("tool_name"));
}

#[test]
fn predicate_embedded_receipt_json_must_match_resolved_receipt() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let (mut envelope, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let (mut statement, _) = envelope.decode_statement().unwrap();
    let mut embedded: ChioReceipt =
        serde_json::from_str(statement.predicate.receipt_canonical_json.as_ref().unwrap()).unwrap();
    embedded.capability_id = "different-capability".to_string();
    statement.predicate.receipt_canonical_json = Some(canonical_json_string(&embedded).unwrap());
    resign_envelope(
        &mut envelope,
        &kp_a,
        &kp_b,
        &statement.canonical_bytes().unwrap(),
    );
    let cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "subject.digest_mismatch");
    assert!(err.to_string().contains("embedded receipt"));
}

#[test]
fn unsupported_policy_verdict_is_rejected() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let mut ext = happy_path_extensions(now_ms);
    if let Some(summary) = ext.policy_evaluation_summary.as_mut() {
        summary.server_a_verdict.verdict = "observe".to_string();
        summary.server_b_verdict.verdict = "observe".to_string();
        summary.joint_disposition = Some("observe".to_string());
    }
    let envelope = sign_dsse_envelope_full(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());
    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: None,
    });
    let governance_store = InMemoryGovernanceReceiptStore::new();
    let oracle = DemoAllowAllRevocationOracle;
    let mut peers = PeerPinSet::new();
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });
    let cfg = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "policy.verdict_disagreement");
    assert!(err.to_string().contains("unsupported verdict"));
}

#[test]
fn policy_provenance_fields_must_be_non_empty() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let mut ext = happy_path_extensions(now_ms);
    if let Some(summary) = ext.policy_evaluation_summary.as_mut() {
        summary.server_a_verdict.policy_id.clear();
    }
    let envelope = sign_dsse_envelope_full(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();

    let (_unused, store, lease_registry, governance_store, oracle, peers) =
        fixture(&kp_a, &kp_b, &receipt, now_ms);
    let cfg = config(
        &peers,
        &store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "policy.verdict_disagreement");
    assert!(err.to_string().contains("policy_id must be non-empty"));
}

#[test]
fn scope_digest_hash_record_must_be_sha256() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;
    let scope_value = "a".repeat(64);

    let mut ext = happy_path_extensions(now_ms);
    if let Some(lease) = ext.capability_lease_ref.as_mut() {
        lease.scope_digest = Some(HashRecord {
            alg: "sha512".to_string(),
            value: scope_value.clone(),
        });
    }
    let envelope = sign_dsse_envelope_full(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());
    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: Some(scope_value),
    });
    let governance_store = InMemoryGovernanceReceiptStore::new();
    let oracle = DemoAllowAllRevocationOracle;
    let mut peers = PeerPinSet::new();
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });
    let cfg = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "capability.lease_expired_or_unknown");
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn governance_digest_hash_record_must_be_sha256() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let now_ms = 1_734_000_000_000;

    let governance_json = r#"{"governance":"receipt"}"#.to_string();
    let governance_digest = sha256_hex(governance_json.as_bytes());
    let mut ext = happy_path_extensions(now_ms);
    ext.governance_receipt_ref = Some(GovernanceReceiptRef {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        digest: HashRecord {
            alg: "blake3".to_string(),
            value: governance_digest,
        },
    });
    let envelope = sign_dsse_envelope_full(
        &receipt,
        &kp_a,
        &kp_b,
        "did:chio:org-a",
        "did:chio:org-b",
        "file_read",
        now_ms,
        ext,
    )
    .unwrap();
    let mut receipt_store = InMemoryReceiptStore::new();
    receipt_store.insert(receipt.clone());
    let mut lease_registry = InMemoryLeaseRegistry::new();
    lease_registry.insert(ResolvedLease {
        lease_id: "lease-c2-happy".to_string(),
        issuer: "did:chio:org-a".to_string(),
        expires_at_unix_ms: now_ms + 60_000,
        scope_digest_hex: None,
    });
    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    governance_store.insert(ResolvedGovernanceReceipt {
        receipt_id: "gov-1".to_string(),
        kernel_id: "did:chio:governance".to_string(),
        canonical_json: governance_json,
    });
    let oracle = DemoAllowAllRevocationOracle;
    let mut peers = PeerPinSet::new();
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-a".to_string(),
        public_key: kp_a.public_key(),
        ladder_manifest_ref: None,
    });
    peers.insert(PinnedPeer {
        kernel_id: "did:chio:org-b".to_string(),
        public_key: kp_b.public_key(),
        ladder_manifest_ref: None,
    });
    let mut cfg = config(
        &peers,
        &receipt_store,
        &lease_registry,
        &governance_store,
        &oracle,
        now_ms,
    );
    cfg.action_classes
        .insert("file_read".to_string(), ActionClassKind::ReceiptBacked);

    let err = verify_bilateral_cosign_invocation(&envelope, &cfg).unwrap_err();
    assert_eq!(err.code(), "governance.receipt_required_missing");
    assert!(err.to_string().contains("sha256"));
}
