use chio_selective_disclosure::{
    verify_bbs_projection_manifest, verify_transparency_inclusion_proof, BbsProjectionDisclosure,
    BbsProjectionManifest, BbsProjectionMessageSlot, DisclosedMessage, Projection,
    ProjectionMessage, SelectiveDisclosureError, SelectiveDisclosureProof,
    TransparencyInclusionProof, BBS_CIPHERSUITE_SHA256, BBS_PROJECTION_MANIFEST_SCHEMA_V2,
    SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1, TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1,
};
use sha2::{Digest, Sha256};

#[test]
fn projection_manifest_rejects_missing_required_disclosed_slot() {
    let proof = sample_proof(vec![DisclosedMessage {
        index: 0,
        field: "capability_id".to_string(),
        encoding: "utf8".to_string(),
        bytes_hex: hex::encode("cap-123"),
    }]);
    let manifest = sample_manifest(vec![
        message_slot(0, "capability_id", BbsProjectionDisclosure::Disclosed),
        message_slot(1, "tool_name", BbsProjectionDisclosure::Disclosed),
    ]);

    let error = verify_bbs_projection_manifest(&proof, &manifest)
        .err()
        .unwrap_or_else(|| panic!("missing disclosed slot verified"));

    assert!(matches!(
        error,
        SelectiveDisclosureError::ProjectionManifestInvalid(message)
            if message.contains("slot 1 is marked disclosed but missing from proof")
    ));
}

#[test]
fn projection_manifest_rejects_exact_duration_disclosure_by_default() {
    let proof = sample_proof(vec![
        DisclosedMessage {
            index: 0,
            field: "duration_ms".to_string(),
            encoding: "U64".to_string(),
            bytes_hex: hex::encode(42_u64.to_le_bytes()),
        },
        DisclosedMessage {
            index: 1,
            field: "tool_name".to_string(),
            encoding: "utf8".to_string(),
            bytes_hex: hex::encode("capture"),
        },
    ]);
    let mut manifest = sample_manifest(vec![
        message_slot(0, "duration_ms", BbsProjectionDisclosure::Disclosed),
        message_slot(1, "tool_name", BbsProjectionDisclosure::Disclosed),
    ]);
    manifest.message_slots[0].encoding = "U64".to_string();

    let error = verify_bbs_projection_manifest(&proof, &manifest)
        .err()
        .unwrap_or_else(|| panic!("exact duration disclosure verified"));

    assert!(matches!(
        error,
        SelectiveDisclosureError::ProjectionManifestInvalid(message)
            if message.contains("exact timing field duration_ms cannot be directly disclosed")
    ));
}

#[test]
fn generated_projection_manifest_hides_exact_duration_by_default() {
    let projection = Projection {
        version: "projection-manifest-v2-test".to_string(),
        subject_sha256_hex: sha256_hex(b"subject"),
        messages: vec![ProjectionMessage {
            index: 0,
            field: "duration_ms".to_string(),
            encoding: "U64".to_string(),
            bytes_hex: hex::encode(42_u64.to_le_bytes()),
            wholesale_only: false,
        }],
    };

    let manifest = chio_selective_disclosure::bbs_projection_manifest_from_projection(&projection);
    assert_eq!(
        manifest.message_slots[0].disclosure,
        BbsProjectionDisclosure::Hidden
    );
    assert!(manifest.message_slots[0].wholesale_only);
}

#[test]
fn transparency_inclusion_rejects_truncated_path_before_root_width() {
    let proof = sample_proof(Vec::new());
    let leaf_hash = sha256_hex(proof.subject_sha256_hex.as_bytes());
    let inclusion = TransparencyInclusionProof {
        schema: TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1.to_string(),
        proof_id: "transparency-proof-1".to_string(),
        log_id: "log-1".to_string(),
        checkpoint: "checkpoint-1".to_string(),
        artifact_ref: proof.subject_sha256_hex.clone(),
        root_hash: leaf_hash.clone(),
        leaf_hash,
        tree_size: 2,
        leaf_index: 0,
        inclusion_path: Vec::new(),
        verified_at: 1,
    };

    let error = verify_transparency_inclusion_proof(&proof, &inclusion)
        .err()
        .unwrap_or_else(|| panic!("truncated inclusion path verified"));

    assert!(matches!(
        error,
        SelectiveDisclosureError::TransparencyInclusionInvalid(message)
            if message.contains("inclusion path did not reach the root")
    ));
}

fn sample_proof(disclosed: Vec<DisclosedMessage>) -> SelectiveDisclosureProof {
    SelectiveDisclosureProof {
        schema: SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1.to_string(),
        projection_version: "projection-manifest-v2-test".to_string(),
        subject_sha256_hex: sha256_hex(b"subject"),
        ciphersuite: BBS_CIPHERSUITE_SHA256.to_string(),
        issuer_fingerprint: "issuer-1".to_string(),
        issuer_public_key_hex: "ab".repeat(32),
        message_count: 2,
        disclosed_indices: disclosed.iter().map(|message| message.index).collect(),
        disclosed,
        proof_nonce_hex: hex::encode("nonce"),
        proof_bytes_hex: hex::encode("proof"),
    }
}

fn sample_manifest(message_slots: Vec<BbsProjectionMessageSlot>) -> BbsProjectionManifest {
    BbsProjectionManifest {
        schema: BBS_PROJECTION_MANIFEST_SCHEMA_V2.to_string(),
        manifest_id: "projection-manifest-v2-test".to_string(),
        artifact_ref: sha256_hex(b"subject"),
        canonicalization: "jcs".to_string(),
        hash_algorithm: "sha-256".to_string(),
        message_slots,
        hidden_predicates: Vec::new(),
        issuer_key_ref: None,
        signature_ref: None,
    }
}

fn message_slot(
    slot: u16,
    field: &str,
    disclosure: BbsProjectionDisclosure,
) -> BbsProjectionMessageSlot {
    BbsProjectionMessageSlot {
        slot,
        field: field.to_string(),
        message_class: "public_field".to_string(),
        sensitivity_class: "public".to_string(),
        encoding: "utf8".to_string(),
        disclosure,
        wholesale_only: false,
        value_sha256: None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}
