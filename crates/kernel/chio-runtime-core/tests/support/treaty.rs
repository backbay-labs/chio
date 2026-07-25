use chio_core_types::crypto::Keypair;
use chio_runtime_core::{
    GovernanceLadderActionClass, GovernanceLadderManifest, TreatyScope,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};

pub fn treaty_action_class(
    mode: &str,
    destructive: bool,
    consistency_model: &str,
    evidence_required: Vec<&str>,
) -> GovernanceLadderActionClass {
    GovernanceLadderActionClass {
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        mode: mode.to_string(),
        destructive,
        consistency_model: consistency_model.to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        evidence_required: evidence_required
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect(),
        aliases: Vec::new(),
    }
}

pub fn treaty_manifest(
    kernel_id: &str,
    action: GovernanceLadderActionClass,
) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: format!("did:chio:{kernel_id}"),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![action],
    }
}

pub fn treaty_scope() -> TreatyScope {
    let buyer_key = Keypair::generate();
    let vendor_key = Keypair::generate();
    TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
        participant_public_keys: vec![buyer_key.public_key(), vendor_key.public_key()],
        ladder_manifest_sha256s: vec!["a".repeat(64), "b".repeat(64)],
        allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    }
}
