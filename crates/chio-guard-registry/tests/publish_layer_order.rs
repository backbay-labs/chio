use std::collections::HashMap;

use chio_guard_registry::{
    GuardArtifactConfig, GuardPublishArtifact, GuardPublishArtifactInput,
    GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE, GUARD_LAYER_ROLE_ANNOTATION,
    GUARD_MANIFEST_LAYER_MEDIA_TYPE, GUARD_MANIFEST_LAYER_ROLE, GUARD_MODULE_LAYER_MEDIA_TYPE,
    GUARD_MODULE_LAYER_ROLE, GUARD_OCI_MANIFEST_MEDIA_TYPE, GUARD_SIGNER_SUBJECT_ANNOTATION,
    GUARD_WIT_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_ROLE, GUARD_WIT_WORLD, GUARD_WIT_WORLD_ANNOTATION,
};
use oci_distribution::manifest::OciDescriptor;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn publish_artifact_uses_normative_three_layer_order() {
    let wit = b"package chio:guard@0.2.0;".to_vec();
    let module = b"\0asm\x01\0\0\0".to_vec();
    let manifest = br#"name: tool-gate
version: "1.0.0"
abi_version: "1"
wit_world: "chio:guard/guard@0.2.0"
wasm_path: "tool_gate.wasm"
wasm_sha256: "abc"
"#
    .to_vec();
    let signer = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let artifact = match GuardPublishArtifact::build(GuardPublishArtifactInput {
        wit: wit.clone(),
        module: module.clone(),
        manifest: manifest.clone(),
        config: GuardArtifactConfig::new(
            signer,
            5_000_000,
            16_777_216,
            "01HX0000000000000000000000",
        ),
        signer_subject: Some(
            "https://github.com/chio-protocol/.github/workflows/release.yml@refs/tags/v1"
                .to_owned(),
        ),
    }) {
        Ok(artifact) => artifact,
        Err(error) => panic!("publish artifact should build: {error}"),
    };

    assert_eq!(artifact.config.media_type, GUARD_CONFIG_MEDIA_TYPE);
    let config_json = match serde_json::from_slice::<Value>(&artifact.config.data) {
        Ok(value) => value,
        Err(error) => panic!("config blob should be JSON: {error}"),
    };
    assert_eq!(config_json["schema_version"], "chio.guard.config.v2");
    assert_eq!(config_json["wit_world"], GUARD_WIT_WORLD);
    assert_eq!(config_json["signer_public_key"], signer);
    assert_eq!(config_json["fuel_limit"], 5_000_000);
    assert_eq!(config_json["memory_limit_bytes"], 16_777_216);
    assert_eq!(config_json["epoch_id_seed"], "01HX0000000000000000000000");

    assert_eq!(
        artifact.manifest.media_type.as_deref(),
        Some(GUARD_OCI_MANIFEST_MEDIA_TYPE)
    );
    assert_eq!(
        artifact.manifest.artifact_type.as_deref(),
        Some(GUARD_ARTIFACT_MEDIA_TYPE)
    );
    assert_eq!(artifact.manifest.config.media_type, GUARD_CONFIG_MEDIA_TYPE);
    assert_eq!(
        artifact.manifest.config.digest,
        sha256_digest(&artifact.config.data)
    );
    assert_eq!(
        artifact.manifest.config.size,
        artifact.config.data.len() as i64
    );
    assert_eq!(
        annotation(&artifact.manifest.annotations, GUARD_WIT_WORLD_ANNOTATION),
        GUARD_WIT_WORLD
    );
    assert_eq!(
        annotation(
            &artifact.manifest.annotations,
            GUARD_SIGNER_SUBJECT_ANNOTATION
        ),
        "https://github.com/chio-protocol/.github/workflows/release.yml@refs/tags/v1"
    );

    assert_eq!(artifact.layers.len(), 3);
    assert_eq!(artifact.manifest.layers.len(), 3);
    assert_layer(
        &artifact.manifest.layers[0],
        &wit,
        GUARD_WIT_LAYER_MEDIA_TYPE,
        GUARD_WIT_LAYER_ROLE,
    );
    assert_layer(
        &artifact.manifest.layers[1],
        &module,
        GUARD_MODULE_LAYER_MEDIA_TYPE,
        GUARD_MODULE_LAYER_ROLE,
    );
    assert_layer(
        &artifact.manifest.layers[2],
        &manifest,
        GUARD_MANIFEST_LAYER_MEDIA_TYPE,
        GUARD_MANIFEST_LAYER_ROLE,
    );

    assert_eq!(artifact.layers[0].media_type, GUARD_WIT_LAYER_MEDIA_TYPE);
    assert_eq!(artifact.layers[1].media_type, GUARD_MODULE_LAYER_MEDIA_TYPE);
    assert_eq!(
        artifact.layers[2].media_type,
        GUARD_MANIFEST_LAYER_MEDIA_TYPE
    );
    assert_eq!(
        annotation(&artifact.layers[0].annotations, GUARD_LAYER_ROLE_ANNOTATION),
        GUARD_WIT_LAYER_ROLE
    );
    assert_eq!(
        annotation(&artifact.layers[1].annotations, GUARD_LAYER_ROLE_ANNOTATION),
        GUARD_MODULE_LAYER_ROLE
    );
    assert_eq!(
        annotation(&artifact.layers[2].annotations, GUARD_LAYER_ROLE_ANNOTATION),
        GUARD_MANIFEST_LAYER_ROLE
    );
}

fn assert_layer(descriptor: &OciDescriptor, bytes: &[u8], media_type: &str, role: &str) {
    assert_eq!(descriptor.media_type, media_type);
    assert_eq!(descriptor.digest, sha256_digest(bytes));
    assert_eq!(descriptor.size, bytes.len() as i64);
    assert_eq!(
        annotation(&descriptor.annotations, GUARD_LAYER_ROLE_ANNOTATION),
        role
    );
}

fn annotation<'a>(annotations: &'a Option<HashMap<String, String>>, key: &str) -> &'a str {
    let Some(annotations) = annotations else {
        panic!("expected annotations");
    };
    let Some(value) = annotations.get(key) else {
        panic!("expected annotation {key}");
    };
    value
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
