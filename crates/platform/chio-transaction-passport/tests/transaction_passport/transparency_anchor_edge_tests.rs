use super::*;

fn transparency_anchored_fixture_with_raw_artifact(
    mutate_artifact: impl FnOnce(&str) -> String,
) -> (BTreeMap<String, Vec<u8>>, Vec<u8>, Vec<u8>) {
    let (mut artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});
    let artifact_path = "transparency-inclusion-proof.json";
    let artifact_text = std::str::from_utf8(
        artifacts
            .get(artifact_path)
            .test_expect("inclusion artifact exists"),
    )
    .test_expect("inclusion artifact is UTF-8");
    let artifact_bytes = mutate_artifact(artifact_text).into_bytes();
    let artifact_digest = sha256_hex(&artifact_bytes);
    artifacts.insert(artifact_path.to_string(), artifact_bytes);

    let mut graph: Value =
        serde_json::from_slice(&evidence_graph_bytes).test_expect("evidence graph parses");
    let proof_node = graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes are an array")
        .iter_mut()
        .find(|node| node["path"].as_str() == Some(artifact_path))
        .test_expect("evidence graph carries the inclusion proof");
    proof_node["id"] = json!(artifact_digest);
    proof_node["sha256"] = json!(artifact_digest);
    let evidence_graph_bytes = serde_json::to_vec(&graph).test_expect("evidence graph serializes");

    (artifacts, evidence_graph_bytes, verifier_policy_bytes)
}

#[test]
fn standalone_minimal_passport_accepts_unique_key_proof_with_noncanonical_whitespace() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture_with_raw_artifact(|artifact| format!("\n  {artifact}\n"));

    let report =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect("strict parsing preserves valid proof semantics");

    assert_eq!(report.transparency_state, "trust_anchored");
}

#[test]
fn standalone_minimal_passport_rejects_duplicate_v2_proof_keys() {
    for (label, needle, replacement) in [
        (
            "proof envelope",
            r#""root_hash":"#,
            format!(r#""root_hash":"0x{}","root_hash":"#, "0".repeat(64)),
        ),
        (
            "signed checkpoint body",
            r#""checkpoint_seq":1"#,
            r#""checkpoint_seq":2,"checkpoint_seq":1"#.to_string(),
        ),
    ] {
        let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
            transparency_anchored_fixture_with_raw_artifact(|artifact| {
                let mutated = artifact.replacen(needle, &replacement, 1);
                assert_ne!(mutated, artifact, "{label} mutation must apply");
                mutated
            });

        let error =
            verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
                .test_expect_err("duplicate proof keys must deny");
        assert!(
            error.to_string().contains("duplicate object key"),
            "{label}: {error}"
        );
    }
}

#[test]
fn standalone_minimal_passport_rejects_anchor_over_a_non_receipt_artifact() {
    // A genuine, pinned-key-signed anchor over some other digest-bound
    // artifact must not carry the anchored tier: otherwise a published
    // (artifact, proof, checkpoint) triple grafts into any graph.
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) = transparency_anchored_fixture(
        |artifact| {
            let policy_bytes = br#"{"schema":"chio.policy.bundle.v1","id":"policy","version":"2026-06-10","rules":[{"id":"allow-demo-echo","effect":"allow","scope":"tool:demo.echo"}]}"#.to_vec();
            let leaf = chio_core_types::merkle::leaf_hash(&policy_bytes);
            let leaf_hex = format!("0x{}", leaf.to_hex());
            let kernel = transparency_checkpoint_keypair();
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["merkle_root"] = json!(leaf_hex);
            let checkpoint_chain_leaf = json!({
                "checkpoint_seq": body["checkpoint_seq"],
                "batch_start_seq": body["batch_start_seq"],
                "batch_end_seq": body["batch_end_seq"],
                "merkle_root": body["merkle_root"]
            });
            let chain_root = chio_core_types::merkle::leaf_hash(
                &chio_core_types::canonical_json_bytes(&checkpoint_chain_leaf)
                    .test_expect("canonical policy checkpoint chain leaf"),
            );
            body["chain_root"] = json!(format!("0x{}", chain_root.to_hex()));
            let signature = kernel
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical policy-anchor statement body"),
                )
                .to_hex();
            artifact["artifact_ref"] = json!(sha256_hex(&policy_bytes));
            artifact["root_hash"] = json!(leaf_hex);
            artifact["leaf_hash"] = json!(leaf_hex);
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        },
    );

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("an anchor over a non-receipt artifact must not promote");

    assert!(
        error
            .to_string()
            .contains("inclusion proof subject is not this transaction's receipt"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_denies_a_checkable_but_invalid_transparency_anchor() {
    // A malformed anchor this verifier CAN judge is an evaluation error, not a
    // silent downgrade: reporting the preview tier would let it ride through a
    // policy that accepts preview.
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["inclusion_path"] = json!([format!("0x{}", "11".repeat(32))]);
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a checkable invalid anchor must deny");

    assert!(
        error
            .to_string()
            .contains("transparency inclusion proof is invalid"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_validates_every_transparency_candidate() {
    let (mut artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});
    let mut invalid_artifact: Value = serde_json::from_slice(
        artifacts
            .get("transparency-inclusion-proof.json")
            .test_expect("valid inclusion artifact exists"),
    )
    .test_expect("valid inclusion artifact parses");
    invalid_artifact["inclusion_path"] = json!([format!("0x{}", "11".repeat(32))]);
    let invalid_bytes =
        serde_json::to_vec(&invalid_artifact).test_expect("invalid inclusion artifact serializes");
    let invalid_digest = sha256_hex(&invalid_bytes);
    artifacts.insert(
        "transparency-inclusion-proof-invalid.json".to_string(),
        invalid_bytes,
    );

    let mut graph: Value =
        serde_json::from_slice(&evidence_graph_bytes).test_expect("evidence graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes are an array")
        .push(json!({
            "id": invalid_digest,
            "schema": "chio.transparency.inclusion-proof.v2",
            "path": "transparency-inclusion-proof-invalid.json",
            "sha256": invalid_digest,
            "role": "transparency-inclusion-proof"
        }));
    let evidence_graph_bytes = serde_json::to_vec(&graph).test_expect("evidence graph serializes");

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a later invalid candidate must deny after a valid candidate");
    assert!(
        error
            .to_string()
            .contains("transparency inclusion proof is invalid"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_signed_checkpoint_missing_required_body_fields() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body.as_object_mut()
                .test_expect("checkpoint body is an object")
                .remove("checkpoint_seq");
            let signature = transparency_checkpoint_keypair()
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical malformed checkpoint body"),
                )
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a signed partial checkpoint body must deny");
    assert!(
        error
            .to_string()
            .contains("checkpoint statement body is invalid"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_signed_checkpoint_unknown_body_fields() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["smuggled"] = json!("field");
            let signature = transparency_checkpoint_keypair()
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical field-smuggled checkpoint body"),
                )
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a signed field-smuggled checkpoint body must deny");
    assert!(
        error.to_string().contains("unknown field `smuggled`"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_signed_checkpoint_explicit_null_options() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["previous_checkpoint_sha256"] = Value::Null;
            let signature = transparency_checkpoint_keypair()
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical explicit-null checkpoint body"),
                )
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a signed explicit-null checkpoint option must deny");
    assert!(
        error
            .to_string()
            .contains("previous_checkpoint_sha256 must be omitted rather than null"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_noncanonical_checkpoint_body_encodings() {
    for field in ["merkle_root", "chain_root", "kernel_key"] {
        let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
            transparency_anchored_fixture(|artifact| {
                let mut body = artifact["checkpoint_statement"]["body"].clone();
                let wire_value = body[field]
                    .as_str()
                    .test_expect("checkpoint field is encoded as a string");
                let noncanonical = match wire_value.strip_prefix("0x") {
                    Some(hex) => format!("0x{}", hex.to_uppercase()),
                    None => wire_value.to_uppercase(),
                };
                assert_ne!(
                    noncanonical, wire_value,
                    "fixture field {field} must contain hexadecimal letters"
                );
                body[field] = json!(noncanonical);
                let signature = transparency_checkpoint_keypair()
                    .sign(
                        &chio_core_types::canonical_json_bytes(&body)
                            .test_expect("canonical noncanonical-wire checkpoint body"),
                    )
                    .to_hex();
                artifact["checkpoint_statement"] = json!({
                    "body": body,
                    "signature": signature
                });
            });

        let error =
            verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
                .test_expect_err("a noncanonical checkpoint field encoding must deny");
        assert!(
            error
                .to_string()
                .contains("checkpoint statement body uses noncanonical field encodings"),
            "{field}: {error}"
        );
    }
}

#[test]
fn standalone_minimal_passport_rejects_noncanonical_checkpoint_signature_encoding() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let signature = artifact["checkpoint_statement"]["signature"]
                .as_str()
                .test_expect("checkpoint signature is a string")
                .to_uppercase();
            artifact["checkpoint_statement"]["signature"] = json!(signature);
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a noncanonical checkpoint signature encoding must deny");
    assert!(
        error
            .to_string()
            .contains("checkpoint statement signature uses a noncanonical encoding"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_accepts_canonical_inclusion_proof_hash_encodings() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            configure_two_leaf_transparency_proof(artifact);
            for field in ["root_hash", "leaf_hash"] {
                let encoded = artifact[field]
                    .as_str()
                    .test_expect("proof hash is encoded as a string");
                artifact[field] = json!(encoded
                    .strip_prefix("0x")
                    .test_expect("fixture proof hash is prefixed"));
            }
        });

    let report =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect("lowercase proof hashes with either schema-supported prefix form promote");

    assert_eq!(report.transparency_state, "trust_anchored");
}

#[test]
fn standalone_minimal_passport_rejects_noncanonical_inclusion_proof_hash_encodings() {
    for (field, expected_reason) in [
        (
            "root_hash",
            "inclusion proof root_hash uses a noncanonical encoding",
        ),
        (
            "leaf_hash",
            "inclusion proof leaf_hash uses a noncanonical encoding",
        ),
        (
            "inclusion_path",
            "inclusion proof audit path uses a noncanonical encoding",
        ),
    ] {
        let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
            transparency_anchored_fixture(|artifact| {
                configure_two_leaf_transparency_proof(artifact);
                let encoded = if field == "inclusion_path" {
                    artifact["inclusion_path"][0]
                        .as_str()
                        .test_expect("audit path hash is encoded as a string")
                } else {
                    artifact[field]
                        .as_str()
                        .test_expect("proof hash is encoded as a string")
                };
                let noncanonical = match encoded.strip_prefix("0x") {
                    Some(hex) => format!("0x{}", hex.to_uppercase()),
                    None => encoded.to_uppercase(),
                };
                assert_ne!(
                    noncanonical, encoded,
                    "fixture field {field} must contain hexadecimal letters"
                );
                if field == "inclusion_path" {
                    artifact["inclusion_path"][0] = json!(noncanonical);
                } else {
                    artifact[field] = json!(noncanonical);
                }
            });

        let error =
            verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
                .test_expect_err("a noncanonical inclusion proof hash encoding must deny");
        assert!(
            error.to_string().contains(expected_reason),
            "{field}: {error}"
        );
    }
}

fn configure_two_leaf_transparency_proof(artifact: &mut Value) {
    let leaf = chio_core_types::Hash::from_hex(
        artifact["leaf_hash"]
            .as_str()
            .test_expect("fixture leaf hash is encoded as a string"),
    )
    .test_expect("fixture leaf hash parses");
    let sibling = chio_core_types::merkle::leaf_hash(b"canonical audit path sibling");
    let root = chio_core_types::merkle::node_hash(&leaf, &sibling);
    let root_hex = root.to_hex_prefixed();

    artifact["root_hash"] = json!(root_hex);
    artifact["tree_size"] = json!(2);
    artifact["inclusion_path"] = json!([sibling.to_hex_prefixed()]);

    let mut body = artifact["checkpoint_statement"]["body"].clone();
    body["batch_end_seq"] = json!(2);
    body["tree_size"] = json!(2);
    body["merkle_root"] = json!(root_hex);
    let checkpoint_chain_leaf = json!({
        "checkpoint_seq": body["checkpoint_seq"],
        "batch_start_seq": body["batch_start_seq"],
        "batch_end_seq": body["batch_end_seq"],
        "merkle_root": body["merkle_root"]
    });
    let chain_root = chio_core_types::merkle::leaf_hash(
        &chio_core_types::canonical_json_bytes(&checkpoint_chain_leaf)
            .test_expect("canonical two-leaf checkpoint chain leaf"),
    );
    body["chain_root"] = json!(chain_root.to_hex_prefixed());
    let signature = transparency_checkpoint_keypair()
        .sign(
            &chio_core_types::canonical_json_bytes(&body)
                .test_expect("canonical two-leaf checkpoint body"),
        )
        .to_hex();
    artifact["checkpoint_statement"] = json!({
        "body": body,
        "signature": signature
    });
}

#[test]
fn standalone_minimal_passport_rejects_zero_checkpoint_issuance_time() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["issued_at"] = json!(0);
            let signature = transparency_checkpoint_keypair()
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical zero-time checkpoint body"),
                )
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a signed zero-time checkpoint must deny");
    assert!(
        error
            .to_string()
            .contains("checkpoint statement issued_at must be greater than zero"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_requires_node_and_artifact_schema_parity() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});
    let mut graph: Value =
        serde_json::from_slice(&evidence_graph_bytes).test_expect("evidence graph parses");
    let inclusion_node = graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes are an array")
        .iter_mut()
        .find(|node| node["role"] == "transparency-inclusion-proof")
        .test_expect("transparency node exists");
    inclusion_node["schema"] = json!("chio.transparency.inclusion-proof.v1");
    let evidence_graph_bytes =
        serde_json::to_vec(&graph).test_expect("mismatched evidence graph serializes");

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a node cannot promote an artifact under a different schema");
    assert!(
        error
            .to_string()
            .contains("does not match artifact schema chio.transparency.inclusion-proof.v2"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_keeps_preview_when_the_anchor_is_not_evaluable() {
    // With no pinned checkpoint keys the verifier cannot judge the anchor, so
    // the graph settles at the preview tier instead of erroring. The fixture
    // policy demands the anchored tier, so the denial names the tier reached
    // rather than a proof defect.
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});

    let error = verify_standalone_anchored_with_checkpoint_keys(
        &artifacts,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &[],
    )
    .test_expect_err("the fixture policy requires the anchored tier");

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: transparency_preview"),
        "an unjudgeable anchor must degrade rather than error: {error}"
    );
}
