#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::bilateral::{co_sign_with_origin_full, InProcessCoSigner};

const ORG_A_KERNEL_ID: &str = "kernel.c4-org-a";
const ORG_B_KERNEL_ID: &str = "kernel.c4-org-b";

fn sample_receipt(tool_host_kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-release work-c4-fixture".to_string(),
        timestamp: 1_736_000_000,
        capability_id: "cap-release work-c4".to_string(),
        tool_server: "srv-c4-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "/data/c4.txt"}))
            .unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core_types::crypto::sha256_hex(br#"{"c4":true}"#),
        policy_hash: "c4-policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: tool_host_kp.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, tool_host_kp).unwrap()
}

fn write_artifact_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let cosigner = InProcessCoSigner::new(ORG_A_KERNEL_ID, kp_a.clone(), kp_b.public_key());
    let artifacts = co_sign_with_origin_full(
        ORG_A_KERNEL_ID,
        &kp_a,
        ORG_B_KERNEL_ID,
        &kp_b,
        receipt,
        &cosigner,
        "file_read",
        1_736_000_000_000,
    )
    .expect("hot path must produce both artifacts");

    // Hand-serialise to the snake_case shape the renderer detects. We
    // include both halves so the renderer detection (`is_bilateral_artifacts_value`)
    // fires unambiguously.
    let value = serde_json::json!({
        "dual_signed_receipt": serde_json::to_value(&artifacts.dual_signed_receipt).unwrap(),
        "dsse_envelope": serde_json::to_value(&artifacts.dsse_envelope).unwrap(),
    });
    let path = dir.join("bilateral.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}

#[test]
fn receipt_explain_bilateral_renders_dual_dsse_and_inspection_trace() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_artifact_fixture(tmp.path());

    let out = Command::new(bin)
        .args([
            "--json",
            "receipt",
            "explain",
            "bilateral", // sentinel receipt_id; the bilateral path is keyed off --input-file shape
            "--input-file",
            fixture.to_str().unwrap(),
            // The flag is `--inspect-bilateral`. The alias
            // (`--explain-bilateral`) is retained as a clap alias on the
            // parent enum (see types.rs).
            "--inspect-bilateral",
        ])
        .output()
        .expect("invoke chio receipt explain");

    assert!(
        out.status.success(),
        "chio receipt explain --inspect-bilateral exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("renderer must emit valid JSON");

    assert_eq!(
        parsed["shape"].as_str(),
        Some("BilateralCoSignArtifacts"),
        "renderer must detect BilateralCoSignArtifacts shape"
    );
    assert_eq!(
        parsed["schema"].as_str(),
        Some("chio.cli.receipt-explain.bilateral.v1"),
        "renderer must declare its own report schema"
    );
    let dual = &parsed["dual_signed_receipt"];
    let disclaimer = dual["non_section6_disclaimer"]
        .as_str()
        .expect("dual section must carry non-section-6 disclaimer string");
    assert!(
        disclaimer
            .to_lowercase()
            .contains("not section-6 conformant"),
        "disclaimer must call out non-section-6 status: got {disclaimer}"
    );

    // (2) DSSE envelope section: section-6 binding.
    let dsse = &parsed["dsse_envelope"];
    assert_eq!(
        dsse["payload_type"].as_str(),
        Some("application/vnd.in-toto+json"),
        "DSSE envelope MUST use the in-toto payloadType"
    );
    let sigs = dsse["signatures"]
        .as_array()
        .expect("dsse_envelope.signatures must be array");
    assert_eq!(sigs.len(), 2, "envelopes carry exactly two signatures");
    for sig in sigs {
        assert!(
            sig["keyid"].as_str().is_some(),
            "each DSSE signature must expose its keyid"
        );
        assert!(
            sig["sig"].as_str().is_some(),
            "each DSSE signature must expose its base64 signature bytes"
        );
    }

    // (3) Bilateral inspection trace: must self-identify as inspection
    // (not a verifier trace) so users do not mistake it for cryptographic
    // verification.
    let trace = &parsed["bilateral_inspection_trace"];
    assert!(
        trace.is_object(),
        "--inspect-bilateral must emit bilateral_inspection_trace"
    );
    assert_eq!(
        trace["trace_kind"].as_str(),
        Some("inspection"),
        "trace MUST self-identify as `inspection`, not a verifier trace"
    );
    assert_eq!(
        trace["verification_performed"].as_bool(),
        Some(false),
        "trace MUST declare verification_performed = false"
    );
    let steps = trace["steps"]
        .as_array()
        .expect("trace.steps must be array");
    assert_eq!(
        steps.len(),
        17,
        "trace iterates the section-7 step structure even though only a subset is locally verifiable"
    );

    // Signature verification steps are labelled `not-verified` (the CLI
    // does not perform Ed25519 verification); other deferred steps
    // remain `bounded`. No step should `fail` on a healthy hot-path
    // artifact.
    for step in steps {
        let status = step["status"].as_str().unwrap_or("");
        assert!(
            status == "ok" || status == "bounded" || status == "not-verified",
            "step {} ({}) must not fail on a hot-path artifact: status={status}, note={}",
            step["step"],
            step["name"].as_str().unwrap_or("?"),
            step["note"].as_str().unwrap_or("")
        );
    }

    // The "ok" set must include the locally-checkable section-7 prerequisites:
    // payload type, payload base64, predicate type recognised, statement
    // type, subject arity, signature count, signature fields, keyid<->
    // predicate fingerprint binding, and predicate body schema.
    let must_be_ok = [
        "receipt_body_present",
        "payload_type_binding",
        "payload_base64_decodable",
        "predicate_type_recognised",
        "statement_type_v1",
        "subject_arity_one",
        "signature_count_two",
        "signature_fields_present",
        "keyids_match_predicate_fingerprints",
        "predicate_body_schema",
    ];
    for name in must_be_ok {
        let entry = steps
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("trace must include step `{name}`"));
        assert_eq!(
            entry["status"].as_str(),
            Some("ok"),
            "step `{name}` must be ok on a hot-path artifact"
        );
    }

    // Cryptographic verification steps are `not-verified` (honest about
    // the absence of signature verification in the CLI). Other deferred
    // steps remain `bounded` (out-of-scope, not just unverified).
    let must_be_not_verified = ["ed25519_verify_org_a_pae", "ed25519_verify_org_b_pae"];
    for name in must_be_not_verified {
        let entry = steps
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("trace must include step `{name}`"));
        assert_eq!(
            entry["status"].as_str(),
            Some("not-verified"),
            "step `{name}` must be `not-verified` (the CLI does not verify signatures)"
        );
    }
    let must_be_bounded = [
        "capability_lease_resolution",
        "governance_receipt_resolution",
        "consistency_anchor_reconciliation",
        "peer_pin_revocation_freshness",
    ];
    for name in must_be_bounded {
        let entry = steps
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("trace must include step `{name}`"));
        assert_eq!(
            entry["status"].as_str(),
            Some("bounded"),
            "step `{name}` must be marked bounded (out of CLI verifier scope)"
        );
    }
}

/// Negative path: when `--inspect-bilateral` is omitted, the renderer
/// must NOT emit the trace (we don't want operators to think the trace
/// ran when it didn't). The dual + DSSE sections still render.
#[test]
fn receipt_explain_bilateral_without_flag_omits_trace() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_artifact_fixture(tmp.path());

    let out = Command::new(bin)
        .args([
            "--json",
            "receipt",
            "explain",
            "bilateral",
            "--input-file",
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("invoke chio receipt explain");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("renderer must emit valid JSON");
    assert_eq!(
        parsed["shape"].as_str(),
        Some("BilateralCoSignArtifacts"),
        "shape must still be detected without --inspect-bilateral"
    );
    // Trace key may exist but value must be null.
    assert!(
        parsed["bilateral_inspection_trace"].is_null()
            || parsed.get("bilateral_inspection_trace").is_none(),
        "trace must be absent or null when --inspect-bilateral is not set"
    );
}

/// The `--explain-bilateral` spelling is retained as an alias.
/// The output schema is identical to the new flag.
#[test]
fn explain_bilateral_flag_accepted_as_alias() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_artifact_fixture(tmp.path());

    let out = Command::new(bin)
        .args([
            "--json",
            "receipt",
            "explain",
            "bilateral",
            "--input-file",
            fixture.to_str().unwrap(),
            "--explain-bilateral",
        ])
        .output()
        .expect("invoke chio receipt explain with alias flag");
    assert!(
        out.status.success(),
        "--explain-bilateral alias must be accepted: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("renderer must emit valid JSON");
    let trace = &parsed["bilateral_inspection_trace"];
    assert_eq!(
        trace["trace_kind"].as_str(),
        Some("inspection"),
        "trace_kind MUST be `inspection` even when invoked via alias"
    );
}

/// Pretty-print path: when `--json` is omitted, the human renderer must
/// emit the boxed sections. We don't lock the exact text formatting,
/// but we do require the section-6 marker so operators see the conformance
/// boundary.
#[test]
fn receipt_explain_bilateral_human_renderer_marks_section6_boundary() {
    let bin = env!("CARGO_BIN_EXE_chio");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_artifact_fixture(tmp.path());

    let out = Command::new(bin)
        .args([
            "receipt",
            "explain",
            "bilateral",
            "--input-file",
            fixture.to_str().unwrap(),
            "--inspect-bilateral",
        ])
        .output()
        .expect("invoke chio receipt explain");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DualSignedReceipt"),
        "human renderer must label the legacy section: {stdout}"
    );
    assert!(
        stdout.contains("DSSE envelope"),
        "human renderer must label the section-6 section: {stdout}"
    );
    // The human renderer labels the trace as "inspection trace" with an
    // explicit warning that signatures are NOT verified. Any "verifier
    // trace" wording would mis-state what the CLI actually does.
    assert!(
        stdout.contains("inspection trace"),
        "human renderer must label the trace section as `inspection trace`: {stdout}"
    );
    assert!(
        stdout.contains("NOT cryptographically verified"),
        "human renderer must warn that signatures are not verified: {stdout}"
    );
}
