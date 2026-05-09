// Threat test for threat ID `tee_quote_forgery`.
//
// Threat: tee_quote_forgery (TEE quote forgery or misbinding).
// Surfaces: hosted_mcp, native_chio.
//
// Coverage strategy: import the production
// `chio_tee_frame::schema::{validate_signed, verify_tenant_sig}`
// functions directly. Build a `chio_tee_frame::Frame` and sign its
// canonical-JSON payload with a known tenant keypair. Then exercise
// four forgery / misbinding deny branches:
//
//   1. Verifier-key swap. Present the genuinely-signed frame to a
//      verifier holding a different tenant public key. The
//      production `validate_signed` MUST return
//      `SchemaError::TenantSigVerification`.
//   2. Tampered body. Mutate `request_blob_sha256` after signing.
//      The canonical-JSON payload no longer matches the signature
//      and `validate_signed` MUST reject with
//      `SchemaError::TenantSigVerification`.
//   3. Forged signature. Replace `tenant_sig` with random 64-byte
//      data. `verify_tenant_sig` MUST reject with
//      `SchemaError::TenantSigVerification`.
//   4. Cross-TEE misbinding (rebinding attack). Take a frame
//      genuinely signed for one tee_id and swap the tee_id to a
//      different TEE while keeping the original signature. The
//      attacker is replaying a valid quote against the wrong TEE
//      principal; canonical-JSON includes tee_id, so the signature
//      no longer verifies under the genuine public key and
//      `validate_signed` MUST reject with
//      `SchemaError::TenantSigVerification`. This is a distinct
//      production deny path from #2 (request_blob_sha256) because
//      it pins the threat-row's "or misbinding" sub-vector
//      separately from generic body tampering.
//
// Production call sites:
//   `crates/chio-tee-frame/src/schema.rs:93` (`validate_signed`).
//   `crates/chio-tee-frame/src/schema.rs:117` (`verify_tenant_sig`).

use std::path::PathBuf;

use base64::Engine;
use chio_core::crypto::Keypair;
use chio_tee_frame::frame::{Frame, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use chio_tee_frame::schema::{
    signing_payload, validate_signed, verify_tenant_sig, SchemaError, SCHEMA_VERSION,
};

const VALIDATOR_EVIDENCE_FILES: &[(&str, Option<&str>)] = &[
    (
        "crates/chio-attest-verify/tests/cross_backend_conformance.rs",
        Some("nitro_backend_rejects_tdx_and_sev_snp_fixtures"),
    ),
    (
        "crates/chio-attest-verify/tests/expect_report_data.rs",
        Some("tdx_verifier_rejects_when_only_upper_half_of_report_data_is_tampered"),
    ),
    (
        "crates/chio-attest-verify/tests/tdx_integration.rs",
        Some("negative_fixtures_reject_with_expected_reason"),
    ),
    (
        "crates/chio-attest-verify/tests/sev_snp_integration.rs",
        Some("negative_fixtures_reject_with_expected_reason"),
    ),
    (
        "crates/chio-attest-verify/tests/nitro_unit.rs",
        Some("nitro_verifier_rejects_signature_mismatch"),
    ),
    (
        "crates/chio-attest-verify/tests/nitro_root_rotation.rs",
        Some("root_rotation_rejects_fixtures_anchored_at_old_root"),
    ),
    (
        "crates/chio-kernel/tests/pq_key_load_after_self_quote.rs",
        Some("allow_hybrid_loads_pq_only_after_verified_self_quote"),
    ),
];

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn unsigned_frame() -> Frame {
    Frame {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        ts: "2026-05-08T00:00:00.000Z".to_string(),
        tee_id: "tee-prod-1".to_string(),
        upstream: Upstream {
            system: UpstreamSystem::Openai,
            operation: "responses.create".to_string(),
            api_version: "2026-05-01".to_string(),
        },
        invocation: serde_json::json!({"tool":"x"}),
        provenance: Provenance {
            otel: Otel {
                trace_id: "0".repeat(32),
                span_id: "0".repeat(16),
            },
            supply_chain: None,
        },
        request_blob_sha256: "a".repeat(64),
        response_blob_sha256: "b".repeat(64),
        redaction_pass_id: "test-redactors@1.0.0".to_string(),
        verdict: Verdict::Allow,
        deny_reason: None,
        would_have_blocked: false,
        // Placeholder while we compute the canonical signing payload.
        tenant_sig: format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 64])
        ),
    }
}

fn signed_frame() -> (Frame, [u8; 32]) {
    let keypair = Keypair::from_seed(&[0x42u8; 32]);
    let public_key = *keypair.public_key().as_bytes();
    let mut frame = unsigned_frame();
    let payload = match signing_payload(&frame) {
        Ok(payload) => payload,
        Err(err) => panic!("signing_payload: {err}"),
    };
    let signature = keypair.sign(&payload);
    frame.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    (frame, public_key)
}

#[test]
fn threat_tee_quote_forgery_wrong_tenant_key_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: the frame is genuinely signed by the legitimate
    // tenant key, but a misbinding causes the verifier to use a
    // different tenant's public key (e.g. tenant_id swap). The
    // production validate_signed MUST reject.
    let (frame, _genuine_pk) = signed_frame();
    let attacker_pk = *Keypair::from_seed(&[0xAAu8; 32]).public_key().as_bytes();
    assert_ne!(_genuine_pk, attacker_pk);

    let err = match validate_signed(&frame, &attacker_pk) {
        Ok(()) => panic!(
            "validate_signed MUST reject when the tenant public key does \
             not match the signing key (misbinding); got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on key mismatch, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_tampered_body_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: an attacker post-signing alters the request
    // blob hash to claim a different attestation payload. The
    // canonical-JSON signing payload no longer matches the signature.
    let (mut frame, public_key) = signed_frame();
    frame.request_blob_sha256 = "c".repeat(64);

    let err = match validate_signed(&frame, &public_key) {
        Ok(()) => panic!(
            "validate_signed MUST reject when the request_blob_sha256 \
             field has been tampered with after signing; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on tampered body, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_forged_signature_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: an attacker constructs a frame and substitutes
    // a 64-byte blob of their choosing for `tenant_sig`. The signature
    // surface MUST reject because no Ed25519 signature over the
    // canonical-JSON body can match a forged byte sequence under the
    // genuine tenant's public key.
    let (_legit_frame, public_key) = signed_frame();
    let mut forged = unsigned_frame();
    forged.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode([0xFFu8; 64])
    );

    let err = match verify_tenant_sig(&forged, &public_key) {
        Ok(()) => panic!("verify_tenant_sig MUST reject a forged 64-byte signature; got Ok"),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on forged sig, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_cross_tee_misbinding_rejected() {
    // covers: tee_quote_forgery (misbinding sub-vector)
    //
    // Attacker scenario: a quote genuinely signed for tee-prod-1 is
    // replayed against a session that claims tee-prod-2. The
    // attacker swaps the `tee_id` field after signing while keeping
    // the original `tenant_sig`. Because canonical-JSON includes
    // tee_id, the signing payload no longer matches the signature
    // under the genuine tenant public key; `validate_signed` MUST
    // reject. This pins the threat-row's "or misbinding" half of
    // its name as a distinct deny path from #2 (request_blob_sha256
    // tampering, which is a generic body-tamper case rather than a
    // cross-TEE binding violation).
    //
    // Revert-to-prove-it-fails recipe: replace the signature
    // verification in `chio_tee_frame::schema::verify_tenant_sig`
    // with `Ok(())` (or short-circuit before
    // `public_key.verify(&payload, &signature)` returns false), and
    // this assertion will flip from a pass to a panic because the
    // misbound frame would be admitted.
    let (mut frame, public_key) = signed_frame();
    assert_eq!(
        frame.tee_id, "tee-prod-1",
        "test fixture invariant: signed_frame() must build a tee-prod-1 frame so the misbinding swap produces a distinct canonical-JSON payload"
    );
    frame.tee_id = "tee-prod-2".to_string();

    let err = match validate_signed(&frame, &public_key) {
        Ok(()) => panic!(
            "validate_signed MUST reject when tee_id has been rebound \
             after signing (cross-TEE misbinding); got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on tee_id rebinding, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_validator_evidence_files_remain_in_tree() {
    // covers: tee_quote_forgery
    //
    // Defense-in-depth pin: the threat-model JSON's `covered_by_tests`
    // array names the Nitro / TDX / SEV-SNP integration suites and
    // the kernel self-quote gate fixture as the production-test
    // surfaces for this threat. The conformance test arms above only
    // exercise the chio-tee-frame tenant-signature surface; this
    // test asserts the cited validator-side evidence files remain
    // in-tree so a regression that deletes or guts them trips this
    // gate before the threat-row evidence claims `caught: 4` again.
    for (evidence, needle) in VALIDATOR_EVIDENCE_FILES {
        let path = repo_path(evidence);
        assert!(
            path.is_file(),
            "TEE quote-validator evidence file {} must remain in-tree \
             (cited by spec/security/chio-threat-model.v1.json \
             tee_quote_forgery covered_by_tests)",
            path.display()
        );
        if let Some(needle) = needle {
            let raw = match std::fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(err) => panic!("read {}: {err}", path.display()),
            };
            assert!(
                raw.contains(needle),
                "{} must mention named fixture {needle:?} so the \
                 self-quote gate evidence stays pinned",
                path.display()
            );
        }
    }
}

#[test]
fn threat_tee_quote_forgery_genuine_frame_round_trips() {
    // covers: tee_quote_forgery
    //
    // Sanity arm: a frame correctly signed by the legitimate tenant
    // key passes validate_signed under that same key. Guards against
    // a deny path that over-rejects valid evidence.
    let (frame, public_key) = signed_frame();
    if let Err(err) = validate_signed(&frame, &public_key) {
        panic!(
            "legitimate signed frame MUST validate (otherwise the deny \
             guard is over-rejecting); got {err:?}"
        );
    }
}
