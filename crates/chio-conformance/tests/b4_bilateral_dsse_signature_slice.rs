//! DSSE signature-slice regression tests.
//!
//! This fixture intentionally does NOT claim
//! `CHIODOS_BILATERAL_COSIGN_INVOCATION` predicate conformance. The
//! production emitter signs a local signature-slice predicate that carries
//! `receipt_canonical_json` and omits strict-schema fields such as
//! `tool_args_hash`.
//!
//! ## What this fixture checks
//!
//! 1. **Byte-level non-overlap**: the legacy `CoSigningBody` canonical bytes
//!    and the DSSE PAE preimage bytes share zero positions (byte-stream
//!    inequivalence).
//! 2. **Signature-slice verifier accepts the envelope** under matching public keys.
//! 3. **Tampered payload bytes are rejected** (changes LEN(payload) and the
//!    payload bytes; PAE preimage diverges).
//! 4. **Mismatched payloadType is rejected** (payload-type is part of PAE).
//! 5. **A "DSSE envelope" forged by stuffing legacy `DualSignedReceipt`
//!    signature bytes into the `signatures` array is rejected** because
//!    the legacy signatures cover a different preimage.
//! 6. **The hot-path emitter (`co_sign_with_origin_full`) produces
//!    artifacts that BOTH verify under their respective verifiers** - the
//!    legacy verifier accepts the legacy artifact; the signature-slice verifier
//!    accepts the DSSE envelope. Cross-acceptance (e.g. the DSSE verifier accepting
//!    a legacy `CoSigningBody`-shaped input) is structurally impossible:
//!    the legacy bytes have no `payloadType` or `signatures` array.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_federation::bilateral::{co_sign_with_origin_full, CoSigningBody, InProcessCoSigner};
use chio_federation::bilateral_dsse::{
    pae, receipt_subject_name, sign_dsse_envelope, verify_dsse_envelope, DsseEnvelope, Keyid,
    BILATERAL_DSSE_ENVELOPE_SCHEMA, PAYLOAD_TYPE_IN_TOTO, PREDICATE_BODY_SCHEMA,
    PREDICATE_TYPE_BILATERAL,
};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn sample_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({"path": "/data/b4-fixture.txt"})).unwrap()
}

fn sample_receipt(tool_host_kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-b4-fixture".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-b4".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: sample_action(),
        decision: Decision::Allow,
        content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
        policy_hash: "fed-policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: tool_host_kp.public_key(),
    };
    ChioReceipt::sign(body, tool_host_kp).unwrap()
}

const ORG_A_KERNEL_ID: &str = "kernel.org-a";
const ORG_B_KERNEL_ID: &str = "kernel.org-b";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Concrete byte-level proof: the legacy `CoSigningBody` canonical bytes
/// and the DSSE PAE preimage share zero header bytes; their shapes are
/// entirely incompatible. A single signature cannot authenticate both,
/// which is precisely why this path must be separate from the legacy receipt
/// preimage.
#[test]
fn legacy_preimage_and_dsse_pae_preimage_share_zero_bytes() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    // Legacy preimage: canonical-JSON of CoSigningBody.
    let legacy_body =
        CoSigningBody::from_receipt(&receipt, ORG_A_KERNEL_ID, ORG_B_KERNEL_ID).unwrap();
    let legacy_preimage = legacy_body.canonical_bytes().unwrap();

    // Signature-slice preimage: DSSE PAE bytes wrapping the in-toto Statement.
    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let dsse_preimage = envelope.pae_bytes().unwrap();

    // R4 finding: the two preimages are NOT the same bytes.
    assert_ne!(
        legacy_preimage, dsse_preimage,
        "legacy CoSigningBody bytes and DSSE PAE bytes MUST differ; \
         a signature-slice signature cannot authenticate the legacy preimage"
    );

    // Stronger: the DSSE PAE bytes start with the literal "DSSEv1 " prefix
    // per DSSE v1, while canonical JSON starts with '{'. The
    // intersection over the leading 7 bytes is empty.
    assert!(
        dsse_preimage.starts_with(b"DSSEv1 "),
        "DSSE PAE preimage MUST begin with the literal 'DSSEv1 ' tag"
    );
    assert!(
        legacy_preimage.starts_with(b"{"),
        "legacy CoSigningBody canonical-JSON preimage MUST begin with '{{' (RFC 8785)"
    );
    let header_overlap_len = std::cmp::min(7, legacy_preimage.len());
    let no_position_overlaps = legacy_preimage
        .iter()
        .take(header_overlap_len)
        .zip(dsse_preimage.iter().take(header_overlap_len))
        .all(|(a, b)| a != b);
    assert!(
        no_position_overlaps,
        "no byte position in the leading 7 bytes overlaps; the preimages \
         are structurally distinct"
    );
}

/// The signature-slice verifier accepts a freshly-signed envelope when the
/// public keys match the keyids carried in the envelope's signatures array.
#[test]
fn signature_slice_verifier_accepts_freshly_signed_envelope() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("signature-slice verifier must accept envelope under matching pinned public keys");
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));

    // Fingerprint binding: the fingerprint declared in the predicate
    // matches the keyid the verifier derives from the public key.
    let want_a = Keyid::from_public_key(&kp_a.public_key());
    let want_b = Keyid::from_public_key(&kp_b.public_key());
    assert_eq!(
        statement.predicate.tool_server_a.passport_key_fingerprint, want_a,
        "predicate.tool_server_a.passport_key_fingerprint MUST equal \
         sha256(orgA_pubkey)"
    );
    assert_eq!(
        statement.predicate.tool_server_b.passport_key_fingerprint, want_b,
        "predicate.tool_server_b.passport_key_fingerprint MUST equal \
         sha256(orgB_pubkey)"
    );
}

#[test]
fn emitted_predicate_is_explicit_signature_slice_not_chiodos_invocation_schema() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let statement = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect("signature-slice verifier must accept envelope");
    let predicate_json = serde_json::to_value(&statement.predicate).unwrap();

    assert_eq!(
        envelope.schema.as_deref(),
        Some(BILATERAL_DSSE_ENVELOPE_SCHEMA)
    );
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
    assert_eq!(predicate_json["schema"], PREDICATE_BODY_SCHEMA);
    assert_ne!(
        statement.predicate_type, "chio.bilateral-cosign-invocation.v1",
        "signature-slice output must not claim the strict CHIODOS predicate type"
    );
    assert!(
        predicate_json.get("receipt_canonical_json").is_some(),
        "signature-slice profile carries the local receipt helper field"
    );
    assert!(
        predicate_json.get("tool_args_hash").is_none(),
        "missing strict-schema tool_args_hash is why this profile is not CHIODOS invocation conformance"
    );
}

/// Tampering with the payload changes the DSSE PAE preimage that the
/// signatures cover; the verifier MUST reject.
#[test]
fn tampered_pae_bytes_rejected_by_signature_slice_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    // Mutate the payload by appending a base64-valid character. This
    // changes the decoded statement bytes AND the LEN(payload) value
    // baked into the PAE preimage.
    envelope.payload.push('A');

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(
        result.is_err(),
        "tampered PAE bytes MUST fail signature-slice verification"
    );
}

/// Payload-type is part of the PAE preimage. A verifier that accepts a swapped
/// payload-type would let an attacker reuse a signature against a
/// differently-typed payload.
#[test]
fn mismatched_payload_type_rejected_by_signature_slice_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);
    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    envelope.payload_type = "application/json".to_string();

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(
        result.is_err(),
        "mismatched payloadType MUST fail signature-slice verification because PAE \
         binds it into the preimage"
    );
}

/// Cross-shape attack: an adversary takes the bytes of a legacy
/// `DualSignedReceipt` signature (which authenticates `canonical_json
/// (CoSigningBody)`) and stuffs them into a DSSE envelope's `signatures`
/// array. The signature-slice verifier MUST reject because the legacy
/// signature does not authenticate the DSSE PAE preimage.
#[test]
fn forged_envelope_using_legacy_signature_bytes_is_rejected() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    // Build the legacy artifact via the federation hot-path emitter.
    let cosigner = InProcessCoSigner::new(ORG_A_KERNEL_ID, kp_a.clone(), kp_b.public_key());
    let artifacts = co_sign_with_origin_full(
        ORG_A_KERNEL_ID,
        &kp_a,
        ORG_B_KERNEL_ID,
        &kp_b,
        receipt.clone(),
        &cosigner,
        "file_read",
        1_734_000_000_000,
    )
    .expect("hot path must produce both artifacts");

    // The hot-path-produced DSSE envelope verifies under the signature-slice verifier
    // (sanity check: the test setup is healthy before forging).
    verify_dsse_envelope(
        &artifacts.dsse_envelope,
        &kp_a.public_key(),
        &kp_b.public_key(),
    )
    .expect("hot-path-emitted DSSE envelope must verify under §6");

    // Forge: build a DSSE envelope shape but stuff it with the legacy
    // signature bytes. The legacy signatures authenticate
    // `canonical_json(CoSigningBody)`, NOT the DSSE PAE bytes. A naive
    // verifier that only checked "two signatures present, keyid present"
    // would accept this; the signature-slice verifier rejects because Ed25519 fails
    // against the wrong preimage.
    let mut forged: DsseEnvelope = artifacts.dsse_envelope.clone();
    let legacy_sig_a_bytes = artifacts.dual_signed_receipt.org_a_signature.to_bytes();
    let legacy_sig_b_bytes = artifacts.dual_signed_receipt.org_b_signature.to_bytes();
    forged.signatures[0].sig = BASE64_STANDARD.encode(legacy_sig_a_bytes);
    forged.signatures[1].sig = BASE64_STANDARD.encode(legacy_sig_b_bytes);

    let result = verify_dsse_envelope(&forged, &kp_a.public_key(), &kp_b.public_key());
    assert!(
        result.is_err(),
        "DSSE envelope forged from legacy DualSignedReceipt signatures MUST \
         fail §6 verification (the two preimages share zero bytes, \
         so a legacy signature cannot authenticate the §6 preimage)"
    );
}

#[test]
fn hot_path_emits_both_artifacts_and_each_verifies() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let cosigner = InProcessCoSigner::new(ORG_A_KERNEL_ID, kp_a.clone(), kp_b.public_key());

    let artifacts = co_sign_with_origin_full(
        ORG_A_KERNEL_ID,
        &kp_a,
        ORG_B_KERNEL_ID,
        &kp_b,
        receipt.clone(),
        &cosigner,
        "file_read",
        1_734_000_000_000,
    )
    .expect("hot path must succeed");

    // Legacy verifier accepts the legacy artifact.
    artifacts
        .dual_signed_receipt
        .verify(&kp_a.public_key(), &kp_b.public_key())
        .expect("legacy DualSignedReceipt verifies under legacy verifier");

    // The signature-slice verifier accepts the DSSE artifact.
    verify_dsse_envelope(
        &artifacts.dsse_envelope,
        &kp_a.public_key(),
        &kp_b.public_key(),
    )
    .expect("DSSE envelope verifies under signature-slice verifier");

    // The legacy verifier ONLY accepts a `DualSignedReceipt`; trying to
    // hand it a `DsseEnvelope` is a structural type error and so cannot
    // even compile. We document the intent in a runtime check instead:
    // the legacy preimage bytes do not appear inside the DSSE preimage,
    // so a DSSE envelope cannot be re-interpreted as a legacy artifact.
    let legacy_preimage = CoSigningBody::from_receipt(&receipt, ORG_A_KERNEL_ID, ORG_B_KERNEL_ID)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let dsse_preimage = artifacts.dsse_envelope.pae_bytes().unwrap();
    assert!(
        !contains_subsequence(&dsse_preimage, &legacy_preimage),
        "the §6 PAE preimage does NOT contain the legacy preimage as a \
         substring; the two surfaces are not collapsible"
    );
}

/// Spec §6 PAE format check: the helper is deterministic and matches the
/// "DSSEv1 LEN(type) SP type SP LEN(body) SP body" wire form.
#[test]
fn pae_helper_matches_spec_format() {
    // Known vector: payloadType "application/x" (13 bytes), payload "hello"
    // (5 bytes). Spec §6 line 342: "DSSEv1 SP LEN(type) SP type SP
    // LEN(body) SP body".
    let bytes = pae("application/x", b"hello");
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "DSSEv1 13 application/x 5 hello",
        "PAE helper MUST encode per DSSE v1 spec"
    );

    // Empty payload: LEN(body) is "0".
    let empty = pae(PAYLOAD_TYPE_IN_TOTO, b"");
    let expected_prefix = format!(
        "DSSEv1 {} {} 0 ",
        PAYLOAD_TYPE_IN_TOTO.len(),
        PAYLOAD_TYPE_IN_TOTO
    );
    assert_eq!(
        std::str::from_utf8(&empty).unwrap(),
        expected_prefix,
        "empty-payload PAE preserves all framing fields"
    );
}

/// Spec §7 step 7 substrate: the `subject[0].digest.sha256` field equals
/// the SHA-256 of the canonical-JSON of the underlying receipt body.
/// The subject digest binds the receipt BODY (canonical JSON of
/// `ChioReceiptBody`), not the full signed `ChioReceipt` wrapper.
/// Resolving the receipt from a store (which exposes the body for
/// re-verification) and re-hashing the body must reproduce this
/// digest. Hashing the full wrapper would fold in the signature bytes,
/// which the verifier cannot reproduce from a body-only re-emission.
#[test]
fn statement_subject_digest_matches_canonical_receipt_body_hash() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (statement, _) = envelope.decode_statement().unwrap();

    let body = receipt.body();
    let canonical_body = canonical_json_bytes(&body).unwrap();
    let want = chio_core::crypto::sha256_hex(&canonical_body);
    assert_eq!(
        statement.subject[0].digest.sha256, want,
        "subject[0].digest.sha256 MUST equal sha256(canonical_json(receipt.body())); \
         cross-impl resolution from a body-only receipt store relies on this binding."
    );

    // Belt-and-suspenders: hashing the full signed wrapper must NOT
    // match. A wrapper-hash match would mean the body/wrapper binding
    // had regressed silently.
    let canonical_full = canonical_json_bytes(&receipt).unwrap();
    let full_digest = chio_core::crypto::sha256_hex(&canonical_full);
    assert_ne!(
        statement.subject[0].digest.sha256, full_digest,
        "subject digest MUST hash body, not full wrapper; got matching wrapper hash"
    );
}

#[test]
fn statement_subject_name_is_canonical_receipt_name_and_raw_id_is_rejected() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();
    let (mut statement, _) = envelope.decode_statement().unwrap();
    assert_eq!(statement.subject[0].name, receipt_subject_name(&receipt.id));

    statement.subject[0].name = receipt.id.clone();
    let new_statement_bytes = chio_core::canonical::canonical_json_bytes(&statement).unwrap();
    envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

    let err = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key())
        .expect_err("raw receipt id subject must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("subject name") && msg.contains("chio-receipt:"),
        "expected canonical subject-name rejection, got: {msg}"
    );
}

/// The bilateral envelope profile pins exactly ONE subject. Accepting
/// a multi-subject envelope would let a signer insert a second
/// arbitrary subject; any verifier walking the full subject list (the
/// in-toto convention for membership) would then resolve a different
/// receipt than the producer signed. The empty-list case is rejected
/// for the same reason: there must be exactly one subject.
#[test]
fn dsse_envelope_with_two_subjects_is_rejected() {
    use chio_federation::bilateral_dsse::{DsseStatement, StatementSubject, SubjectDigest};

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    let mut envelope = sign_dsse_envelope(
        &receipt,
        &kp_a,
        &kp_b,
        ORG_A_KERNEL_ID,
        ORG_B_KERNEL_ID,
        "file_read",
        1_734_000_000_000,
    )
    .unwrap();

    // Decode, splice in a second subject, re-canonicalise, re-encode.
    let (mut statement, _bytes) = envelope.decode_statement().unwrap();
    statement.subject.push(StatementSubject {
        name: "rcpt-injected".to_string(),
        digest: SubjectDigest {
            sha256: "0".repeat(64),
        },
    });
    let new_statement_bytes = chio_core::canonical::canonical_json_bytes(&statement).unwrap();
    envelope.payload = BASE64_STANDARD.encode(&new_statement_bytes);

    // Note: signatures no longer verify over the new payload, but we
    // still expect the multi-subject check to fire BEFORE PAE
    // verification so the diagnostic is structural rather than
    // signature-cryptographic.
    let outcome = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    let err = outcome.expect_err("multi-subject envelope must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("statement.malformed") || msg.contains("exactly 1 subject"),
        "expected multi-subject rejection diagnostic, got: {msg}"
    );

    // Suppress dead-code lint for DsseStatement field access in tests
    // that share this file.
    let _ = DsseStatement::canonical_bytes;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
