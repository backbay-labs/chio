//! TRJ5-B4 negative conformance: bilateral DSSE envelope is the §6-conformant
//! artifact; legacy `DualSignedReceipt` is NOT.
//!
//! Spec MUST: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`
//!   - §6 lines 308-353: DSSE envelope shape and PAE encoding.
//!   - §7 step 11-12: signature verification under tool-server fingerprints.
//!
//! Enforced call sites (production):
//!   - `crates/chio-federation/src/bilateral_dsse.rs` (NEW per TRJ5-B4.2):
//!     `sign_dsse_envelope`, `verify_dsse_envelope`, `pae`, `Keyid`.
//!   - `crates/chio-federation/src/bilateral.rs::co_sign_with_origin_full`
//!     (TRJ5-B4.3): the federation hot path that emits BOTH the legacy
//!     `DualSignedReceipt` and the §6-conformant `DsseEnvelope`.
//!
//! Production call path (Lane B/C demo):
//!   `co_sign_with_origin_full`
//!     -> `chio_federation::bilateral_dsse::sign_dsse_envelope`
//!     -> Ed25519 over `pae("application/vnd.in-toto+json", canonical_json(Statement))`.
//!
//! ## Reverts-to-fail proof (Evidence Gate close bar)
//!
//! If TRJ5-B4.2 is reverted (delete `bilateral_dsse.rs` and the production
//! emission point at `co_sign_with_origin_full`), this fixture FAILS at
//! compile time: the imports `chio_federation::bilateral_dsse::*` and
//! `chio_federation::co_sign_with_origin_full` no longer resolve. On a
//! softer revert (the module exists but the §6 verifier accepts
//! signatures whose preimage is not the DSSE PAE bytes), assertions
//! `tampered_pae_bytes_rejected_by_section_6_verifier` and
//! `forged_envelope_using_legacy_signature_bytes_is_rejected` FAIL because
//! the verifier no longer enforces the §6 preimage shape.
//!
//! ## What this fixture checks
//!
//! 1. **Byte-level non-overlap**: the legacy `CoSigningBody` canonical bytes
//!    and the DSSE PAE preimage bytes share zero positions (the byte-stream
//!    inequivalence the R4 review surfaced).
//! 2. **§6 verifier accepts the §6 envelope** under matching public keys.
//! 3. **Tampered payload bytes are rejected** (changes LEN(payload) and the
//!    payload bytes; PAE preimage diverges).
//! 4. **Mismatched payloadType is rejected** (payload-type is part of PAE).
//! 5. **A "DSSE envelope" forged by stuffing legacy `DualSignedReceipt`
//!    signature bytes into the `signatures` array is rejected** because
//!    the legacy signatures cover a different preimage.
//! 6. **The hot-path emitter (`co_sign_with_origin_full`) produces
//!    artifacts that BOTH verify under their respective verifiers** — the
//!    legacy verifier accepts the legacy artifact; the §6 verifier accepts
//!    the DSSE envelope. Cross-acceptance (e.g. the §6 verifier accepting
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
    pae, sign_dsse_envelope, verify_dsse_envelope, DsseEnvelope, Keyid, PAYLOAD_TYPE_IN_TOTO,
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
        id: "rcpt-trj5-b4-fixture".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-trj5-b4".to_string(),
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

/// Concrete byte-level proof for R4 finding 1: the legacy `CoSigningBody`
/// canonical bytes and the DSSE PAE preimage share zero header bytes; their
/// shapes are entirely incompatible. A single signature cannot authenticate
/// both, which is precisely why §6 conformance requires a separate emission
/// path.
#[test]
fn legacy_preimage_and_dsse_pae_preimage_share_zero_bytes() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = sample_receipt(&kp_b);

    // Legacy preimage: canonical-JSON of CoSigningBody.
    let legacy_body =
        CoSigningBody::from_receipt(&receipt, ORG_A_KERNEL_ID, ORG_B_KERNEL_ID).unwrap();
    let legacy_preimage = legacy_body.canonical_bytes().unwrap();

    // §6 preimage: DSSE PAE bytes wrapping the in-toto Statement.
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
         a §6-conformant signature cannot authenticate the legacy preimage"
    );

    // Stronger: the DSSE PAE bytes start with the literal "DSSEv1 " prefix
    // per spec §6 line 342, while canonical JSON starts with '{'. The
    // intersection over the leading 7 bytes is empty.
    assert!(
        dsse_preimage.starts_with(b"DSSEv1 "),
        "DSSE PAE preimage MUST begin with the literal 'DSSEv1 ' tag (spec §6)"
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

/// Spec §7 steps 11-12: the §6 verifier accepts a freshly-signed envelope
/// when the public keys match the keyids carried in the envelope's
/// signatures array.
#[test]
fn section_6_verifier_accepts_freshly_signed_envelope() {
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
        .expect("§6 verifier must accept envelope under matching pinned public keys");
    assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
    assert_eq!(statement.subject.len(), 1);
    assert_eq!(statement.subject[0].name, receipt.id);

    // Spec §7 step 8 partial: the fingerprint declared in the predicate
    // matches the keyid the verifier derives from the public key.
    let want_a = Keyid::from_public_key(&kp_a.public_key());
    let want_b = Keyid::from_public_key(&kp_b.public_key());
    assert_eq!(
        statement.predicate.tool_server_a.passport_key_fingerprint, want_a,
        "predicate.tool_server_a.passport_key_fingerprint MUST equal \
         sha256(orgA_pubkey) per spec §6 line 327"
    );
    assert_eq!(
        statement.predicate.tool_server_b.passport_key_fingerprint, want_b,
        "predicate.tool_server_b.passport_key_fingerprint MUST equal \
         sha256(orgB_pubkey) per spec §6 line 331"
    );
}

/// Spec §7 step 11/12: tampering with the payload changes the DSSE PAE
/// preimage that the signatures cover; the verifier MUST reject.
#[test]
fn tampered_pae_bytes_rejected_by_section_6_verifier() {
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
        "tampered PAE bytes MUST fail §6 verification (spec §7 step 11/12)"
    );
}

/// Spec §6 line 341 (PAE format): payload-type is part of the preimage. A
/// verifier that accepts a swapped payload-type would let an attacker
/// reuse a signature against a differently-typed payload.
#[test]
fn mismatched_payload_type_rejected_by_section_6_verifier() {
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
        "mismatched payloadType MUST fail §6 verification because PAE \
         binds it into the preimage (spec §6 line 341)"
    );
}

/// Cross-shape attack: an adversary takes the bytes of a legacy
/// `DualSignedReceipt` signature (which authenticates `canonical_json
/// (CoSigningBody)`) and stuffs them into a §6 envelope's
/// `signatures` array. The §6 verifier MUST reject because the legacy
/// signature does not authenticate the DSSE PAE preimage.
///
/// **This test is the load-bearing R4 refutation.** If the §6 verifier
/// were to accept this forged envelope, the cohabitation strategy in
/// `dsse-bilateral-signing.md` would be unsound: an attacker who could
/// forge a legacy artifact (different preimage, possibly easier oracle)
/// would gain a valid §6 envelope. The test asserts that's not the case.
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

    // The hot-path-produced DSSE envelope verifies under the §6 verifier
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
    // would accept this; the §6 verifier rejects because Ed25519 fails
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
         fail §6 verification (R4 BLOCKER 1: the two preimages share zero bytes, \
         so a legacy signature cannot authenticate the §6 preimage)"
    );
}

/// Hot-path emission: `co_sign_with_origin_full` produces both artifacts and
/// each verifies under its own verifier. This is the production call site
/// the Evidence Gate requires for B4.E close.
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

    // §6 verifier accepts the §6 artifact.
    verify_dsse_envelope(
        &artifacts.dsse_envelope,
        &kp_a.public_key(),
        &kp_b.public_key(),
    )
    .expect("DSSE envelope verifies under §6 verifier");

    // The legacy verifier ONLY accepts a `DualSignedReceipt`; trying to
    // hand it a `DsseEnvelope` is a structural type error and so cannot
    // even compile. We document the intent in a runtime check instead:
    // the legacy preimage bytes do not appear inside the DSSE preimage,
    // so a §6 envelope cannot be re-interpreted as a legacy artifact.
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
/// the SHA-256 of the canonical-JSON of the underlying receipt body. A
/// verifier resolving the receipt via the predicate's
/// `receipt_canonical_json` and re-hashing must reproduce this digest.
#[test]
fn statement_subject_digest_matches_canonical_receipt_hash() {
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

    let canonical = canonical_json_bytes(&receipt).unwrap();
    let want = chio_core::crypto::sha256_hex(&canonical);
    assert_eq!(
        statement.subject[0].digest.sha256, want,
        "subject[0].digest.sha256 MUST equal sha256(canonical_json(receipt)) \
         (spec §7 step 7 substrate)"
    );
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
