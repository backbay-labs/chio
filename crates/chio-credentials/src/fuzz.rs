//! libFuzzer entry-point module.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the
//! standalone `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-credentials` never pulls in `arbitrary`, never exposes these
//! symbols, and never gets recompiled with libFuzzer instrumentation.
//!
//! The entry point [`fuzz_jwt_vc_verify`] consumes arbitrary bytes
//! and drives them through [`crate::verify_chio_passport_jwt_vc_json`], the
//! Chio-flavoured JWT-VC trust boundary. The verifier is fail-closed by
//! construction (every invalid input must surface as
//! `Err(CredentialError::*)`, never a panic), so this fuzz target exists to
//! catch parse-path regressions in the compact-JWT decoder, base64url path,
//! `serde_json` decoder, and downstream schema-shape checks.
//!
//! Cleanup C6: arbitrary fuzzer bytes can almost never produce a valid
//! Ed25519 signature against the fixed-issuer keypair, so the verifier
//! always returns at the signature-check step before reaching the
//! payload-shape branch (`vc` typed-claim shape, `cnf.jwk`,
//! `iat`/`nbf`/`exp` consistency). To get coverage on those paths
//! WITHOUT producing valid signatures, we additionally drive the same
//! bytes through `serde_json::from_slice` against the typed envelope and
//! verification structs ([`ChioPassportJwtVcJsonEnvelope`] and
//! [`ChioPassportJwtVcJsonVerification`]). Both have `deny_unknown_fields`
//! semantics on every nested struct, so this exercise hardens the
//! schema layer that the signature gate would otherwise hide. The
//! `Result` is discarded on purpose: any panic surfaces as a libFuzzer
//! crash; `Err(_)` is the fail-closed expected result.
//!
//! The issuer keypair is fixed via [`Keypair::from_seed`] with a constant
//! 32-byte seed, wrapped in a [`OnceLock`] so the keypair is materialised
//! once per fuzzer process. Varying the issuer key across iterations would
//! mask parse-path failures behind signature-mismatch errors that the
//! verifier reports before reaching the body of the JWT-VC schema check.

use std::sync::OnceLock;

use chio_core::{Keypair, PublicKey};

use crate::{
    verify_chio_passport_jwt_vc_json, verify_oid4vp_direct_post_response,
    ChioPassportJwtVcJsonEnvelope, ChioPassportJwtVcJsonVerification, Oid4vpDcqlQuery,
    Oid4vpRequestObject, Oid4vpRequestedCredential, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    CHIO_PASSPORT_SD_JWT_VC_TYPE, OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI,
    OID4VP_RESPONSE_MODE_DIRECT_POST_JWT, OID4VP_RESPONSE_TYPE_VP_TOKEN,
};

/// Deterministic 32-byte seed used to materialise the test issuer keypair.
/// Fixed so the corpus surface is stable across libFuzzer runs.
const FUZZ_ISSUER_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fixed `now` clock value. Sits inside the validity window of any seed that
/// chooses to set realistic `iat`/`nbf`/`exp` claims, but the verifier's
/// time-claim path is reachable from arbitrary bytes regardless.
const FUZZ_NOW: u64 = 1_710_000_200;

/// Build the issuer public key once per process. `Keypair::from_seed` is
/// infallible for a fixed 32-byte seed, so this is guaranteed to succeed.
fn issuer_public_key() -> &'static PublicKey {
    static ISSUER: OnceLock<PublicKey> = OnceLock::new();
    ISSUER.get_or_init(|| Keypair::from_seed(&FUZZ_ISSUER_SEED).public_key())
}

/// Drive arbitrary bytes through the Chio JWT-VC verify trust boundary.
///
/// Bytes are interpreted as a UTF-8 compact-JWT string. Non-UTF-8 inputs are
/// dropped early; well-formed UTF-8 (including UTF-8 garbage) is forwarded
/// to [`verify_chio_passport_jwt_vc_json`], whose result is intentionally
/// discarded. The trust-boundary contract guarantees the only outcomes are
/// `Err(CredentialError::*)` (good) or a panic / abort (which libFuzzer
/// surfaces as a crash). No arbitrary input can produce `Ok(_)` because the
/// signature check requires a key controlled by the issuer keypair above.
///
/// Cleanup C6: arbitrary fuzzer bytes essentially never produce a valid
/// Ed25519 signature, so the verifier always returns at the
/// signature-check step before reaching the payload-shape branches
/// (`vc` typed-claim shape, `cnf.jwk`, `iat`/`nbf`/`exp` consistency).
/// We therefore additionally drive the same bytes through
/// `serde_json::from_slice` against the typed envelope and
/// verification-result structs so the schema layer
/// (`deny_unknown_fields` plus camelCase rename plus typed
/// `PortableEd25519Jwk` decode) gets exercised on every iteration.
/// The `Result`s are discarded; panics are the only fuzz finding.
pub fn fuzz_jwt_vc_verify(data: &[u8]) {
    // Trust-boundary path: compact-JWT string -> verify pipeline.
    if let Ok(compact) = std::str::from_utf8(data) {
        let _ = verify_chio_passport_jwt_vc_json(compact, issuer_public_key(), FUZZ_NOW);
    }

    // Schema-shape paths: typed deserialization for envelope and
    // verification-result structs. These cover the JWT-VC schema layer
    // that the signature gate hides on the verify path. Both structs
    // declare `serde(rename_all = "camelCase")` plus
    // `deny_unknown_fields` semantics on every nested struct.
    let _ = serde_json::from_slice::<ChioPassportJwtVcJsonEnvelope>(data);
    let _ = serde_json::from_slice::<ChioPassportJwtVcJsonVerification>(data);
}

/// Stable Chio OID4VP verifier identifier used for the fuzz request fixture.
/// All endpoint URLs in the fixture are rooted at this issuer so
/// [`Oid4vpRequestObject::validate`] succeeds; the OID4VP fail-closed
/// contract then guarantees that arbitrary bytes routed through the response
/// verifier cannot produce `Ok(_)` (the holder-binding signature check will
/// always reject them).
const FUZZ_VERIFIER_CLIENT_ID: &str = "https://verifier.fuzz.chio";

/// Fixed request-object fixture passed to the OID4VP response verifier on
/// every fuzz iteration. Built lazily and cached so each iteration sees the
/// same constant request shape; varying the request would mask response
/// parse-path failures behind nonce/state/audience mismatches that the
/// verifier reports before reaching the embedded VP-token decode path.
fn oid4vp_request_fixture() -> &'static Oid4vpRequestObject {
    static REQUEST: OnceLock<Oid4vpRequestObject> = OnceLock::new();
    REQUEST.get_or_init(|| Oid4vpRequestObject {
        client_id: FUZZ_VERIFIER_CLIENT_ID.to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: format!("{FUZZ_VERIFIER_CLIENT_ID}/oid4vp/response"),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "fuzz-nonce".to_string(),
        state: "fuzz-state".to_string(),
        iat: FUZZ_NOW.saturating_sub(60),
        exp: FUZZ_NOW.saturating_add(86_400),
        jti: "fuzz-request-id".to_string(),
        request_uri: format!("{FUZZ_VERIFIER_CLIENT_ID}/oid4vp/request/fuzz"),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "fuzz-credential".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: Vec::new(),
                issuer_allowlist: Vec::new(),
            }],
        },
        identity_assertion: None,
    })
}

/// Drive arbitrary bytes through the Chio OID4VP presentation-response
/// verify trust boundary.
///
/// Bytes are interpreted as a UTF-8 compact-JWT string carrying a
/// `direct_post.jwt` OID4VP response (see
/// `crates/chio-credentials/src/oid4vp.rs::verify_oid4vp_direct_post_response`).
/// The verifier parses three base64url segments, decodes the header and
/// payload as JSON, decodes the embedded `vp_token` as an SD-JWT VC, and
/// verifies the holder-binding signature against the credential's `cnf.jwk`.
/// Every step is fail-closed: arbitrary bytes can only surface as
/// `Err(CredentialError::InvalidOid4vp{Request,Response,...})` or as a panic
/// or abort that libFuzzer reports as a crash.
///
/// A constant [`Oid4vpRequestObject`] fixture pins `client_id`, `nonce`,
/// `state`, `response_uri`, the credential `id/format/vct`, and the
/// validity window. The fixture's nonce/state/audience guarantee that no
/// arbitrary byte stream can satisfy the post-decode equality checks, so
/// `Ok(_)` is unreachable. The issuer key is the same fixture-controlled
/// keypair as [`fuzz_jwt_vc_verify`] for symmetry across the two targets.
pub fn fuzz_oid4vp_presentation(data: &[u8]) {
    let Ok(compact) = std::str::from_utf8(data) else {
        return;
    };
    // Errors are discarded by design; we are exercising the parse path.
    let _ = verify_oid4vp_direct_post_response(
        compact,
        oid4vp_request_fixture(),
        issuer_public_key(),
        FUZZ_NOW,
    );
}
