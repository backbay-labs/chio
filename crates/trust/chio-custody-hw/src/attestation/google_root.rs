//! Pinned Play Integrity verifier key material.
//!
//! The Play Integrity verifier pins its trust anchor here rather than
//! trusting a caller-supplied JWKS. [`play_integrity_pinned_jwks_json`]
//! returns the JWKS the production verification path uses; the signing key
//! and the caller-supplied-JWKS test helpers below are compiled only under
//! `cfg(test)` or the `dev-fixtures` feature so a shipped binary cannot mint
//! its own Play Integrity tokens or swap in a different verification key.
//!
//! ============================================================================
//! SECURITY / PLACEHOLDER: the pinned key material below is NOT a
//! real Google key. It is the SYNTHETIC FIXTURE key whose private half is
//! committed in this file. See the block on the pinned constants and the
//! [`assert_play_integrity_root_is_production_ready`] startup guard before
//! shipping. DO NOT deploy this crate to production with the fixture key in
//! place.
//! ============================================================================

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use jsonwebtoken::DecodingKey;
#[cfg(any(test, feature = "dev-fixtures"))]
use jsonwebtoken::EncodingKey;

// =============================================================================
// SECURITY / PLACEHOLDER - READ BEFORE ANY PRODUCTION DEPLOYMENT
// =============================================================================
//
// The `PLAY_INTEGRITY_PINNED_X_B64` / `PLAY_INTEGRITY_PINNED_Y_B64` coordinates
// and the `GOOGLE_PLAY_INTEGRITY_ROOT_KID` ("chio-play-integrity-fixture-root")
// below are a *** SYNTHETIC FIXTURE KEY ***, NOT Google's real Play Integrity
// verification key. They are byte-identical to the development/test signer, and
// the matching PRIVATE KEY is committed in this very file
// (`PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM`). Because the production verification
// path pins exactly this key set, a binary built today would "trust" a key whose
// private half lives in version control - i.e. anyone with repo access could mint
// Play Integrity tokens the verifier accepts.
//
// BEFORE ANY PRODUCTION DEPLOYMENT:
//   1. REPLACE the pinned coordinates + kid below with Google's real Play
//      Integrity public verification keys (rotate `GOOGLE_PLAY_INTEGRITY_ROOT_KID`
//      off the `*-fixture-root` placeholder value).
//   2. REMOVE / ROTATE the committed fixture private key - it must never coexist
//      with a real pinned root, and the fixture signer must stay test/dev-only.
//   3. The [`assert_play_integrity_root_is_production_ready`] runtime guard below
//      MUST pass (it fails loudly while the placeholder kid is still pinned).
//      Production startup paths MUST call it; see that fn's docs for why this is a
//      runtime guard and not a `compile_error!`.
//
// A `#[cfg(not(any(test, feature = "dev-fixtures")))] compile_error!(...)` was
// deliberately NOT used here: the default-feature (prod) build legitimately needs
// to compile today (CI builds `chio-custody-hw` with default features), and the
// crate is consumed by other workspace members that must keep compiling while the
// real key is being provisioned. Hard-failing the build would break
// that. Instead we fail *loudly at startup* via the guard below, which is gated so
// it is hard to ship the fixture key into prod silently while leaving the build
// (and the test/dev-fixtures path) working.
// =============================================================================

/// Private key for the synthetic Play Integrity signer. Test/dev only:
/// it is the counterpart to the pinned public coordinates so deterministic
/// tests can mint tokens that the pinned verifier accepts. Never compiled
/// into a production binary.
///
/// SECURITY / PLACEHOLDER: this committed key is the private half of
/// the pinned public coordinates below. It MUST be removed/rotated before the
/// real Google root is pinned - a real pinned root and a committed private key
/// must never coexist.
#[cfg(any(test, feature = "dev-fixtures"))]
const PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----"#;

/// Pinned Play Integrity verification key (P-256) affine coordinates.
///
/// SECURITY / PLACEHOLDER: these coordinates are the SYNTHETIC FIXTURE
/// public key, NOT Google's real Play Integrity verification key. They MUST be
/// replaced with Google's real public verification keys before any production
/// deployment. While they remain in place,
/// [`assert_play_integrity_root_is_production_ready`] fails loudly. The verifier
/// trusts only this key material; in production the caller does not get to supply
/// its own JWKS.
const PLAY_INTEGRITY_PINNED_X_B64: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const PLAY_INTEGRITY_PINNED_Y_B64: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

/// kid of the pinned Play Integrity root.
///
/// SECURITY / PLACEHOLDER: the current value
/// ([`PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID`]) marks the synthetic fixture key.
/// Replacing the pinned root with Google's real verification keys MUST also
/// rotate this kid off the `*-fixture-root` placeholder; the production startup
/// guard keys off that change to decide whether a real key has been provided.
pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";
pub const GOOGLE_PLAY_INTEGRITY_ISSUER: &str = "https://playintegrity.googleapis.com";

/// Sentinel kid value that marks the pinned root as the committed SYNTHETIC
/// FIXTURE key rather than a real Google verification key.
///
/// SECURITY / PLACEHOLDER: while
/// [`GOOGLE_PLAY_INTEGRITY_ROOT_KID`] equals this value, the pinned key is the
/// fixture key whose private half is committed in this file, and
/// [`assert_play_integrity_root_is_production_ready`] fails. Provisioning the
/// real Google root rotates `GOOGLE_PLAY_INTEGRITY_ROOT_KID` off this value.
pub const PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID: &str = "chio-play-integrity-fixture-root";

/// Sentinel public-key coordinates that mark the pinned root as the committed
/// SYNTHETIC FIXTURE key.
///
/// SECURITY / PLACEHOLDER: these are byte-identical to the fixture
/// public coordinates whose private half is committed in this file. The
/// readiness guard compares the live pinned coordinates against these sentinels
/// so a kid-only edit (rotating `GOOGLE_PLAY_INTEGRITY_ROOT_KID` off the
/// sentinel while leaving the fixture key bytes in place) cannot accidentally
/// bless production. Provisioning the real Google root replaces the pinned
/// coordinates above with real key bytes, so they no longer match these
/// sentinels.
const PLAY_INTEGRITY_FIXTURE_X_B64: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const PLAY_INTEGRITY_FIXTURE_Y_B64: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

/// Whether the pinned Play Integrity root is still the committed SYNTHETIC
/// FIXTURE placeholder (i.e. NOT a real Google verification key).
///
/// SECURITY / PLACEHOLDER: this is `true` until the pinned root is
/// replaced with Google's real keys (which also rotates the kid off
/// [`PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID`]). Production startup paths use
/// [`assert_play_integrity_root_is_production_ready`], which keys off this flag.
///
/// The check is tied to BOTH the kid AND the pinned key coordinate bytes: it
/// returns `true` if the kid still equals the sentinel OR the pinned
/// coordinates still equal the committed fixture coordinates. This way, swapping
/// the kid off the sentinel without also installing real key bytes (the
/// placeholder-root provisioning footgun) still reports the root as a placeholder and keeps the
/// guard failing.
#[must_use]
pub const fn play_integrity_root_is_placeholder() -> bool {
    // `const` byte comparison (no external deps). The root is a placeholder
    // while EITHER the pinned kid still equals the fixture sentinel OR the
    // pinned coordinates still equal the committed fixture public key, so a
    // kid-only edit cannot bless the fixture key bytes as production-ready.
    const_str_eq(
        GOOGLE_PLAY_INTEGRITY_ROOT_KID,
        PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID,
    ) || const_str_eq(PLAY_INTEGRITY_PINNED_X_B64, PLAY_INTEGRITY_FIXTURE_X_B64)
        || const_str_eq(PLAY_INTEGRITY_PINNED_Y_B64, PLAY_INTEGRITY_FIXTURE_Y_B64)
}

/// `const`-evaluable byte-wise string equality (stable-Rust friendly).
const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Production startup tripwire for the pinned Play Integrity root.
///
/// Returns `Err` while the pinned root is still the committed SYNTHETIC FIXTURE
/// placeholder (i.e. [`play_integrity_root_is_placeholder`] is `true`). It is a
/// no-op (`Ok`) once the real Google verification key has been pinned and the
/// kid rotated off [`PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID`].
///
/// SECURITY / PLACEHOLDER: production binaries that perform Play
/// Integrity verification MUST call this during startup (and abort if it
/// returns `Err`) so the fixture key cannot silently ship to prod. It is also
/// asserted at first verification via [`debug_assert!`] in `play_integrity`.
///
/// # Why a runtime guard and not `compile_error!`
///
/// A `#[cfg(not(any(test, feature = "dev-fixtures")))] compile_error!(...)`
/// would refuse to compile the default-feature (prod) build, but that build
/// legitimately needs to compile today: CI builds `chio-custody-hw` with
/// default features, and other workspace crates depend on it while the real key
/// is being provisioned. So the placeholder is enforced at
/// startup instead - loud and hard to miss, without breaking the build or the
/// test/`dev-fixtures` signing path.
///
/// # Errors
///
/// Returns a descriptive error string while the pinned root is the fixture key.
pub fn assert_play_integrity_root_is_production_ready() -> Result<(), String> {
    if play_integrity_root_is_placeholder() {
        return Err(format!(
            "SECURITY: Play Integrity verifier is pinned to the SYNTHETIC FIXTURE root \
             (kid `{PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID}`) whose private key is committed in \
             version control. This MUST NOT run in production. Replace the pinned key with \
             Google's real Play Integrity verification keys and remove the committed fixture \
             private key before deploying."
        ));
    }
    Ok(())
}

/// Decoding key derived from the pinned Play Integrity public coordinates.
///
/// # Errors
///
/// Returns an error if the embedded pinned coordinates are malformed.
pub fn play_integrity_decoding_key() -> Result<DecodingKey, String> {
    DecodingKey::from_ec_components(PLAY_INTEGRITY_PINNED_X_B64, PLAY_INTEGRITY_PINNED_Y_B64)
        .map_err(|error| format!("invalid pinned Play Integrity P-256 public key: {error}"))
}

/// Encoding key for the synthetic Play Integrity signer. Test/dev only.
///
/// # Errors
///
/// Returns an error if the embedded fixture private key is malformed.
#[cfg(any(test, feature = "dev-fixtures"))]
pub fn play_integrity_encoding_key() -> Result<EncodingKey, String> {
    EncodingKey::from_ec_pem(PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM)
        .map_err(|error| format!("invalid Play Integrity P-256 fixture key: {error}"))
}

/// The pinned Play Integrity JWKS used by the production verification path.
///
/// SECURITY / PLACEHOLDER: the key returned here is the SYNTHETIC
/// FIXTURE key, NOT Google's real Play Integrity verification key. Its private
/// half is committed in this file. The production verification path pins
/// exactly this JWKS, so until the pinned coordinates/kid are replaced with
/// Google's real keys (see the constants above and
/// [`assert_play_integrity_root_is_production_ready`]), a prod binary trusts a
/// key whose private half is in version control. MUST be replaced before any
/// production deployment.
#[must_use]
pub fn play_integrity_pinned_jwks_json() -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "kid": GOOGLE_PLAY_INTEGRITY_ROOT_KID,
                "use": "sig",
                "x": PLAY_INTEGRITY_PINNED_X_B64,
                "y": PLAY_INTEGRITY_PINNED_Y_B64
            }
        ]
    })
    .to_string()
}

/// Backwards-compatible alias used by deterministic tests that need the
/// JWKS the pinned verifier trusts.
#[cfg(any(test, feature = "dev-fixtures"))]
#[must_use]
pub fn play_integrity_jwks_json() -> String {
    play_integrity_pinned_jwks_json()
}

/// SHA-256 fingerprint (hex) of the pinned Play Integrity public point.
///
/// # Errors
///
/// Returns an error if the embedded pinned coordinates are malformed.
pub fn play_integrity_root_sha256_hex() -> Result<String, String> {
    let mut point = Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_PINNED_X_B64)
        .map_err(|error| format!("invalid pinned Play Integrity x coordinate: {error}"))?;
    let y = Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_PINNED_Y_B64)
        .map_err(|error| format!("invalid pinned Play Integrity y coordinate: {error}"))?;
    point.extend_from_slice(&y);
    Ok(hex::encode(Sha256::digest(point)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_root_is_flagged_and_guard_fails() {
        // SECURITY / PLACEHOLDER: while the synthetic fixture root is
        // pinned, the placeholder flag is set and the production-readiness guard
        // fails loudly. When the real Google root is provisioned (kid rotated off
        // the `*-fixture-root` sentinel) both of these flip; this test then needs
        // updating, which is the intended forcing function.
        assert!(
            play_integrity_root_is_placeholder(),
            "pinned root is still the committed fixture key"
        );
        let Err(err) = assert_play_integrity_root_is_production_ready() else {
            panic!("placeholder root must fail the production-readiness guard");
        };
        assert!(
            err.contains("SYNTHETIC FIXTURE"),
            "guard must name the synthetic fixture root: {err}"
        );
        assert!(
            err.contains(PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID),
            "guard must name the placeholder kid: {err}"
        );
    }

    #[test]
    fn readiness_guard_is_tied_to_pinned_key_bytes() {
        // SECURITY / PLACEHOLDER: the pinned coordinates are still the
        // committed fixture public key, so the readiness guard must treat the
        // root as a placeholder regardless of the kid. This proves the guard is
        // tied to the key bytes, not just the kid string, so a kid-only edit
        // cannot bless the fixture key.
        assert_eq!(
            PLAY_INTEGRITY_PINNED_X_B64, PLAY_INTEGRITY_FIXTURE_X_B64,
            "pinned x coordinate must still match the fixture sentinel"
        );
        assert_eq!(
            PLAY_INTEGRITY_PINNED_Y_B64, PLAY_INTEGRITY_FIXTURE_Y_B64,
            "pinned y coordinate must still match the fixture sentinel"
        );

        // Replicate the placeholder predicate with a NON-sentinel kid but the
        // committed fixture coordinates: a kid-only rotation must still report
        // the root as a placeholder via the coordinate-byte tie.
        let kid_only_rotation_still_placeholder =
            const_str_eq(
                "real-google-kid-but-fixture-bytes",
                PLAY_INTEGRITY_PLACEHOLDER_ROOT_KID,
            ) || const_str_eq(PLAY_INTEGRITY_PINNED_X_B64, PLAY_INTEGRITY_FIXTURE_X_B64)
                || const_str_eq(PLAY_INTEGRITY_PINNED_Y_B64, PLAY_INTEGRITY_FIXTURE_Y_B64);
        assert!(
            kid_only_rotation_still_placeholder,
            "kid-only rotation with fixture key bytes must still be flagged as placeholder"
        );
    }

    #[test]
    fn const_str_eq_matches_std_eq() {
        assert!(const_str_eq("abc", "abc"));
        assert!(!const_str_eq("abc", "abd"));
        assert!(!const_str_eq("abc", "abcd"));
        assert!(const_str_eq("", ""));
    }
}
