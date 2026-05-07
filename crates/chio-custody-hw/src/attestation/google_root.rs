//! Pinned Play Integrity verifier key material for deterministic tests.

use base64ct::{Base64UrlUnpadded, Encoding};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sha2::{Digest, Sha256};

const PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----"#;

const PLAY_INTEGRITY_FIXTURE_X_B64: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const PLAY_INTEGRITY_FIXTURE_Y_B64: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";
pub const GOOGLE_PLAY_INTEGRITY_ISSUER: &str = "https://playintegrity.googleapis.com";

pub fn play_integrity_decoding_key() -> DecodingKey {
    match DecodingKey::from_ec_components(
        PLAY_INTEGRITY_FIXTURE_X_B64,
        PLAY_INTEGRITY_FIXTURE_Y_B64,
    ) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity P-256 fixture public key: {error}"),
    }
}

pub fn play_integrity_encoding_key() -> EncodingKey {
    match EncodingKey::from_ec_pem(PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity P-256 fixture key: {error}"),
    }
}

#[must_use]
pub fn play_integrity_jwks_json() -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "kid": GOOGLE_PLAY_INTEGRITY_ROOT_KID,
                "use": "sig",
                "x": PLAY_INTEGRITY_FIXTURE_X_B64,
                "y": PLAY_INTEGRITY_FIXTURE_Y_B64
            }
        ]
    })
    .to_string()
}

#[must_use]
pub fn play_integrity_root_sha256_hex() -> String {
    let mut point = match Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_FIXTURE_X_B64) {
        Ok(bytes) => bytes,
        Err(error) => panic!("invalid Play Integrity P-256 fixture x coordinate: {error}"),
    };
    let y = match Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_FIXTURE_Y_B64) {
        Ok(bytes) => bytes,
        Err(error) => panic!("invalid Play Integrity P-256 fixture y coordinate: {error}"),
    };
    point.extend_from_slice(&y);
    hex::encode(Sha256::digest(point))
}
