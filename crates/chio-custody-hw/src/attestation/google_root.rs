//! Pinned Play Integrity verifier key material for trajectory-3 tests.

use jsonwebtoken::{DecodingKey, EncodingKey};
use sha2::{Digest, Sha256};

const PLAY_INTEGRITY_FIXTURE_SECRET: &[u8] =
    b"chio trajectory-3 play integrity fixture verifier key";

pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";

pub fn play_integrity_decoding_key() -> DecodingKey {
    DecodingKey::from_secret(PLAY_INTEGRITY_FIXTURE_SECRET)
}

pub fn play_integrity_encoding_key() -> EncodingKey {
    EncodingKey::from_secret(PLAY_INTEGRITY_FIXTURE_SECRET)
}

#[must_use]
pub fn play_integrity_root_sha256_hex() -> String {
    hex::encode(Sha256::digest(PLAY_INTEGRITY_FIXTURE_SECRET))
}
