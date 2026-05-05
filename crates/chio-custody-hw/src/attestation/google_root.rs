//! Pinned Play Integrity verifier key material for deterministic tests.

use jsonwebtoken::{DecodingKey, EncodingKey};
use sha2::{Digest, Sha256};

const PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCof01CR7oPvSRa
/S18A9pSUVGxtSd+BOuq7Nd2NnuItdZk5O3Um0XKH5lpV8V/rTscEJj3cNETLlO5
CUgi5GaWQ0vpxwIRz6oNMVYW5gB1v7Jbvasj7jIro1qfja9k1xaTmdvLut84QWtR
mPNRe6oIzL4ehoOWJadG1P5MmZAptQMv3hH5VnZXL3g57oG4nhm1gUI5pAzaogRd
GplXyFA2Fe+m7P+LqwXxMnsfuEK2WpP3AnltAaYS+9ev+TKPJ61PA+gOXQPT77U9
0lvtXuahnXr/zISm0YVz16z12VfGT70QVe75++nHstOMEpav3M2YXUbRSsfuvM+w
JNos5943AgMBAAECggEAUsBCdzy2uigQBMe2YOObgzYAwx/Ox2svOoCayKm1Pczg
ACkWTIX9XmjqdPvwOOYg04WrOkqjw6HK6GMQlGJLp5xhWeysrYapY1VJjHFk5G9C
7x9VP44qAZh2V0nES+f+ZHr5oTKjkgM+65IMXYY4WZ4D+QXi9giEAJt2ULRSQsih
OXe0+DmIIlkTGw6GPHViwiNKgO+qT2ycNQy/NXPNkt6hf5tpPGXjOe4juqDfX5pe
2OGdKIR0v2r0dubZT3ldGntNN7+1kGr2re7Ig8rUXKhErW+sgFCO82btGcdatH8I
fpgSf/Lw9RubOmiM520GZO95sbWLUSRWzVDINet7YQKBgQDU7UhU+y3m6uj4U6yd
Jns+79WtLYZ2T+hBm+Bq2cf1zfM1oH+YhgEbES/YrjLRRKwFZBDm3FPui86HOcov
Q4Y0ze4zg7XFGLsKfZ6+Y9obFol+VYa8GO0HgpFALz9n1JAgeUF+2lTLdFFMCZ0g
bMcD5Ha2rtsu0OA4nezYhiP9SQKBgQDKlStggcX+ib4QpB3mVCnUDAt3vmv8hDZN
xgICkeTG+GpW50HbVu0pYJBrz5PnMBjdCTJU8DTXZE9fjx3AYsFD6kcyK8X73vId
9kJ8QQiGMMQWtUcewd61HDHSFdVI0ih/g57TKe77Q93cJ0tkWbC2fJtpKuOOT1pO
zlQmkTZ/fwKBgEwCZHbJr6omI4I6RH1Y9lgSP6HxhXWIsu1w2pzqH2KU4YQ8RjBJ
be2epgjgro1byVinTw1Ki7+1MsW9EHrszOTeunCzTNkOKf7ltxxaAsr2saBioZVW
BI9Qwc86zpSfIdAl2QaSpAB5BmhxaiDgE+9EyEgQhXfh4pjzb1AgGorZAoGBALBH
xYsg4e1wZteMOAhpTEycfo4gQU9mrOpYVv9tfKo3GDGu4nu+1Hig8oseAhG2pKwS
iJ2ouBKF0xvQKY9zX8F9Z56cwJc/lWfFFm2RGZ3LaZZpAA4fnW/zrNam8QWA+oSb
P+V4I+C5WaFtAAm+kir5mzKUg5ceLfNNT6SPz+B5AoGAPic2TxfHbmSS3H3dttoX
6BC4YGrIaJMMLqGMqnxuLK/epFM7t1TT70PDaUvAr+knqEzXFPBNw1D8szZCbCO0
oIaI37ey+H6j9PytBtUi+hJA9Oet+T93RMa32QHYHRkSUJL0BiOZ6VC1uvB4vHB1
Jwjge04LAAqapzjoksv1ryo=
-----END PRIVATE KEY-----"#;

const PLAY_INTEGRITY_FIXTURE_MODULUS_B64: &str = "qH9NQke6D70kWv0tfAPaUlFRsbUnfgTrquzXdjZ7iLXWZOTt1JtFyh-ZaVfFf607HBCY93DREy5TuQlIIuRmlkNL6ccCEc-qDTFWFuYAdb-yW72rI-4yK6Nan42vZNcWk5nby7rfOEFrUZjzUXuqCMy-HoaDliWnRtT-TJmQKbUDL94R-VZ2Vy94Oe6BuJ4ZtYFCOaQM2qIEXRqZV8hQNhXvpuz_i6sF8TJ7H7hCtlqT9wJ5bQGmEvvXr_kyjyetTwPoDl0D0--1PdJb7V7moZ16_8yEptGFc9es9dlXxk-9EFXu-fvpx7LTjBKWr9zNmF1G0UrH7rzPsCTaLOfeNw";
const PLAY_INTEGRITY_FIXTURE_EXPONENT_B64: &str = "AQAB";

pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";
pub const GOOGLE_PLAY_INTEGRITY_ISSUER: &str = "https://playintegrity.googleapis.com";

pub fn play_integrity_decoding_key() -> DecodingKey {
    match DecodingKey::from_rsa_components(
        PLAY_INTEGRITY_FIXTURE_MODULUS_B64,
        PLAY_INTEGRITY_FIXTURE_EXPONENT_B64,
    ) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity RSA fixture public key: {error}"),
    }
}

pub fn play_integrity_encoding_key() -> EncodingKey {
    match EncodingKey::from_rsa_pem(PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity RSA fixture key: {error}"),
    }
}

#[must_use]
pub fn play_integrity_jwks_json() -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "kid": GOOGLE_PLAY_INTEGRITY_ROOT_KID,
                "use": "sig",
                "n": PLAY_INTEGRITY_FIXTURE_MODULUS_B64,
                "e": PLAY_INTEGRITY_FIXTURE_EXPONENT_B64
            }
        ]
    })
    .to_string()
}

#[must_use]
pub fn play_integrity_root_sha256_hex() -> String {
    hex::encode(Sha256::digest(PLAY_INTEGRITY_FIXTURE_MODULUS_B64))
}
