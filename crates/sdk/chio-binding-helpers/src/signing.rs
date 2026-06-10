use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utf8MessageSignature {
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalJsonSignature {
    pub canonical_json: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

fn normalize_hex(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

#[must_use]
pub fn public_key_hex_matches(left: &str, right: &str) -> bool {
    normalize_hex(left).eq_ignore_ascii_case(normalize_hex(right))
}

#[must_use]
pub fn is_valid_public_key_hex(value: &str) -> bool {
    chio_core::PublicKey::from_hex(value).is_ok()
}

#[must_use]
pub fn is_valid_signature_hex(value: &str) -> bool {
    chio_core::Signature::from_hex(value).is_ok()
}

pub fn sign_utf8_message_ed25519(input: &str, seed_hex: &str) -> Result<Utf8MessageSignature> {
    let keypair = chio_core::Keypair::from_seed_hex(seed_hex)?;
    let signature = keypair.sign(input.as_bytes());
    Ok(Utf8MessageSignature {
        public_key_hex: keypair.public_key().to_hex(),
        signature_hex: signature.to_hex(),
    })
}

pub fn verify_utf8_message_ed25519(
    input: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<bool> {
    let public_key = chio_core::PublicKey::from_hex(public_key_hex)?;
    let signature = chio_core::Signature::from_hex(signature_hex)?;
    Ok(public_key.verify(input.as_bytes(), &signature))
}

pub fn sign_json_str_ed25519(input: &str, seed_hex: &str) -> Result<CanonicalJsonSignature> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    let keypair = chio_core::Keypair::from_seed_hex(seed_hex)?;
    let (signature, canonical_bytes) = keypair.sign_canonical(&value)?;
    let canonical_json = String::from_utf8(canonical_bytes)
        .map_err(|error| chio_core::Error::CanonicalJson(error.to_string()))?;

    Ok(CanonicalJsonSignature {
        canonical_json,
        public_key_hex: keypair.public_key().to_hex(),
        signature_hex: signature.to_hex(),
    })
}

pub fn verify_json_str_signature_ed25519(
    input: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<bool> {
    let value: serde_json::Value = serde_json::from_str(input)?;
    let public_key = chio_core::PublicKey::from_hex(public_key_hex)?;
    let signature = chio_core::Signature::from_hex(signature_hex)?;
    Ok(public_key.verify_canonical(&value, &signature)?)
}

#[cfg(test)]
mod tests {
    use super::{
        public_key_hex_matches, sign_json_str_ed25519, sign_utf8_message_ed25519,
        verify_json_str_signature_ed25519, verify_utf8_message_ed25519,
    };

    #[test]
    fn sign_and_verify_utf8_message() -> crate::Result<()> {
        let signed = sign_utf8_message_ed25519("hello chio", &"09".repeat(32))?;
        assert!(verify_utf8_message_ed25519(
            "hello chio",
            &signed.public_key_hex,
            &signed.signature_hex,
        )?);
        assert!(!verify_utf8_message_ed25519(
            "hello chio!",
            &signed.public_key_hex,
            &signed.signature_hex,
        )?);
        Ok(())
    }

    #[test]
    fn sign_and_verify_json_string() -> crate::Result<()> {
        let signed = sign_json_str_ed25519("{\"z\":1,\"a\":2}", &"09".repeat(32))?;
        assert_eq!(signed.canonical_json, "{\"a\":2,\"z\":1}");
        assert!(verify_json_str_signature_ed25519(
            "{\"z\":1,\"a\":2}",
            &signed.public_key_hex,
            &signed.signature_hex,
        )?);
        assert!(!verify_json_str_signature_ed25519(
            "{\"z\":2,\"a\":2}",
            &signed.public_key_hex,
            &signed.signature_hex,
        )?);
        Ok(())
    }

    #[test]
    fn public_key_matching_ignores_case_and_prefix() {
        assert!(public_key_hex_matches("0xABCD", "abcd"));
    }
}
