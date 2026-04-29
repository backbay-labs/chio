//! Self-certifying `did:chio` identifiers and DID Document resolution.
//!
//! `did:chio` is intentionally narrow: the method-specific identifier is the
//! lowercase hex form of an Ed25519 public key already used by Chio agents and
//! operators. Basic resolution is self-certifying and requires no registry
//! lookup. Optional receipt-log service endpoints can be attached by the
//! resolving environment.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "fuzz")]
pub mod fuzz;

use std::fmt;
use std::str::FromStr;

use chio_core::{crypto::SigningAlgorithm, PublicKey};
use serde::{Deserialize, Serialize};
use url::Url;

const DID_CHIO_PREFIX: &str = "did:chio:";
const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";
const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";
const ED25519_PUB_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
pub const RECEIPT_LOG_SERVICE_TYPE: &str = "ChioReceiptLogService";
pub const PASSPORT_STATUS_SERVICE_TYPE: &str = "ChioPassportStatusService";

#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("did:chio identifiers must start with did:chio:")]
    InvalidPrefix,

    #[error("did:chio method-specific identifier must be exactly 64 hex characters")]
    InvalidMethodSpecificId,

    #[error("invalid did:chio public key: {0}")]
    InvalidPublicKey(String),

    #[error("did:chio only supports ed25519 public keys, got {0}")]
    UnsupportedKeyAlgorithm(String),

    #[error("invalid service endpoint URL: {0}")]
    InvalidServiceEndpoint(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidChio {
    public_key: PublicKey,
}

impl DidChio {
    pub fn from_public_key(public_key: PublicKey) -> Result<Self, DidError> {
        if public_key.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(DidError::UnsupportedKeyAlgorithm(
                public_key.algorithm().prefix().to_string(),
            ));
        }
        Ok(Self { public_key })
    }

    pub fn try_from_public_key(public_key: PublicKey) -> Result<Self, DidError> {
        Self::from_public_key(public_key)
    }

    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{DID_CHIO_PREFIX}{}", self.public_key.to_hex())
    }

    #[must_use]
    pub fn verification_method_id(&self) -> String {
        format!("{}#key-1", self.as_str())
    }

    #[must_use]
    pub fn public_key_multibase(&self) -> String {
        let mut value = Vec::with_capacity(ED25519_PUB_MULTICODEC_PREFIX.len() + 32);
        value.extend_from_slice(&ED25519_PUB_MULTICODEC_PREFIX);
        value.extend_from_slice(self.public_key.as_bytes());
        format!("z{}", bs58::encode(value).into_string())
    }

    #[must_use]
    pub fn resolve(&self) -> DidDocument {
        self.resolve_with_options(&ResolveOptions::default())
    }

    #[must_use]
    pub fn resolve_with_options(&self, options: &ResolveOptions) -> DidDocument {
        let did = self.as_str();
        let verification_method_id = self.verification_method_id();
        DidDocument {
            context: DID_CONTEXT_V1.to_string(),
            id: did.clone(),
            verification_method: vec![DidVerificationMethod {
                id: verification_method_id.clone(),
                verification_type: ED25519_VERIFICATION_KEY_2020.to_string(),
                controller: did.clone(),
                public_key_multibase: self.public_key_multibase(),
            }],
            authentication: vec![verification_method_id.clone()],
            assertion_method: vec![verification_method_id],
            service: options.services.clone(),
        }
    }
}

impl fmt::Display for DidChio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl TryFrom<PublicKey> for DidChio {
    type Error = DidError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        Self::from_public_key(value)
    }
}

impl FromStr for DidChio {
    type Err = DidError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let suffix = value
            .strip_prefix(DID_CHIO_PREFIX)
            .ok_or(DidError::InvalidPrefix)?;
        if suffix.len() != 64
            || !suffix
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(DidError::InvalidMethodSpecificId);
        }
        let public_key = PublicKey::from_hex(suffix)
            .map_err(|error| DidError::InvalidPublicKey(error.to_string()))?;
        Self::from_public_key(public_key)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOptions {
    services: Vec<DidService>,
}

impl ResolveOptions {
    #[must_use]
    pub fn with_service(mut self, service: DidService) -> Self {
        self.services.push(service);
        self
    }

    #[must_use]
    pub fn services(&self) -> &[DidService] {
        &self.services
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<DidVerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

impl DidService {
    pub fn new(
        id: impl Into<String>,
        service_type: impl Into<String>,
        service_endpoint: impl Into<String>,
    ) -> Result<Self, DidError> {
        let service_endpoint = service_endpoint.into();
        Url::parse(&service_endpoint)
            .map_err(|error| DidError::InvalidServiceEndpoint(error.to_string()))?;
        Ok(Self {
            id: id.into(),
            service_type: service_type.into(),
            service_endpoint,
        })
    }

    pub fn receipt_log(
        did: &DidChio,
        ordinal: usize,
        service_endpoint: impl Into<String>,
    ) -> Result<Self, DidError> {
        let fragment = if ordinal == 0 {
            "receipt-log".to_string()
        } else {
            format!("receipt-log-{}", ordinal + 1)
        };
        Self::new(
            format!("{}#{fragment}", did.as_str()),
            RECEIPT_LOG_SERVICE_TYPE,
            service_endpoint,
        )
    }

    pub fn passport_status(
        did: &DidChio,
        ordinal: usize,
        service_endpoint: impl Into<String>,
    ) -> Result<Self, DidError> {
        let fragment = if ordinal == 0 {
            "passport-status".to_string()
        } else {
            format!("passport-status-{}", ordinal + 1)
        };
        Self::new(
            format!("{}#{fragment}", did.as_str()),
            PASSPORT_STATUS_SERVICE_TYPE,
            service_endpoint,
        )
    }
}

pub fn resolve_did_arc(value: &str, options: &ResolveOptions) -> Result<DidDocument, DidError> {
    DidChio::from_str(value).map(|did| did.resolve_with_options(options))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Keypair;

    fn fixed_did() -> DidChio {
        let seed = [7u8; 32];
        DidChio::from_public_key(Keypair::from_seed(&seed).public_key()).expect("ed25519 key")
    }

    #[test]
    fn parses_and_canonicalizes_did_chio_identifier() {
        let canonical = fixed_did().to_string();
        let uppercase = canonical
            .to_uppercase()
            .replacen("DID:CHIO:", "did:chio:", 1);
        let parsed = DidChio::from_str(&uppercase).expect("did");
        assert_eq!(parsed.to_string(), canonical);
    }

    #[test]
    fn rejects_invalid_method_specific_id() {
        let error = DidChio::from_str("did:chio:not-hex").expect_err("invalid did");
        assert!(matches!(error, DidError::InvalidMethodSpecificId));
    }

    #[test]
    fn rejects_non_ed25519_public_keys() {
        let p256_generator = PublicKey::from_hex(
            "p256:046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .expect("valid p256 public key");

        let error =
            DidChio::try_from_public_key(p256_generator).expect_err("unsupported algorithm");
        assert!(matches!(error, DidError::UnsupportedKeyAlgorithm(_)));
    }

    #[test]
    fn resolves_document_with_ed25519_multibase_key() {
        let did = fixed_did();
        let document = did.resolve();

        assert_eq!(document.id, did.to_string());
        assert_eq!(document.authentication, vec![did.verification_method_id()]);
        assert_eq!(
            document.assertion_method,
            vec![did.verification_method_id()]
        );

        let encoded = document.verification_method[0]
            .public_key_multibase
            .strip_prefix('z')
            .expect("base58btc prefix");
        let decoded = bs58::decode(encoded).into_vec().expect("decode multibase");
        assert_eq!(&decoded[..2], &ED25519_PUB_MULTICODEC_PREFIX);
        assert_eq!(&decoded[2..], did.public_key().as_bytes());
    }

    #[test]
    fn attaches_validated_receipt_log_services_deterministically() {
        let did = fixed_did();
        let options = ResolveOptions::default()
            .with_service(
                DidService::receipt_log(&did, 0, "https://trust.example.com/v1/receipts")
                    .expect("receipt log"),
            )
            .with_service(
                DidService::receipt_log(&did, 1, "https://mirror.example.com/v1/receipts")
                    .expect("receipt log"),
            );

        let document = did.resolve_with_options(&options);
        assert_eq!(document.service.len(), 2);
        assert_eq!(document.service[0].id, format!("{did}#receipt-log"));
        assert_eq!(document.service[1].id, format!("{did}#receipt-log-2"));
        assert_eq!(document.service[0].service_type, RECEIPT_LOG_SERVICE_TYPE);
    }

    #[test]
    fn rejects_invalid_receipt_log_service_endpoint() {
        let did = fixed_did();
        let error =
            DidService::receipt_log(&did, 0, "not-a-url").expect_err("invalid service endpoint");
        assert!(matches!(error, DidError::InvalidServiceEndpoint(_)));
    }
}
