use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ChioPackageError;
use crate::validation::{is_lower_hex, validate_non_empty};

pub const TRUSTED_ISSUER_REGISTRY_SCHEMA: &str = "chio.attest.trusted-issuer-registry.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedBbsIssuer {
    pub issuer_fingerprint: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedIssuerRegistryDocument {
    pub schema: String,
    pub issuers: Vec<TrustedBbsIssuer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerRegistry {
    public_keys: BTreeMap<String, String>,
}

impl TrustedIssuerRegistry {
    pub fn from_document(
        document: TrustedIssuerRegistryDocument,
    ) -> Result<Self, ChioPackageError> {
        if document.schema != TRUSTED_ISSUER_REGISTRY_SCHEMA {
            return Err(ChioPackageError::TrustedIssuer(format!(
                "trusted issuer registry schema {} is unsupported",
                document.schema
            )));
        }
        if document.issuers.is_empty() {
            return Err(ChioPackageError::TrustedIssuer(
                "trusted issuer registry is empty".to_string(),
            ));
        }

        let mut public_keys = BTreeMap::new();
        for issuer in document.issuers {
            validate_non_empty(&issuer.issuer_fingerprint, "issuerFingerprint")?;
            validate_non_empty(&issuer.public_key_hex, "publicKeyHex")?;
            if !is_lower_hex(&issuer.issuer_fingerprint) {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "issuerFingerprint {} is not lowercase hex",
                    issuer.issuer_fingerprint
                )));
            }
            if !is_lower_hex(&issuer.public_key_hex) || issuer.public_key_hex.len() % 2 != 0 {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "publicKeyHex for issuer {} is not lowercase even-length hex",
                    issuer.issuer_fingerprint
                )));
            }
            if public_keys
                .insert(issuer.issuer_fingerprint.clone(), issuer.public_key_hex)
                .is_some()
            {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "duplicate issuer fingerprint {}",
                    issuer.issuer_fingerprint
                )));
            }
        }

        Ok(Self { public_keys })
    }

    pub(crate) fn public_key_hex(&self, issuer_fingerprint: &str) -> Option<&str> {
        self.public_keys
            .get(issuer_fingerprint)
            .map(std::string::String::as_str)
    }
}

pub fn trusted_issuer_registry_from_json(
    json: &str,
) -> Result<TrustedIssuerRegistry, ChioPackageError> {
    let document: TrustedIssuerRegistryDocument =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    TrustedIssuerRegistry::from_document(document)
}

pub fn trusted_issuer_registry_json(
    registry: &TrustedIssuerRegistryDocument,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(registry)
        .map_err(|error| ChioPackageError::Json(error.to_string()))
}
