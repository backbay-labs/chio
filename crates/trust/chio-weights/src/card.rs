//! Model card schema and `ModelCard` type.
//!
//! A [`ModelCard`] is the signed declaration that binds a model's loaded
//! weights to an allowed capability set, banned tools, and a training-data
//! class. The on-the-wire shape is locked under
//! `spec/schemas/model-card.v1.json` and the canonical-JSON encoding rules
//! match `chio-custody-hw`'s `PasskeyCapability`:
//!
//! - object keys sorted by UTF-16 code units (RFC 8785 / JCS),
//! - sets serialised as sorted unique JSON arrays,
//! - timestamps as RFC 3339 UTC,
//! - no inter-token whitespace.
//!
//! Two implementations (Rust, TypeScript / Python / Go) producing the same
//! card must produce byte-identical canonical bytes; cosign signatures are
//! taken over those bytes.
//!
//! # Trust contract
//!
//! - `weights_hash` is a lowercase 64-character hexadecimal SHA-256 digest.
//!   The kernel binding refusal recomputes the digest from the loaded
//!   weights blob and rejects fail-closed on mismatch.
//! - `allowed_capability_set` is the upper bound on the kernel's grantable
//!   scope set under this card. Provider bind verifies subset containment
//!   for the requested capability set.
//! - `banned_tools` rejects at provider bind, not at first call.
//! - `expires_at` rejects fail-closed once exceeded.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::error::WeightsError;

/// Schema version for v1 model cards. The `card_version` field on
/// [`ModelCard`] MUST be this literal string.
pub const CARD_VERSION_V1: &str = "1";

/// Sorted unique-string set of capability scopes or tool identifiers.
///
/// Encoded as a JSON array in canonical (sorted) order. Set semantics are
/// enforced at construction time so the canonical-JSON encoding is
/// deterministic across implementations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StringSet(BTreeSet<String>);

impl<'de> Deserialize<'de> for StringSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let items = Vec::<String>::deserialize(deserializer)?;
        let mut set = BTreeSet::new();
        for item in items {
            if item.trim().is_empty() {
                return Err(de::Error::custom(
                    "string set entries must be non-empty strings",
                ));
            }
            if item.trim() != item {
                return Err(de::Error::custom(
                    "string set entries must not contain surrounding whitespace",
                ));
            }
            if set.contains(&item) {
                return Err(de::Error::custom(format!(
                    "duplicate string set entry {item:?}"
                )));
            }
            set.insert(item);
        }
        Ok(Self(set))
    }
}

impl StringSet {
    /// Build a [`StringSet`] from any iterable. Duplicates are deduplicated;
    /// final order is lexicographic per `BTreeSet`.
    pub fn new<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(items.into_iter().map(Into::into).collect())
    }

    /// True if every item in `subset` is also in `self`.
    #[must_use]
    pub fn covers(&self, subset: &StringSet) -> bool {
        subset.0.is_subset(&self.0)
    }

    /// True if `self` and `other` share at least one element.
    #[must_use]
    pub fn intersects(&self, other: &StringSet) -> bool {
        self.0.intersection(&other.0).next().is_some()
    }

    /// True if `self` contains the given item.
    #[must_use]
    pub fn contains(&self, item: &str) -> bool {
        self.0.contains(item)
    }

    /// Iterate the items in canonical (lexicographic) order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Number of distinct items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if no items are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the underlying `BTreeSet` (canonical iteration order).
    #[must_use]
    pub fn as_set(&self) -> &BTreeSet<String> {
        &self.0
    }

    fn validate_entries(&self, field: &'static str) -> Result<(), WeightsError> {
        for item in &self.0 {
            if item.trim().is_empty() {
                return Err(WeightsError::SchemaRejected(format!(
                    "{field} entries must be non-empty strings"
                )));
            }
            if item.trim() != item {
                return Err(WeightsError::SchemaRejected(format!(
                    "{field} entries must not contain surrounding whitespace"
                )));
            }
        }
        Ok(())
    }
}

/// Signed declaration binding a model's loaded weights to a permitted
/// capability set, banned tools, and a training-data class.
///
/// Schema locked at `spec/schemas/model-card.v1.json`. Canonical-JSON
/// encoding (RFC 8785 / JCS) is the on-the-wire byte form that cosign
/// signatures are taken over; the serde field declaration order is
/// therefore irrelevant to the hashed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCard {
    /// Schema version. MUST be [`CARD_VERSION_V1`] for v1 cards; any other
    /// value rejects at validation.
    pub card_version: String,
    /// Lowercase 64-character hexadecimal SHA-256 digest of the canonical
    /// weights blob.
    pub weights_hash: String,
    /// Capability scopes the kernel is permitted to grant against a
    /// provider bound under this card.
    pub allowed_capability_set: StringSet,
    /// Tool identifiers the kernel MUST NOT route to under this card.
    pub banned_tools: StringSet,
    /// Coarse-grained training-data classification (free-form).
    pub training_data_class: String,
    /// Logical issuer identity (URI / OIDC subject / SAN).
    pub issuer: String,
    /// RFC 3339 UTC timestamp at which the issuer minted this card.
    pub issued_at: DateTime<Utc>,
    /// RFC 3339 UTC timestamp at which this card expires.
    pub expires_at: DateTime<Utc>,
}

impl ModelCard {
    /// Build a v1 model card. Performs structural validation; returns a
    /// [`WeightsError`] if any required invariant is violated.
    ///
    /// Validated invariants:
    ///
    /// - `weights_hash` is a 64-character lowercase hexadecimal string.
    /// - `training_data_class` is non-empty.
    /// - `issuer` is non-empty.
    /// - `expires_at >= issued_at`.
    pub fn new(
        weights_hash: impl Into<String>,
        allowed_capability_set: StringSet,
        banned_tools: StringSet,
        training_data_class: impl Into<String>,
        issuer: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, WeightsError> {
        let card = Self {
            card_version: CARD_VERSION_V1.to_string(),
            weights_hash: weights_hash.into(),
            allowed_capability_set,
            banned_tools,
            training_data_class: training_data_class.into(),
            issuer: issuer.into(),
            issued_at,
            expires_at,
        };
        card.validate()?;
        Ok(card)
    }

    /// Re-run structural validation. Called by [`Self::new`] and exposed for
    /// post-deserialisation use.
    pub fn validate(&self) -> Result<(), WeightsError> {
        if self.card_version != CARD_VERSION_V1 {
            return Err(WeightsError::SchemaRejected(format!(
                "card_version must be {CARD_VERSION_V1:?}, got {:?}",
                self.card_version
            )));
        }
        if !is_lowercase_sha256_hex(&self.weights_hash) {
            return Err(WeightsError::SchemaRejected(format!(
                "weights_hash must be 64 lowercase hex chars, got {:?}",
                self.weights_hash
            )));
        }
        self.allowed_capability_set
            .validate_entries("allowed_capability_set")?;
        self.banned_tools.validate_entries("banned_tools")?;
        validate_required_text_field(&self.training_data_class, "training_data_class")?;
        validate_required_text_field(&self.issuer, "issuer")?;
        if self.expires_at < self.issued_at {
            return Err(WeightsError::SchemaRejected(format!(
                "expires_at ({}) precedes issued_at ({})",
                self.expires_at, self.issued_at,
            )));
        }
        Ok(())
    }

    /// Verifier-side liveness check.
    pub fn require_live(&self, now: DateTime<Utc>) -> Result<(), WeightsError> {
        if now < self.expires_at {
            Ok(())
        } else {
            Err(WeightsError::Expired {
                expires_at: self.expires_at,
                now,
            })
        }
    }

    /// Encode to canonical JSON bytes (RFC 8785 / JCS). Deterministic across
    /// any compliant implementation.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, WeightsError> {
        chio_core_types::canonical::canonical_json_bytes(self)
            .map_err(|err| WeightsError::Encoding(format!("canonical-json encode: {err}")))
    }

    /// Decode from canonical JSON bytes. Round-trip with
    /// [`Self::to_canonical_json`]. Validates after deserialisation.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, WeightsError> {
        let card: Self = serde_json::from_slice(bytes)
            .map_err(|err| WeightsError::Encoding(format!("canonical-json decode: {err}")))?;
        card.validate()?;
        let canonical = card.to_canonical_json()?;
        if canonical.as_slice() != bytes {
            return Err(WeightsError::Encoding(
                "model card bytes are not RFC 8785 canonical JSON".to_string(),
            ));
        }
        Ok(card)
    }
}

/// Compute the lowercase hex SHA-256 of a byte slice. Used by the kernel
/// binding refusal path to recompute `weights_hash` from a loaded
/// weights blob.
#[must_use]
pub fn weights_hash_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[inline]
fn is_lowercase_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

#[inline]
fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lowercase_hex_byte)
}

fn validate_required_text_field(value: &str, field: &'static str) -> Result<(), WeightsError> {
    if value.trim().is_empty() {
        return Err(WeightsError::MissingField(field));
    }
    if value.trim() != value {
        return Err(WeightsError::SchemaRejected(format!(
            "{field} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_issued_at() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_issued_at fixture must construct"),
        }
    }

    fn good_card() -> ModelCard {
        let issued = fixed_issued_at();
        let expires = issued + chrono::Duration::days(30);
        match ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new(["tool:read", "tool:write"]),
            StringSet::new(["tool:exec"]),
            "public-internet",
            "https://example.com/issuer",
            issued,
            expires,
        ) {
            Ok(card) => card,
            Err(e) => panic!("good_card must construct: {e}"),
        }
    }

    fn good_card_value() -> serde_json::Value {
        serde_json::json!({
            "allowed_capability_set": ["tool:read", "tool:write"],
            "banned_tools": ["tool:exec"],
            "card_version": CARD_VERSION_V1,
            "expires_at": "2026-05-30T12:00:00Z",
            "issued_at": "2026-04-30T12:00:00Z",
            "issuer": "https://example.com/issuer",
            "training_data_class": "public-internet",
            "weights_hash": "0000000000000000000000000000000000000000000000000000000000000001",
        })
    }

    fn value_to_bytes(value: &serde_json::Value) -> Vec<u8> {
        match serde_json::to_vec(value) {
            Ok(bytes) => bytes,
            Err(e) => panic!("serialize fixture value: {e}"),
        }
    }

    #[test]
    fn lowercase_sha256_hex_helper_accepts_only_exact_lowercase_digest() {
        assert!(is_lowercase_sha256_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(!is_lowercase_sha256_hex(
            "ABCDEF0000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(!is_lowercase_sha256_hex("abcdef"));
        assert!(!is_lowercase_sha256_hex(
            "000000000000000000000000000000000000000000000000000000000000000g"
        ));
    }

    #[test]
    fn validate_rejects_uppercase_weights_hash() {
        let issued = fixed_issued_at();
        let res = ModelCard::new(
            "ABCDEF0000000000000000000000000000000000000000000000000000000001",
            StringSet::new(["tool:read"]),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(res, Err(WeightsError::SchemaRejected(_))));
    }

    #[test]
    fn validate_rejects_short_weights_hash() {
        let issued = fixed_issued_at();
        let res = ModelCard::new(
            "abcdef",
            StringSet::default(),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(res, Err(WeightsError::SchemaRejected(_))));
    }

    #[test]
    fn validate_rejects_empty_training_data_class() {
        let issued = fixed_issued_at();
        let res = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::default(),
            StringSet::default(),
            "",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(res, Err(WeightsError::MissingField(_))));
    }

    #[test]
    fn validate_rejects_blank_or_padded_required_text_fields() {
        let issued = fixed_issued_at();
        let blank_training = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::default(),
            StringSet::default(),
            " ",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(
            blank_training,
            Err(WeightsError::MissingField("training_data_class"))
        ));

        let padded_issuer = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::default(),
            StringSet::default(),
            "public-internet",
            " https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(
            padded_issuer,
            Err(WeightsError::SchemaRejected(message)) if message.contains("issuer")
        ));
    }

    #[test]
    fn validate_rejects_expires_before_issued() {
        let issued = fixed_issued_at();
        let res = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::default(),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued - chrono::Duration::seconds(1),
        );
        assert!(matches!(res, Err(WeightsError::SchemaRejected(_))));
    }

    #[test]
    fn from_canonical_json_rejects_unknown_fields() {
        let mut value = good_card_value();
        match value {
            serde_json::Value::Object(ref mut map) => {
                map.insert(
                    "unexpected".to_string(),
                    serde_json::Value::String("field".to_string()),
                );
            }
            _ => panic!("fixture must be a JSON object"),
        }
        let bytes = value_to_bytes(&value);
        let res = ModelCard::from_canonical_json(&bytes);
        assert!(matches!(res, Err(WeightsError::Encoding(_))));
    }

    #[test]
    fn from_canonical_json_rejects_duplicate_set_entries() {
        let mut value = good_card_value();
        match value {
            serde_json::Value::Object(ref mut map) => {
                map.insert(
                    "allowed_capability_set".to_string(),
                    serde_json::json!(["tool:read", "tool:read"]),
                );
            }
            _ => panic!("fixture must be a JSON object"),
        }
        let bytes = value_to_bytes(&value);
        let res = ModelCard::from_canonical_json(&bytes);
        assert!(matches!(res, Err(WeightsError::Encoding(_))));
    }

    #[test]
    fn from_canonical_json_rejects_empty_set_entries() {
        let mut value = good_card_value();
        match value {
            serde_json::Value::Object(ref mut map) => {
                map.insert(
                    "banned_tools".to_string(),
                    serde_json::json!(["tool:exec", ""]),
                );
            }
            _ => panic!("fixture must be a JSON object"),
        }
        let bytes = value_to_bytes(&value);
        let res = ModelCard::from_canonical_json(&bytes);
        assert!(matches!(res, Err(WeightsError::Encoding(_))));
    }

    #[test]
    fn new_rejects_empty_set_entries() {
        let issued = fixed_issued_at();
        let res = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new([""]),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(res, Err(WeightsError::SchemaRejected(_))));
    }

    #[test]
    fn new_rejects_blank_or_padded_set_entries() {
        let issued = fixed_issued_at();
        let blank = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new([" "]),
            StringSet::default(),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(
            blank,
            Err(WeightsError::SchemaRejected(message)) if message.contains("allowed_capability_set")
        ));

        let padded = ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::default(),
            StringSet::new([" tool:exec"]),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(1),
        );
        assert!(matches!(
            padded,
            Err(WeightsError::SchemaRejected(message)) if message.contains("banned_tools")
        ));
    }

    #[test]
    fn require_live_rejects_expired_card() {
        let card = good_card();
        let later = card.expires_at + chrono::Duration::seconds(1);
        let res = card.require_live(later);
        assert!(matches!(res, Err(WeightsError::Expired { .. })));
    }

    #[test]
    fn canonical_round_trip_is_byte_stable() {
        let card = good_card();
        let bytes = match card.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("encode must succeed: {e}"),
        };
        let again = match ModelCard::from_canonical_json(&bytes) {
            Ok(c) => c,
            Err(e) => panic!("decode must succeed: {e}"),
        };
        let bytes2 = match again.to_canonical_json() {
            Ok(b) => b,
            Err(e) => panic!("re-encode must succeed: {e}"),
        };
        assert_eq!(bytes, bytes2, "canonical-json bytes must round-trip stably");
    }

    #[test]
    fn from_canonical_json_rejects_noncanonical_whitespace() {
        let card = good_card();
        let pretty = match serde_json::to_vec_pretty(&card) {
            Ok(bytes) => bytes,
            Err(e) => panic!("pretty encode must succeed: {e}"),
        };
        let res = ModelCard::from_canonical_json(&pretty);
        assert!(
            matches!(res, Err(WeightsError::Encoding(_))),
            "signed model cards must be presented as RFC 8785 canonical bytes"
        );
    }

    #[test]
    fn weights_hash_of_matches_known_vector() {
        // sha256(b"") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            weights_hash_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn allowed_capability_set_covers_subset() {
        let card = good_card();
        let req = StringSet::new(["tool:read"]);
        assert!(card.allowed_capability_set.covers(&req));
        let bad = StringSet::new(["tool:read", "tool:admin"]);
        assert!(!card.allowed_capability_set.covers(&bad));
    }

    #[test]
    fn banned_tools_intersects_detects_overlap() {
        let card = good_card();
        let req = StringSet::new(["tool:read", "tool:exec"]);
        assert!(card.banned_tools.intersects(&req));
        let benign = StringSet::new(["tool:read"]);
        assert!(!card.banned_tools.intersects(&benign));
    }
}
