//! Marketplace manifest extension.
//!
//! Adds optional `price: GuardPrice` and `reputation_floor: ReputationTier`
//! fields parsed out of a guard manifest layer JSON document. The fields
//! are additive: a manifest layer without a `marketplace` block parses
//! cleanly with `price = GuardPrice::zero("USD")` and
//! `reputation_floor = ReputationTier::Tier0`, preserving the
//! local Sigstore-bundle verification and pull semantics verbatim.
//!
//! This module is gated behind the `marketplace` cargo feature so the
//! default `chio-guard-registry` build, including the `--no-default-features`
//! build, never sees the new dependency on `chio-reputation`.

use chio_reputation::ReputationTier;
use serde::{Deserialize, Serialize};

use crate::oci::GuardRegistryError;

/// Default ISO 4217 currency for zero-priced manifests.
pub const DEFAULT_GUARD_PRICE_CURRENCY: &str = "USD";

/// JSON Pointer-style key under which the marketplace block lives in a
/// guard manifest layer document. Manifests without this block are
/// interpreted as zero-price, `tier_0`-floor.
pub const MARKETPLACE_BLOCK_KEY: &str = "marketplace";

/// Per-invocation guard price expressed in currency minor units.
///
/// Mirrors `chio_core::capability::scope::MonetaryAmount` shape but lives on
/// the registry surface so callers that only depend on
/// `chio-guard-registry` do not pull `chio-core` transitively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardPrice {
    /// Amount per invocation in the currency's smallest unit
    /// (for example USD cents). Zero means free-tier.
    pub units: u64,
    /// ISO 4217 currency code. Examples: "USD", "EUR", "JPY".
    pub currency: String,
}

impl GuardPrice {
    /// Build a price from raw minor units and a currency code.
    #[must_use]
    pub fn new(units: u64, currency: impl Into<String>) -> Self {
        Self {
            units,
            currency: currency.into(),
        }
    }

    /// The free-tier sentinel for manifests without marketplace pricing.
    #[must_use]
    pub fn zero(currency: impl Into<String>) -> Self {
        Self::new(0, currency)
    }

    /// Whether this price is the free-tier sentinel.
    #[must_use]
    pub fn is_free(&self) -> bool {
        self.units == 0
    }
}

impl Default for GuardPrice {
    fn default() -> Self {
        Self::zero(DEFAULT_GUARD_PRICE_CURRENCY)
    }
}

/// Optional marketplace block parsed out of a guard manifest layer JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GuardMarketplaceBlock {
    /// Per-invocation price. Defaults to `GuardPrice::zero("USD")`.
    #[serde(default)]
    pub price: GuardPrice,
    /// Reputation floor required for marketplace discovery. Defaults
    /// to `ReputationTier::Tier0` (no signal required).
    #[serde(default)]
    pub reputation_floor: ReputationTier,
}

impl GuardMarketplaceBlock {
    /// Parse a guard manifest layer JSON document and extract the
    /// optional `marketplace` block. Manifests without a block return
    /// `GuardMarketplaceBlock::default()`. Manifests with a malformed
    /// block fail closed via `GuardRegistryError::ConfigSerialize`.
    pub fn from_manifest_bytes(bytes: &[u8]) -> Result<Self, GuardRegistryError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let Some(object) = value.as_object() else {
            return Ok(Self::default());
        };
        let Some(block) = object.get(MARKETPLACE_BLOCK_KEY) else {
            return Ok(Self::default());
        };
        let parsed: GuardMarketplaceBlock = serde_json::from_value(block.clone())?;
        Ok(parsed)
    }

    /// Whether the marketplace block is the zero-priced default
    /// (zero-priced, `tier_0`-floor). Used by callers who want to know
    /// if explicit marketplace metadata was attached.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.price.is_free()
            && self.price.currency == DEFAULT_GUARD_PRICE_CURRENCY
            && matches!(self.reputation_floor, ReputationTier::Tier0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_without_marketplace_block_is_default() {
        let bytes = b"{\"name\":\"pii-mask\"}";
        let block = match GuardMarketplaceBlock::from_manifest_bytes(bytes) {
            Ok(block) => block,
            Err(error) => panic!("manifest should parse: {error}"),
        };
        assert!(block.is_default());
        assert!(block.price.is_free());
        assert_eq!(block.price.currency, DEFAULT_GUARD_PRICE_CURRENCY);
        assert_eq!(block.reputation_floor, ReputationTier::Tier0);
    }

    #[test]
    fn manifest_with_marketplace_block_round_trips() {
        let bytes = br#"{
            "name": "pii-mask",
            "marketplace": {
                "price": { "units": 250, "currency": "USD" },
                "reputation_floor": "tier2"
            }
        }"#;
        let block = match GuardMarketplaceBlock::from_manifest_bytes(bytes) {
            Ok(block) => block,
            Err(error) => panic!("manifest should parse: {error}"),
        };
        assert!(!block.is_default());
        assert_eq!(block.price.units, 250);
        assert_eq!(block.price.currency, "USD");
        assert_eq!(block.reputation_floor, ReputationTier::Tier2);
    }

    #[test]
    fn empty_marketplace_block_falls_back_to_defaults() {
        let bytes = br#"{"marketplace": {}}"#;
        let block = match GuardMarketplaceBlock::from_manifest_bytes(bytes) {
            Ok(block) => block,
            Err(error) => panic!("manifest should parse: {error}"),
        };
        assert!(block.is_default());
    }

    #[test]
    fn marketplace_block_rejects_unknown_fields() {
        let bytes = br#"{"marketplace": {"unknown_field": 1}}"#;
        assert!(GuardMarketplaceBlock::from_manifest_bytes(bytes).is_err());
    }

    #[test]
    fn non_object_root_is_default() {
        // Permissive on shape: a manifest that is not a JSON object is
        // not the marketplace's concern. Existing manifest validation
        // (verify.rs) catches this on the publish/pull path.
        let bytes = b"[1, 2, 3]";
        let block = match GuardMarketplaceBlock::from_manifest_bytes(bytes) {
            Ok(block) => block,
            Err(error) => panic!("manifest should parse: {error}"),
        };
        assert!(block.is_default());
    }

    #[test]
    fn guard_price_zero_is_free() {
        assert!(GuardPrice::zero("USD").is_free());
        assert!(!GuardPrice::new(1, "USD").is_free());
    }
}
