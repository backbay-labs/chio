use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Capability-negotiation schema exchanged during federation handshakes.
pub const CHIO_CAPABILITIES_SCHEMA: &str = "chio.capabilities.v1";

/// Peers can process anchor-batch v1 signed artifacts.
pub const ACCEPTS_ANCHOR_BATCH_V1: &str = "accepts_anchor_batch_v1";

/// Peers can process hybrid classical-plus-ML-DSA signatures.
pub const ACCEPTS_HYBRID_SIGNATURES: &str = "accepts_hybrid_signatures";

/// Peers enforce delegation-chain binding for attenuated capability tokens.
pub const DELEGATION_CHAIN_BINDING: &str = "delegation_chain_binding";

/// Peers can verify and enforce aggregate invocation budgets.
pub const AGGREGATE_INVOCATION_BUDGET: &str = "aggregate_invocation_budget";

/// Peers can verify and enforce cumulative approval budgets.
pub const CUMULATIVE_APPROVAL_BUDGET: &str = "cumulative_approval_budget";

/// Peers can verify policy-bound threshold governed approval sets.
pub const THRESHOLD_GOVERNED_APPROVALS: &str = "threshold_governed_approvals";

/// Peers can verify protocol-owned active-response plan intents.
pub const GOVERNED_ACTIVE_RESPONSE_PLAN: &str = "governed_active_response_plan";

fn capabilities_schema() -> String {
    CHIO_CAPABILITIES_SCHEMA.to_string()
}

fn is_empty_capability_features(features: &BTreeMap<String, bool>) -> bool {
    features.is_empty()
}

/// Peer-advertised protocol feature bitset.
///
/// The map is intentionally string-keyed so new additive features can be
/// introduced without a flag-day enum release. Validation still rejects
/// malformed names fail-closed before any negotiated feature is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityNegotiation {
    #[serde(default = "capabilities_schema")]
    pub schema: String,
    #[serde(default, skip_serializing_if = "is_empty_capability_features")]
    pub features: BTreeMap<String, bool>,
}

impl Default for CapabilityNegotiation {
    fn default() -> Self {
        Self::v1_default()
    }
}

impl CapabilityNegotiation {
    /// Baseline peer profile: v1 capability tokens only.
    #[must_use]
    pub fn v1_default() -> Self {
        Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features: BTreeMap::new(),
        }
    }

    /// T1 peer profile: current capability semantics and anchor batches.
    ///
    /// The [`DELEGATION_CHAIN_BINDING`] flag is
    /// advertised as `true` so production peers exercise the
    /// chain-binding check by default. Peers that need to interoperate
    /// with a counterparty that has not rolled out chain-binding can
    /// explicitly clear the flag in the intersected profile, but the
    /// safe direction is to leave it on.
    #[must_use]
    pub fn t1_default() -> Self {
        let mut features = BTreeMap::new();
        features.insert(ACCEPTS_ANCHOR_BATCH_V1.to_string(), true);
        features.insert(DELEGATION_CHAIN_BINDING.to_string(), true);
        features.insert(THRESHOLD_GOVERNED_APPROVALS.to_string(), true);
        features.insert(GOVERNED_ACTIVE_RESPONSE_PLAN.to_string(), true);
        Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features,
        }
    }

    /// Return whether a named feature is explicitly advertised.
    #[must_use]
    pub fn supports(&self, feature: &str) -> bool {
        self.features.get(feature).copied().unwrap_or(false)
    }

    /// Validate schema and feature-name shape before negotiation.
    pub fn validate(&self) -> Result<()> {
        if self.schema != CHIO_CAPABILITIES_SCHEMA {
            return Err(Error::CanonicalJson(format!(
                "unsupported capability negotiation schema: {}",
                self.schema
            )));
        }
        for feature in self.features.keys() {
            validate_capability_feature_name(feature)?;
        }
        Ok(())
    }

    /// Intersect two negotiated feature sets.
    pub fn negotiated_with(&self, remote: &Self) -> Result<Self> {
        self.validate()?;
        remote.validate()?;
        let mut features = BTreeMap::new();
        for feature in self.features.keys().chain(remote.features.keys()) {
            if features.contains_key(feature) {
                continue;
            }
            let local = self.features.get(feature).copied();
            let remote = remote.features.get(feature).copied();
            match (local, remote) {
                (Some(true), Some(true)) => {
                    features.insert(feature.clone(), true);
                }
                (Some(false), _) | (_, Some(false)) => {
                    features.insert(feature.clone(), false);
                }
                _ => {}
            }
        }
        Ok(Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features,
        })
    }
}

fn validate_capability_feature_name(feature: &str) -> Result<()> {
    let valid = !feature.is_empty()
        && feature.len() <= 96
        && feature
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::CanonicalJson(format!(
            "malformed capability negotiation feature: {feature}"
        )))
    }
}
