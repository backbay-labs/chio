use std::collections::BTreeMap;

use chio_core::capability::{attenuation::ScopeHash, features::CapabilityNegotiation};
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::event::EventClassification;

/// Configuration for the AG-UI proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiProxyConfig {
    /// Whether to allow display-only events without a capability token.
    #[serde(default)]
    pub allow_display_without_capability: bool,

    /// Event classifications that require explicit capability grants.
    /// Defaults to all mutating actions.
    #[serde(default = "default_restricted_classifications")]
    pub restricted_classifications: Vec<EventClassification>,

    /// Maximum events per second before throttling.
    #[serde(default = "default_max_events_per_second")]
    pub max_events_per_second: u64,

    /// Capability issuer keys trusted for restricted AG-UI events.
    ///
    /// Restricted events fail closed unless the capability issuer is in this
    /// set and the token signature and time bounds verify.
    #[serde(default)]
    pub trusted_issuers: Vec<PublicKey>,

    /// Capability IDs revoked by the embedding runtime.
    ///
    /// Operators should feed this from the kernel revocation view or another
    /// authoritative revocation source when one is available.
    #[serde(default)]
    pub revoked_capability_ids: Vec<String>,

    /// Peer-negotiated capability feature profile. The proxy validates the
    /// advertised feature set before using it and defaults to
    /// `CapabilityNegotiation::t1_default()`, which enables current
    /// chain-binding semantics.
    #[serde(default = "default_proxy_peer_capabilities")]
    pub peer_capabilities: CapabilityNegotiation,

    /// Chain-binding trust roots, keyed by issuer public-key hex. Tokens with
    /// attenuation, budget sharing, scope attenuation, or delegation require an
    /// entry for their issuer; absent issuers fail-closed. Operators feed this
    /// from the kernel's trust-root registry.
    #[serde(default)]
    pub capability_trust_roots: BTreeMap<String, ScopeHash>,

    /// Signed direct-root tokens keyed by capability id for delegated
    /// negotiated family features.
    #[serde(default)]
    pub capability_family_roots: BTreeMap<String, chio_core::capability::token::CapabilityToken>,

    /// Parent-budget snapshots used to seed sibling-sum enforcement for
    /// delegated restricted events.
    #[serde(default)]
    pub parent_budget_snapshots: Vec<ParentBudgetSnapshot>,
}

/// Parent budget state supplied by the embedding runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentBudgetSnapshot {
    /// Parent capability id referenced by delegated child tokens.
    pub parent_token_id: String,
    /// Parent budget share in basis points.
    pub parent_share_bps: u16,
    /// Siblings already admitted under this parent.
    #[serde(default)]
    pub admitted_children: Vec<AdmittedChildBudget>,
}

/// Already-admitted child share in a parent budget snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittedChildBudget {
    /// Child capability id already admitted under the parent.
    pub child_token_id: String,
    /// Child share in basis points.
    pub share_bps: u16,
}

fn default_proxy_peer_capabilities() -> CapabilityNegotiation {
    CapabilityNegotiation::t1_default()
}

fn default_restricted_classifications() -> Vec<EventClassification> {
    vec![
        EventClassification::Mutate,
        EventClassification::Navigate,
        EventClassification::Create,
        EventClassification::Destroy,
        EventClassification::Submit,
    ]
}

fn default_max_events_per_second() -> u64 {
    1000
}

impl Default for AgUiProxyConfig {
    fn default() -> Self {
        Self {
            allow_display_without_capability: false,
            restricted_classifications: default_restricted_classifications(),
            max_events_per_second: default_max_events_per_second(),
            trusted_issuers: Vec::new(),
            revoked_capability_ids: Vec::new(),
            peer_capabilities: default_proxy_peer_capabilities(),
            capability_trust_roots: BTreeMap::new(),
            capability_family_roots: BTreeMap::new(),
            parent_budget_snapshots: Vec::new(),
        }
    }
}
