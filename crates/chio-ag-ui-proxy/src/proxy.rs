//! Core proxy logic for validating capability tokens on UI-facing events.

use std::collections::BTreeMap;
use std::sync::Mutex;

use chio_core::capability::{
    CapabilityCryptoFloor, CapabilityNegotiation, CapabilityToken, Constraint, ScopeHash, ToolGrant,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel_core::scope::{resolve_capability_grants, ScopeMatchError};
use chio_kernel_core::{
    verify_capability_full, BudgetRegistry, BudgetSplitError, CapabilityError, Clock,
    InMemoryBudgetRegistry, NoopBudgetRegistry, MAX_BUDGET_SHARE_BPS,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::event::{AgUiEvent, EventClassification, EventType};
use crate::receipt::{AgUiReceipt, AgUiReceiptBody};
use crate::transport::{Transport, TransportKind};

const AG_UI_SERVER_ID: &str = "ag-ui";

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
            parent_budget_snapshots: Vec::new(),
        }
    }
}

/// The proxy's decision for an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDecision {
    /// Forward the event to the UI.
    Forward,
    /// Block the event with a reason.
    Block { reason: String },
}

/// AG-UI proxy that validates capability tokens for UI-facing events.
pub struct AgUiProxy {
    config: AgUiProxyConfig,
    signing_key: Keypair,
    /// Persistent sibling-sum budget registry on the hot path. Hoisted
    /// onto the proxy so siblings on a delegated
    /// chain can be tracked across AG-UI events for the lifetime of
    /// the proxy. A fresh per-event registry would let two siblings
    /// on different events both see the same residual headroom and
    /// admit beyond the parent's share. Wrapped in `Mutex` because
    /// the underlying `InMemoryBudgetRegistry` interface takes
    /// `&mut dyn BudgetRegistry`; the lock is held only for the
    /// duration of one verify step inside a single event.
    budget_registry: Mutex<InMemoryBudgetRegistry>,
}

impl AgUiProxy {
    /// Create a new AG-UI proxy with the given config and signing key.
    pub fn new(config: AgUiProxyConfig, signing_key: Keypair) -> Self {
        let mut budget_registry = InMemoryBudgetRegistry::new();
        if let Err(error) =
            seed_budget_registry(&mut budget_registry, &config.parent_budget_snapshots)
        {
            warn!(
                reason = %error,
                "AG-UI proxy ignored invalid parent budget snapshot"
            );
            budget_registry = InMemoryBudgetRegistry::new();
        }
        Self {
            config,
            signing_key,
            budget_registry: Mutex::new(budget_registry),
        }
    }

    /// Create a new AG-UI proxy and reject invalid budget snapshot config.
    pub fn try_new(config: AgUiProxyConfig, signing_key: Keypair) -> Result<Self, AgUiProxyError> {
        let mut budget_registry = InMemoryBudgetRegistry::new();
        seed_budget_registry(&mut budget_registry, &config.parent_budget_snapshots)?;
        Ok(Self {
            config,
            signing_key,
            budget_registry: Mutex::new(budget_registry),
        })
    }

    /// Register a parent budget share for future delegated restricted events.
    pub fn register_parent_budget(
        &self,
        parent_token_id: impl Into<String>,
        parent_share_bps: u16,
    ) -> Result<(), AgUiProxyError> {
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets
            .register_parent(parent_token_id.into(), parent_share_bps)
            .map_err(|error| budget_seed_error("parent budget registration", &error))
    }

    /// Register an already-admitted child share under a parent budget.
    pub fn register_admitted_child_budget(
        &self,
        parent_token_id: &str,
        child_token_id: impl Into<String>,
        share_bps: u16,
    ) -> Result<(), AgUiProxyError> {
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets
            .try_admit_child(parent_token_id, child_token_id.into(), share_bps)
            .map_err(|error| budget_seed_error("admitted child budget registration", &error))
    }

    /// Evaluate an event against the proxy policy and produce a receipt.
    ///
    /// Returns the decision and a signed receipt.
    pub fn evaluate(
        &self,
        event: &AgUiEvent,
        capability: Option<&CapabilityToken>,
        transport: &mut Transport,
    ) -> Result<(ProxyDecision, AgUiReceipt), AgUiProxyError> {
        let mut server_event = event.clone();
        let decision = match derive_server_classification(event) {
            Ok(classification) => {
                server_event.classification = classification.clone();
                if classification != event.classification {
                    ProxyDecision::Block {
                        reason: format!(
                            "event classification mismatch: supplied {:?}, derived {:?}",
                            event.classification, classification
                        ),
                    }
                } else {
                    self.decide(&server_event, capability)
                }
            }
            Err(reason) => ProxyDecision::Block { reason },
        };
        let receipt = self.build_receipt(&server_event, capability, transport.kind, &decision)?;

        match &decision {
            ProxyDecision::Forward => {
                debug!(
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    "AG-UI proxy forwarding event"
                );
                transport.record_forwarded();
            }
            ProxyDecision::Block { reason } => {
                warn!(
                    event_id = %event.event_id,
                    reason = %reason,
                    "AG-UI proxy blocked event"
                );
                transport.record_blocked();
            }
        }

        Ok((decision, receipt))
    }

    fn decide(&self, event: &AgUiEvent, capability: Option<&CapabilityToken>) -> ProxyDecision {
        // Check if this classification requires a capability
        let requires_capability = self
            .config
            .restricted_classifications
            .contains(&event.classification);

        if requires_capability {
            match capability {
                None => ProxyDecision::Block {
                    reason: format!("capability required for {:?} events", event.classification),
                },
                Some(cap) => self.decide_restricted_event(event, cap),
            }
        } else if self.config.allow_display_without_capability || capability.is_some() {
            ProxyDecision::Forward
        } else {
            ProxyDecision::Block {
                reason: "no capability token provided".to_string(),
            }
        }
    }

    fn decide_restricted_event(
        &self,
        event: &AgUiEvent,
        capability: &CapabilityToken,
    ) -> ProxyDecision {
        if self
            .config
            .revoked_capability_ids
            .iter()
            .any(|revoked_id| revoked_id == &capability.id)
        {
            return ProxyDecision::Block {
                reason: "capability has been revoked".to_string(),
            };
        }

        let clock = SystemClock;
        // Route through `verify_capability_full` so feature validation and
        // chain-binding are enforced before forwarding any AG-UI event.
        let trust_roots = &self.config.capability_trust_roots;
        let trust_resolver = |issuer: &PublicKey| -> Option<ScopeHash> {
            trust_roots.get(&issuer.to_hex()).cloned()
        };
        let mut verify_only_budgets = NoopBudgetRegistry;
        if let Err(error) = verify_capability_full(
            capability,
            &self.config.trusted_issuers,
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &self.config.peer_capabilities,
            &trust_resolver,
            &mut verify_only_budgets,
        ) {
            return ProxyDecision::Block {
                reason: format!(
                    "capability verification failed: {}",
                    capability_error_message(&error)
                ),
            };
        }

        match resolve_capability_grants(
            capability,
            restricted_tool_name(&event.classification),
            AG_UI_SERVER_ID,
            &event_scope_arguments(event),
        ) {
            Ok(matches)
                if matches
                    .iter()
                    .any(|matched| grant_binds_event(matched.grant, event)) =>
            {
                match self.admit_capability_budget(capability) {
                    Ok(()) => ProxyDecision::Forward,
                    Err(error) => ProxyDecision::Block {
                        reason: format!(
                            "capability verification failed: capability rejected by sibling-sum budget: {error}"
                        ),
                    },
                }
            }
            Ok(_) | Err(ScopeMatchError::OutOfScope) => ProxyDecision::Block {
                reason: "capability scope does not authorize this AG-UI event".to_string(),
            },
            Err(ScopeMatchError::ConstraintError(reason)) => ProxyDecision::Block {
                reason: format!("capability scope constraint failed: {reason}"),
            },
        }
    }

    fn admit_capability_budget(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), BudgetSplitError> {
        if let Some(parent_link) = capability.delegation_chain.last() {
            let proposed_share = capability.budget_share_bps.unwrap_or(MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            budgets.try_admit_child(
                parent_link.capability_id.as_str(),
                capability.id.clone(),
                proposed_share,
            )?;
        }

        Ok(())
    }

    fn build_receipt(
        &self,
        event: &AgUiEvent,
        capability: Option<&CapabilityToken>,
        transport_kind: TransportKind,
        decision: &ProxyDecision,
    ) -> Result<AgUiReceipt, AgUiProxyError> {
        let payload_hash = AgUiReceipt::hash_payload(&event.payload)
            .map_err(|e| AgUiProxyError::ReceiptSigning(e.to_string()))?;

        let (allowed, denial_reason) = match decision {
            ProxyDecision::Forward => (true, None),
            ProxyDecision::Block { reason } => (false, Some(reason.clone())),
        };

        let capability_id = capability
            .map(|c| c.id.clone())
            .unwrap_or_else(|| "<none>".to_string());

        let body = AgUiReceiptBody {
            id: format!("agui-{}", event.event_id),
            timestamp: event.timestamp,
            event_id: event.event_id.clone(),
            agent_id: event.agent_id.clone(),
            session_id: event.session_id.clone(),
            capability_id,
            event_type: event.event_type.clone(),
            target: event.target.clone(),
            classification: event.classification.clone(),
            transport: transport_kind,
            allowed,
            denial_reason,
            payload_hash,
            kernel_key: self.signing_key.public_key(),
        };

        AgUiReceipt::sign(body, &self.signing_key)
            .map_err(|e| AgUiProxyError::ReceiptSigning(e.to_string()))
    }

    /// Return a reference to the proxy configuration.
    #[must_use]
    pub fn config(&self) -> &AgUiProxyConfig {
        &self.config
    }
}

fn derive_server_classification(event: &AgUiEvent) -> Result<EventClassification, String> {
    match &event.event_type {
        EventType::TextStream => Ok(EventClassification::Display),
        EventType::StateUpdate => Ok(EventClassification::Mutate),
        EventType::Navigation => Ok(EventClassification::Navigate),
        EventType::Lifecycle => derive_lifecycle_classification(&event.payload),
        EventType::FormAction => Ok(EventClassification::Submit),
        EventType::Notification | EventType::Error => Ok(EventClassification::Alert),
        EventType::Custom(name) => Err(format!(
            "custom AG-UI event type cannot be server-classified: {name}"
        )),
    }
}

fn derive_lifecycle_classification(
    payload: &serde_json::Value,
) -> Result<EventClassification, String> {
    let action = payload
        .get("action")
        .or_else(|| payload.get("lifecycle"))
        .or_else(|| payload.get("event"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_lowercase);

    match action.as_deref() {
        Some("create" | "created" | "mount" | "mounted" | "open" | "opened") => {
            Ok(EventClassification::Create)
        }
        Some("destroy" | "destroyed" | "unmount" | "unmounted" | "close" | "closed") => {
            Ok(EventClassification::Destroy)
        }
        Some("update" | "updated" | "change" | "changed") => Ok(EventClassification::Mutate),
        Some(other) => Err(format!(
            "lifecycle AG-UI event action is not classifiable: {other}"
        )),
        None => Err("lifecycle AG-UI event missing classifiable action".to_string()),
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

fn capability_error_message(error: &CapabilityError) -> &'static str {
    match error {
        CapabilityError::UntrustedIssuer => "issuer is not trusted",
        CapabilityError::InvalidSignature => "signature did not verify",
        CapabilityError::NotYetValid => "token is not yet valid",
        CapabilityError::Expired => "token has expired",
        CapabilityError::CryptoFloorRejected(_) => "capability crypto floor rejected",
        CapabilityError::AttenuationViolation(_) => "capability rejected by chain binding",
        CapabilityError::BudgetSplitRejected(_) => "capability rejected by sibling-sum budget",
        CapabilityError::Internal(_) => "internal verification error",
    }
}

fn restricted_tool_name(classification: &EventClassification) -> &'static str {
    match classification {
        EventClassification::Display => "display",
        EventClassification::Mutate => "mutate",
        EventClassification::Navigate => "navigate",
        EventClassification::Create => "create",
        EventClassification::Destroy => "destroy",
        EventClassification::Submit => "submit",
        EventClassification::Alert => "alert",
    }
}

fn event_scope_arguments(event: &AgUiEvent) -> serde_json::Value {
    let mut args = serde_json::json!({
        "event_id": event.event_id,
        "agent_id": event.agent_id,
        "event_classification": restricted_tool_name(&event.classification),
        "payload": event.payload,
    });

    if let serde_json::Value::Object(ref mut map) = args {
        if let Some(session_id) = &event.session_id {
            map.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.clone()),
            );
        }
        if let Some(target) = &event.target {
            map.insert(
                "target_component_type".to_string(),
                serde_json::Value::String(target.component_type.clone()),
            );
            if let Some(component_id) = &target.component_id {
                map.insert(
                    "target_component_id".to_string(),
                    serde_json::Value::String(component_id.clone()),
                );
            }
        }
    }

    args
}

fn grant_binds_event(grant: &ToolGrant, event: &AgUiEvent) -> bool {
    if !custom_constraint_matches_if_present(grant, "event_id", &event.event_id) {
        return false;
    }

    if !trusted_custom_constraint_matches(grant, "session_id", event.session_id.as_deref()) {
        return false;
    }

    let target_component_type = event
        .target
        .as_ref()
        .map(|target| target.component_type.as_str());
    if !trusted_custom_constraint_matches(grant, "target_component_type", target_component_type) {
        return false;
    }

    let target_component_id = event
        .target
        .as_ref()
        .and_then(|target| target.component_id.as_deref());
    if !trusted_custom_constraint_matches(grant, "target_component_id", target_component_id) {
        return false;
    }

    true
}

fn trusted_custom_constraint_matches(
    grant: &ToolGrant,
    key: &str,
    trusted_value: Option<&str>,
) -> bool {
    let mut saw_constraint = false;

    for constraint in &grant.constraints {
        if let Constraint::Custom(candidate_key, candidate_value) = constraint {
            if candidate_key == key {
                saw_constraint = true;
                if trusted_value != Some(candidate_value.as_str()) {
                    return false;
                }
            }
        }
    }

    if trusted_value.is_some() {
        saw_constraint
    } else {
        !saw_constraint
    }
}

fn custom_constraint_matches_if_present(grant: &ToolGrant, key: &str, expected: &str) -> bool {
    grant.constraints.iter().all(|constraint| match constraint {
        Constraint::Custom(candidate_key, candidate_value) if candidate_key == key => {
            candidate_value == expected
        }
        _ => true,
    })
}

fn seed_budget_registry(
    budgets: &mut InMemoryBudgetRegistry,
    snapshots: &[ParentBudgetSnapshot],
) -> Result<(), AgUiProxyError> {
    for snapshot in snapshots {
        budgets
            .register_parent(snapshot.parent_token_id.clone(), snapshot.parent_share_bps)
            .map_err(|error| budget_seed_error("parent budget snapshot", &error))?;
        for child in &snapshot.admitted_children {
            budgets
                .try_admit_child(
                    snapshot.parent_token_id.as_str(),
                    child.child_token_id.clone(),
                    child.share_bps,
                )
                .map_err(|error| budget_seed_error("admitted child budget snapshot", &error))?;
        }
    }
    Ok(())
}

fn budget_seed_error(context: &str, error: &BudgetSplitError) -> AgUiProxyError {
    AgUiProxyError::BudgetRegistry(format!("{context}: {error}"))
}

/// Errors from the AG-UI proxy.
#[derive(Debug, thiserror::Error)]
pub enum AgUiProxyError {
    #[error("receipt signing failed: {0}")]
    ReceiptSigning(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("budget registry failed: {0}")]
    BudgetRegistry(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, TargetComponent};
    use chio_core::capability::{
        CapabilityTokenBody, ChioScope, DelegationLink, DelegationLinkBody, Operation,
    };

    fn make_event(classification: EventClassification) -> AgUiEvent {
        let event_type = match classification {
            EventClassification::Display => EventType::TextStream,
            EventClassification::Mutate => EventType::StateUpdate,
            EventClassification::Navigate => EventType::Navigation,
            EventClassification::Create | EventClassification::Destroy => EventType::Lifecycle,
            EventClassification::Submit => EventType::FormAction,
            EventClassification::Alert => EventType::Notification,
        };
        AgUiEvent {
            event_id: "evt-test".to_string(),
            timestamp: 1700000000,
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            event_type,
            target: Some(TargetComponent {
                component_type: "chat".to_string(),
                component_id: None,
            }),
            classification,
            payload: serde_json::json!({"text": "hi"}),
        }
    }

    fn make_event_with_type(
        event_type: EventType,
        classification: EventClassification,
    ) -> AgUiEvent {
        AgUiEvent {
            event_type,
            classification,
            ..make_event(EventClassification::Display)
        }
    }

    fn make_capability() -> CapabilityToken {
        let kp = Keypair::generate();
        CapabilityToken::sign(
            chio_core::capability::CapabilityTokenBody {
                id: "cap-test".to_string(),
                issuer: kp.public_key(),
                subject: Keypair::generate().public_key(),
                scope: chio_core::capability::ChioScope::default(),
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &kp,
        )
        .unwrap()
    }

    fn make_scoped_capability(issuer: &Keypair, tool_name: &str) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-scoped".to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: AG_UI_SERVER_ID.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![
                            Constraint::Custom("session_id".to_string(), "sess-1".to_string()),
                            Constraint::Custom(
                                "target_component_type".to_string(),
                                "chat".to_string(),
                            ),
                        ],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            issuer,
        )
        .unwrap()
    }

    fn make_delegated_scoped_capability(
        issuer: &Keypair,
        tool_name: &str,
        child_id: &str,
        parent_id: &str,
    ) -> CapabilityToken {
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: Keypair::generate().public_key(),
                attenuations: vec![],
                timestamp: 0,
                scope_hash: None,
            },
            issuer,
        )
        .unwrap();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: child_id.to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: AG_UI_SERVER_ID.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![
                            Constraint::Custom("session_id".to_string(), "sess-1".to_string()),
                            Constraint::Custom(
                                "target_component_type".to_string(),
                                "chat".to_string(),
                            ),
                        ],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![parent_link],
            },
            issuer,
        )
        .unwrap()
    }

    fn make_delegated_component_scoped_capability(
        issuer: &Keypair,
        tool_name: &str,
        child_id: &str,
        parent_id: &str,
        component_id: &str,
    ) -> CapabilityToken {
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: Keypair::generate().public_key(),
                attenuations: vec![],
                timestamp: 0,
                scope_hash: None,
            },
            issuer,
        )
        .unwrap();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: child_id.to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: AG_UI_SERVER_ID.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![
                            Constraint::Custom("session_id".to_string(), "sess-1".to_string()),
                            Constraint::Custom(
                                "target_component_type".to_string(),
                                "chat".to_string(),
                            ),
                            Constraint::Custom(
                                "target_component_id".to_string(),
                                component_id.to_string(),
                            ),
                        ],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![parent_link],
            },
            issuer,
        )
        .unwrap()
    }

    fn make_delegated_event_scoped_capability(
        issuer: &Keypair,
        tool_name: &str,
        child_id: &str,
        parent_id: &str,
        event_id: &str,
    ) -> CapabilityToken {
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: Keypair::generate().public_key(),
                attenuations: vec![],
                timestamp: 0,
                scope_hash: None,
            },
            issuer,
        )
        .unwrap();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: child_id.to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: AG_UI_SERVER_ID.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![
                            Constraint::Custom("event_id".to_string(), event_id.to_string()),
                            Constraint::Custom("session_id".to_string(), "sess-1".to_string()),
                            Constraint::Custom(
                                "target_component_type".to_string(),
                                "chat".to_string(),
                            ),
                        ],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![parent_link],
            },
            issuer,
        )
        .unwrap()
    }

    fn parent_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshot {
        ParentBudgetSnapshot {
            parent_token_id: parent_id.to_string(),
            parent_share_bps: 10_000,
            admitted_children: vec![],
        }
    }

    fn oversubscribed_budget_snapshot(parent_id: &str) -> ParentBudgetSnapshot {
        ParentBudgetSnapshot {
            parent_token_id: parent_id.to_string(),
            parent_share_bps: 10_000,
            admitted_children: vec![AdmittedChildBudget {
                child_token_id: "cap-sibling".to_string(),
                share_bps: 1,
            }],
        }
    }

    fn proxy_with_trusted_issuer(issuer: &Keypair) -> AgUiProxy {
        AgUiProxy::new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                ..Default::default()
            },
            Keypair::generate(),
        )
    }

    #[test]
    fn display_event_blocked_without_capability_by_default() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Display);
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-1".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
    }

    #[test]
    fn display_event_allowed_when_configured() {
        let config = AgUiProxyConfig {
            allow_display_without_capability: true,
            ..Default::default()
        };
        let proxy = AgUiProxy::new(config, Keypair::generate());
        let event = make_event(EventClassification::Display);
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-1".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(transport.events_forwarded, 1);
    }

    #[test]
    fn mutating_event_requires_capability() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Mutate);
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-1".to_string(),
            "agent-1".to_string(),
        );

        // Without capability
        let (decision, _) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert!(matches!(decision, ProxyDecision::Block { .. }));

        // With an untrusted empty-scope capability
        let cap = make_capability();
        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();
        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-test");
    }

    #[test]
    fn restricted_event_rejects_self_signed_empty_scope_capability() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Submit);
        let cap = make_capability();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-2".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
    }

    #[test]
    fn restricted_event_accepts_properly_scoped_trusted_capability() {
        let issuer = Keypair::generate();
        let proxy = proxy_with_trusted_issuer(&issuer);
        let event = make_event(EventClassification::Submit);
        let cap = make_scoped_capability(&issuer, "submit");
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-3".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(transport.events_forwarded, 1);
        assert_eq!(receipt.capability_id, "cap-scoped");
    }

    #[test]
    fn restricted_event_accepts_delegated_capability_with_parent_budget_snapshot() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::try_new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![parent_budget_snapshot("cap-parent")],
                ..Default::default()
            },
            Keypair::generate(),
        )
        .unwrap();
        let event = make_event(EventClassification::Submit);
        let cap = make_delegated_scoped_capability(&issuer, "submit", "cap-child", "cap-parent");
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(transport.events_forwarded, 1);
        assert_eq!(receipt.capability_id, "cap-child");
    }

    #[test]
    fn restricted_event_accepts_delegated_capability_after_runtime_parent_registration() {
        let issuer = Keypair::generate();
        let proxy = proxy_with_trusted_issuer(&issuer);
        proxy
            .register_parent_budget("cap-parent", 10_000)
            .expect("register parent budget");
        let event = make_event(EventClassification::Submit);
        let cap = make_delegated_scoped_capability(&issuer, "submit", "cap-child", "cap-parent");
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated-runtime".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-child");
    }

    #[test]
    fn denied_delegated_event_does_not_consume_sibling_budget() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::try_new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![parent_budget_snapshot("cap-parent")],
                ..Default::default()
            },
            Keypair::generate(),
        )
        .unwrap();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated-scope-deny".to_string(),
            "agent-1".to_string(),
        );

        let wrong_session_event = AgUiEvent {
            event_id: "evt-wrong-session".to_string(),
            session_id: Some("sess-2".to_string()),
            ..make_event(EventClassification::Submit)
        };
        let wrong_session_cap =
            make_delegated_scoped_capability(&issuer, "submit", "cap-wrong", "cap-parent");

        let (decision, receipt) = proxy
            .evaluate(
                &wrong_session_event,
                Some(&wrong_session_cap),
                &mut transport,
            )
            .unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("scope does not authorize"));

        let valid_event = AgUiEvent {
            event_id: "evt-valid-session".to_string(),
            ..make_event(EventClassification::Submit)
        };
        let valid_cap =
            make_delegated_scoped_capability(&issuer, "submit", "cap-valid", "cap-parent");

        let (decision, receipt) = proxy
            .evaluate(&valid_event, Some(&valid_cap), &mut transport)
            .unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-valid");
        assert_eq!(transport.events_forwarded, 1);
    }

    #[test]
    fn payload_event_id_spoofing_is_denied_without_consuming_sibling_budget() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::try_new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![parent_budget_snapshot("cap-parent")],
                ..Default::default()
            },
            Keypair::generate(),
        )
        .unwrap();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated-event-spoof".to_string(),
            "agent-1".to_string(),
        );

        let spoofed_event = AgUiEvent {
            event_id: "evt-spoofed".to_string(),
            payload: serde_json::json!({
                "event_id": "evt-authorized",
                "text": "spoof"
            }),
            ..make_event(EventClassification::Submit)
        };
        let spoofed_cap = make_delegated_event_scoped_capability(
            &issuer,
            "submit",
            "cap-spoofed",
            "cap-parent",
            "evt-authorized",
        );

        let (decision, receipt) = proxy
            .evaluate(&spoofed_event, Some(&spoofed_cap), &mut transport)
            .unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("scope does not authorize"));

        let valid_event = AgUiEvent {
            event_id: "evt-valid-sibling".to_string(),
            payload: serde_json::json!({"text": "valid"}),
            ..make_event(EventClassification::Submit)
        };
        let valid_cap = make_delegated_event_scoped_capability(
            &issuer,
            "submit",
            "cap-valid-sibling",
            "cap-parent",
            "evt-valid-sibling",
        );

        let (decision, receipt) = proxy
            .evaluate(&valid_event, Some(&valid_cap), &mut transport)
            .unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-valid-sibling");
        assert_eq!(transport.events_forwarded, 1);
    }

    #[test]
    fn payload_session_and_target_spoofing_is_denied_without_consuming_sibling_budget() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::try_new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![parent_budget_snapshot("cap-parent")],
                ..Default::default()
            },
            Keypair::generate(),
        )
        .unwrap();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated-metadata-spoof".to_string(),
            "agent-1".to_string(),
        );

        let spoofed_event = AgUiEvent {
            event_id: "evt-metadata-spoof".to_string(),
            session_id: None,
            target: None,
            payload: serde_json::json!({
                "metadata": {
                    "session_id": "sess-1",
                    "target_component_type": "chat",
                    "target_component_id": "composer"
                },
                "text": "spoof"
            }),
            ..make_event(EventClassification::Submit)
        };
        let spoofed_cap = make_delegated_component_scoped_capability(
            &issuer,
            "submit",
            "cap-metadata-spoof",
            "cap-parent",
            "composer",
        );

        let (decision, receipt) = proxy
            .evaluate(&spoofed_event, Some(&spoofed_cap), &mut transport)
            .unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("scope does not authorize"));

        let valid_event = AgUiEvent {
            event_id: "evt-valid-metadata-sibling".to_string(),
            target: Some(TargetComponent {
                component_type: "chat".to_string(),
                component_id: Some("composer".to_string()),
            }),
            payload: serde_json::json!({"text": "valid"}),
            ..make_event(EventClassification::Submit)
        };
        let valid_cap = make_delegated_component_scoped_capability(
            &issuer,
            "submit",
            "cap-valid-metadata-sibling",
            "cap-parent",
            "composer",
        );

        let (decision, receipt) = proxy
            .evaluate(&valid_event, Some(&valid_cap), &mut transport)
            .unwrap();

        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-valid-metadata-sibling");
        assert_eq!(transport.events_forwarded, 1);
    }

    #[test]
    fn restricted_event_rejects_oversubscribed_delegated_sibling() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::try_new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![oversubscribed_budget_snapshot("cap-parent")],
                ..Default::default()
            },
            Keypair::generate(),
        )
        .unwrap();
        let event = make_event(EventClassification::Submit);
        let cap = make_delegated_scoped_capability(&issuer, "submit", "cap-child", "cap-parent");
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-delegated-oversub".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("sibling-sum budget"));
    }

    #[test]
    fn state_update_cannot_downgrade_classification_to_display() {
        let config = AgUiProxyConfig {
            allow_display_without_capability: true,
            ..Default::default()
        };
        let proxy = AgUiProxy::new(config, Keypair::generate());
        let event = make_event_with_type(EventType::StateUpdate, EventClassification::Display);
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-spoof".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, None, &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
    }

    #[test]
    fn server_classified_restricted_event_requires_verified_capability() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event_with_type(EventType::StateUpdate, EventClassification::Mutate);
        let cap = make_capability();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-forged-cap".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
    }

    #[test]
    fn receipt_includes_transport_and_event_metadata() {
        let kp = Keypair::generate();
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), kp);
        let event = make_event(EventClassification::Display);
        let cap = make_capability();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-2".to_string(),
            "agent-1".to_string(),
        );

        let (_, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();
        assert_eq!(receipt.transport, TransportKind::WebSocket);
        assert_eq!(receipt.event_type, EventType::TextStream);
        assert!(receipt.target.is_some());
        assert!(receipt.verify_embedded_signature().unwrap());
    }
}
