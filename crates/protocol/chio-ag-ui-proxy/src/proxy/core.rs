use std::sync::Mutex;

use chio_core::capability::{
    attenuation::ScopeHash, crypto_floor::CapabilityCryptoFloor, token::CapabilityToken,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel_core::scope::{resolve_capability_grants, ScopeMatchError};
use chio_kernel_core::{
    verify_capability_full, BudgetRegistry, BudgetSplitError, InMemoryBudgetRegistry,
    NoopBudgetRegistry, MAX_BUDGET_SHARE_BPS,
};
use tracing::{debug, warn};

use crate::event::AgUiEvent;
use crate::receipt::{AgUiReceipt, AgUiReceiptBody};
use crate::transport::{Transport, TransportKind};

use super::budget::{budget_seed_error, build_budget_registry};
use super::classify::derive_server_classification;
use super::clock::SystemClock;
use super::config::AgUiProxyConfig;
use super::decision::{AgUiProxyError, ProxyDecision};
use super::helpers::{
    capability_error_message, event_scope_arguments, grant_binds_event, restricted_tool_name,
};
use super::AG_UI_SERVER_ID;

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
        let budget_registry = build_budget_registry(&config.parent_budget_snapshots)
            .unwrap_or_else(|error| {
                warn!(
                    reason = %error,
                    "AG-UI proxy ignored invalid parent budget snapshot"
                );
                InMemoryBudgetRegistry::new()
            });
        Self {
            config,
            signing_key,
            budget_registry: Mutex::new(budget_registry),
        }
    }

    /// Create a new AG-UI proxy and reject invalid budget snapshot config.
    pub fn try_new(config: AgUiProxyConfig, signing_key: Keypair) -> Result<Self, AgUiProxyError> {
        let budget_registry = build_budget_registry(&config.parent_budget_snapshots)?;
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
        event
            .validate_boundary()
            .map_err(AgUiProxyError::InvalidEvent)?;
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
        let requires_capability = self
            .config
            .restricted_classifications
            .contains(&event.classification);

        if let Some(capability) = capability {
            return self.decide_capability_bound_event(event, capability);
        }

        if self.config.allow_display_without_capability && !requires_capability {
            return ProxyDecision::Forward;
        }

        let reason = if requires_capability {
            format!("capability required for {:?} events", event.classification)
        } else {
            "no capability token provided".to_string()
        };
        ProxyDecision::Block { reason }
    }

    fn decide_capability_bound_event(
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
