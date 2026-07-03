//! Core proxy logic for validating capability tokens on UI-facing events.

mod budget;
mod classify;
mod clock;
mod config;
mod core;
mod decision;
mod helpers;

pub use config::{AdmittedChildBudget, AgUiProxyConfig, ParentBudgetSnapshot};
pub use core::AgUiProxy;
pub use decision::{AgUiProxyError, ProxyDecision};

const AG_UI_SERVER_ID: &str = "ag-ui";

#[cfg(test)]
mod tests {
    use super::budget::build_budget_registry;
    use super::*;
    use crate::event::{AgUiEvent, EventClassification, EventType, TargetComponent};
    use crate::transport::{Transport, TransportKind};
    use chio_core::capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Constraint, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;

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
            chio_core::capability::token::CapabilityTokenBody {
                id: "cap-test".to_string(),
                issuer: kp.public_key(),
                subject: Keypair::generate().public_key(),
                scope: chio_core::capability::scope::ChioScope::default(),
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
        let delegatee = Keypair::generate().public_key();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: delegatee.clone(),
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
                subject: delegatee,
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
        let delegatee = Keypair::generate().public_key();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: delegatee.clone(),
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
                subject: delegatee,
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
        let delegatee = Keypair::generate().public_key();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent_id.to_string(),
                delegator: issuer.public_key(),
                delegatee: delegatee.clone(),
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
                subject: delegatee,
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

    #[test]
    fn budget_registry_builder_rejects_invalid_parent_snapshot() {
        let error = build_budget_registry(&[ParentBudgetSnapshot {
            parent_token_id: "cap-parent-invalid".to_string(),
            parent_share_bps: 10_001,
            admitted_children: vec![],
        }])
        .expect_err("invalid parent share should fail closed");

        assert!(error
            .to_string()
            .contains("budget registry failed: parent budget snapshot"));
    }

    #[test]
    fn permissive_constructor_with_invalid_budget_snapshot_still_fails_closed_on_delegation() {
        let issuer = Keypair::generate();
        let proxy = AgUiProxy::new(
            AgUiProxyConfig {
                trusted_issuers: vec![issuer.public_key()],
                parent_budget_snapshots: vec![ParentBudgetSnapshot {
                    parent_token_id: "cap-parent-invalid".to_string(),
                    parent_share_bps: 10_001,
                    admitted_children: vec![],
                }],
                ..Default::default()
            },
            Keypair::generate(),
        );
        let event = make_event(EventClassification::Submit);
        let cap = make_delegated_scoped_capability(
            &issuer,
            "submit",
            "cap-child-invalid-parent",
            "cap-parent-invalid",
        );
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-invalid-budget-snapshot".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("sibling-sum budget"));
        assert_eq!(transport.events_blocked, 1);
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
    fn display_event_rejects_untrusted_capability_by_default() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Display);
        let cap = make_capability();
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-display-untrusted".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-test");
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("issuer is not trusted"));
    }

    #[test]
    fn display_event_requires_display_scope_when_capability_supplied() {
        let issuer = Keypair::generate();
        let proxy = proxy_with_trusted_issuer(&issuer);
        let event = make_event(EventClassification::Display);
        let submit_cap = make_scoped_capability(&issuer, "submit");
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-display-wrong-scope".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy
            .evaluate(&event, Some(&submit_cap), &mut transport)
            .unwrap();

        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
        assert!(receipt
            .denial_reason
            .as_deref()
            .unwrap_or_default()
            .contains("scope does not authorize"));
    }

    #[test]
    fn proxy_rejects_empty_event_id_before_receipt() {
        let config = AgUiProxyConfig {
            allow_display_without_capability: true,
            ..Default::default()
        };
        let proxy = AgUiProxy::new(config, Keypair::generate());
        let event = AgUiEvent {
            event_id: "  ".to_string(),
            ..make_event(EventClassification::Display)
        };
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-empty-event-id".to_string(),
            "agent-1".to_string(),
        );

        let err = proxy
            .evaluate(&event, None, &mut transport)
            .expect_err("empty event_id must fail before AG-UI receipt construction");
        assert_eq!(
            err.to_string(),
            "invalid event: event_id must be a non-empty string"
        );
        assert_eq!(transport.total_events(), 0);
    }

    #[test]
    fn proxy_rejects_empty_target_component_before_receipt() {
        let config = AgUiProxyConfig {
            allow_display_without_capability: true,
            ..Default::default()
        };
        let proxy = AgUiProxy::new(config, Keypair::generate());
        let event = AgUiEvent {
            target: Some(TargetComponent {
                component_type: " ".to_string(),
                component_id: Some("composer".to_string()),
            }),
            ..make_event(EventClassification::Display)
        };
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-empty-target".to_string(),
            "agent-1".to_string(),
        );

        let err = proxy
            .evaluate(&event, None, &mut transport)
            .expect_err("empty target component type must fail before receipt construction");
        assert_eq!(
            err.to_string(),
            "invalid event: target.component_type must be a non-empty string"
        );
        assert_eq!(transport.total_events(), 0);
    }

    #[test]
    fn proxy_rejects_padded_or_control_event_identity_before_receipt() {
        let cases = vec![
            (
                "event_id",
                AgUiEvent {
                    event_id: " evt-padded ".to_string(),
                    ..make_event(EventClassification::Display)
                },
            ),
            (
                "agent_id",
                AgUiEvent {
                    agent_id: "agent\ncontrol".to_string(),
                    ..make_event(EventClassification::Display)
                },
            ),
            (
                "session_id",
                AgUiEvent {
                    session_id: Some(" sess-padded ".to_string()),
                    ..make_event(EventClassification::Display)
                },
            ),
            (
                "target.component_id",
                AgUiEvent {
                    target: Some(TargetComponent {
                        component_type: "chat".to_string(),
                        component_id: Some("composer\rcontrol".to_string()),
                    }),
                    ..make_event(EventClassification::Display)
                },
            ),
        ];

        for (field, event) in cases {
            let config = AgUiProxyConfig {
                allow_display_without_capability: true,
                ..Default::default()
            };
            let proxy = AgUiProxy::new(config, Keypair::generate());
            let mut transport = Transport::new(
                TransportKind::Sse,
                format!("conn-malformed-{field}"),
                "agent-1".to_string(),
            );

            let err = proxy
                .evaluate(&event, None, &mut transport)
                .expect_err("malformed event identity must fail before receipt construction");
            assert_eq!(
                err.to_string(),
                format!(
                    "invalid event: {field} must be unpadded and contain no control characters"
                )
            );
            assert_eq!(transport.total_events(), 0);
        }
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
