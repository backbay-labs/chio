use super::*;
use std::sync::{Arc, Barrier};

fn make_context(request_id: &str) -> OperationContext {
    OperationContext {
        session_id: SessionId::new("sess-1"),
        request_id: RequestId::new(request_id),
        agent_id: "agent-1".to_string(),
        parent_request_id: None,
        progress_token: Some(ProgressToken::String("progress-1".to_string())),
    }
}

#[test]
fn lifecycle_transitions_cover_ready_draining_closed() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

    assert_eq!(session.state(), SessionState::Initializing);
    session.activate().unwrap();
    assert_eq!(session.state(), SessionState::Ready);
    session.begin_draining().unwrap();
    assert_eq!(session.state(), SessionState::Draining);
    session.close().unwrap();
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn lifecycle_transitions_do_not_require_exclusive_session_borrow() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let shared = &session;

    shared.activate().unwrap();
    assert_eq!(shared.state(), SessionState::Ready);
    shared.begin_draining().unwrap();
    assert_eq!(shared.state(), SessionState::Draining);
}

#[test]
fn close_refuses_to_clear_active_requests_until_drained() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-close-drain");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();

    let err = session.close().unwrap_err();
    assert!(matches!(
        err,
        SessionError::CloseRequiresDrain {
            active_count: 1,
            ..
        }
    ));
    assert_eq!(session.state(), SessionState::Draining);
    assert_eq!(session.inflight().len(), 1);
    assert!(session.terminal().get(&context.request_id).is_none());

    session
        .complete_request_with_terminal_state(
            &context.request_id,
            OperationTerminalState::Incomplete {
                reason: "closed while request was active".to_string(),
            },
        )
        .unwrap();
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Incomplete {
            reason: "closed while request was active".to_string(),
        })
    );

    session.close().unwrap();
    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn tool_calls_not_allowed_during_initializing_or_draining() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

    let err = session
        .ensure_operation_allowed(OperationKind::ToolCall)
        .unwrap_err();
    assert!(matches!(err, SessionError::OperationNotAllowed { .. }));

    session.activate().unwrap();
    session.begin_draining().unwrap();

    let err = session
        .ensure_operation_allowed(OperationKind::ToolCall)
        .unwrap_err();
    assert!(matches!(err, SessionError::OperationNotAllowed { .. }));
}

#[test]
fn peer_capabilities_and_roots_are_session_scoped() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

    session.set_peer_capabilities(PeerCapabilities {
        supports_progress: false,
        supports_cancellation: false,
        supports_subscriptions: false,
        supports_chio_tool_streaming: false,
        supports_roots: true,
        roots_list_changed: true,
        supports_sampling: true,
        sampling_context: true,
        sampling_tools: false,
        supports_elicitation: false,
        elicitation_form: false,
        elicitation_url: false,
    });
    session.replace_roots(vec![RootDefinition {
        uri: "file:///workspace/project".to_string(),
        name: Some("Project".to_string()),
    }]);

    assert!(session.peer_capabilities().supports_roots);
    assert!(session.peer_capabilities().roots_list_changed);
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project");
    assert_eq!(session.normalized_roots().len(), 1);
    assert!(matches!(
        session.normalized_roots()[0],
        NormalizedRoot::EnforceableFileSystem {
            ref normalized_path,
            ..
        } if normalized_path == "/workspace/project"
    ));
    assert_eq!(session.enforceable_filesystem_roots().len(), 1);

    session.close().unwrap();
    assert!(session.roots().is_empty());
    assert!(session.normalized_roots().is_empty());
}

#[test]
fn mixed_roots_preserve_metadata_without_widening_enforceable_set() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    session.replace_roots(vec![
        RootDefinition {
            uri: "file:///workspace/project/src".to_string(),
            name: Some("Code".to_string()),
        },
        RootDefinition {
            uri: "repo://docs/roadmap".to_string(),
            name: Some("Roadmap".to_string()),
        },
        RootDefinition {
            uri: "file://remote-host/workspace/project".to_string(),
            name: Some("Remote".to_string()),
        },
    ]);

    assert_eq!(session.normalized_roots().len(), 3);
    assert!(matches!(
        session.normalized_roots()[0],
        NormalizedRoot::EnforceableFileSystem {
            ref normalized_path,
            ..
        } if normalized_path == "/workspace/project/src"
    ));
    assert!(matches!(
        session.normalized_roots()[1],
        NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
    ));
    assert!(matches!(
        session.normalized_roots()[2],
        NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
            if reason == "non_local_file_authority"
    ));
    assert_eq!(session.enforceable_filesystem_roots().len(), 1);
}

#[test]
fn inflight_registry_tracks_and_completes_requests() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-1");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    assert_eq!(session.inflight().len(), 1);

    let completed = session.complete_request(&context.request_id).unwrap();
    assert_eq!(completed.request_id, RequestId::new("req-1"));
    assert_eq!(completed.parent_request_id, None);
    assert!(completed.cancellable);
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
}

#[test]
fn child_request_requires_parent_inflight() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let mut child_context = make_context("req-child");
    child_context.parent_request_id = Some(RequestId::new("req-parent"));

    session.activate().unwrap();
    let err = session
        .track_request(&child_context, OperationKind::CreateMessage, true)
        .unwrap_err();
    assert!(matches!(err, SessionError::ParentRequestNotInflight { .. }));
}

#[test]
fn duplicate_inflight_request_is_rejected() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-1");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();

    let err = session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap_err();
    assert!(matches!(err, SessionError::DuplicateInflightRequest { .. }));
}

#[test]
fn cancellation_marks_cancellable_request() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-1");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    session.request_cancellation(&context.request_id).unwrap();

    let inflight = session.inflight().get(&context.request_id).unwrap();
    assert!(inflight.cancellation_requested);
    assert_eq!(inflight.cancellation_reason, None);
}

#[test]
fn cancellation_preserves_first_supplied_reason() {
    let registry = InflightRegistry::default();
    let context = make_context("req-cancel-reason-first");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();

    registry
        .mark_cancellation_requested_with_reason(&context.request_id, Some("first reason"))
        .unwrap();
    registry
        .mark_cancellation_requested_with_reason(&context.request_id, Some("later reason"))
        .unwrap();

    let inflight = registry.get(&context.request_id).unwrap();
    assert!(inflight.cancellation_requested);
    assert_eq!(
        inflight.cancellation_reason.as_deref(),
        Some("first reason")
    );
    assert_eq!(
        registry.try_mark_dispatch_started(&context.request_id, "anchor-1"),
        Err(DispatchStartFailure::CancellationRequested {
            reason: Some("first reason".to_string())
        })
    );
}

#[test]
fn reasonless_cancellation_accepts_first_later_reason() {
    let registry = InflightRegistry::default();
    let context = make_context("req-cancel-reason-later");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();

    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();
    registry
        .mark_cancellation_requested_with_reason(&context.request_id, Some("available reason"))
        .unwrap();

    let inflight = registry.get(&context.request_id).unwrap();
    assert!(inflight.cancellation_requested);
    assert_eq!(
        inflight.cancellation_reason.as_deref(),
        Some("available reason")
    );
}

#[test]
fn cancellation_before_dispatch_prevents_dispatch_start() {
    let registry = InflightRegistry::default();
    let context = make_context("req-cancel-wins");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();

    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();
    assert_eq!(
        registry.try_mark_dispatch_started(&context.request_id, "anchor-1"),
        Err(DispatchStartFailure::CancellationRequested { reason: None })
    );
}

#[test]
fn dispatch_start_allows_late_cancellation_to_latch() {
    let registry = InflightRegistry::default();
    let context = make_context("req-dispatch-wins");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();

    registry
        .try_mark_dispatch_started(&context.request_id, "anchor-1")
        .unwrap();
    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();
    assert!(registry
        .get(&context.request_id)
        .is_some_and(|request| request.cancellation_requested));
    assert_eq!(
        registry.try_mark_dispatch_started(&context.request_id, "anchor-1"),
        Err(DispatchStartFailure::CancellationRequested { reason: None })
    );
}

#[test]
fn dispatch_scope_clears_active_marker_without_clearing_cancellation() {
    let registry = InflightRegistry::default();
    let context = make_context("req-dispatch-scope");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();

    registry
        .try_mark_dispatch_started(&context.request_id, "anchor-1")
        .unwrap();
    assert!(registry.is_dispatch_active(&context.request_id));
    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();

    registry.mark_dispatch_finished(&context.request_id);

    assert!(!registry.is_dispatch_active(&context.request_id));
    assert!(registry
        .get(&context.request_id)
        .is_some_and(|request| request.cancellation_requested));
}

#[test]
fn completing_dispatch_clears_private_dispatch_state_for_reuse() {
    let registry = InflightRegistry::default();
    let context = make_context("req-dispatch-reuse");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();
    registry
        .try_mark_dispatch_started(&context.request_id, "anchor-1")
        .unwrap();
    registry.complete(&context.request_id).unwrap();

    registry
        .track(&context, OperationKind::ToolCall, "anchor-2", true)
        .unwrap();
    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();
}

#[test]
fn cancellation_and_dispatch_start_preserve_atomic_pre_dispatch_boundary() {
    let registry = InflightRegistry::default();
    let context = make_context("req-dispatch-race");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();
    let barrier = Barrier::new(3);

    let (cancellation, dispatch) = std::thread::scope(|scope| {
        let cancellation = scope.spawn(|| {
            barrier.wait();
            registry.mark_cancellation_requested(&context.request_id)
        });
        let dispatch = scope.spawn(|| {
            barrier.wait();
            registry.try_mark_dispatch_started(&context.request_id, "anchor-1")
        });
        barrier.wait();
        (
            cancellation
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload)),
            dispatch
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload)),
        )
    });

    match (cancellation, dispatch) {
        (Ok(()), Err(DispatchStartFailure::CancellationRequested { .. })) | (Ok(()), Ok(())) => {}
        outcome => panic!("invalid cancellation and dispatch race outcome: {outcome:?}"),
    }
    assert!(registry
        .get(&context.request_id)
        .is_some_and(|request| request.cancellation_requested));

    registry.complete(&context.request_id).unwrap();
    registry
        .track(&context, OperationKind::ToolCall, "anchor-2", true)
        .unwrap();
    registry
        .mark_cancellation_requested(&context.request_id)
        .unwrap();
}

#[test]
fn cancelled_dispatching_parent_cannot_start_another_child() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let parent_context = make_context("req-parent-cancelled");
    let mut child_context = make_context("req-child-after-cancel");
    child_context.parent_request_id = Some(parent_context.request_id.clone());

    session.activate().unwrap();
    session
        .track_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    session
        .try_mark_request_dispatch_started(&parent_context.request_id)
        .unwrap();
    session
        .request_cancellation(&parent_context.request_id)
        .unwrap();

    let error = session
        .track_request(&child_context, OperationKind::CreateMessage, true)
        .unwrap_err();
    assert!(matches!(
        error,
        SessionError::ParentRequestCancelled {
            request_id,
            parent_request_id,
            ..
        } if request_id == child_context.request_id
            && parent_request_id == parent_context.request_id
    ));
}

#[test]
fn inflight_request_reports_request_owned_semantics() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-1");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();

    let inflight = session.inflight().get(&context.request_id).unwrap();
    let ownership = inflight.ownership();
    assert_eq!(ownership.work_owner, chio_core::session::WorkOwner::Request);
    assert_eq!(
        ownership.result_stream_owner,
        chio_core::session::StreamOwner::RequestStream
    );
    assert_eq!(
        ownership.terminal_state_owner,
        chio_core::session::WorkOwner::Request
    );
}

#[test]
fn complete_request_can_record_cancelled_terminal_state() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-1");

    session.activate().unwrap();
    session
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    session.request_cancellation(&context.request_id).unwrap();
    session
        .complete_request_with_terminal_state(
            &context.request_id,
            OperationTerminalState::Cancelled {
                reason: "cancelled by client".to_string(),
            },
        )
        .unwrap();

    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: "cancelled by client".to_string(),
        })
    );
}

#[test]
fn terminal_registry_keeps_first_terminal_state() {
    let registry = TerminalRegistry::default();
    let request_id = RequestId::new("req-terminal");
    let first_state = OperationTerminalState::Completed;

    assert!(registry.record(request_id.clone(), first_state.clone()));
    assert!(!registry.record(
        request_id.clone(),
        OperationTerminalState::Cancelled {
            reason: "late cancellation".to_string(),
        },
    ));

    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get(&request_id), Some(first_state));
}

#[test]
fn terminal_marking_accepts_shared_session_borrow_and_updates_lineage() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-terminal-shared");
    let terminal_state = OperationTerminalState::Incomplete {
        reason: "upstream closed".to_string(),
    };
    let shared = &session;

    shared.activate().unwrap();
    shared
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    shared
        .complete_request_with_terminal_state(&context.request_id, terminal_state.clone())
        .unwrap();

    assert!(shared.inflight().is_empty());
    assert_eq!(
        shared.terminal().get(&context.request_id),
        Some(terminal_state.clone())
    );
    let lineage = shared.request_lineage(&context.request_id).unwrap();
    assert_eq!(lineage.terminal_state, Some(terminal_state));
}

#[test]
fn inflight_request_lifecycle_accepts_shared_session_borrow() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let context = make_context("req-shared");
    let shared = &session;

    shared.activate().unwrap();
    shared
        .track_request(&context, OperationKind::ToolCall, true)
        .unwrap();
    shared.request_cancellation(&context.request_id).unwrap();
    let completed = shared.complete_request(&context.request_id).unwrap();

    assert_eq!(completed.request_id, context.request_id);
    assert!(completed.cancellation_requested);
    assert!(shared.inflight().is_empty());
    assert_eq!(
        shared.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
}

#[test]
fn inflight_registry_complete_missing_request_keeps_zero_count() {
    let registry = InflightRegistry::default();
    let request_id = RequestId::new("missing");

    let err = registry.complete(&request_id).unwrap_err();
    assert!(matches!(err, SessionError::RequestNotInflight { .. }));
    assert_eq!(registry.len(), 0);

    let context = make_context("req-1");
    registry
        .track(&context, OperationKind::ToolCall, "anchor-1", true)
        .unwrap();
    assert_eq!(registry.len(), 1);
    registry.complete(&context.request_id).unwrap();
    assert_eq!(registry.len(), 0);

    let err = registry.complete(&context.request_id).unwrap_err();
    assert!(matches!(err, SessionError::RequestNotInflight { .. }));
    assert_eq!(registry.len(), 0);
}

#[test]
fn resource_subscriptions_are_cleared_on_close() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());

    session.activate().unwrap();
    session.subscribe_resource("repo://docs/roadmap");

    assert!(session.is_resource_subscribed("repo://docs/roadmap"));
    assert_eq!(session.subscriptions().len(), 1);

    session.close().unwrap();

    assert!(!session.is_resource_subscribed("repo://docs/roadmap"));
    assert_eq!(session.subscriptions().len(), 0);
}

#[test]
fn resource_subscriptions_accept_shared_arc_session() {
    let session = Arc::new(Session::new(
        SessionId::new("sess-1"),
        "agent-1".to_string(),
        Vec::new(),
    ));
    let subscriber = Arc::clone(&session);
    let observer = Arc::clone(&session);

    subscriber.subscribe_resource("repo://docs/roadmap");

    assert!(observer.is_resource_subscribed("repo://docs/roadmap"));
    assert_eq!(observer.subscriptions().len(), 1);

    subscriber.unsubscribe_resource("repo://docs/roadmap");

    assert!(!observer.is_resource_subscribed("repo://docs/roadmap"));
    assert!(observer.subscriptions().is_empty());
}

#[test]
fn session_anchor_rotates_on_auth_context_change() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let initial_anchor = session.session_anchor().clone();
    assert_eq!(
        session.auth_context(),
        SessionAuthContext::in_process_anonymous()
    );

    let (rotated, _snapshot, supersedes_anchor_id) =
        session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        ));

    assert!(rotated);
    assert_eq!(supersedes_anchor_id.as_deref(), Some(initial_anchor.id()));
    assert!(session.auth_context().is_authenticated());
    assert_eq!(
        session.auth_context().principal(),
        Some("static-bearer:abcd1234")
    );
    assert_ne!(session.session_anchor().id(), initial_anchor.id());
    assert_eq!(session.session_anchor().auth_epoch(), 1);
    assert_ne!(
        session.session_anchor().auth_context_hash(),
        initial_anchor.auth_context_hash()
    );
}

#[test]
fn session_anchor_does_not_rotate_when_auth_context_is_unchanged() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let auth_context = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("http://localhost:3000".to_string()),
    );
    let initial_anchor = session.session_anchor().clone();

    let (rotated, _snapshot, supersedes_anchor_id) = session.set_auth_context(auth_context.clone());
    assert!(rotated);
    assert_eq!(supersedes_anchor_id.as_deref(), Some(initial_anchor.id()));
    let rotated_anchor = session.session_anchor().clone();
    let (rotated, _snapshot, supersedes_anchor_id) = session.set_auth_context(auth_context);
    assert!(!rotated);
    assert_eq!(supersedes_anchor_id, None);

    assert_eq!(session.session_anchor(), rotated_anchor);
}

#[test]
fn close_persisted_appends_terminal_anchor_with_supersedes_link() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let initial_anchor = session.session_anchor().clone();
    let (rotated, _snapshot, supersedes_anchor_id) =
        session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
            "static-bearer:abcd1234",
            "cafebabe",
            Some("http://localhost:3000".to_string()),
        ));
    assert!(rotated);
    assert_eq!(supersedes_anchor_id.as_deref(), Some(initial_anchor.id()));
    let active_anchor = session.session_anchor().clone();

    let mut captured_snapshot = None;
    let mut captured_supersedes = None;
    session
        .close_persisted(|snapshot, supersedes| {
            captured_snapshot = Some(snapshot.clone());
            captured_supersedes = supersedes.map(str::to_string);
            Ok::<(), ()>(())
        })
        .unwrap();

    let snapshot = captured_snapshot.expect("close persisted snapshot");
    assert_eq!(captured_supersedes.as_deref(), Some(active_anchor.id()));
    assert_eq!(
        snapshot.auth_context,
        SessionAuthContext::in_process_anonymous()
    );
    assert_eq!(
        snapshot.session_anchor.auth_epoch(),
        active_anchor.auth_epoch() + 1
    );
    assert_ne!(snapshot.session_anchor.id(), initial_anchor.id());
    assert_ne!(snapshot.session_anchor.id(), active_anchor.id());
    assert_eq!(session.session_anchor(), snapshot.session_anchor);
}

#[test]
fn close_persisted_is_idempotent_once_closed() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("http://localhost:3000".to_string()),
    ));

    let mut persisted = Vec::new();
    session
        .close_persisted(|snapshot, supersedes| {
            persisted.push((
                snapshot.session_anchor.clone(),
                supersedes.map(str::to_string),
            ));
            Ok::<(), ()>(())
        })
        .unwrap();
    let closed_anchor = session.session_anchor();

    session
        .close_persisted(|snapshot, supersedes| {
            persisted.push((
                snapshot.session_anchor.clone(),
                supersedes.map(str::to_string),
            ));
            Ok::<(), ()>(())
        })
        .unwrap();

    assert_eq!(persisted.len(), 1);
    assert_eq!(session.session_anchor(), closed_anchor);
}

#[test]
fn child_request_is_rejected_after_parent_anchor_rotation() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    let parent_context = make_context("req-parent");
    let mut child_context = make_context("req-child");
    child_context.parent_request_id = Some(parent_context.request_id.clone());

    session.activate().unwrap();
    session
        .track_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    assert!(
        session
            .set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:abcd1234",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ))
            .0
    );

    let err = session
        .track_request(&child_context, OperationKind::CreateMessage, true)
        .unwrap_err();
    assert!(matches!(
        err,
        SessionError::ParentRequestAnchorMismatch { .. }
    ));
}

#[test]
fn url_elicitation_completions_become_session_late_events() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    session.register_pending_url_elicitation("elicit-1", Some("task-7".to_string()));

    session.queue_elicitation_completion("elicit-1");
    session.queue_elicitation_completion("unknown");

    assert_eq!(
        session.take_late_events(),
        vec![LateSessionEvent::ElicitationCompleted {
            elicitation_id: "elicit-1".to_string(),
            related_task_id: Some("task-7".to_string()),
        }]
    );
    assert!(session.take_late_events().is_empty());
}

#[test]
fn tool_server_events_are_filtered_and_stored_per_session() {
    let session = Session::new(SessionId::new("sess-1"), "agent-1".to_string(), Vec::new());
    session.activate().unwrap();
    session.subscribe_resource("repo://docs/roadmap");
    session.register_pending_url_elicitation("elicit-2", None);

    session.queue_tool_server_event(ToolServerEvent::ResourceUpdated {
        uri: "repo://secret/ops".to_string(),
    });
    session.queue_tool_server_event(ToolServerEvent::ResourceUpdated {
        uri: "repo://docs/roadmap".to_string(),
    });
    session.queue_tool_server_event(ToolServerEvent::ResourcesListChanged);
    session.queue_tool_server_event(ToolServerEvent::ElicitationCompleted {
        elicitation_id: "elicit-2".to_string(),
    });

    assert_eq!(
        session.take_late_events(),
        vec![
            LateSessionEvent::ResourceUpdated {
                uri: "repo://docs/roadmap".to_string(),
            },
            LateSessionEvent::ResourcesListChanged,
            LateSessionEvent::ElicitationCompleted {
                elicitation_id: "elicit-2".to_string(),
                related_task_id: None,
            },
        ]
    );
}
