use super::*;

impl RemoteSession {
    pub(super) fn new(init: RemoteSessionInit) -> Self {
        let now = session_now_millis();
        let mut lifecycle_snapshot =
            init.lifecycle_snapshot
                .unwrap_or(RemoteSessionLifecycleSnapshot {
                    state: RemoteSessionState::Initializing,
                    created_at: now,
                    last_seen_at: now,
                    idle_expires_at: now,
                    drain_deadline_at: None,
                });
        if lifecycle_snapshot.state == RemoteSessionState::Ready {
            lifecycle_snapshot.drain_deadline_at = None;
        }
        Self {
            session_id: init.session_id,
            agent_id: init.agent_id,
            capabilities: init.capabilities,
            issued_capabilities: init.issued_capabilities,
            auth_context: init.auth_context,
            auth_mode_fingerprint: init.auth_mode_fingerprint,
            policy_fingerprint: init.policy_fingerprint,
            hosted_isolation: init.hosted_isolation,
            lifecycle_policy: init.lifecycle_policy,
            protocol_version: StdMutex::new(init.protocol_version),
            peer_capabilities: StdMutex::new(init.peer_capabilities),
            initialize_params: StdMutex::new(init.initialize_params),
            lifecycle: StdMutex::new(lifecycle_snapshot),
            input_tx: init.input_tx,
            event_tx: init.event_tx,
            retained_notification_events: init.retained_notification_events,
            active_request_stream: Arc::new(Mutex::new(())),
            notification_stream_attached: Arc::new(AtomicBool::new(false)),
            next_event_id: init.next_event_id,
            session_db_path: init.session_db_path,
            resume_integrity_secret: init.resume_integrity_secret,
        }
    }

    pub(super) fn send(&self, message: Value) -> Result<(), CliError> {
        self.input_tx
            .send(message)
            .map_err(|_| CliError::cli_other_error("remote MCP session worker is unavailable".to_string()))
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.event_tx.subscribe()
    }

    pub(super) fn next_stream_event_id(&self) -> String {
        let next = self.next_event_id.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{}-{next}", self.session_id)
    }

    pub(super) fn has_active_notification_stream(&self) -> bool {
        self.notification_stream_attached.load(Ordering::SeqCst)
    }

    pub(super) fn has_active_request_stream(&self) -> bool {
        self.active_request_stream.try_lock().is_err()
    }

    pub(super) fn try_attach_notification_stream(&self) -> bool {
        self.notification_stream_attached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(super) fn detach_notification_stream(&self) {
        self.notification_stream_attached
            .store(false, Ordering::SeqCst);
    }

    pub(super) fn replay_notifications_after(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<(u64, Vec<RemoteSessionEvent>), Response> {
        let Some(last_event_id) = last_event_id else {
            return Ok((0, Vec::new()));
        };

        let replay_after = parse_session_event_id(last_event_id, &self.session_id)
            .map_err(|message| plain_http_error(StatusCode::CONFLICT, &message))?;
        let retained = self.retained_notification_events.lock().map_err(|_| {
            plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to inspect retained session notifications",
            )
        })?;

        if retained.is_empty() {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is no longer provable for this session",
            ));
        }

        let oldest = retained.front().map(|event| event.seq).unwrap_or_default();
        let newest = retained.back().map(|event| event.seq).unwrap_or_default();
        if replay_after < oldest.saturating_sub(1) || replay_after > newest {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is outside the retained session window",
            ));
        }

        let replay = retained
            .iter()
            .filter(|event| event.seq > replay_after)
            .map(|event| RemoteSessionEvent {
                seq: event.seq,
                event_id: event.event_id.clone(),
                kind: RemoteSessionEventKind::Notification,
                message: event.message.clone(),
            })
            .collect();
        Ok((replay_after, replay))
    }

    pub(super) fn protocol_version(&self) -> Option<String> {
        self.protocol_version
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub(super) fn set_protocol_version(&self, protocol_version: Option<String>) {
        if let Ok(mut guard) = self.protocol_version.lock() {
            *guard = protocol_version;
        }
    }

    pub(super) fn set_initialize_contract(
        &self,
        initialize_params: Value,
        peer_capabilities: PeerCapabilities,
    ) {
        if let Ok(mut guard) = self.initialize_params.lock() {
            *guard = Some(initialize_params);
        }
        if let Ok(mut guard) = self.peer_capabilities.lock() {
            *guard = Some(peer_capabilities);
        }
    }

    pub(super) fn lifecycle_snapshot(&self) -> RemoteSessionLifecycleSnapshot {
        self.lifecycle
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or(RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Closed,
                created_at: 0,
                last_seen_at: 0,
                idle_expires_at: 0,
                drain_deadline_at: None,
            })
    }

    pub(super) fn resume_record(&self) -> Option<RemoteSessionResumeRecord> {
        let lifecycle = self.lifecycle_snapshot();
        if lifecycle.state != RemoteSessionState::Ready {
            return None;
        }
        let protocol_version = self.protocol_version();
        let peer_capabilities = self
            .peer_capabilities
            .lock()
            .ok()
            .and_then(|guard| guard.clone())?;
        let initialize_params = self
            .initialize_params
            .lock()
            .ok()
            .and_then(|guard| guard.clone())?;
        let mut record = RemoteSessionResumeRecord {
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            auth_context: self.auth_context.clone(),
            auth_mode_fingerprint: Some(self.auth_mode_fingerprint.clone()),
            policy_fingerprint: Some(self.policy_fingerprint.clone()),
            hosted_isolation: self.hosted_isolation,
            lifecycle,
            protocol_version,
            peer_capabilities,
            initialize_params,
            issued_capabilities: self.issued_capabilities.clone(),
            resume_integrity_tag: None,
        };
        let seed = self.resume_integrity_secret.as_ref()?;
        record.resume_integrity_tag = Some(compute_resume_record_integrity_tag(seed, &record).ok()?);
        Some(record)
    }

    pub(super) fn persist_resumable_record(&self) {
        let Some(path) = self.session_db_path.as_deref() else {
            return;
        };
        let Some(record) = self.resume_record() else {
            return;
        };
        if let Err(error) = persist_active_session_record(path, &record) {
            warn!(
                session_id = %self.session_id,
                error = %error,
                "failed to persist resumable MCP session record"
            );
        }
    }

    pub(super) fn remove_resumable_record(&self) -> Result<(), CliError> {
        let Some(path) = self.session_db_path.as_deref() else {
            return Ok(());
        };
        delete_active_session_record(path, &self.session_id)
    }

    pub(super) fn mark_ready(
        &self,
        protocol_version: Option<String>,
        initialize_params: Value,
        peer_capabilities: PeerCapabilities,
    ) {
        self.set_protocol_version(protocol_version);
        self.set_initialize_contract(initialize_params, peer_capabilities);
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Ready;
            guard.last_seen_at = session_now_millis();
            guard.idle_expires_at = guard
                .last_seen_at
                .saturating_add(self.lifecycle_policy.idle_expiry_millis);
            guard.drain_deadline_at = None;
        }
        self.persist_resumable_record();
    }

    pub(super) fn touch(&self) {
        let mut touched = false;
        if let Ok(mut guard) = self.lifecycle.lock() {
            if guard.state == RemoteSessionState::Ready {
                let now = session_now_millis();
                touched =
                    now.saturating_sub(guard.last_seen_at) >= SESSION_TOUCH_PERSIST_INTERVAL_MILLIS;
                guard.last_seen_at = now;
                guard.idle_expires_at = guard
                    .last_seen_at
                    .saturating_add(self.lifecycle_policy.idle_expiry_millis);
            }
        }
        if touched {
            self.persist_resumable_record();
        }
    }

    pub(super) fn begin_draining(&self) -> Result<(), CliError> {
        self.remove_resumable_record()?;
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Draining;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = Some(
                guard
                    .last_seen_at
                    .saturating_add(self.lifecycle_policy.drain_grace_millis),
            );
        }
        Ok(())
    }

    pub(super) fn mark_deleted(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Deleted;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    pub(super) fn mark_expired(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Expired;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    pub(super) fn mark_closed(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Closed;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    pub(super) fn auth_context(&self) -> &SessionAuthContext {
        &self.auth_context
    }

    pub(super) fn diagnostic_record(&self) -> RemoteSessionDiagnosticRecord {
        RemoteSessionDiagnosticRecord {
            session_id: self.session_id.clone(),
            auth_context: self.auth_context.clone(),
            capabilities: self.capabilities.clone(),
            lifecycle: self.lifecycle_snapshot(),
            protocol_version: self.protocol_version(),
            ownership: self.ownership_snapshot(),
            terminal_at: session_now_millis(),
        }
    }

    pub(super) fn ownership_snapshot(&self) -> RemoteSessionOwnershipSnapshot {
        let notification_stream_attached = self.has_active_notification_stream();
        RemoteSessionOwnershipSnapshot {
            hosted_isolation: self.hosted_isolation,
            hosted_identity_profile: self.hosted_isolation.identity_profile(),
            notification_delivery: if notification_stream_attached {
                RemoteNotificationDelivery::GetSse
            } else {
                RemoteNotificationDelivery::PostResponseFallback
            },
            request_stream_active: self.has_active_request_stream(),
            notification_stream_attached,
            ..RemoteSessionOwnershipSnapshot::default()
        }
    }
}
