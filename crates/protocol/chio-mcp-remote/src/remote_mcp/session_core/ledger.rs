use super::*;

impl RemoteSessionLedger {
    pub(super) fn new(
        lifecycle_policy: SessionLifecyclePolicy,
        tombstone_db_path: Option<PathBuf>,
    ) -> Result<Self, CliError> {
        let terminal = if let Some(path) = tombstone_db_path.as_deref() {
            load_terminal_session_records(path)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            active: Arc::new(Mutex::new(HashMap::new())),
            terminal: Arc::new(Mutex::new(terminal)),
            lifecycle_policy,
            tombstone_db_path,
        })
    }

    pub(super) async fn insert_active(&self, session: Arc<RemoteSession>) {
        self.active
            .lock()
            .await
            .insert(session.session_id.clone(), session);
    }

    pub(super) async fn remove_active(&self, session_id: &str) -> Option<Arc<RemoteSession>> {
        self.active.lock().await.remove(session_id)
    }

    pub(super) async fn lookup(&self, session_id: &str) -> Option<RemoteSessionEntry> {
        if let Some(session) = self.active.lock().await.get(session_id).cloned() {
            return Some(RemoteSessionEntry::Active(session));
        }

        self.terminal
            .lock()
            .await
            .get(session_id)
            .cloned()
            .map(RemoteSessionEntry::Terminal)
    }

    pub(super) async fn snapshot(
        &self,
    ) -> (
        Vec<RemoteSessionDiagnosticRecord>,
        Vec<RemoteSessionDiagnosticRecord>,
    ) {
        let active = self
            .active
            .lock()
            .await
            .values()
            .map(|session| session.diagnostic_record())
            .collect::<Vec<_>>();
        let terminal = self
            .terminal
            .lock()
            .await
            .values()
            .map(|record| (*record.as_ref()).clone())
            .collect::<Vec<_>>();
        (active, terminal)
    }

    pub(super) async fn mark_deleted(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Deleted)
            .await
    }

    pub(super) async fn mark_draining(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        session.begin_draining()
    }

    pub(super) async fn mark_closed(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Closed)
            .await
    }

    pub(super) async fn mark_expired(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Expired)
            .await
    }

    pub(super) async fn cleanup_due_sessions(&self) {
        let now = session_now_millis();
        let sessions = {
            let guard = self.active.lock().await;
            guard.values().cloned().collect::<Vec<_>>()
        };

        for session in sessions {
            let snapshot = session.lifecycle_snapshot();
            match snapshot.state {
                RemoteSessionState::Ready if snapshot.idle_expires_at <= now => {
                    match self.mark_expired(&session).await {
                        Ok(()) => {
                            self.active.lock().await.remove(&session.session_id);
                        }
                        Err(error) => {
                            warn!(
                                session_id = %session.session_id,
                                error = %error,
                                "failed to expire MCP session without resumable-state risk"
                            );
                        }
                    }
                }
                RemoteSessionState::Ready => {}
                RemoteSessionState::Draining => {
                    if snapshot
                        .drain_deadline_at
                        .is_some_and(|deadline| deadline <= now)
                    {
                        match self.mark_deleted(&session).await {
                            Ok(()) => {
                                self.active.lock().await.remove(&session.session_id);
                            }
                            Err(error) => {
                                warn!(
                                    session_id = %session.session_id,
                                    error = %error,
                                    "failed to delete drained MCP session without resumable-state risk"
                                );
                            }
                        }
                    }
                }
                RemoteSessionState::Initializing
                | RemoteSessionState::Deleted
                | RemoteSessionState::Expired => {}
                RemoteSessionState::Closed => {
                    self.active.lock().await.remove(&session.session_id);
                }
            }
        }

        self.purge_old_terminal_records(now).await;
    }

    pub(super) async fn transition_to_terminal(
        &self,
        session: &Arc<RemoteSession>,
        state: RemoteSessionState,
    ) -> Result<(), CliError> {
        match state {
            RemoteSessionState::Deleted | RemoteSessionState::Expired | RemoteSessionState::Closed => {}
            RemoteSessionState::Initializing | RemoteSessionState::Ready | RemoteSessionState::Draining => {
                return Err(CliError::cli_other_error(format!(
                    "unsupported terminal MCP session state: {}",
                    state.as_str()
                )));
            }
        }
        // Guard against re-terminalizing a session that has already reached a
        // terminal state. Without this, a concurrent reaper expiry followed by
        // an admin shutdown (or DELETE) on the same session would overwrite the
        // first tombstone's state, refresh `terminal_at` (extending retention),
        // and re-issue spurious resumable-record deletes against SQLite.
        let current_state = session.lifecycle_snapshot().state;
        match current_state {
            RemoteSessionState::Deleted
            | RemoteSessionState::Expired
            | RemoteSessionState::Closed => {
                return Ok(());
            }
            RemoteSessionState::Initializing
            | RemoteSessionState::Ready
            | RemoteSessionState::Draining => {}
        }
        let terminal_at = session_now_millis();
        let mut record = session.diagnostic_record();
        record.lifecycle.state = state;
        record.lifecycle.last_seen_at = terminal_at;
        record.lifecycle.drain_deadline_at = None;
        record.terminal_at = terminal_at;
        let mut tombstone_guards_restore = self.tombstone_db_path.is_none();
        let mut tombstone_error = None;
        if let Some(path) = self.tombstone_db_path.as_deref() {
            match persist_terminal_session_record(path, &record) {
                Ok(()) => {
                    tombstone_guards_restore = true;
                }
                Err(error) => {
                    tombstone_error = Some(error.to_string());
                    warn!(
                        session_id = %session.session_id,
                        error = %error,
                        "failed to persist terminal MCP session tombstone"
                    );
                }
            }
        }

        if let Err(delete_error) = session.remove_resumable_record() {
            if tombstone_guards_restore {
                warn!(
                    session_id = %session.session_id,
                    error = %delete_error,
                    "failed to delete resumable MCP session record; terminal tombstone will block restore"
                );
            } else {
                let tombstone_error = tombstone_error
                    .unwrap_or_else(|| "terminal tombstone was not persisted".to_string());
                return Err(CliError::cli_other_error(format!(
                    "failed to terminalize MCP session {}: {tombstone_error}; active resume delete failed: {delete_error}",
                    session.session_id
                )));
            }
        }

        match state {
            RemoteSessionState::Deleted => session.mark_deleted(),
            RemoteSessionState::Expired => session.mark_expired(),
            RemoteSessionState::Closed => session.mark_closed(),
            RemoteSessionState::Initializing | RemoteSessionState::Ready | RemoteSessionState::Draining => {}
        }

        self.terminal
            .lock()
            .await
            .insert(session.session_id.clone(), Arc::new(record));
        Ok(())
    }

    pub(super) async fn purge_old_terminal_records(&self, now: u64) {
        let retention = self.lifecycle_policy.tombstone_retention_millis;
        let cutoff = now.saturating_sub(retention);
        let mut terminal = self.terminal.lock().await;
        terminal.retain(|_, record| now.saturating_sub(record.terminal_at) <= retention);
        if let Some(path) = self.tombstone_db_path.as_deref() {
            if let Err(error) = purge_terminal_session_records_before(path, cutoff) {
                warn!(
                    cutoff,
                    error = %error,
                    "failed to purge expired MCP session tombstones"
                );
            }
        }
    }
}
