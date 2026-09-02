#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering};
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chio_core::crypto::{canonical_json_bytes, sha256_hex};
use chio_core::session::{
    CreateElicitationOperation, NormalizedRoot, OperationContext, OperationKind,
    OperationTerminalState, ProgressToken, RequestId, RequestOwnershipSnapshot, RootDefinition,
    SessionAnchorReference, SessionAuthContext, SessionId,
};
// Consumed only by SessionOperationResponse and queue_tool_server_event, both of
// which are gated out under loom.
#[cfg(not(loom))]
use chio_core::session::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition,
};
use chio_core::{capability::token::CapabilityToken, AgentId};
#[cfg(loom)]
use loom::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(not(loom))]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(loom))]
use crate::{ToolCallResponse, ToolServerEvent};
// Consumed only by SessionOperationResponse, gated out under loom.
#[cfg(not(loom))]
use chio_core::receipt::body::ChioReceipt;

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Debug)]
struct SnapshotState<T> {
    current: RwLock<T>,
}

impl<T> SnapshotState<T> {
    fn new(initial: T) -> Self {
        Self {
            current: RwLock::new(initial),
        }
    }

    fn with_current<R>(&self, read: impl FnOnce(&T) -> R) -> R {
        let current = read_lock(&self.current);
        read(&current)
    }

    fn replace(&self, next: T) {
        *write_lock(&self.current) = next;
    }

    fn replace_with<R>(&self, update: impl FnOnce(&T) -> (Option<T>, R)) -> R {
        let mut current = write_lock(&self.current);
        let (next, result) = update(&current);
        if let Some(next) = next {
            *current = next;
        }
        result
    }
}

impl<T: Clone> Clone for SnapshotState<T> {
    fn clone(&self) -> Self {
        Self::new(self.with_current(Clone::clone))
    }
}

/// Lifecycle state of a logical kernel session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Initializing,
    Ready,
    Draining,
    Closed,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }
}

/// Feature flags negotiated with the peer at session establishment.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerCapabilities {
    pub supports_progress: bool,
    pub supports_cancellation: bool,
    pub supports_subscriptions: bool,
    pub supports_chio_tool_streaming: bool,
    pub supports_roots: bool,
    pub roots_list_changed: bool,
    pub supports_sampling: bool,
    pub sampling_context: bool,
    pub sampling_tools: bool,
    pub supports_elicitation: bool,
    pub elicitation_form: bool,
    pub elicitation_url: bool,
}

/// Bookkeeping record for an in-flight request.
#[derive(Debug, Clone)]
pub struct InflightRequest {
    pub request_id: RequestId,
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    pub session_anchor_id: String,
    pub started_at: Instant,
    pub progress_token: Option<ProgressToken>,
    pub cancellation_requested: bool,
    pub cancellation_reason: Option<String>,
    pub cancellable: bool,
    pub pending_execution_nonce_id: Option<String>,
}

impl InflightRequest {
    pub fn ownership(&self) -> RequestOwnershipSnapshot {
        RequestOwnershipSnapshot::request_owned()
    }
}

/// Registry of requests that are currently active within a session.
#[derive(Debug)]
pub struct InflightRegistry {
    requests: RwLock<HashMap<RequestId, InflightRequest>>,
    dispatching: RwLock<HashSet<RequestId>>,
    active_count: AtomicU64,
}

impl Clone for InflightRegistry {
    fn clone(&self) -> Self {
        let requests_guard = self.read_requests();
        let requests = requests_guard.clone();
        let dispatching = read_lock(&self.dispatching).clone();
        Self {
            active_count: AtomicU64::new(requests.len() as u64),
            requests: RwLock::new(requests),
            dispatching: RwLock::new(dispatching),
        }
    }
}

impl Default for InflightRegistry {
    fn default() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
            dispatching: RwLock::new(HashSet::new()),
            active_count: AtomicU64::new(0),
        }
    }
}

impl InflightRegistry {
    fn read_requests(&self) -> RwLockReadGuard<'_, HashMap<RequestId, InflightRequest>> {
        read_lock(&self.requests)
    }

    fn write_requests(&self) -> RwLockWriteGuard<'_, HashMap<RequestId, InflightRequest>> {
        write_lock(&self.requests)
    }

    pub fn track(
        &self,
        context: &OperationContext,
        operation_kind: OperationKind,
        session_anchor_id: &str,
        cancellable: bool,
    ) -> Result<(), SessionError> {
        let mut requests = self.write_requests();
        if requests.contains_key(&context.request_id) {
            return Err(SessionError::DuplicateInflightRequest {
                request_id: context.request_id.clone(),
            });
        }

        requests.insert(
            context.request_id.clone(),
            InflightRequest {
                request_id: context.request_id.clone(),
                parent_request_id: context.parent_request_id.clone(),
                operation_kind,
                session_anchor_id: session_anchor_id.to_string(),
                started_at: Instant::now(),
                progress_token: context.progress_token.clone(),
                cancellation_requested: false,
                cancellation_reason: None,
                cancellable,
                pending_execution_nonce_id: None,
            },
        );
        self.active_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn track_locked(
        &self,
        requests: &mut HashMap<RequestId, InflightRequest>,
        context: &OperationContext,
        operation_kind: OperationKind,
        session_anchor_id: &str,
        cancellable: bool,
    ) -> Result<(), SessionError> {
        if requests.contains_key(&context.request_id) {
            return Err(SessionError::DuplicateInflightRequest {
                request_id: context.request_id.clone(),
            });
        }

        requests.insert(
            context.request_id.clone(),
            InflightRequest {
                request_id: context.request_id.clone(),
                parent_request_id: context.parent_request_id.clone(),
                operation_kind,
                session_anchor_id: session_anchor_id.to_string(),
                started_at: Instant::now(),
                progress_token: context.progress_token.clone(),
                cancellation_requested: false,
                cancellation_reason: None,
                cancellable,
                pending_execution_nonce_id: None,
            },
        );
        self.active_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    pub fn complete(&self, request_id: &RequestId) -> Result<InflightRequest, SessionError> {
        let mut requests = self.write_requests();
        let completed =
            requests
                .remove(request_id)
                .ok_or_else(|| SessionError::RequestNotInflight {
                    request_id: request_id.clone(),
                })?;
        write_lock(&self.dispatching).remove(request_id);
        if self
            .active_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            self.active_count
                .store(requests.len() as u64, Ordering::Release);
        }
        Ok(completed)
    }

    pub fn mark_cancellation_requested(&self, request_id: &RequestId) -> Result<(), SessionError> {
        self.mark_cancellation_requested_with_reason(request_id, None)
    }

    pub(crate) fn mark_cancellation_requested_with_reason(
        &self,
        request_id: &RequestId,
        reason: Option<&str>,
    ) -> Result<(), SessionError> {
        let mut requests = self.write_requests();
        let request =
            requests
                .get_mut(request_id)
                .ok_or_else(|| SessionError::RequestNotInflight {
                    request_id: request_id.clone(),
                })?;

        if !request.cancellable {
            return Err(SessionError::RequestNotCancellable {
                request_id: request_id.clone(),
            });
        }

        // Dispatch start wins the current side-effect race, but cancellation
        // still latches on the request. The active dispatch may finish; any
        // later nested child or repeated dispatch start observes the flag and
        // fails before another side effect begins.
        request.cancellation_requested = true;
        if request.cancellation_reason.is_none() {
            request.cancellation_reason = reason.map(str::to_owned);
        }
        Ok(())
    }

    pub(crate) fn try_mark_dispatch_started(
        &self,
        request_id: &RequestId,
        current_session_anchor_id: &str,
    ) -> Result<(), DispatchStartFailure> {
        let mut requests = self.write_requests();
        let request = requests
            .get_mut(request_id)
            .ok_or(DispatchStartFailure::RequestNotInflight)?;
        if request.cancellation_requested {
            return Err(DispatchStartFailure::CancellationRequested {
                reason: request.cancellation_reason.clone(),
            });
        }
        if request.session_anchor_id != current_session_anchor_id {
            return Err(DispatchStartFailure::SessionAnchorChanged);
        }
        write_lock(&self.dispatching).insert(request_id.clone());
        Ok(())
    }

    pub(crate) fn mark_dispatch_finished(&self, request_id: &RequestId) {
        write_lock(&self.dispatching).remove(request_id);
    }

    #[cfg(test)]
    pub(crate) fn is_dispatch_active(&self, request_id: &RequestId) -> bool {
        read_lock(&self.dispatching).contains(request_id)
    }

    pub fn get(&self, request_id: &RequestId) -> Option<InflightRequest> {
        self.read_requests().get(request_id).cloned()
    }

    pub fn mark_execution_nonce_pending(
        &self,
        request_id: &RequestId,
        nonce_id: &str,
    ) -> Result<(), SessionError> {
        let mut requests = self.write_requests();
        let request = requests.get_mut(request_id).ok_or_else(|| {
            SessionError::ExecutionNonceRetryMismatch {
                request_id: request_id.clone(),
            }
        })?;
        if request.pending_execution_nonce_id.is_some() {
            return Err(SessionError::ExecutionNonceRetryMismatch {
                request_id: request_id.clone(),
            });
        }
        request.pending_execution_nonce_id = Some(nonce_id.to_string());
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.active_count.load(Ordering::Acquire) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.active_count.load(Ordering::Acquire) == 0
    }

    pub fn clear(&self) {
        let mut requests = self.write_requests();
        requests.clear();
        write_lock(&self.dispatching).clear();
        self.active_count.store(0, Ordering::Release);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DispatchStartFailure {
    RequestNotInflight,
    CancellationRequested { reason: Option<String> },
    SessionAnchorChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SubscriptionSubject {
    Resource(String),
}

/// Registry for session-scoped subscriptions.
#[derive(Debug)]
pub struct SubscriptionRegistry {
    subscriptions: RwLock<HashSet<SubscriptionSubject>>,
    subscription_count: AtomicU64,
}

impl Clone for SubscriptionRegistry {
    fn clone(&self) -> Self {
        let subscriptions = read_lock(&self.subscriptions).clone();
        Self {
            subscription_count: AtomicU64::new(subscriptions.len() as u64),
            subscriptions: RwLock::new(subscriptions),
        }
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        Self {
            subscriptions: RwLock::new(HashSet::new()),
            subscription_count: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateSessionEvent {
    ElicitationCompleted {
        elicitation_id: String,
        related_task_id: Option<String>,
    },
    ResourceUpdated {
        uri: String,
    },
    ResourcesListChanged,
    ToolsListChanged,
    PromptsListChanged,
}

#[derive(Debug, Clone)]
struct PendingUrlElicitation {
    related_task_id: Option<String>,
}

impl SubscriptionRegistry {
    pub fn subscribe_resource(&self, uri: impl Into<String>) {
        let mut subscriptions = write_lock(&self.subscriptions);
        subscriptions.insert(SubscriptionSubject::Resource(uri.into()));
        self.subscription_count
            .store(subscriptions.len() as u64, Ordering::Release);
    }

    pub fn unsubscribe_resource(&self, uri: &str) {
        let mut subscriptions = write_lock(&self.subscriptions);
        subscriptions.remove(&SubscriptionSubject::Resource(uri.to_string()));
        self.subscription_count
            .store(subscriptions.len() as u64, Ordering::Release);
    }

    pub fn contains_resource(&self, uri: &str) -> bool {
        read_lock(&self.subscriptions).contains(&SubscriptionSubject::Resource(uri.to_string()))
    }

    pub fn len(&self) -> usize {
        self.subscription_count.load(Ordering::Acquire) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.subscription_count.load(Ordering::Acquire) == 0
    }

    pub fn clear(&self) {
        write_lock(&self.subscriptions).clear();
        self.subscription_count.store(0, Ordering::Release);
    }
}

const TERMINAL_HISTORY_LIMIT: usize = 256;

/// Bounded history of terminal request outcomes for a session.
#[derive(Debug, Clone)]
struct TerminalRegistryInner {
    states: HashMap<RequestId, OperationTerminalState>,
    order: VecDeque<RequestId>,
    limit: usize,
}

impl Default for TerminalRegistryInner {
    fn default() -> Self {
        Self {
            states: HashMap::new(),
            order: VecDeque::new(),
            limit: TERMINAL_HISTORY_LIMIT,
        }
    }
}

/// Bounded history of terminal request outcomes for a session.
#[derive(Debug)]
pub struct TerminalRegistry {
    inner: SnapshotState<TerminalRegistryInner>,
}

impl Clone for TerminalRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Default for TerminalRegistry {
    fn default() -> Self {
        Self {
            inner: SnapshotState::new(TerminalRegistryInner::default()),
        }
    }
}

impl TerminalRegistry {
    pub fn record(&self, request_id: RequestId, state: OperationTerminalState) -> bool {
        self.inner.replace_with(|current| {
            if current.states.contains_key(&request_id) {
                return (None, false);
            }

            let mut next = current.clone();
            next.order.push_back(request_id.clone());
            next.states.insert(request_id, state);

            while next.order.len() > next.limit {
                if let Some(oldest) = next.order.pop_front() {
                    next.states.remove(&oldest);
                }
            }
            (Some(next), true)
        })
    }

    pub fn get(&self, request_id: &RequestId) -> Option<OperationTerminalState> {
        self.inner
            .with_current(|current| current.states.get(request_id).cloned())
    }

    pub fn remove(&self, request_id: &RequestId) {
        self.inner.replace_with(|current| {
            if !current.states.contains_key(request_id) {
                return (None, ());
            }

            let mut next = current.clone();
            next.states.remove(request_id);
            next.order.retain(|existing| existing != request_id);
            (Some(next), ())
        });
    }

    pub fn len(&self) -> usize {
        self.inner.with_current(|current| current.states.len())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.with_current(|current| current.states.is_empty())
    }
}

/// Errors for session lifecycle and in-flight management.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("invalid session transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("session {session_id} cannot handle {operation} while {state}")]
    OperationNotAllowed {
        session_id: SessionId,
        operation: &'static str,
        state: &'static str,
    },

    #[error("operation context session {actual} does not match runtime session {expected}")]
    ContextSessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },

    #[error("operation context agent {actual} does not match session agent {expected}")]
    ContextAgentMismatch { expected: AgentId, actual: AgentId },

    #[error("request {request_id} is already in flight")]
    DuplicateInflightRequest { request_id: RequestId },

    #[error("request {request_id} already has authoritative lineage in this session")]
    DuplicateRequestLineage { request_id: RequestId },

    #[error("request {request_id} is not in flight")]
    RequestNotInflight { request_id: RequestId },

    #[error(
        "execution nonce retry for request {request_id} does not match a pending session preflight"
    )]
    ExecutionNonceRetryMismatch { request_id: RequestId },

    #[error("request {request_id} is not cancellable")]
    RequestNotCancellable { request_id: RequestId },

    #[error("session {session_id} cannot close while {active_count} request(s) remain active")]
    CloseRequiresDrain {
        session_id: SessionId,
        active_count: u64,
    },

    #[error("parent request {parent_request_id} is not in flight for child request {request_id}")]
    ParentRequestNotInflight {
        request_id: RequestId,
        parent_request_id: RequestId,
    },

    #[error("parent request {parent_request_id} was cancelled before child request {request_id} could start")]
    ParentRequestCancelled {
        request_id: RequestId,
        parent_request_id: RequestId,
        reason: Option<String>,
    },

    #[error(
        "parent request {parent_request_id} for child request {request_id} belongs to stale session anchor {parent_session_anchor_id}, current anchor is {current_session_anchor_id}"
    )]
    ParentRequestAnchorMismatch {
        request_id: RequestId,
        parent_request_id: RequestId,
        parent_session_anchor_id: String,
        current_session_anchor_id: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionPersistError<E> {
    Session(SessionError),
    Persist(E),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAnchorState {
    id: String,
    auth_epoch: u64,
    auth_context_hash: String,
    issued_at: u64,
}

impl SessionAnchorState {
    fn new(session_id: &SessionId, auth_context: &SessionAuthContext, auth_epoch: u64) -> Self {
        let auth_context_hash = auth_context_hash(auth_context);
        let hash_prefix = &auth_context_hash[..12.min(auth_context_hash.len())];
        Self {
            id: format!("{session_id}:anchor:{auth_epoch}:{hash_prefix}"),
            auth_epoch,
            auth_context_hash,
            issued_at: current_unix_timestamp(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn auth_epoch(&self) -> u64 {
        self.auth_epoch
    }

    pub fn auth_context_hash(&self) -> &str {
        &self.auth_context_hash
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn reference(&self) -> SessionAnchorReference {
        SessionAnchorReference::new(self.id.clone(), self.auth_context_hash.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLineageRecord {
    pub request_id: RequestId,
    pub session_anchor_id: String,
    pub auth_epoch: u64,
    pub parent_request_id: Option<RequestId>,
    pub operation_kind: OperationKind,
    pub started_at: u64,
    pub terminal_state: Option<OperationTerminalState>,
}

#[derive(Debug, Clone)]
struct SessionInner {
    state: SessionState,
}

#[derive(Debug, Clone)]
struct SessionAuthState {
    auth_context: SessionAuthContext,
    session_anchor: SessionAnchorState,
}

#[derive(Debug, Clone)]
struct SessionRoots {
    roots: Vec<RootDefinition>,
    normalized_roots: Vec<NormalizedRoot>,
}

#[derive(Debug, Clone)]
pub struct SessionAnchorSnapshot {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub auth_context: SessionAuthContext,
    pub session_anchor: SessionAnchorState,
}

#[derive(Debug, Clone)]
pub struct SessionRequestStart {
    pub session: SessionAnchorSnapshot,
    pub lineage: RequestLineageRecord,
}

/// Session host object owned by the kernel.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    agent_id: AgentId,
    inner: RwLock<SessionInner>,
    auth_state: SnapshotState<SessionAuthState>,
    peer_capabilities: SnapshotState<PeerCapabilities>,
    roots: SnapshotState<SessionRoots>,
    issued_capabilities: Vec<CapabilityToken>,
    inflight: InflightRegistry,
    subscriptions: SubscriptionRegistry,
    terminal: TerminalRegistry,
    request_lineage: RwLock<HashMap<RequestId, RequestLineageRecord>>,
    pending_url_elicitations: RwLock<HashMap<String, PendingUrlElicitation>>,
    late_events: RwLock<VecDeque<LateSessionEvent>>,
}

fn operation_allowed_for_state(state: SessionState, operation: OperationKind) -> bool {
    match state {
        SessionState::Initializing => matches!(
            operation,
            OperationKind::ListCapabilities | OperationKind::Heartbeat
        ),
        SessionState::Ready => true,
        SessionState::Draining => matches!(
            operation,
            OperationKind::ListCapabilities | OperationKind::Heartbeat
        ),
        SessionState::Closed => false,
    }
}

fn validate_parent_request_lineage_locked(
    request_id: &RequestId,
    parent_request_id: &RequestId,
    requests: &HashMap<RequestId, InflightRequest>,
    request_lineage: &HashMap<RequestId, RequestLineageRecord>,
    current_session_anchor_id: &str,
) -> Result<RequestLineageRecord, SessionError> {
    let Some(parent_inflight) = requests.get(parent_request_id) else {
        return Err(SessionError::ParentRequestNotInflight {
            request_id: request_id.clone(),
            parent_request_id: parent_request_id.clone(),
        });
    };
    if parent_inflight.cancellation_requested {
        return Err(SessionError::ParentRequestCancelled {
            request_id: request_id.clone(),
            parent_request_id: parent_request_id.clone(),
            reason: parent_inflight.cancellation_reason.clone(),
        });
    }
    let Some(parent_lineage) = request_lineage.get(parent_request_id).cloned() else {
        return Err(SessionError::ParentRequestNotInflight {
            request_id: request_id.clone(),
            parent_request_id: parent_request_id.clone(),
        });
    };
    if parent_lineage.session_anchor_id != current_session_anchor_id {
        return Err(SessionError::ParentRequestAnchorMismatch {
            request_id: request_id.clone(),
            parent_request_id: parent_request_id.clone(),
            parent_session_anchor_id: parent_inflight.session_anchor_id.clone(),
            current_session_anchor_id: current_session_anchor_id.to_string(),
        });
    }
    Ok(parent_lineage)
}

impl Clone for Session {
    fn clone(&self) -> Self {
        let inner = self.read_inner().clone();
        Self {
            id: self.id.clone(),
            agent_id: self.agent_id.clone(),
            inner: RwLock::new(inner),
            auth_state: self.auth_state.clone(),
            peer_capabilities: self.peer_capabilities.clone(),
            roots: self.roots.clone(),
            issued_capabilities: self.issued_capabilities.clone(),
            inflight: self.inflight.clone(),
            subscriptions: self.subscriptions.clone(),
            terminal: self.terminal.clone(),
            request_lineage: RwLock::new(self.read_request_lineage().clone()),
            pending_url_elicitations: RwLock::new(self.read_pending_url_elicitations().clone()),
            late_events: RwLock::new(self.read_late_events().clone()),
        }
    }
}

impl Session {
    pub fn new(
        id: SessionId,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> Self {
        let auth_context = SessionAuthContext::in_process_anonymous();
        let session_anchor = SessionAnchorState::new(&id, &auth_context, 0);
        Self {
            id,
            agent_id,
            inner: RwLock::new(SessionInner {
                state: SessionState::Initializing,
            }),
            auth_state: SnapshotState::new(SessionAuthState {
                auth_context,
                session_anchor,
            }),
            peer_capabilities: SnapshotState::new(PeerCapabilities::default()),
            roots: SnapshotState::new(SessionRoots {
                roots: Vec::new(),
                normalized_roots: Vec::new(),
            }),
            issued_capabilities,
            inflight: InflightRegistry::default(),
            subscriptions: SubscriptionRegistry::default(),
            terminal: TerminalRegistry::default(),
            request_lineage: RwLock::new(HashMap::new()),
            pending_url_elicitations: RwLock::new(HashMap::new()),
            late_events: RwLock::new(VecDeque::new()),
        }
    }

    fn read_inner(&self) -> RwLockReadGuard<'_, SessionInner> {
        read_lock(&self.inner)
    }

    fn write_inner(&self) -> RwLockWriteGuard<'_, SessionInner> {
        write_lock(&self.inner)
    }

    fn read_request_lineage(
        &self,
    ) -> RwLockReadGuard<'_, HashMap<RequestId, RequestLineageRecord>> {
        read_lock(&self.request_lineage)
    }

    fn read_pending_url_elicitations(
        &self,
    ) -> RwLockReadGuard<'_, HashMap<String, PendingUrlElicitation>> {
        read_lock(&self.pending_url_elicitations)
    }

    fn write_pending_url_elicitations(
        &self,
    ) -> RwLockWriteGuard<'_, HashMap<String, PendingUrlElicitation>> {
        write_lock(&self.pending_url_elicitations)
    }

    fn read_late_events(&self) -> RwLockReadGuard<'_, VecDeque<LateSessionEvent>> {
        read_lock(&self.late_events)
    }

    fn write_late_events(&self) -> RwLockWriteGuard<'_, VecDeque<LateSessionEvent>> {
        write_lock(&self.late_events)
    }

    fn write_request_lineage(
        &self,
    ) -> RwLockWriteGuard<'_, HashMap<RequestId, RequestLineageRecord>> {
        write_lock(&self.request_lineage)
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn state(&self) -> SessionState {
        self.read_inner().state
    }

    pub fn auth_context(&self) -> SessionAuthContext {
        self.auth_state
            .with_current(|current| current.auth_context.clone())
    }

    pub fn session_anchor(&self) -> SessionAnchorState {
        self.auth_state
            .with_current(|current| current.session_anchor.clone())
    }

    pub fn session_anchor_snapshot(&self) -> SessionAnchorSnapshot {
        self.auth_state
            .with_current(|current| SessionAnchorSnapshot {
                session_id: self.id.clone(),
                agent_id: self.agent_id.clone(),
                auth_context: current.auth_context.clone(),
                session_anchor: current.session_anchor.clone(),
            })
    }

    pub fn request_lineage(&self, request_id: &RequestId) -> Option<RequestLineageRecord> {
        self.read_request_lineage().get(request_id).cloned()
    }

    pub fn peer_capabilities(&self) -> PeerCapabilities {
        self.peer_capabilities.with_current(Clone::clone)
    }

    pub fn capabilities(&self) -> &[CapabilityToken] {
        &self.issued_capabilities
    }

    pub fn roots(&self) -> Vec<RootDefinition> {
        self.roots.with_current(|current| current.roots.clone())
    }

    pub fn normalized_roots(&self) -> Vec<NormalizedRoot> {
        self.roots
            .with_current(|current| current.normalized_roots.clone())
    }

    pub fn enforceable_filesystem_roots(&self) -> Vec<NormalizedRoot> {
        self.roots.with_current(|current| {
            current
                .normalized_roots
                .iter()
                .filter(|root| root.is_enforceable_filesystem())
                .cloned()
                .collect()
        })
    }

    pub fn inflight(&self) -> &InflightRegistry {
        &self.inflight
    }

    pub fn mark_execution_nonce_pending(
        &self,
        request_id: &RequestId,
        nonce_id: &str,
    ) -> Result<(), SessionError> {
        self.inflight
            .mark_execution_nonce_pending(request_id, nonce_id)
    }

    pub fn validate_execution_nonce_retry(
        &self,
        context: &OperationContext,
        operation_kind: OperationKind,
        nonce_id: &str,
    ) -> Result<(), SessionError> {
        self.validate_context(context)?;
        self.ensure_operation_allowed(operation_kind)?;
        let current_anchor = self.session_anchor();
        let request = self.inflight.get(&context.request_id).ok_or_else(|| {
            SessionError::ExecutionNonceRetryMismatch {
                request_id: context.request_id.clone(),
            }
        })?;
        if request.operation_kind != operation_kind
            || request.session_anchor_id != current_anchor.id()
            || request.parent_request_id != context.parent_request_id
            || request.progress_token != context.progress_token
            || request.pending_execution_nonce_id.as_deref() != Some(nonce_id)
        {
            return Err(SessionError::ExecutionNonceRetryMismatch {
                request_id: context.request_id.clone(),
            });
        }
        Ok(())
    }

    pub fn subscriptions(&self) -> &SubscriptionRegistry {
        &self.subscriptions
    }

    pub fn terminal(&self) -> TerminalRegistry {
        self.terminal.clone()
    }

    pub fn register_pending_url_elicitation(
        &self,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) {
        self.write_pending_url_elicitations().insert(
            elicitation_id.into(),
            PendingUrlElicitation { related_task_id },
        );
    }

    pub fn register_required_url_elicitations(
        &self,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) {
        for elicitation in elicitations {
            let CreateElicitationOperation::Url { elicitation_id, .. } = elicitation else {
                continue;
            };
            self.register_pending_url_elicitation(
                elicitation_id.clone(),
                related_task_id.map(ToString::to_string),
            );
        }
    }

    pub fn queue_late_event(&self, event: LateSessionEvent) {
        self.write_late_events().push_back(event);
    }

    pub fn take_late_events(&self) -> Vec<LateSessionEvent> {
        self.write_late_events().drain(..).collect()
    }

    #[cfg(not(loom))]
    pub fn queue_tool_server_event(&self, event: ToolServerEvent) {
        match event {
            ToolServerEvent::ElicitationCompleted { elicitation_id } => {
                let Some(pending) = self
                    .write_pending_url_elicitations()
                    .remove(&elicitation_id)
                else {
                    return;
                };
                self.queue_late_event(LateSessionEvent::ElicitationCompleted {
                    elicitation_id,
                    related_task_id: pending.related_task_id,
                });
            }
            ToolServerEvent::ResourceUpdated { uri } => {
                if self.is_resource_subscribed(&uri) {
                    self.queue_late_event(LateSessionEvent::ResourceUpdated { uri });
                }
            }
            ToolServerEvent::ResourcesListChanged => {
                self.queue_late_event(LateSessionEvent::ResourcesListChanged);
            }
            ToolServerEvent::ToolsListChanged => {
                self.queue_late_event(LateSessionEvent::ToolsListChanged);
            }
            ToolServerEvent::PromptsListChanged => {
                self.queue_late_event(LateSessionEvent::PromptsListChanged);
            }
        }
    }

    pub fn queue_elicitation_completion(&self, elicitation_id: &str) {
        let Some(pending) = self.write_pending_url_elicitations().remove(elicitation_id) else {
            return;
        };
        self.queue_late_event(LateSessionEvent::ElicitationCompleted {
            elicitation_id: elicitation_id.to_string(),
            related_task_id: pending.related_task_id,
        });
    }

    pub fn subscribe_resource(&self, uri: impl Into<String>) {
        self.subscriptions.subscribe_resource(uri);
    }

    pub fn unsubscribe_resource(&self, uri: &str) {
        self.subscriptions.unsubscribe_resource(uri);
    }

    pub fn is_resource_subscribed(&self, uri: &str) -> bool {
        self.subscriptions.contains_resource(uri)
    }

    pub fn set_auth_context(
        &self,
        auth_context: SessionAuthContext,
    ) -> (bool, SessionAnchorSnapshot, Option<String>) {
        self.auth_state.replace_with(|current| {
            let rotated = current.auth_context != auth_context;
            if rotated {
                let previous_anchor_id = current.session_anchor.id().to_string();
                let next_epoch = current.session_anchor.auth_epoch.saturating_add(1);
                let session_anchor = SessionAnchorState::new(&self.id, &auth_context, next_epoch);
                let snapshot = SessionAnchorSnapshot {
                    session_id: self.id.clone(),
                    agent_id: self.agent_id.clone(),
                    auth_context: auth_context.clone(),
                    session_anchor: session_anchor.clone(),
                };
                (
                    Some(SessionAuthState {
                        auth_context,
                        session_anchor,
                    }),
                    (true, snapshot, Some(previous_anchor_id)),
                )
            } else {
                (
                    None,
                    (
                        false,
                        SessionAnchorSnapshot {
                            session_id: self.id.clone(),
                            agent_id: self.agent_id.clone(),
                            auth_context: current.auth_context.clone(),
                            session_anchor: current.session_anchor.clone(),
                        },
                        None,
                    ),
                )
            }
        })
    }

    pub fn set_auth_context_persisted<E>(
        &self,
        auth_context: SessionAuthContext,
        persist: impl FnOnce(&SessionAnchorSnapshot, Option<&str>) -> Result<(), E>,
    ) -> Result<(), SessionPersistError<E>> {
        let state_guard = self.write_inner();
        if state_guard.state == SessionState::Closed {
            return Err(SessionPersistError::Session(
                SessionError::OperationNotAllowed {
                    session_id: self.id.clone(),
                    operation: "set_auth_context",
                    state: state_guard.state.as_str(),
                },
            ));
        }

        self.auth_state.replace_with(|current| {
            let rotated = current.auth_context != auth_context;
            let (next, snapshot, supersedes_anchor_id) = if rotated {
                let previous_anchor_id = current.session_anchor.id().to_string();
                let next_epoch = current.session_anchor.auth_epoch.saturating_add(1);
                let session_anchor = SessionAnchorState::new(&self.id, &auth_context, next_epoch);
                let snapshot = SessionAnchorSnapshot {
                    session_id: self.id.clone(),
                    agent_id: self.agent_id.clone(),
                    auth_context: auth_context.clone(),
                    session_anchor: session_anchor.clone(),
                };
                (
                    Some(SessionAuthState {
                        auth_context,
                        session_anchor,
                    }),
                    snapshot,
                    Some(previous_anchor_id),
                )
            } else {
                (
                    None,
                    SessionAnchorSnapshot {
                        session_id: self.id.clone(),
                        agent_id: self.agent_id.clone(),
                        auth_context: current.auth_context.clone(),
                        session_anchor: current.session_anchor.clone(),
                    },
                    None,
                )
            };

            let result = persist(&snapshot, supersedes_anchor_id.as_deref());
            match result {
                Ok(()) => (next, Ok(())),
                Err(error) => (None, Err(SessionPersistError::Persist(error))),
            }
        })
    }

    pub fn set_peer_capabilities(&self, peer_capabilities: PeerCapabilities) {
        self.peer_capabilities.replace(peer_capabilities);
    }

    pub fn replace_roots(&self, roots: Vec<RootDefinition>) {
        let normalized_roots = roots
            .iter()
            .map(RootDefinition::normalize_for_runtime)
            .collect();
        self.roots.replace(SessionRoots {
            roots,
            normalized_roots,
        });
    }

    pub fn activate(&self) -> Result<(), SessionError> {
        self.transition(SessionState::Ready)
    }

    pub fn begin_draining(&self) -> Result<(), SessionError> {
        self.transition(SessionState::Draining)
    }

    pub fn close(&self) -> Result<(), SessionError> {
        {
            let mut inner = self.write_inner();
            if inner.state == SessionState::Closed {
                return Ok(());
            }

            let active_count = self.inflight.len() as u64;
            if active_count > 0 {
                if inner.state != SessionState::Closed {
                    inner.state = SessionState::Draining;
                }
                return Err(SessionError::CloseRequiresDrain {
                    session_id: self.id.clone(),
                    active_count,
                });
            }

            inner.state = SessionState::Closed;
        }

        self.inflight.clear();
        self.subscriptions.clear();
        self.auth_state.replace_with(|current| {
            let auth_context = SessionAuthContext::in_process_anonymous();
            let next_epoch = current.session_anchor.auth_epoch.saturating_add(1);
            let session_anchor = SessionAnchorState::new(&self.id, &auth_context, next_epoch);
            (
                Some(SessionAuthState {
                    auth_context,
                    session_anchor,
                }),
                (),
            )
        });
        self.roots.replace(SessionRoots {
            roots: Vec::new(),
            normalized_roots: Vec::new(),
        });
        self.write_pending_url_elicitations().clear();
        self.write_late_events().clear();
        Ok(())
    }

    pub fn close_persisted<E>(
        &self,
        persist: impl FnOnce(&SessionAnchorSnapshot, Option<&str>) -> Result<(), E>,
    ) -> Result<(), SessionPersistError<E>> {
        let mut inner = self.write_inner();
        if inner.state == SessionState::Closed {
            return Ok(());
        }

        let active_count = self.inflight.len() as u64;
        if active_count > 0 {
            if inner.state != SessionState::Closed {
                inner.state = SessionState::Draining;
            }
            return Err(SessionPersistError::Session(
                SessionError::CloseRequiresDrain {
                    session_id: self.id.clone(),
                    active_count,
                },
            ));
        }

        self.auth_state.replace_with(|current| {
            let auth_context = SessionAuthContext::in_process_anonymous();
            let previous_anchor_id = current.session_anchor.id().to_string();
            let next_epoch = current.session_anchor.auth_epoch.saturating_add(1);
            let session_anchor = SessionAnchorState::new(&self.id, &auth_context, next_epoch);
            let snapshot = SessionAnchorSnapshot {
                session_id: self.id.clone(),
                agent_id: self.agent_id.clone(),
                auth_context: auth_context.clone(),
                session_anchor: session_anchor.clone(),
            };
            let result = persist(&snapshot, Some(previous_anchor_id.as_str()));
            match result {
                Ok(()) => (
                    Some(SessionAuthState {
                        auth_context,
                        session_anchor,
                    }),
                    Ok(()),
                ),
                Err(error) => (None, Err(SessionPersistError::Persist(error))),
            }
        })?;

        inner.state = SessionState::Closed;
        drop(inner);

        self.inflight.clear();
        self.subscriptions.clear();
        self.roots.replace(SessionRoots {
            roots: Vec::new(),
            normalized_roots: Vec::new(),
        });
        self.write_pending_url_elicitations().clear();
        self.write_late_events().clear();
        Ok(())
    }

    pub fn ensure_operation_allowed(&self, operation: OperationKind) -> Result<(), SessionError> {
        let state = self.state();
        let allowed = operation_allowed_for_state(state, operation);

        if allowed {
            Ok(())
        } else {
            Err(SessionError::OperationNotAllowed {
                session_id: self.id.clone(),
                operation: operation.as_str(),
                state: state.as_str(),
            })
        }
    }

    /// Capture authentication under an allowed lifecycle state and keep that
    /// state stable until the caller's effect boundary returns.
    #[cfg(feature = "finding-market")]
    pub(crate) fn with_operation_boundary<R>(
        &self,
        context: &OperationContext,
        operation: OperationKind,
        run: impl FnOnce(&SessionAnchorSnapshot) -> R,
    ) -> Result<R, SessionError> {
        self.validate_context(context)?;
        let state_guard = self.read_inner();
        if !operation_allowed_for_state(state_guard.state, operation) {
            return Err(SessionError::OperationNotAllowed {
                session_id: self.id.clone(),
                operation: operation.as_str(),
                state: state_guard.state.as_str(),
            });
        }
        let snapshot = self.session_anchor_snapshot();
        let result = run(&snapshot);
        drop(state_guard);
        Ok(result)
    }

    pub fn track_request(
        &self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<SessionRequestStart, SessionError> {
        self.validate_context(context)?;

        let state_guard = self.read_inner();
        let state = state_guard.state;
        if !operation_allowed_for_state(state, operation_kind) {
            return Err(SessionError::OperationNotAllowed {
                session_id: self.id.clone(),
                operation: operation_kind.as_str(),
                state: state.as_str(),
            });
        }

        let start = self.auth_state.with_current(|auth_state| {
            let session_snapshot = SessionAnchorSnapshot {
                session_id: self.id.clone(),
                agent_id: self.agent_id.clone(),
                auth_context: auth_state.auth_context.clone(),
                session_anchor: auth_state.session_anchor.clone(),
            };
            let mut requests = self.inflight.write_requests();
            let mut request_lineage = self.write_request_lineage();
            if requests.contains_key(&context.request_id) {
                return Err(SessionError::DuplicateInflightRequest {
                    request_id: context.request_id.clone(),
                });
            }
            if let Some(parent_request_id) = &context.parent_request_id {
                validate_parent_request_lineage_locked(
                    &context.request_id,
                    parent_request_id,
                    &requests,
                    &request_lineage,
                    auth_state.session_anchor.id(),
                )?;
            }
            if request_lineage.contains_key(&context.request_id) {
                return Err(SessionError::DuplicateRequestLineage {
                    request_id: context.request_id.clone(),
                });
            }
            self.inflight.track_locked(
                &mut requests,
                context,
                operation_kind,
                auth_state.session_anchor.id(),
                cancellable,
            )?;
            let lineage = RequestLineageRecord {
                request_id: context.request_id.clone(),
                session_anchor_id: auth_state.session_anchor.id().to_string(),
                auth_epoch: auth_state.session_anchor.auth_epoch(),
                parent_request_id: context.parent_request_id.clone(),
                operation_kind,
                started_at: current_unix_timestamp(),
                terminal_state: None,
            };
            request_lineage.insert(context.request_id.clone(), lineage.clone());
            Ok(SessionRequestStart {
                session: session_snapshot,
                lineage,
            })
        })?;
        drop(state_guard);
        Ok(start)
    }

    pub fn complete_request(
        &self,
        request_id: &RequestId,
    ) -> Result<InflightRequest, SessionError> {
        self.complete_request_with_terminal_state(request_id, OperationTerminalState::Completed)
    }

    pub fn complete_request_with_terminal_state(
        &self,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<InflightRequest, SessionError> {
        let inflight = self.inflight.complete(request_id)?;
        self.mark_request_terminal(request_id, terminal_state);
        Ok(inflight)
    }

    pub fn discard_unpersisted_request_start(&self, request_id: &RequestId) {
        let _ = self.inflight.complete(request_id);
        self.write_request_lineage().remove(request_id);
        self.terminal.remove(request_id);
    }

    fn mark_request_terminal(
        &self,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) {
        let recorded = self
            .terminal
            .record(request_id.clone(), terminal_state.clone());
        if recorded {
            if let Some(lineage) = self.write_request_lineage().get_mut(request_id) {
                lineage.terminal_state = Some(terminal_state);
            }
        }
    }

    pub fn request_cancellation(&self, request_id: &RequestId) -> Result<(), SessionError> {
        self.inflight.mark_cancellation_requested(request_id)
    }

    pub(crate) fn request_cancellation_with_reason(
        &self,
        request_id: &RequestId,
        reason: &str,
    ) -> Result<(), SessionError> {
        self.inflight
            .mark_cancellation_requested_with_reason(request_id, Some(reason))
    }

    pub(crate) fn try_mark_request_dispatch_started(
        &self,
        request_id: &RequestId,
    ) -> Result<(), DispatchStartFailure> {
        self.auth_state.with_current(|auth_state| {
            self.inflight
                .try_mark_dispatch_started(request_id, auth_state.session_anchor.id())
        })
    }

    pub(crate) fn mark_request_dispatch_finished(&self, request_id: &RequestId) {
        self.inflight.mark_dispatch_finished(request_id);
    }

    #[cfg(test)]
    pub(crate) fn is_request_dispatch_active(&self, request_id: &RequestId) -> bool {
        self.inflight.is_dispatch_active(request_id)
    }

    pub fn validate_parent_request_lineage(
        &self,
        request_id: &RequestId,
        parent_request_id: &RequestId,
    ) -> Result<RequestLineageRecord, SessionError> {
        self.auth_state.with_current(|auth_state| {
            let requests = self.inflight.read_requests();
            let request_lineage = self.read_request_lineage();
            validate_parent_request_lineage_locked(
                request_id,
                parent_request_id,
                &requests,
                &request_lineage,
                auth_state.session_anchor.id(),
            )
        })
    }

    fn transition(&self, next: SessionState) -> Result<(), SessionError> {
        let mut inner = self.write_inner();
        let valid = match (inner.state, next) {
            (SessionState::Initializing, SessionState::Ready)
            | (SessionState::Initializing, SessionState::Closed)
            | (SessionState::Ready, SessionState::Draining)
            | (SessionState::Ready, SessionState::Closed)
            | (SessionState::Draining, SessionState::Closed) => true,
            _ if inner.state == next => true,
            _ => false,
        };

        if !valid {
            return Err(SessionError::InvalidTransition {
                from: inner.state.as_str(),
                to: next.as_str(),
            });
        }

        inner.state = next;
        Ok(())
    }

    pub fn validate_context(&self, context: &OperationContext) -> Result<(), SessionError> {
        if context.session_id != self.id {
            return Err(SessionError::ContextSessionMismatch {
                expected: self.id.clone(),
                actual: context.session_id.clone(),
            });
        }

        if context.agent_id != self.agent_id {
            return Err(SessionError::ContextAgentMismatch {
                expected: self.agent_id.clone(),
                actual: context.agent_id.clone(),
            });
        }

        Ok(())
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn auth_context_hash(auth_context: &SessionAuthContext) -> String {
    canonical_json_bytes(auth_context)
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_else(|_| "session-auth-context-hash-unavailable".to_string())
}

/// Session-aware kernel response, decoupled from the current wire protocol.
#[cfg(not(loom))]
#[derive(Debug)]
pub enum SessionOperationResponse {
    ToolCall(ToolCallResponse),
    RootList {
        roots: Vec<RootDefinition>,
    },
    ResourceList {
        resources: Vec<ResourceDefinition>,
    },
    ResourceRead {
        contents: Vec<ResourceContent>,
    },
    ResourceReadDenied {
        receipt: ChioReceipt,
    },
    ResourceTemplateList {
        templates: Vec<ResourceTemplateDefinition>,
    },
    PromptList {
        prompts: Vec<PromptDefinition>,
    },
    PromptGet {
        prompt: PromptResult,
    },
    Completion {
        completion: CompletionResult,
    },
    CapabilityList {
        capabilities: Vec<CapabilityToken>,
    },
    Heartbeat,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
