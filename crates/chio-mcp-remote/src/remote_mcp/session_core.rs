use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex as StdMutex, Weak};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::CapabilityToken;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, Signature as Ed25519Signature};
use chio_core::session::{
    ChioIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext,
    OAuthBearerFederatedClaims, RequestOwnershipSnapshot, SessionAuthContext, SessionAuthMethod,
    SessionId,
};
use chio_kernel::operator_report::{
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER,
};
use chio_kernel::{
    is_supported_dpop_schema, ChioOAuthAuthorizationProfile, DpopConfig, DpopNonceStore, DpopProof,
    GovernedAuthorizationDetail, GovernedAuthorizationTransactionContext, KernelError,
    PeerCapabilities, RevocationStore, ToolServerConnection,
    CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID,
    CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA, CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT, CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP,
};
use chio_mcp_adapter::{
    AdaptedMcpServer, AdapterError, ChioMcpEdge, McpAdapter, McpAdapterConfig, McpEdgeConfig,
    McpTransport, SerializedMcpTransport, StdioMcpTransport,
};
use async_stream::stream;
use axum::extract::{Form, Path as AxumPath, Query, Request, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use reqwest::Client as HttpClient;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey as JwtRsaPublicKey};
use rusqlite::{params, Connection};
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use url::Url;

use chio_control_plane::policy::{load_policy, LoadedPolicy};
use chio_control_plane::trust_control::{
    self, ChildReceiptQuery, RevocationQuery, ToolReceiptQuery,
};
use chio_control_plane::{
    authority_public_key_from_seed_file, build_kernel, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation::{
        EnterpriseProviderKind, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    },
    issue_default_capabilities, load_or_create_authority_keypair, rotate_authority_keypair,
};

const MCP_ENDPOINT_PATH: &str = "/mcp";
const ADMIN_HEALTH_PATH: &str = "/admin/health";
const ADMIN_AUTHORITY_PATH: &str = "/admin/authority";
const ADMIN_TOOL_RECEIPTS_PATH: &str = "/admin/receipts/tools";
const ADMIN_CHILD_RECEIPTS_PATH: &str = "/admin/receipts/children";
const ADMIN_REVOCATIONS_PATH: &str = "/admin/revocations";
const ADMIN_BUDGETS_PATH: &str = "/admin/budgets";
const ADMIN_SESSIONS_PATH: &str = "/admin/sessions";
const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const LOCAL_AUTHORIZATION_PATH: &str = "/oauth/authorize";
const LOCAL_TOKEN_PATH: &str = "/oauth/token";
const LOCAL_JWKS_PATH: &str = "/oauth/jwks.json";
const DPOP_HEADER: &str = "dpop";
const HTTP_DPOP_ACTION_HASH_EMPTY: &[u8] = b"";
const CHIO_MTLS_THUMBPRINT_HEADER: &str = "x-chio-mtls-thumbprint-sha256";
const CHIO_RUNTIME_ATTESTATION_HEADER: &str = "x-chio-runtime-attestation-sha256";
const CHIO_SENDER_DPOP_PUBLIC_KEY_PARAMETER: &str = "chio_sender_dpop_public_key";
const CHIO_SENDER_MTLS_THUMBPRINT_PARAMETER: &str = "chio_sender_mtls_thumbprint_sha256";
const CHIO_SENDER_ATTESTATION_PARAMETER: &str = "chio_sender_attestation_sha256";
const ADMIN_SESSION_TRUST_PATH: &str = "/admin/sessions/{session_id}/trust";
const ADMIN_SESSION_DRAIN_PATH: &str = "/admin/sessions/{session_id}/drain";
const ADMIN_SESSION_SHUTDOWN_PATH: &str = "/admin/sessions/{session_id}/shutdown";
const PROTECTED_RESOURCE_METADATA_ROOT_PATH: &str = "/.well-known/oauth-protected-resource";
const PROTECTED_RESOURCE_METADATA_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const CHIO_RESPONSE_MODE_HEADER: &str = "x-chio-mcp-response-mode";
const CHIO_TOOL_STREAMING_CAPABILITY_KEY: &str = "chioToolStreaming";
const DEFAULT_STREAM_RETRY_MILLIS: u64 = 1_000;
const DEFAULT_NOTIFICATION_STREAM_IDLE_MILLIS: u64 = 100;
const DEFAULT_NOTIFICATION_REPLAY_WINDOW: usize = 64;
const DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS: u64 = 25;
const DEFAULT_ADMIN_LIST_LIMIT: usize = 50;
const MAX_ADMIN_LIST_LIMIT: usize = 200;
const DEFAULT_SESSION_IDLE_EXPIRY_MILLIS: u64 = 15 * 60 * 1000;
const DEFAULT_SESSION_DRAIN_GRACE_MILLIS: u64 = 5 * 1000;
const DEFAULT_SESSION_REAPER_INTERVAL_MILLIS: u64 = 250;
const DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS: u64 = 30 * 60 * 1000;
const IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS: u64 = 5;
const TOKEN_INTROSPECTION_TIMEOUT_SECS: u64 = 5;
const IDENTITY_FEDERATION_DERIVATION_LABEL: &[u8] = b"chio.identity_federation.v1";
const REMOTE_SESSION_RESUME_INTEGRITY_LABEL: &[u8] = b"chio.remote_mcp.resume_integrity.v1";
const SESSION_IDLE_EXPIRY_ENV: &str = "CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS";
const SESSION_DRAIN_GRACE_ENV: &str = "CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS";
const SESSION_REAPER_INTERVAL_ENV: &str = "CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS";
const SESSION_TOMBSTONE_RETENTION_ENV: &str = "CHIO_MCP_SESSION_TOMBSTONE_RETENTION_MILLIS";
const SESSION_TOUCH_PERSIST_INTERVAL_MILLIS: u64 = 5_000;

type NotificationTapQueue = Arc<StdMutex<VecDeque<Value>>>;
type NotificationTapWeak = Weak<StdMutex<VecDeque<Value>>>;
type NotificationSubscriberList = Arc<StdMutex<Vec<NotificationTapWeak>>>;

#[derive(Clone)]
pub struct RemoteServeHttpConfig {
    pub listen: SocketAddr,
    pub auth_token: Option<String>,
    pub auth_jwt_public_key: Option<String>,
    pub auth_jwt_discovery_url: Option<String>,
    pub auth_introspection_url: Option<String>,
    pub auth_introspection_client_id: Option<String>,
    pub auth_introspection_client_secret: Option<String>,
    pub auth_jwt_provider_profile: Option<JwtProviderProfile>,
    pub auth_server_seed_path: Option<PathBuf>,
    pub identity_federation_seed_path: Option<PathBuf>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub auth_jwt_issuer: Option<String>,
    pub auth_jwt_audience: Option<String>,
    pub admin_token: Option<String>,
    pub control_url: Option<String>,
    pub control_token: Option<String>,
    pub public_base_url: Option<String>,
    pub auth_servers: Vec<String>,
    pub auth_authorization_endpoint: Option<String>,
    pub auth_token_endpoint: Option<String>,
    pub auth_registration_endpoint: Option<String>,
    pub auth_jwks_uri: Option<String>,
    pub auth_scopes: Vec<String>,
    pub auth_subject: String,
    pub auth_code_ttl_secs: u64,
    pub auth_access_token_ttl_secs: u64,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub session_db_path: Option<PathBuf>,
    pub policy_path: PathBuf,
    pub server_id: String,
    pub server_name: String,
    pub server_version: String,
    pub manifest_public_key: Option<String>,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub shared_hosted_owner: bool,
    pub wrapped_command: String,
    pub wrapped_args: Vec<String>,
    /// Typed HTTP egress contract that gates outbound HTTP from the remote
    /// MCP runtime (most prominently the OAuth introspection endpoint).
    /// Production deployments must populate this; absence falls back to
    /// substrate fail-closed at dispatch.
    pub egress_contract: Option<HttpEgressContract>,
}

#[derive(Clone)]
struct RemoteAppState {
    sessions: Arc<RemoteSessionLedger>,
    factory: Arc<RemoteSessionFactory>,
    auth_mode: Arc<RemoteAuthMode>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    admin_token: Option<Arc<str>>,
    protected_resource_metadata: Option<Arc<ProtectedResourceMetadata>>,
    authorization_server_metadata: Option<Arc<AuthorizationServerMetadata>>,
    local_auth_server: Option<Arc<LocalAuthorizationServer>>,
}

struct RemoteSessionFactory {
    config: RemoteServeHttpConfig,
    shared_upstream_owner: Arc<StdMutex<Option<Arc<SharedUpstreamOwner>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
}

#[derive(Clone, Debug)]
struct SessionLifecyclePolicy {
    idle_expiry_millis: u64,
    drain_grace_millis: u64,
    reaper_interval_millis: u64,
    tombstone_retention_millis: u64,
}

impl SessionLifecyclePolicy {
    fn from_env() -> Self {
        read_session_lifecycle_policy()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionDiagnosticRecord {
    session_id: String,
    auth_context: SessionAuthContext,
    capabilities: Vec<RemoteSessionCapability>,
    lifecycle: RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
    #[serde(default)]
    ownership: RemoteSessionOwnershipSnapshot,
    terminal_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionResumeRecord {
    session_id: String,
    agent_id: String,
    auth_context: SessionAuthContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_mode_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_fingerprint: Option<String>,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle: RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
    peer_capabilities: PeerCapabilities,
    initialize_params: Value,
    issued_capabilities: Vec<CapabilityToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume_integrity_tag: Option<String>,
}

#[derive(Clone, Debug)]
enum RemoteSessionEntry {
    Active(Arc<RemoteSession>),
    Terminal(Arc<RemoteSessionDiagnosticRecord>),
}

#[derive(Clone)]
struct RemoteSessionLedger {
    active: Arc<Mutex<HashMap<String, Arc<RemoteSession>>>>,
    terminal: Arc<Mutex<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
    tombstone_db_path: Option<PathBuf>,
}

#[derive(Clone)]
struct SharedUpstreamToolServer {
    upstream: Arc<AdaptedMcpServer>,
    server_id: String,
    tool_names: Vec<String>,
}

struct SharedUpstreamOwner {
    upstream_server: Arc<AdaptedMcpServer>,
    notification_subscribers: NotificationSubscriberList,
    notification_stats: Arc<SharedUpstreamNotificationStats>,
}

struct SharedUpstreamNotificationTap {
    queue: NotificationTapQueue,
}

#[derive(Default)]
struct SharedUpstreamNotificationStats {
    fanout_batches: AtomicU64,
    fanout_notifications: AtomicU64,
    fanout_targets: AtomicU64,
    pruned_subscribers: AtomicU64,
    queue_lock_skips: AtomicU64,
    subscriber_lock_failures: AtomicU64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedUpstreamNotificationStatsSnapshot {
    fanout_batches: u64,
    fanout_notifications: u64,
    fanout_targets: u64,
    pruned_subscribers: u64,
    queue_lock_skips: u64,
    subscriber_lock_failures: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RetainedRemoteSessionEvent {
    seq: u64,
    event_id: String,
    message: Value,
}

#[derive(Clone, Debug)]
struct RemoteSessionEvent {
    seq: u64,
    event_id: String,
    kind: RemoteSessionEventKind,
    message: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteSessionEventKind {
    Notification,
    RequestCorrelated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RemoteSessionState {
    Initializing,
    Ready,
    Draining,
    Deleted,
    Expired,
    Closed,
}

impl RemoteSessionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionLifecycleSnapshot {
    state: RemoteSessionState,
    created_at: u64,
    last_seen_at: u64,
    idle_expires_at: u64,
    drain_deadline_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteRequestStreamOwner {
    ExclusiveRequestStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteNotificationStreamOwner {
    SessionNotificationStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteNotificationDelivery {
    PostResponseFallback,
    GetSse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum RemoteHostedIsolationMode {
    #[default]
    DedicatedPerSession,
    SharedHostedOwnerCompatibility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum RemoteHostedIdentityProfile {
    #[default]
    StrongDedicatedSession,
    WeakSharedHostedOwnerCompatibility,
}

impl RemoteHostedIsolationMode {
    fn identity_profile(self) -> RemoteHostedIdentityProfile {
        match self {
            Self::DedicatedPerSession => RemoteHostedIdentityProfile::StrongDedicatedSession,
            Self::SharedHostedOwnerCompatibility => {
                RemoteHostedIdentityProfile::WeakSharedHostedOwnerCompatibility
            }
        }
    }

    fn snapshot_auth_context(self, auth_context: SessionAuthContext) -> SessionAuthContext {
        match (self, auth_context) {
            (
                Self::SharedHostedOwnerCompatibility,
                SessionAuthContext {
                    transport,
                    method,
                    origin,
                },
            ) if matches!(
                transport,
                chio_core::session::SessionTransport::StreamableHttp
            ) =>
            {
                match method {
                    SessionAuthMethod::OAuthBearer {
                        principal,
                        issuer,
                        subject,
                        audience,
                        scopes,
                        federated_claims,
                        enterprise_identity,
                        ..
                    } => SessionAuthContext {
                        transport,
                        method: SessionAuthMethod::OAuthBearer {
                            principal,
                            issuer,
                            subject,
                            audience,
                            scopes,
                            federated_claims,
                            enterprise_identity,
                            token_fingerprint: None,
                        },
                        origin,
                    },
                    other_method => SessionAuthContext {
                        transport,
                        method: other_method,
                        origin,
                    },
                }
            }
            (_, auth_context) => auth_context,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteSessionOwnershipSnapshot {
    request_ownership: RequestOwnershipSnapshot,
    #[serde(default)]
    hosted_isolation: RemoteHostedIsolationMode,
    #[serde(default)]
    hosted_identity_profile: RemoteHostedIdentityProfile,
    request_stream_owner: RemoteRequestStreamOwner,
    notification_stream_owner: RemoteNotificationStreamOwner,
    notification_delivery: RemoteNotificationDelivery,
    request_stream_active: bool,
    notification_stream_attached: bool,
}

impl Default for RemoteSessionOwnershipSnapshot {
    fn default() -> Self {
        Self {
            request_ownership: RequestOwnershipSnapshot::request_owned(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            hosted_identity_profile: RemoteHostedIdentityProfile::StrongDedicatedSession,
            request_stream_owner: RemoteRequestStreamOwner::ExclusiveRequestStream,
            notification_stream_owner: RemoteNotificationStreamOwner::SessionNotificationStream,
            notification_delivery: RemoteNotificationDelivery::PostResponseFallback,
            request_stream_active: false,
            notification_stream_attached: false,
        }
    }
}

#[derive(Debug)]
struct RemoteSession {
    session_id: String,
    agent_id: String,
    capabilities: Vec<RemoteSessionCapability>,
    issued_capabilities: Vec<CapabilityToken>,
    auth_context: SessionAuthContext,
    auth_mode_fingerprint: String,
    policy_fingerprint: String,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle_policy: SessionLifecyclePolicy,
    protocol_version: StdMutex<Option<String>>,
    peer_capabilities: StdMutex<Option<PeerCapabilities>>,
    initialize_params: StdMutex<Option<Value>>,
    lifecycle: StdMutex<RemoteSessionLifecycleSnapshot>,
    input_tx: mpsc::Sender<Value>,
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    active_request_stream: Arc<Mutex<()>>,
    notification_stream_attached: Arc<AtomicBool>,
    next_event_id: Arc<AtomicU64>,
    session_db_path: Option<PathBuf>,
    resume_integrity_secret: Option<[u8; 32]>,
}

struct RemoteSessionInit {
    session_id: String,
    agent_id: String,
    capabilities: Vec<RemoteSessionCapability>,
    issued_capabilities: Vec<CapabilityToken>,
    auth_context: SessionAuthContext,
    auth_mode_fingerprint: String,
    policy_fingerprint: String,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle_policy: SessionLifecyclePolicy,
    protocol_version: Option<String>,
    peer_capabilities: Option<PeerCapabilities>,
    initialize_params: Option<Value>,
    lifecycle_snapshot: Option<RemoteSessionLifecycleSnapshot>,
    input_tx: mpsc::Sender<Value>,
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    next_event_id: Arc<AtomicU64>,
    session_db_path: Option<PathBuf>,
    resume_integrity_secret: Option<[u8; 32]>,
}

struct NotificationStreamAttachment {
    session: Arc<RemoteSession>,
}

impl Drop for NotificationStreamAttachment {
    fn drop(&mut self) {
        self.session.detach_notification_stream();
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone)]
enum RemoteAuthMode {
    StaticBearer {
        token: Arc<str>,
    },
    JwtBearer {
        verifier: Arc<JwtBearerVerifier>,
    },
    IntrospectionBearer {
        verifier: Arc<IntrospectionBearerVerifier>,
    },
}

impl std::fmt::Debug for RemoteAuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaticBearer { .. } => f.write_str("StaticBearer"),
            Self::JwtBearer { .. } => f.write_str("JwtBearer"),
            Self::IntrospectionBearer { .. } => f.write_str("IntrospectionBearer"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JwtSignatureAlgorithm {
    EdDsa,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
}

#[derive(Clone, Debug)]
enum JwtVerificationKeySource {
    Static(PublicKey),
    Jwks(JwtJwksKeySet),
}

#[derive(Clone)]
struct JwtBearerVerifier {
    key_source: JwtVerificationKeySource,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    sender_dpop_nonce_store: Arc<DpopNonceStore>,
    sender_dpop_config: DpopConfig,
}

#[derive(Clone)]
struct IntrospectionBearerVerifier {
    client: HttpClient,
    introspection_url: Url,
    client_id: Option<String>,
    client_secret: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    sender_dpop_nonce_store: Arc<DpopNonceStore>,
    sender_dpop_config: DpopConfig,
    /// Typed HTTP egress contract that gates every introspection-endpoint
    /// dispatch. Production deployments must populate this; without a
    /// contract the verifier substrate will fail closed if introspection is
    /// invoked.
    #[allow(dead_code)]
    egress_contract: Option<HttpEgressContract>,
}

#[derive(Clone)]
struct ProtectedResourceMetadata {
    resource: String,
    resource_metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    chio_authorization_profile: Value,
}

#[derive(Clone)]
struct AuthorizationServerMetadata {
    metadata_path: String,
    document: Value,
}

#[derive(Clone)]
struct LocalAuthorizationServer {
    signing_key: Keypair,
    issuer: String,
    default_audience: String,
    supported_scopes: Vec<String>,
    subject: String,
    code_ttl_secs: u64,
    access_token_ttl_secs: u64,
    codes: Arc<StdMutex<HashMap<String, AuthorizationCodeGrant>>>,
    sender_dpop_nonce_store: Arc<DpopNonceStore>,
    sender_dpop_config: DpopConfig,
}

impl RemoteAppState {
    // Retained for enterprise-provider validation paths shared with the local
    // trust-control surface even though the current remote flow does not call it.
    #[allow(dead_code)]
    fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    // Retained for enterprise-provider validation paths shared with the local
    // trust-control surface even though the current remote flow does not call it.
    #[allow(dead_code)]
    fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }
}

#[derive(Clone, Debug)]
struct AuthorizationCodeGrant {
    client_id: String,
    redirect_uri: String,
    resource: String,
    scopes: Vec<String>,
    subject: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: u64,
    authorization_details: Option<Vec<GovernedAuthorizationDetail>>,
    transaction_context: Option<GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ChioSenderConstraintClaims {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioSenderKey"
    )]
    chio_sender_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "x5t#S256")]
    mtls_thumbprint_sha256: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioAttestationSha256"
    )]
    chio_attestation_sha256: Option<String>,
}

impl ChioSenderConstraintClaims {
    fn is_empty(&self) -> bool {
        self.chio_sender_key.is_none()
            && self.mtls_thumbprint_sha256.is_none()
            && self.chio_attestation_sha256.is_none()
    }
}

#[derive(Clone, Debug)]
struct JwtJwksKeySet {
    keys_by_kid: HashMap<String, JwtResolvedJwkPublicKey>,
    anonymous_keys: Vec<JwtResolvedJwkPublicKey>,
}

#[derive(Clone, Debug)]
struct DiscoveredIdentityProvider {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    jwks_uri: Option<String>,
    jwks_keys: Option<JwtJwksKeySet>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<JwtAudience>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Vec<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    groups: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    roles: Vec<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<Value>,
    #[serde(default)]
    chio_transaction_context: Option<Value>,
    #[serde(default)]
    cnf: Option<ChioSenderConstraintClaims>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JwtAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthIntrospectionResponse {
    active: bool,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(flatten)]
    claims: JwtClaims,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    #[serde(default)]
    keys: Vec<JwkDocumentKey>,
}

#[derive(Debug, Deserialize)]
struct JwkDocumentKey {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Clone, Debug)]
struct JwtResolvedJwkPublicKey {
    key: JwtResolvedPublicKey,
    alg_hint: Option<String>,
}

#[derive(Clone, Debug)]
enum JwtResolvedPublicKey {
    Ed25519(PublicKey),
    Rsa(JwtRsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionCapability {
    id: String,
    issuer_public_key: String,
    subject_public_key: String,
}

fn canonicalize_federated_issuer(issuer: &str) -> String {
    let trimmed = issuer.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

impl JwtSignatureAlgorithm {
    fn from_header(
        header: &JwtHeader,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<Self, Response> {
        match header.alg.as_str() {
            "EdDSA" => Ok(Self::EdDsa),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "PS256" => Ok(Self::Ps256),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            _ => Err(unauthorized_bearer_response(
                "JWT bearer token uses unsupported alg",
                protected_resource_metadata,
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }
}

fn verify_ed25519_jwt_signature(
    public_key: &PublicKey,
    signed_input: &[u8],
    signature_bytes: &[u8],
) -> bool {
    if signature_bytes.len() != 64 {
        return false;
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    public_key.verify(signed_input, &Ed25519Signature::from_bytes(&signature))
}

fn validate_identity_provider_url(url: &Url, field_name: &str) -> Result<(), CliError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme == "https" || (scheme == "http" && localhost) {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "{field_name} must use https, or localhost http during local testing: {url}"
        )))
    }
}

fn parse_identity_provider_url(value: &str, field_name: &str) -> Result<Url, CliError> {
    let url = Url::parse(value)
        .map_err(|error| CliError::cli_other_error(format!("{field_name} is not a valid URL: {error}")))?;
    validate_identity_provider_url(&url, field_name)?;
    Ok(url)
}

fn derive_oidc_discovery_url_from_issuer(issuer: &str) -> Result<Url, CliError> {
    let issuer = parse_identity_provider_url(issuer, "--auth-jwt-issuer")?;
    let mut path = issuer.path().trim_end_matches('/').to_string();
    path.push_str("/.well-known/openid-configuration");
    let mut discovery = issuer;
    discovery.set_path(&path);
    discovery.set_query(None);
    discovery.set_fragment(None);
    Ok(discovery)
}

/// Test-friendly entry point that runs the typed `HttpEgressContract`
/// gate against an OIDC discovery or JWKS URL using the same code path
/// as production OIDC discovery. Returns `Ok(())` when the URL passes
/// the contract; surfaces a `CliError` when it is denied. This lets
/// negative-conformance tests assert that loopback / link-local targets
/// are rejected before a TCP connect is attempted.
pub fn enforce_oidc_egress_contract(
    url: &Url,
    egress_contract: &HttpEgressContract,
) -> Result<(), CliError> {
    egress_contract
        .enforce_url_with_dns(url.as_str(), 0)
        .map(|_| ())
        .map_err(|err| {
            CliError::cli_other_error(format!(
                "HttpEgressContract rejects OIDC fetch `{url}`: {err}"
            ))
        })
}

async fn fetch_identity_provider_json<T: DeserializeOwned>(
    url: &Url,
    field_name: &str,
    egress_contract: Option<&HttpEgressContract>,
) -> Result<T, CliError> {
    // HttpEgressContract: every OIDC discovery and JWKS fetch goes through
    // send_with_contract so target URL, DNS answers, redirects, and response
    // body size are enforced before bytes cross the substrate boundary.
    let contract = egress_contract.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "{field_name} `{url}` requires an HttpEgressContract; substrate fails closed"
        ))
    })?;
    let client = client_builder_with_contract(contract)
        .timeout(Duration::from_secs(IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to build {field_name} HTTP client for `{url}`: {error}"
            ))
        })?;
    let request = client.get(url.as_str()).build().map_err(|error| {
        CliError::cli_other_error(format!("failed to build {field_name} request `{url}`: {error}"))
    })?;
    let response = send_with_contract(contract, &client, request)
        .await
        .map_err(|err| {
            CliError::cli_other_error(format!(
                "HttpEgressContract rejects {field_name} `{url}`: {err}"
            ))
        })?;
    response.json::<T>().await.map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse JSON from {field_name} `{}`: {error}",
            url
        ))
    })
}

fn resolve_identity_provider_discovery_url(
    config: &RemoteServeHttpConfig,
) -> Result<Option<Url>, CliError> {
    if let Some(discovery_url) = config.auth_jwt_discovery_url.as_deref() {
        return parse_identity_provider_url(discovery_url, "--auth-jwt-discovery-url").map(Some);
    }
    if config.auth_jwt_provider_profile.is_some() {
        let issuer = config.auth_jwt_issuer.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "--auth-jwt-provider-profile requires --auth-jwt-issuer or --auth-jwt-discovery-url"
                    .to_string(),
            )
        })?;
        return derive_oidc_discovery_url_from_issuer(issuer).map(Some);
    }
    Ok(None)
}

async fn resolve_jwks_key_set(
    jwks_uri: &Url,
    field_name: &str,
    egress_contract: Option<&HttpEgressContract>,
) -> Result<JwtJwksKeySet, CliError> {
    let document: JwksDocument =
        fetch_identity_provider_json(jwks_uri, field_name, egress_contract).await?;
    let mut keys_by_kid = HashMap::new();
    let mut anonymous_keys = Vec::new();
    for key in document.keys {
        let kid = key.kid.clone();
        let alg_hint = key.alg.clone();
        if let Some(key_use) = key.key_use.as_deref() {
            if key_use != "sig" {
                continue;
            }
        }
        let Some(resolved_key) =
            resolve_jwk_public_key(key, jwks_uri, field_name, alg_hint.clone())?
        else {
            continue;
        };
        if let Some(kid) = kid {
            keys_by_kid.insert(kid, resolved_key);
        } else {
            anonymous_keys.push(resolved_key);
        }
    }
    if keys_by_kid.is_empty() && anonymous_keys.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{field_name} `{}` did not expose any supported signing keys",
            jwks_uri
        )));
    }
    Ok(JwtJwksKeySet {
        keys_by_kid,
        anonymous_keys,
    })
}

fn decode_jwk_component(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<Vec<u8>, CliError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to decode {component_name} from {field_name} `{}`: {error}",
            jwks_uri
        ))
    })
}

fn decode_fixed_jwk_component<const N: usize>(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<[u8; N], CliError> {
    let bytes = decode_jwk_component(value, component_name, jwks_uri, field_name)?;
    if bytes.len() != N {
        return Err(CliError::cli_other_error(format!(
            "{component_name} from {field_name} `{}` had invalid length {}, expected {}",
            jwks_uri,
            bytes.len(),
            N
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_jwk_public_key(
    key: JwkDocumentKey,
    jwks_uri: &Url,
    field_name: &str,
    alg_hint: Option<String>,
) -> Result<Option<JwtResolvedJwkPublicKey>, CliError> {
    let resolved = match key.kty.as_str() {
        "OKP" if key.crv.as_deref() == Some("Ed25519") => {
            let Some(x) = key.x.as_deref() else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            JwtResolvedPublicKey::Ed25519(PublicKey::from_bytes(&x)?)
        }
        "EC" if key.crv.as_deref() == Some("P-256") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<32>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 65];
            encoded[0] = 0x04;
            encoded[1..33].copy_from_slice(&x);
            encoded[33..65].copy_from_slice(&y);
            JwtResolvedPublicKey::P256(P256VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "failed to parse P-256 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "EC" if key.crv.as_deref() == Some("P-384") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<48>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<48>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 97];
            encoded[0] = 0x04;
            encoded[1..49].copy_from_slice(&x);
            encoded[49..97].copy_from_slice(&y);
            JwtResolvedPublicKey::P384(P384VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "failed to parse P-384 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "RSA" => {
            let (Some(n), Some(e)) = (key.n.as_deref(), key.e.as_deref()) else {
                return Ok(None);
            };
            let modulus =
                BigUint::from_bytes_be(&decode_jwk_component(n, "n", jwks_uri, field_name)?);
            let exponent =
                BigUint::from_bytes_be(&decode_jwk_component(e, "e", jwks_uri, field_name)?);
            JwtResolvedPublicKey::Rsa(JwtRsaPublicKey::new(modulus, exponent).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to parse RSA JWK from {field_name} `{}`: {error}",
                    jwks_uri
                ))
            })?)
        }
        _ => return Ok(None),
    };
    Ok(Some(JwtResolvedJwkPublicKey {
        key: resolved,
        alg_hint,
    }))
}

async fn resolve_discovered_identity_provider(
    config: &RemoteServeHttpConfig,
) -> Result<Option<DiscoveredIdentityProvider>, CliError> {
    let Some(discovery_url) = resolve_identity_provider_discovery_url(config)? else {
        return Ok(None);
    };
    let egress_contract = config.egress_contract.as_ref();
    let document: OidcDiscoveryDocument = fetch_identity_provider_json(
        &discovery_url,
        "--auth-jwt-discovery-url",
        egress_contract,
    )
    .await?;
    let issuer_url = parse_identity_provider_url(&document.issuer, "discovered OIDC issuer")?;
    let issuer = canonicalize_federated_issuer(issuer_url.as_str());
    if let Some(expected_issuer) = config.auth_jwt_issuer.as_deref() {
        if canonicalize_federated_issuer(expected_issuer) != issuer {
            return Err(CliError::cli_other_error(format!(
                "OIDC discovery issuer `{issuer}` did not match configured --auth-jwt-issuer `{expected_issuer}`"
            )));
        }
    }

    let authorization_endpoint = document.authorization_endpoint;
    let token_endpoint = document.token_endpoint;
    let registration_endpoint = document.registration_endpoint;
    let jwks_uri = match document.jwks_uri {
        Some(uri) => Some(parse_identity_provider_url(
            &uri,
            "discovered OIDC jwks_uri",
        )?),
        None => None,
    };
    let jwks_keys = if config.auth_jwt_public_key.is_none()
        && config.auth_server_seed_path.is_none()
        && config.auth_introspection_url.is_none()
    {
        let jwks_uri = jwks_uri.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "OIDC discovery metadata did not include `jwks_uri` for JWT verification"
                    .to_string(),
            )
        })?;
        Some(resolve_jwks_key_set(
            jwks_uri,
            "discovered OIDC jwks_uri",
            egress_contract,
        )
        .await?)
    } else {
        None
    };

    Ok(Some(DiscoveredIdentityProvider {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: jwks_uri.map(|url| url.to_string()),
        jwks_keys,
    }))
}

fn build_federated_principal(
    claims: &JwtClaims,
    expected_issuer: Option<&str>,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    provider_profile: JwtProviderProfile,
) -> Result<String, Response> {
    let issuer = claims
        .iss
        .as_deref()
        .or(expected_issuer)
        .map(canonicalize_federated_issuer)
        .ok_or_else(|| {
            unauthorized_bearer_response(
                "JWT bearer token missing issuer for identity federation",
                protected_resource_metadata,
            )
        })?;

    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if let Some(object_id) = claims.oid.as_deref() {
                return Ok(format!("oidc:{issuer}#oid:{object_id}"));
            }
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims
                .azp
                .as_deref()
                .or(claims.appid.as_deref())
                .or(claims.client_id.as_deref())
            {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing oid, subject, and client claims for Azure AD identity federation",
                protected_resource_metadata,
            ))
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims.client_id.as_deref() {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing subject and client_id for identity federation",
                protected_resource_metadata,
            ))
        }
    }
}

fn build_federated_claims(
    claims: &JwtClaims,
    _provider_profile: JwtProviderProfile,
) -> OAuthBearerFederatedClaims {
    OAuthBearerFederatedClaims {
        client_id: claims
            .client_id
            .clone()
            .or_else(|| claims.azp.clone())
            .or_else(|| claims.appid.clone()),
        object_id: claims.oid.clone(),
        tenant_id: claims.tid.clone().or_else(|| claims.tenant_id.clone()),
        organization_id: claims
            .org_id
            .clone()
            .or_else(|| claims.organization_id.clone()),
        groups: normalize_claim_list(&claims.groups),
        roles: normalize_claim_list(&claims.roles),
    }
}

fn matched_bearer_enterprise_provider<'a>(
    registry: Option<&'a EnterpriseProviderRegistry>,
    issuer: Option<&str>,
    kind: EnterpriseProviderKind,
) -> Option<&'a EnterpriseProviderRecord> {
    let issuer = issuer.map(canonicalize_federated_issuer)?;
    registry?.providers.values().find(|record| {
        record.kind == kind
            && record.is_validated_enabled()
            && record
                .issuer
                .as_deref()
                .map(canonicalize_federated_issuer)
                .as_deref()
                == Some(issuer.as_str())
    })
}

fn derive_enterprise_subject_key(provider_scope: &str, canonical_principal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([1u8]);
    hasher.update(provider_scope.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical_principal.as_bytes());
    let digest = hasher.finalize();
    sha256_hex(digest.as_slice())
}

fn build_enterprise_identity_context(
    claims: &JwtClaims,
    federated_claims: &OAuthBearerFederatedClaims,
    principal: &str,
    provider_profile: JwtProviderProfile,
    provider_kind: EnterpriseProviderKind,
    matched_provider: Option<&EnterpriseProviderRecord>,
) -> EnterpriseIdentityContext {
    let issuer = claims
        .iss
        .as_deref()
        .map(canonicalize_federated_issuer)
        .unwrap_or_default();
    let provider_id = matched_provider
        .map(|provider| provider.provider_id.clone())
        .unwrap_or_else(|| issuer.clone());
    let mut attribute_sources = BTreeMap::new();

    if let Some(source) = matched_provider
        .map(|provider| provider.subject_mapping.principal_source.trim())
        .filter(|source| !source.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| bearer_principal_source_field(claims, provider_profile).map(ToOwned::to_owned))
    {
        attribute_sources.insert("principal".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.client_id_field.clone())
        .or_else(|| bearer_client_id_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("clientId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.object_id_field.clone())
        .or_else(|| claims.oid.as_ref().map(|_| "oid".to_string()))
    {
        attribute_sources.insert("objectId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.tenant_id_field.clone())
        .or_else(|| bearer_tenant_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("tenantId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.organization_id_field.clone())
        .or_else(|| bearer_organization_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("organizationId".to_string(), source);
    }
    if !federated_claims.groups.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.groups_field.clone())
            .unwrap_or_else(|| "groups".to_string());
        attribute_sources.insert("groups".to_string(), source);
    }
    if !federated_claims.roles.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.roles_field.clone())
            .unwrap_or_else(|| "roles".to_string());
        attribute_sources.insert("roles".to_string(), source);
    }

    EnterpriseIdentityContext {
        provider_id: provider_id.clone(),
        provider_record_id: matched_provider.map(|provider| provider.provider_id.clone()),
        provider_kind: enterprise_provider_kind_name(&provider_kind).to_string(),
        federation_method: enterprise_federation_method(&provider_kind),
        principal: principal.to_string(),
        subject_key: derive_enterprise_subject_key(&provider_id, principal),
        client_id: federated_claims.client_id.clone(),
        object_id: federated_claims.object_id.clone(),
        tenant_id: federated_claims.tenant_id.clone(),
        organization_id: federated_claims.organization_id.clone(),
        groups: federated_claims.groups.clone(),
        roles: federated_claims.roles.clone(),
        source_subject: claims.sub.clone(),
        attribute_sources,
        trust_material_ref: matched_provider
            .and_then(|provider| provider.provenance.trust_material_ref.clone()),
    }
}

fn enterprise_provider_kind_name(kind: &EnterpriseProviderKind) -> &'static str {
    match kind {
        EnterpriseProviderKind::OidcJwks => "oidc_jwks",
        EnterpriseProviderKind::OauthIntrospection => "oauth_introspection",
        EnterpriseProviderKind::Scim => "scim",
        EnterpriseProviderKind::Saml => "saml",
    }
}

fn enterprise_federation_method(kind: &EnterpriseProviderKind) -> EnterpriseFederationMethod {
    match kind {
        EnterpriseProviderKind::OidcJwks => EnterpriseFederationMethod::Jwt,
        EnterpriseProviderKind::OauthIntrospection => EnterpriseFederationMethod::Introspection,
        EnterpriseProviderKind::Scim => EnterpriseFederationMethod::Scim,
        EnterpriseProviderKind::Saml => EnterpriseFederationMethod::Saml,
    }
}

fn bearer_principal_source_field(
    claims: &JwtClaims,
    provider_profile: JwtProviderProfile,
) -> Option<&'static str> {
    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if claims.oid.is_some() {
                Some("oid")
            } else if claims.sub.is_some() {
                Some("sub")
            } else if claims.azp.is_some() {
                Some("azp")
            } else if claims.appid.is_some() {
                Some("appid")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if claims.sub.is_some() {
                Some("sub")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
    }
}

fn bearer_client_id_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.client_id.is_some() {
        Some("client_id")
    } else if claims.azp.is_some() {
        Some("azp")
    } else if claims.appid.is_some() {
        Some("appid")
    } else {
        None
    }
}

fn bearer_tenant_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.tid.is_some() {
        Some("tid")
    } else if claims.tenant_id.is_some() {
        Some("tenant_id")
    } else {
        None
    }
}

fn bearer_organization_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.org_id.is_some() {
        Some("org_id")
    } else if claims.organization_id.is_some() {
        Some("organization_id")
    } else {
        None
    }
}

fn normalize_claim_list(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn deserialize_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringVecOrString {
        String(String),
        Strings(Vec<String>),
    }

    let raw = Option::<StringVecOrString>::deserialize(deserializer)?;
    Ok(match raw {
        None => Vec::new(),
        Some(StringVecOrString::String(value)) => vec![value],
        Some(StringVecOrString::Strings(values)) => values,
    })
}

fn derive_federated_agent_keypair(
    seed_path: &FsPath,
    federated_principal: &str,
) -> Result<Keypair, CliError> {
    let master_key = load_or_create_authority_keypair(seed_path)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([0u8]);
    hasher.update(master_key.seed_bytes());
    hasher.update([0u8]);
    hasher.update(federated_principal.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    Ok(Keypair::from_seed(&seed))
}

#[derive(Serialize)]
struct RemoteAuthContractFingerprint {
    mode: &'static str,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: String,
    static_token_fingerprint: Option<String>,
    verification_key_identity: Option<String>,
    discovery_url: Option<String>,
    introspection_url: Option<String>,
    enterprise_provider_registry_hash: Option<String>,
}

fn enterprise_provider_registry_hash(path: Option<&FsPath>) -> Result<Option<String>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = std::fs::read(path)?;
    Ok(Some(sha256_hex(&bytes)))
}

fn fingerprint_remote_auth_contract(config: &RemoteServeHttpConfig) -> Result<String, CliError> {
    let provider_profile = config
        .auth_jwt_provider_profile
        .unwrap_or(JwtProviderProfile::Generic);
    let enterprise_provider_registry_hash =
        enterprise_provider_registry_hash(config.enterprise_providers_file.as_deref())?;
    let fingerprint = if let Some(token) = config.auth_token.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "static_bearer",
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: Some(sha256_hex(token.as_bytes())),
            verification_key_identity: None,
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    } else if let Some(seed_path) = config.auth_server_seed_path.as_deref() {
        let verification_key_identity = authority_public_key_from_seed_file(seed_path)?
            .map(|public_key| public_key.to_hex())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "auth server seed file `{}` did not yield a public key",
                    seed_path.display()
                ))
            })?;
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: Some(verification_key_identity),
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    } else if let Some(introspection_url) = config.auth_introspection_url.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "introspection_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: None,
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: Some(introspection_url.to_string()),
            enterprise_provider_registry_hash,
        }
    } else {
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: config.auth_jwt_public_key.clone(),
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: None,
            enterprise_provider_registry_hash,
        }
    };

    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        CliError::cli_other_error(format!("serialize auth contract fingerprint: {error}"))
    })?;
    Ok(sha256_hex(&encoded))
}

fn fingerprint_remote_policy_contract(loaded_policy: &LoadedPolicy) -> Result<String, CliError> {
    let fingerprint = json!({
        "format": loaded_policy.format_name(),
        "identity": {
            "source_hash": loaded_policy.identity.source_hash,
            "runtime_hash": loaded_policy.identity.runtime_hash,
        },
        "default_capabilities": loaded_policy.default_capabilities,
        "issuance_policy": loaded_policy.issuance_policy,
        "runtime_assurance_policy": loaded_policy.runtime_assurance_policy,
    });
    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        CliError::cli_other_error(format!(
            "serialize resumable policy contract fingerprint: {error}"
        ))
    })?;
    Ok(sha256_hex(&encoded))
}

fn derive_session_agent_keypair(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Keypair, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(Keypair::generate());
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => derive_federated_agent_keypair(seed_path, principal),
        _ => Ok(Keypair::generate()),
    }
}

#[derive(Serialize)]
struct RemoteSessionResumeIntegrityEnvelope<'a> {
    session_id: &'a str,
    agent_id: &'a str,
    auth_context: &'a SessionAuthContext,
    auth_mode_fingerprint: Option<&'a str>,
    policy_fingerprint: Option<&'a str>,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle: &'a RemoteSessionLifecycleSnapshot,
    protocol_version: Option<&'a str>,
    initialize_params: &'a Value,
    issued_capabilities: &'a [CapabilityToken],
}

fn derive_resume_integrity_seed_from_secret(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REMOTE_SESSION_RESUME_INTEGRITY_LABEL);
    hasher.update([0u8]);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn derive_resume_record_integrity_seed(
    config: &RemoteServeHttpConfig,
) -> Result<Option<[u8; 32]>, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let authority = chio_store_sqlite::SqliteCapabilityAuthority::open(path)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let keypair = authority
            .local_keypair()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        return Ok(Some(keypair.seed_bytes()));
    }
    if let Some(seed_path) = [
        config.authority_seed_path.as_deref(),
        config.auth_server_seed_path.as_deref(),
        config.identity_federation_seed_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    .next()
    {
        let keypair = load_or_create_authority_keypair(seed_path)?;
        return Ok(Some(keypair.seed_bytes()));
    }
    if let Some(secret) = config.control_token.as_deref() {
        return Ok(Some(derive_resume_integrity_seed_from_secret(
            secret.as_bytes(),
        )));
    }
    if let Some(secret) = config.auth_token.as_deref() {
        return Ok(Some(derive_resume_integrity_seed_from_secret(
            secret.as_bytes(),
        )));
    }
    Ok(None)
}

fn expected_resume_agent_id(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Option<String>, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(None);
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => Ok(Some(
            derive_federated_agent_keypair(seed_path, principal)?
                .public_key()
                .to_hex(),
        )),
        _ => Ok(None),
    }
}

fn compute_resume_record_integrity_tag(
    seed: &[u8; 32],
    record: &RemoteSessionResumeRecord,
) -> Result<String, CliError> {
    let envelope = RemoteSessionResumeIntegrityEnvelope {
        session_id: &record.session_id,
        agent_id: &record.agent_id,
        auth_context: &record.auth_context,
        auth_mode_fingerprint: record.auth_mode_fingerprint.as_deref(),
        policy_fingerprint: record.policy_fingerprint.as_deref(),
        hosted_isolation: record.hosted_isolation,
        lifecycle: &record.lifecycle,
        protocol_version: record.protocol_version.as_deref(),
        initialize_params: &record.initialize_params,
        issued_capabilities: &record.issued_capabilities,
    };
    let canonical = canonical_json_bytes(&envelope)
        .map_err(|error| CliError::cli_other_error(format!("serialize resumable session envelope: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(REMOTE_SESSION_RESUME_INTEGRITY_LABEL);
    hasher.update([0u8]);
    hasher.update(seed);
    hasher.update([0u8]);
    hasher.update(&canonical);
    Ok(sha256_hex(&hasher.finalize()))
}

fn validate_resume_record_integrity(
    config: &RemoteServeHttpConfig,
    record: &RemoteSessionResumeRecord,
) -> Result<(), CliError> {
    let Some(stored_tag) = record.resume_integrity_tag.as_deref() else {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} predates resumable integrity binding and must be re-initialized",
            record.session_id
        )));
    };
    let Some(seed) = derive_resume_record_integrity_seed(config)? else {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} cannot be restored because this server has no local secret material for resumable session integrity",
            record.session_id
        )));
    };
    let expected_tag = compute_resume_record_integrity_tag(&seed, record)?;
    if stored_tag != expected_tag {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} failed resumable integrity validation",
            record.session_id
        )));
    }
    Ok(())
}

fn validate_restored_peer_capabilities(
    record: &RemoteSessionResumeRecord,
) -> Result<PeerCapabilities, CliError> {
    let derived = parse_remote_session_peer_capabilities(&record.initialize_params);
    if derived != record.peer_capabilities {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} failed peer capability re-validation against initialize params",
            record.session_id
        )));
    }
    Ok(derived)
}

impl SharedUpstreamToolServer {
    fn new(upstream: Arc<AdaptedMcpServer>) -> Self {
        let manifest = upstream.manifest_clone();
        Self {
            server_id: manifest.server_id,
            tool_names: manifest
                .tools
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            upstream,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SharedUpstreamToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tool_names.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        ToolServerConnection::invoke(
            self.upstream.as_ref(),
            tool_name,
            arguments,
            nested_flow_bridge,
        )
        .await
    }
}

impl SharedUpstreamOwner {
    fn new(config: &RemoteServeHttpConfig) -> Result<Self, CliError> {
        let wrapped_arg_refs = config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let notification_source: Arc<dyn McpTransport> = Arc::new(StdioMcpTransport::spawn(
            &config.wrapped_command,
            &wrapped_arg_refs,
        )?);
        let adapter = McpAdapter::new(
            McpAdapterConfig {
                server_id: config.server_id.clone(),
                server_name: config.server_name.clone(),
                server_version: config.server_version.clone(),
                public_key: manifest_public_key,
            },
            Box::new(SerializedMcpTransport::from_arc(
                notification_source.clone(),
            )),
        );
        let upstream_server = Arc::new(AdaptedMcpServer::new(adapter)?);
        let notification_subscribers =
            Arc::new(StdMutex::new(Vec::<Weak<StdMutex<VecDeque<Value>>>>::new()));
        let notification_stats = Arc::new(SharedUpstreamNotificationStats::default());
        let notification_source_for_thread = notification_source.clone();
        let notification_subscribers_for_thread = notification_subscribers.clone();
        let notification_stats_for_thread = notification_stats.clone();
        thread::spawn(move || loop {
            let notifications = notification_source_for_thread.drain_notifications();
            fan_out_shared_upstream_notifications(
                &notification_subscribers_for_thread,
                notification_stats_for_thread.as_ref(),
                notifications,
            );
            thread::sleep(Duration::from_millis(
                DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS,
            ));
        });

        Ok(Self {
            upstream_server,
            notification_subscribers,
            notification_stats,
        })
    }

    fn upstream_server(&self) -> Arc<AdaptedMcpServer> {
        self.upstream_server.clone()
    }

    fn notification_tap(&self) -> Arc<dyn McpTransport> {
        let queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut subscribers) = self.notification_subscribers.lock() {
            subscribers.push(Arc::downgrade(&queue));
        }
        Arc::new(SharedUpstreamNotificationTap { queue })
    }

    fn notification_stats_snapshot(&self) -> SharedUpstreamNotificationStatsSnapshot {
        SharedUpstreamNotificationStatsSnapshot {
            fanout_batches: self.notification_stats.fanout_batches.load(Ordering::Relaxed),
            fanout_notifications: self
                .notification_stats
                .fanout_notifications
                .load(Ordering::Relaxed),
            fanout_targets: self
                .notification_stats
                .fanout_targets
                .load(Ordering::Relaxed),
            pruned_subscribers: self
                .notification_stats
                .pruned_subscribers
                .load(Ordering::Relaxed),
            queue_lock_skips: self
                .notification_stats
                .queue_lock_skips
                .load(Ordering::Relaxed),
            subscriber_lock_failures: self
                .notification_stats
                .subscriber_lock_failures
                .load(Ordering::Relaxed),
        }
    }
}

impl McpTransport for SharedUpstreamNotificationTap {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::McpToolInfo>, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn drain_notifications(&self) -> Vec<Value> {
        let Ok(mut queue) = self.queue.lock() else {
            return vec![];
        };
        queue.drain(..).collect()
    }
}

fn fan_out_shared_upstream_notifications(
    subscribers: &NotificationSubscriberList,
    stats: &SharedUpstreamNotificationStats,
    notifications: Vec<Value>,
) {
    if notifications.is_empty() {
        return;
    }
    stats.fanout_batches.fetch_add(1, Ordering::Relaxed);
    stats
        .fanout_notifications
        .fetch_add(notifications.len() as u64, Ordering::Relaxed);
    let Ok(mut subscribers) = subscribers.lock() else {
        stats
            .subscriber_lock_failures
            .fetch_add(1, Ordering::Relaxed);
        warn!("failed to lock shared hosted-owner notification subscribers");
        return;
    };
    let before_prune = subscribers.len();
    subscribers.retain(|subscriber| subscriber.strong_count() > 0);
    let pruned = before_prune.saturating_sub(subscribers.len());
    if pruned > 0 {
        stats
            .pruned_subscribers
            .fetch_add(pruned as u64, Ordering::Relaxed);
    }
    // Shared hosted-owner mode multiplexes one upstream subprocess across many
    // sessions. Each session-local ChioMcpEdge still applies its own resource
    // subscription and elicitation filtering before surfacing client-visible
    // notifications, so the shared tap can safely replay raw upstream
    // notifications into every live session queue.
    for subscriber in subscribers.iter() {
        let Some(queue) = subscriber.upgrade() else {
            continue;
        };
        let Ok(mut queue) = queue.lock() else {
            stats
                .queue_lock_skips
                .fetch_add(notifications.len() as u64, Ordering::Relaxed);
            warn!("failed to lock shared hosted-owner notification tap queue");
            continue;
        };
        stats.fanout_targets.fetch_add(1, Ordering::Relaxed);
        queue.extend(notifications.iter().cloned());
    }
}

#[derive(Debug, Default, Deserialize)]
struct AdminToolReceiptQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    tool_server: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminChildReceiptQuery {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    parent_request_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    operation_kind: Option<String>,
    #[serde(default)]
    terminal_state: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminRevocationQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminBudgetQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AdminRevokeCapabilityRequest {
    capability_id: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    chio_transaction_context: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    chio_sender_attestation_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationApprovalForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    chio_transaction_context: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    chio_sender_attestation_sha256: Option<String>,
    decision: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequestForm {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
}

impl RemoteSession {
    fn new(init: RemoteSessionInit) -> Self {
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

    fn send(&self, message: Value) -> Result<(), CliError> {
        self.input_tx
            .send(message)
            .map_err(|_| CliError::cli_other_error("remote MCP session worker is unavailable".to_string()))
    }

    fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.event_tx.subscribe()
    }

    fn next_stream_event_id(&self) -> String {
        let next = self.next_event_id.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{}-{next}", self.session_id)
    }

    fn has_active_notification_stream(&self) -> bool {
        self.notification_stream_attached.load(Ordering::SeqCst)
    }

    fn has_active_request_stream(&self) -> bool {
        self.active_request_stream.try_lock().is_err()
    }

    fn try_attach_notification_stream(&self) -> bool {
        self.notification_stream_attached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn detach_notification_stream(&self) {
        self.notification_stream_attached
            .store(false, Ordering::SeqCst);
    }

    fn replay_notifications_after(
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

    fn protocol_version(&self) -> Option<String> {
        self.protocol_version
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn set_protocol_version(&self, protocol_version: Option<String>) {
        if let Ok(mut guard) = self.protocol_version.lock() {
            *guard = protocol_version;
        }
    }

    fn set_initialize_contract(
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

    fn lifecycle_snapshot(&self) -> RemoteSessionLifecycleSnapshot {
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

    fn resume_record(&self) -> Option<RemoteSessionResumeRecord> {
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

    fn persist_resumable_record(&self) {
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

    fn remove_resumable_record(&self) -> Result<(), CliError> {
        let Some(path) = self.session_db_path.as_deref() else {
            return Ok(());
        };
        delete_active_session_record(path, &self.session_id)
    }

    fn mark_ready(
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

    fn touch(&self) {
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

    fn begin_draining(&self) -> Result<(), CliError> {
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

    fn mark_deleted(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Deleted;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn mark_expired(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Expired;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn mark_closed(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Closed;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn auth_context(&self) -> &SessionAuthContext {
        &self.auth_context
    }

    fn diagnostic_record(&self) -> RemoteSessionDiagnosticRecord {
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

    fn ownership_snapshot(&self) -> RemoteSessionOwnershipSnapshot {
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

struct BroadcastJsonRpcWriter {
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    next_event_id: Arc<AtomicU64>,
    session_id: String,
    buffer: Vec<u8>,
}

impl BroadcastJsonRpcWriter {
    fn new(
        event_tx: broadcast::Sender<RemoteSessionEvent>,
        retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
        next_event_id: Arc<AtomicU64>,
        session_id: String,
    ) -> Self {
        Self {
            event_tx,
            retained_notification_events,
            next_event_id,
            session_id,
            buffer: Vec::new(),
        }
    }

    fn next_event(&self, message: Value) -> RemoteSessionEvent {
        let next = self.next_event_id.fetch_add(1, Ordering::SeqCst) + 1;
        let event_id = format!("{}-{next}", self.session_id);
        let kind = classify_remote_session_event(&message);
        if kind == RemoteSessionEventKind::Notification {
            if let Ok(mut retained) = self.retained_notification_events.lock() {
                retained.push_back(RetainedRemoteSessionEvent {
                    seq: next,
                    event_id: event_id.clone(),
                    message: message.clone(),
                });
                while retained.len() > DEFAULT_NOTIFICATION_REPLAY_WINDOW {
                    retained.pop_front();
                }
            }
        }

        RemoteSessionEvent {
            seq: next,
            event_id,
            kind,
            message,
        }
    }

    fn flush_complete_lines(&mut self) -> io::Result<()> {
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=position).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }

            let message: Value = serde_json::from_slice(&line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse JSON-RPC output from edge worker: {error}"),
                )
            })?;
            let _ = self.event_tx.send(self.next_event(message));
        }

        Ok(())
    }
}

impl Write for BroadcastJsonRpcWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.flush_complete_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_complete_lines()
    }
}

impl RemoteSessionFactory {
    fn new(config: RemoteServeHttpConfig) -> Self {
        Self {
            config,
            shared_upstream_owner: Arc::new(StdMutex::new(None)),
            lifecycle_policy: read_session_lifecycle_policy(),
        }
    }

    fn build_session_upstream_server(&self) -> Result<Arc<AdaptedMcpServer>, CliError> {
        let wrapped_arg_refs = self
            .config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = self
            .config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let adapted_server = AdaptedMcpServer::from_command(
            &self.config.wrapped_command,
            &wrapped_arg_refs,
            McpAdapterConfig {
                server_id: self.config.server_id.clone(),
                server_name: self.config.server_name.clone(),
                server_version: self.config.server_version.clone(),
                public_key: manifest_public_key,
            },
        )?;

        Ok(Arc::new(adapted_server))
    }

    fn shared_upstream_owner(&self) -> Result<Arc<SharedUpstreamOwner>, CliError> {
        let mut guard = self.shared_upstream_owner.lock().map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to lock shared remote MCP upstream owner cache: {error}"
            ))
        })?;
        if let Some(owner) = guard.as_ref() {
            return Ok(owner.clone());
        }

        let owner = Arc::new(SharedUpstreamOwner::new(&self.config)?);
        info!(
            server_id = %self.config.server_id,
            "created shared remote MCP hosted owner"
        );
        *guard = Some(owner.clone());
        Ok(owner)
    }

    fn configured_hosted_isolation(&self) -> RemoteHostedIsolationMode {
        if self.config.shared_hosted_owner {
            RemoteHostedIsolationMode::SharedHostedOwnerCompatibility
        } else {
            RemoteHostedIsolationMode::DedicatedPerSession
        }
    }

    fn spawn_session(
        &self,
        auth_context: SessionAuthContext,
    ) -> Result<Arc<RemoteSession>, CliError> {
        let loaded_policy = load_policy(&self.config.policy_path)?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(&self.config)?;
        let policy_fingerprint = fingerprint_remote_policy_contract(&loaded_policy)?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        let resume_integrity_secret = derive_resume_record_integrity_seed(&self.config)?;
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let upstream_capabilities = upstream_server.upstream_capabilities();
        let manifest = upstream_server.manifest_clone();

        let kernel_kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kernel_kp);
        configure_receipt_store(
            &mut kernel,
            self.config.receipt_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_revocation_store(
            &mut kernel,
            self.config.revocation_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_capability_authority(
            &mut kernel,
            &kernel_kp,
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
            self.config.receipt_db_path.as_deref(),
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
            issuance_policy,
            runtime_assurance_policy,
        )?;
        configure_budget_store(
            &mut kernel,
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if let Some(resource_provider) = upstream_server.resource_provider() {
            kernel.register_resource_provider(Box::new(resource_provider));
        }
        if let Some(prompt_provider) = upstream_server.prompt_provider() {
            kernel.register_prompt_provider(Box::new(prompt_provider));
        }
        kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
            upstream_server.clone(),
        )));

        let hosted_isolation = self.configured_hosted_isolation();
        let session_auth_context = hosted_isolation.snapshot_auth_context(auth_context);

        let agent_kp = derive_session_agent_keypair(&self.config, &session_auth_context)?;
        let agent_pk = agent_kp.public_key();
        let agent_id = agent_pk.to_hex();
        let capabilities: Vec<CapabilityToken> =
            issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
        let session_capabilities = capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect();

        let mut edge = ChioMcpEdge::new(
            McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            },
            kernel,
            agent_id.clone(),
            capabilities.clone(),
            vec![manifest],
        )?;
        edge.set_session_auth_context(session_auth_context.clone());
        edge.attach_upstream_transport(upstream_notification_source);

        let (input_tx, input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
        let session_id = Keypair::generate().public_key().to_hex();
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let writer = BroadcastJsonRpcWriter::new(
            event_tx.clone(),
            retained_notification_events.clone(),
            next_event_id.clone(),
            session_id.clone(),
        );

        std::thread::spawn(move || {
            if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                error!(error = %error, "remote MCP edge session worker exited with error");
            }
        });

        Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
            session_id,
            agent_id,
            capabilities: session_capabilities,
            issued_capabilities: capabilities,
            auth_context: session_auth_context,
            auth_mode_fingerprint,
            policy_fingerprint,
            hosted_isolation,
            lifecycle_policy: self.lifecycle_policy.clone(),
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: None,
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: self.config.session_db_path.clone(),
            resume_integrity_secret,
        })))
    }

    fn restore_session(
        &self,
        record: &RemoteSessionResumeRecord,
    ) -> Result<Arc<RemoteSession>, CliError> {
        validate_resume_record_integrity(&self.config, record)?;
        let configured_hosted_isolation = self.configured_hosted_isolation();
        if configured_hosted_isolation != record.hosted_isolation {
            return Err(CliError::cli_other_error(format!(
                "stored MCP session {} expects hosted isolation {:?} but the server is configured for {:?}",
                record.session_id, record.hosted_isolation, configured_hosted_isolation
            )));
        }
        if let Some(expected_agent_id) =
            expected_resume_agent_id(&self.config, &record.auth_context)?
        {
            if expected_agent_id != record.agent_id {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} failed authenticated principal re-validation during restore",
                    record.session_id
                )));
            }
        }

        let loaded_policy = load_policy(&self.config.policy_path)?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(&self.config)?;
        let policy_fingerprint = fingerprint_remote_policy_contract(&loaded_policy)?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        let resume_integrity_secret = derive_resume_record_integrity_seed(&self.config)?;
        match record.auth_mode_fingerprint.as_deref() {
            Some(stored) if stored == auth_mode_fingerprint => {}
            Some(_) => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} was created under different serve-http auth settings",
                    record.session_id
                )));
            }
            None => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} predates auth contract fingerprinting and must be re-initialized",
                    record.session_id
                )));
            }
        }
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let upstream_capabilities = upstream_server.upstream_capabilities();
        let manifest = upstream_server.manifest_clone();

        let kernel_kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kernel_kp);
        configure_receipt_store(
            &mut kernel,
            self.config.receipt_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_revocation_store(
            &mut kernel,
            self.config.revocation_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_capability_authority(
            &mut kernel,
            &kernel_kp,
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
            self.config.receipt_db_path.as_deref(),
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
            issuance_policy,
            runtime_assurance_policy,
        )?;
        configure_budget_store(
            &mut kernel,
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if let Some(resource_provider) = upstream_server.resource_provider() {
            kernel.register_resource_provider(Box::new(resource_provider));
        }
        if let Some(prompt_provider) = upstream_server.prompt_provider() {
            kernel.register_prompt_provider(Box::new(prompt_provider));
        }
        kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
            upstream_server.clone(),
        )));

        let agent_public_key = PublicKey::from_hex(&record.agent_id)?;
        let restored_peer_capabilities = validate_restored_peer_capabilities(record)?;
        let issued_capabilities = match record.policy_fingerprint.as_deref() {
            Some(stored)
                if stored == policy_fingerprint
                    && stored_capabilities_are_current(&record.issued_capabilities)
                    && stored_capability_issuers_are_trusted(&kernel, &record.issued_capabilities)
                    && record
                        .issued_capabilities
                        .iter()
                        .all(|capability| capability.subject == agent_public_key) =>
            {
                record.issued_capabilities.clone()
            }
            _ => issue_default_capabilities(&kernel, &agent_public_key, &default_capabilities)?,
        };
        let session_capabilities = issued_capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect::<Vec<_>>();

        let mut edge = ChioMcpEdge::new(
            McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            },
            kernel,
            record.agent_id.clone(),
            issued_capabilities.clone(),
            vec![manifest],
        )?;
        edge.set_session_auth_context(record.auth_context.clone());
        edge.attach_upstream_transport(upstream_notification_source);
        edge.restore_ready_session(
            restored_kernel_session_id(&record.session_id),
            restored_peer_capabilities.clone(),
        )?;

        let (input_tx, input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let writer = BroadcastJsonRpcWriter::new(
            event_tx.clone(),
            retained_notification_events.clone(),
            next_event_id.clone(),
            record.session_id.clone(),
        );

        std::thread::spawn(move || {
            if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                error!(error = %error, "remote MCP edge session worker exited with error");
            }
        });

        Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
            session_id: record.session_id.clone(),
            agent_id: record.agent_id.clone(),
            capabilities: session_capabilities,
            issued_capabilities,
            auth_context: record.auth_context.clone(),
            auth_mode_fingerprint,
            policy_fingerprint,
            hosted_isolation: record.hosted_isolation,
            lifecycle_policy: self.lifecycle_policy.clone(),
            protocol_version: record.protocol_version.clone(),
            peer_capabilities: Some(restored_peer_capabilities),
            initialize_params: Some(record.initialize_params.clone()),
            lifecycle_snapshot: Some(record.lifecycle.clone()),
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: self.config.session_db_path.clone(),
            resume_integrity_secret,
        })))
    }
}

impl RemoteSessionLedger {
    fn new(
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

    async fn insert_active(&self, session: Arc<RemoteSession>) {
        self.active
            .lock()
            .await
            .insert(session.session_id.clone(), session);
    }

    async fn remove_active(&self, session_id: &str) -> Option<Arc<RemoteSession>> {
        self.active.lock().await.remove(session_id)
    }

    async fn lookup(&self, session_id: &str) -> Option<RemoteSessionEntry> {
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

    async fn snapshot(
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

    async fn mark_deleted(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Deleted)
            .await
    }

    async fn mark_draining(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        session.begin_draining()
    }

    async fn mark_closed(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Closed)
            .await
    }

    async fn mark_expired(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Expired)
            .await
    }

    async fn cleanup_due_sessions(&self) {
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

    async fn transition_to_terminal(
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

    async fn purge_old_terminal_records(&self, now: u64) {
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

const SESSION_ACTIVE_TABLE: &str = "remote_active_sessions";
const SESSION_TOMBSTONE_TABLE: &str = "remote_session_tombstones";

struct LoadedActiveSessionRecords {
    records: Vec<RemoteSessionResumeRecord>,
    invalid_session_ids: Vec<String>,
}

fn open_session_state_db(path: &FsPath) -> Result<Connection, CliError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {active_table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            updated_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            terminal_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );",
        active_table = SESSION_ACTIVE_TABLE,
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    Ok(conn)
}

fn load_active_session_records(path: &FsPath) -> Result<LoadedActiveSessionRecords, CliError> {
    let conn = open_session_state_db(path)?;
    let mut terminal_stmt = conn.prepare(&format!(
        "SELECT session_id FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let terminal_rows = terminal_stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut terminal_session_ids = HashSet::new();
    for row in terminal_rows {
        terminal_session_ids.insert(row?);
    }

    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_ACTIVE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = Vec::new();
    let mut invalid_session_ids = Vec::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        if terminal_session_ids.contains(&session_id) {
            warn!(
                session_id = %session_id,
                "dropping persisted MCP active session row because a terminal tombstone exists"
            );
            invalid_session_ids.push(session_id);
            continue;
        }
        match serde_json::from_str::<RemoteSessionResumeRecord>(&record_json) {
            Ok(record) if record.session_id == session_id => records.push(record),
            Ok(record) => {
                warn!(
                    session_id = %session_id,
                    record_session_id = %record.session_id,
                    "dropping persisted MCP session row whose primary key does not match the stored session payload"
                );
                invalid_session_ids.push(session_id);
            }
            Err(error) => {
                warn!(
                    session_id = %session_id,
                    error = %error,
                    "dropping malformed persisted MCP session row"
                );
                invalid_session_ids.push(session_id);
            }
        }
    }

    Ok(LoadedActiveSessionRecords {
        records,
        invalid_session_ids,
    })
}

fn load_terminal_session_records(
    path: &FsPath,
) -> Result<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>, CliError> {
    let conn = open_session_state_db(path)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = HashMap::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        let record: RemoteSessionDiagnosticRecord = serde_json::from_str(&record_json)?;
        records.insert(session_id, Arc::new(record));
    }

    Ok(records)
}

fn stored_capabilities_are_current(capabilities: &[CapabilityToken]) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    capabilities
        .iter()
        .all(|capability| capability.expires_at > now)
}

fn stored_capability_issuers_are_trusted(
    kernel: &chio_kernel::ChioKernel,
    capabilities: &[CapabilityToken],
) -> bool {
    capabilities
        .iter()
        .all(|capability| kernel.capability_issuer_is_trusted(&capability.issuer))
}

fn persist_terminal_session_record(
    path: &FsPath,
    record: &RemoteSessionDiagnosticRecord,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    let record_json = serde_json::to_string(record)?;
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 terminal_at = excluded.terminal_at,
                 record_json = excluded.record_json",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            record.session_id.as_str(),
            record.terminal_at as i64,
            record_json
        ],
    )?;
    Ok(())
}

fn persist_active_session_record(
    path: &FsPath,
    record: &RemoteSessionResumeRecord,
) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    let record_json = serde_json::to_string(record)?;
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, updated_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 updated_at = excluded.updated_at,
                 record_json = excluded.record_json",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![
            record.session_id.as_str(),
            session_now_millis() as i64,
            record_json,
        ],
    )?;
    Ok(())
}

fn delete_active_session_record(path: &FsPath, session_id: &str) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE session_id = ?1",
            table = SESSION_ACTIVE_TABLE,
        ),
        params![session_id],
    )?;
    Ok(())
}

fn purge_terminal_session_records_before(path: &FsPath, cutoff: u64) -> Result<(), CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {terminal_table}
             WHERE terminal_at < ?1
               AND NOT EXISTS (
                   SELECT 1 FROM {active_table}
                   WHERE {active_table}.session_id = {terminal_table}.session_id
               )",
            active_table = SESSION_ACTIVE_TABLE,
            terminal_table = SESSION_TOMBSTONE_TABLE,
        ),
        params![cutoff as i64],
    )?;
    Ok(())
}
