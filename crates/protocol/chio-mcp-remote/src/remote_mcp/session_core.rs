use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex as StdMutex, Weak};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::CapabilityToken;
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
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig, SerializedMcpTransport};
use chio_mcp_adapter::edge::{AdapterError, ChioMcpEdge, McpEdgeConfig, McpTransport};
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::StdioMcpTransport;
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


#[path = "session_core/session.rs"]
mod session_core_session;
#[path = "session_core/factory.rs"]
mod session_core_factory;
#[path = "session_core/ledger.rs"]
mod session_core_ledger;

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
