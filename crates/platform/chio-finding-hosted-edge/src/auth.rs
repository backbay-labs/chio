use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::capability::scope::Operation;
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::{canonical_json_bytes, sha256_hex, PublicKey};
use chio_finding_market_port::{
    HostedCapabilityAdmission, HostedCapabilityAdmissionOutcome, HostedMarketPortError,
    HostedPrincipal, HostedPrincipalRole, HostedTenantId,
};
use chio_kernel::{DpopProof, DPOP_SCHEMA};
use hmac::{Hmac, Mac as _};
use serde::Serialize;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::HostedEdgeError;

const API_KEY_HMAC_DOMAIN: &[u8] = b"chio.finding.hosted.api-key.v1\0";
const MAX_API_KEY_ID_BYTES: usize = 128;
const MAX_API_KEY_SECRET_BYTES: usize = 256;
const MIN_PEPPER_BYTES: usize = 32;
const MAX_PEPPER_BYTES: usize = 4_096;

/// Credential families the edge accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostedAuthMethod {
    CapabilityDpop,
    ApiKey,
}

/// Which credential families one tenant may authenticate with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedTenantAuthPolicy {
    pub tenant_id: HostedTenantId,
    pub allowed_methods: BTreeSet<HostedAuthMethod>,
}

impl HostedTenantAuthPolicy {
    /// Fail closed unless at least one method is allowed.
    pub fn validate(&self) -> Result<(), HostedEdgeError> {
        if self.allowed_methods.is_empty() || self.allowed_methods.len() > 2 {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(())
    }
}

/// Authenticator configuration: pinned capability authorities, DPoP
/// freshness bounds, per-tenant nonce capacity, and the per-tenant
/// method policies. Validated in full at construction.
#[derive(Clone, Debug)]
pub struct HostedAuthenticatorConfig {
    pub deployment_id: String,
    pub public_endpoint: String,
    pub capability_authorities: Vec<PublicKey>,
    pub maximum_capability_ttl_secs: u64,
    pub dpop_proof_ttl_secs: u64,
    pub dpop_clock_skew_secs: u64,
    pub dpop_nonce_capacity_per_tenant: u64,
    pub tenant_policies: Vec<HostedTenantAuthPolicy>,
}

impl HostedAuthenticatorConfig {
    fn validate(&self) -> Result<(), HostedEdgeError> {
        if !valid_identifier(&self.deployment_id, 256)
            || self.capability_authorities.is_empty()
            || self.capability_authorities.len() > 128
            || !(30..=3_600).contains(&self.maximum_capability_ttl_secs)
            || !(5..=300).contains(&self.dpop_proof_ttl_secs)
            || self.dpop_clock_skew_secs > 60
            || !(1_000..=10_000_000).contains(&self.dpop_nonce_capacity_per_tenant)
            || self.tenant_policies.is_empty()
            || self.tenant_policies.len() > 10_000
        {
            return Err(HostedEdgeError::Configuration);
        }
        parse_public_endpoint(&self.public_endpoint)?;
        let mut authorities = BTreeSet::new();
        for authority in &self.capability_authorities {
            if authority.is_weak_ed25519() || !authorities.insert(authority.to_hex()) {
                return Err(HostedEdgeError::Configuration);
            }
        }
        let mut tenants = BTreeSet::new();
        for policy in &self.tenant_policies {
            policy.validate()?;
            if !tenants.insert(policy.tenant_id.as_str()) {
                return Err(HostedEdgeError::Configuration);
            }
        }
        Ok(())
    }
}

/// One presented credential; secrets never appear in Debug output.
pub enum HostedAuthCredential {
    CapabilityDpop {
        capability: Box<CapabilityToken>,
        proof: Box<DpopProof>,
    },
    ApiKey {
        key_id: String,
        secret: String,
    },
}

impl HostedAuthCredential {
    const fn method(&self) -> HostedAuthMethod {
        match self {
            Self::CapabilityDpop { .. } => HostedAuthMethod::CapabilityDpop,
            Self::ApiKey { .. } => HostedAuthMethod::ApiKey,
        }
    }
}

impl fmt::Debug for HostedAuthCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityDpop { .. } => formatter.write_str("CapabilityDpop([REDACTED])"),
            Self::ApiKey { key_id, .. } => formatter
                .debug_struct("ApiKey")
                .field("key_id", key_id)
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Everything one authentication decision consumes: the tenant, the
/// governed action, the exact method/target/body digest the proof must
/// bind, the required role, and the credential.
#[derive(Debug)]
pub struct HostedAuthRequest {
    pub tenant_id: HostedTenantId,
    pub action: String,
    pub method: String,
    pub canonical_target: String,
    pub body_sha256: String,
    pub idempotency_key: Option<String>,
    pub required_role: HostedPrincipalRole,
    pub credential: HostedAuthCredential,
    pub now_unix_secs: u64,
}

/// The authenticated identity a request acts as, including the
/// credential that proved it and the artifact signer key the principal
/// may bind, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedAuthenticatedPrincipal {
    pub tenant_id: HostedTenantId,
    pub principal_id: String,
    pub role: HostedPrincipalRole,
    pub method: HostedAuthMethod,
    pub credential_id: String,
    pub artifact_signer_key: Option<PublicKey>,
}

/// Derives the stored HMAC verifier for an API-key secret; the pepper
/// never leaves the implementation.
pub trait ApiKeyPepper: Send + Sync {
    fn hmac_verifier(
        &self,
        tenant_id: &HostedTenantId,
        key_id: &str,
        secret: &[u8],
    ) -> Result<String, HostedEdgeError>;
}

/// In-process pepper over one fixed byte string of bounded length.
pub struct StaticApiKeyPepper {
    bytes: Vec<u8>,
}

impl StaticApiKeyPepper {
    /// Fail closed unless the pepper length is inside the accepted bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, HostedEdgeError> {
        if !(MIN_PEPPER_BYTES..=MAX_PEPPER_BYTES).contains(&bytes.len()) {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(Self { bytes })
    }
}

impl fmt::Debug for StaticApiKeyPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticApiKeyPepper")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for StaticApiKeyPepper {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ApiKeyPepper for StaticApiKeyPepper {
    fn hmac_verifier(
        &self,
        tenant_id: &HostedTenantId,
        key_id: &str,
        secret: &[u8],
    ) -> Result<String, HostedEdgeError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.bytes)
            .map_err(|_| HostedEdgeError::Configuration)?;
        mac.update(API_KEY_HMAC_DOMAIN);
        mac.update(tenant_id.as_str().as_bytes());
        mac.update(b"\0");
        mac.update(key_id.as_bytes());
        mac.update(b"\0");
        mac.update(secret);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

pub use chio_finding_market_port::HostedAuthPort as HostedAuthRepository;

/// Authenticates hosted requests against the tenant method policies,
/// the pinned capability authorities, and the durable auth port.
pub struct HostedAuthenticator {
    config: HostedAuthenticatorConfig,
    public_endpoint: Url,
    authority_keys: BTreeSet<String>,
    policies: BTreeMap<String, BTreeSet<HostedAuthMethod>>,
    repository: Arc<dyn HostedAuthRepository>,
    pepper: Arc<dyn ApiKeyPepper>,
}

impl HostedAuthenticator {
    /// Fail closed unless the pepper length is inside the accepted bound.
    pub fn new(
        config: HostedAuthenticatorConfig,
        repository: Arc<dyn HostedAuthRepository>,
        pepper: Arc<dyn ApiKeyPepper>,
    ) -> Result<Self, HostedEdgeError> {
        config.validate()?;
        let public_endpoint = parse_public_endpoint(&config.public_endpoint)?;
        let authority_keys = config
            .capability_authorities
            .iter()
            .map(PublicKey::to_hex)
            .collect();
        let policies = config
            .tenant_policies
            .iter()
            .map(|policy| {
                (
                    policy.tenant_id.as_str().to_owned(),
                    policy.allowed_methods.clone(),
                )
            })
            .collect();
        Ok(Self {
            config,
            public_endpoint,
            authority_keys,
            policies,
            repository,
            pepper,
        })
    }

    /// Authenticate one request. Every failure maps to a uniform
    /// AuthenticationFailed so a caller cannot probe which check denied;
    /// DPoP admission consults the durable nonce store so replays fail
    /// across replicas.
    pub async fn authenticate(
        &self,
        request: HostedAuthRequest,
    ) -> Result<HostedAuthenticatedPrincipal, HostedEdgeError> {
        self.validate_request(&request)?;
        let allowed = self
            .policies
            .get(request.tenant_id.as_str())
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        let method = request.credential.method();
        if !allowed.contains(&method) {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        match &request.credential {
            HostedAuthCredential::CapabilityDpop { capability, proof } => {
                self.authenticate_capability(&request, capability, proof)
                    .await
            }
            HostedAuthCredential::ApiKey { key_id, secret } => {
                self.authenticate_api_key(&request, key_id, secret).await
            }
        }
    }

    fn validate_request(&self, request: &HostedAuthRequest) -> Result<(), HostedEdgeError> {
        if !valid_identifier(&request.action, 128)
            || !matches!(request.method.as_str(), "GET" | "POST" | "PUT" | "DELETE")
            || !target_belongs_to_endpoint(&request.canonical_target, &self.public_endpoint)
            || !valid_digest(&request.body_sha256)
            || request
                .idempotency_key
                .as_deref()
                .is_some_and(|value| !valid_identifier(value, 256))
            || request.now_unix_secs == 0
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(())
    }

    async fn authenticate_api_key(
        &self,
        request: &HostedAuthRequest,
        key_id: &str,
        secret: &str,
    ) -> Result<HostedAuthenticatedPrincipal, HostedEdgeError> {
        if !valid_identifier(key_id, MAX_API_KEY_ID_BYTES)
            || secret.len() > MAX_API_KEY_SECRET_BYTES
            || secret.chars().any(char::is_control)
        {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        let secret = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(secret)
                .map_err(|_| HostedEdgeError::AuthenticationFailed)?,
        );
        if secret.len() != 32 {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        let record = self
            .repository
            .active_api_key(&request.tenant_id, key_id, request.now_unix_secs)
            .await
            .map_err(map_store)?
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        let actual = self
            .pepper
            .hmac_verifier(&request.tenant_id, key_id, secret.as_slice())?;
        if record.verifier_sha256.len() != actual.len()
            || !bool::from(record.verifier_sha256.as_bytes().ct_eq(actual.as_bytes()))
        {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        if !record.allowed_actions.contains(&request.action) {
            return Err(HostedEdgeError::AuthorizationFailed);
        }
        let principal = self
            .repository
            .principal(&request.tenant_id, &record.principal_id)
            .await
            .map_err(map_store)?
            .filter(|principal| principal.enabled)
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        require_role(&principal, request.required_role)?;
        let artifact_signer_key = principal_signer_key(&principal)?;
        Ok(HostedAuthenticatedPrincipal {
            tenant_id: request.tenant_id.clone(),
            principal_id: principal.principal_id,
            role: principal.role,
            method: HostedAuthMethod::ApiKey,
            credential_id: record.key_id,
            artifact_signer_key,
        })
    }

    async fn authenticate_capability(
        &self,
        request: &HostedAuthRequest,
        capability: &CapabilityToken,
        proof: &DpopProof,
    ) -> Result<HostedAuthenticatedPrincipal, HostedEdgeError> {
        if !self.authority_keys.contains(&capability.issuer.to_hex())
            || !capability
                .verify_signature_at(request.now_unix_secs)
                .map_err(|_| HostedEdgeError::AuthenticationFailed)?
            || capability
                .expires_at
                .checked_sub(capability.issued_at)
                .is_none_or(|ttl| ttl > self.config.maximum_capability_ttl_secs)
            || !capability.delegation_chain.is_empty()
            || !capability.caveats.is_empty()
            || capability.scope_attenuations.is_some()
            || capability.attenuation_proof.is_some()
            || capability.aggregate_invocation_budget.is_some()
            || capability.budget_share_bps.is_some()
            || !capability.scope.resource_grants.is_empty()
            || !capability.scope.prompt_grants.is_empty()
        {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        let expected_server = self.audience(&request.tenant_id);
        let matching: Vec<_> = capability
            .scope
            .grants
            .iter()
            .filter(|grant| {
                grant.server_id == expected_server
                    && grant.tool_name == request.action
                    && grant.operations == [Operation::Invoke]
                    && grant.constraints.is_empty()
                    && grant.dpop_required == Some(true)
                    && grant.max_cost_per_invocation.is_none()
                    && grant.max_total_cost.is_none()
            })
            .collect();
        if capability.scope.grants.len() != 1 || matching.len() != 1 {
            return Err(HostedEdgeError::AuthorizationFailed);
        }
        let max_invocations = matching[0]
            .max_invocations
            .filter(|value| *value > 0)
            .ok_or(HostedEdgeError::AuthorizationFailed)?;
        let principal = self
            .repository
            .principal_by_capability_key(
                &request.tenant_id,
                &capability.subject.to_hex(),
                request.now_unix_secs,
            )
            .await
            .map_err(map_store)?
            .filter(|principal| principal.enabled)
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        require_role(&principal, request.required_role)?;
        let artifact_signer_key = principal_signer_key(&principal)?;
        let action_hash = request_action_hash(request)?;
        verify_dpop_stateless(
            proof,
            capability,
            &expected_server,
            &request.action,
            &action_hash,
            request.now_unix_secs,
            self.config.dpop_proof_ttl_secs,
            self.config.dpop_clock_skew_secs,
        )?;
        let valid_through = proof
            .body
            .issued_at
            .checked_add(self.config.dpop_proof_ttl_secs)
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        let nonce_sha256 = sha256_hex(proof.body.nonce.as_bytes());
        let admission = self
            .repository
            .consume_capability_dpop_admission(
                &request.tenant_id,
                &HostedCapabilityAdmission {
                    capability_id: &capability.id,
                    nonce_sha256: &nonce_sha256,
                    // Only a mutation with a durable idempotency key may be
                    // resumed from its request binding. A read carries none,
                    // so reusing its proof stays a rejected replay.
                    request_sha256: request
                        .idempotency_key
                        .as_deref()
                        .map(|_| action_hash.as_str()),
                    valid_through,
                    max_invocations,
                    expires_at: capability.expires_at,
                    now: request.now_unix_secs,
                    tenant_nonce_capacity: self.config.dpop_nonce_capacity_per_tenant,
                },
            )
            .await
            .map_err(map_store)?;
        match admission {
            // A retry of the exact request this proof authorized resumes
            // rather than replays: its nonce and budget were already spent
            // on an effect that may have been cut short before it
            // committed, and the write it authorizes is idempotent.
            HostedCapabilityAdmissionOutcome::Admitted
            | HostedCapabilityAdmissionOutcome::RetriedSameRequest => {}
            HostedCapabilityAdmissionOutcome::Replay => {
                return Err(HostedEdgeError::ReplayRejected);
            }
            HostedCapabilityAdmissionOutcome::BudgetExceeded => {
                return Err(HostedEdgeError::AuthorizationFailed);
            }
        }
        Ok(HostedAuthenticatedPrincipal {
            tenant_id: request.tenant_id.clone(),
            principal_id: principal.principal_id,
            role: principal.role,
            method: HostedAuthMethod::CapabilityDpop,
            credential_id: capability.id.clone(),
            artifact_signer_key,
        })
    }

    fn audience(&self, tenant: &HostedTenantId) -> String {
        format!(
            "chio.finding.hosted/{}/{}@{}",
            self.config.deployment_id,
            tenant.as_str(),
            self.config.public_endpoint
        )
    }
}

fn parse_public_endpoint(value: &str) -> Result<Url, HostedEdgeError> {
    let endpoint = Url::parse(value).map_err(|_| HostedEdgeError::Configuration)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint.as_str().trim_end_matches('/') != value
    {
        return Err(HostedEdgeError::Configuration);
    }
    Ok(endpoint)
}

fn target_belongs_to_endpoint(value: &str, endpoint: &Url) -> bool {
    let Ok(target) = Url::parse(value) else {
        return false;
    };
    if target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
        || target.as_str() != value
        || target.scheme() != endpoint.scheme()
        || target.host_str() != endpoint.host_str()
        || target.port_or_known_default() != endpoint.port_or_known_default()
    {
        return false;
    }
    target.path().starts_with('/')
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestActionBinding<'a> {
    schema: &'static str,
    tenant_id: &'a str,
    action: &'a str,
    method: &'a str,
    canonical_target: &'a str,
    body_sha256: &'a str,
    idempotency_key: Option<&'a str>,
}

fn request_action_hash(request: &HostedAuthRequest) -> Result<String, HostedEdgeError> {
    canonical_json_bytes(&RequestActionBinding {
        schema: "chio.finding.hosted-request-action.v1",
        tenant_id: request.tenant_id.as_str(),
        action: &request.action,
        method: &request.method,
        canonical_target: &request.canonical_target,
        body_sha256: &request.body_sha256,
        idempotency_key: request.idempotency_key.as_deref(),
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| HostedEdgeError::InvalidRequest)
}

#[allow(clippy::too_many_arguments)]
fn verify_dpop_stateless(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_server: &str,
    expected_action: &str,
    expected_action_hash: &str,
    now: u64,
    ttl: u64,
    skew: u64,
) -> Result<(), HostedEdgeError> {
    if proof.body.schema != DPOP_SCHEMA
        || proof.body.agent_key != capability.subject
        || proof.body.capability_id != capability.id
        || proof.body.tool_server != expected_server
        || proof.body.tool_name != expected_action
        || proof.body.action_hash != expected_action_hash
        || !valid_nonce(&proof.body.nonce)
        || proof.body.issued_at > now.saturating_add(skew)
        || now > proof.body.issued_at.saturating_add(ttl)
    {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    let message =
        canonical_json_bytes(&proof.body).map_err(|_| HostedEdgeError::AuthenticationFailed)?;
    if !proof.body.agent_key.verify(&message, &proof.signature) {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    Ok(())
}

fn require_role(
    principal: &HostedPrincipal,
    required: HostedPrincipalRole,
) -> Result<(), HostedEdgeError> {
    if principal.role != required {
        return Err(HostedEdgeError::AuthorizationFailed);
    }
    Ok(())
}

fn principal_signer_key(principal: &HostedPrincipal) -> Result<Option<PublicKey>, HostedEdgeError> {
    principal
        .capability_public_key_hex
        .as_deref()
        .map(|value| {
            PublicKey::from_hex(value)
                .map_err(|_| HostedEdgeError::AuthenticationFailed)
                .and_then(|key| {
                    if key.is_weak_ed25519() {
                        Err(HostedEdgeError::AuthenticationFailed)
                    } else {
                        Ok(key)
                    }
                })
        })
        .transpose()
}

fn map_store(error: HostedMarketPortError) -> HostedEdgeError {
    match error {
        HostedMarketPortError::Capacity => HostedEdgeError::CapacityUnavailable,
        HostedMarketPortError::Unavailable => HostedEdgeError::DependencyUnavailable,
        _ => HostedEdgeError::AuthenticationFailed,
    }
}

fn valid_nonce(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chio_core::capability::scope::{ChioScope, ToolGrant};
    use chio_core::capability::token::CapabilityTokenBody;
    use chio_core::Keypair;
    use chio_finding_market_port::HostedApiKeyRecord;
    use chio_kernel::DpopProofBody;
    use std::sync::Mutex;

    struct MockRepository {
        principal: HostedPrincipal,
        key: HostedApiKeyRecord,
        nonce_fresh: Mutex<bool>,
        capability_available: Mutex<bool>,
    }

    #[async_trait]
    impl HostedAuthRepository for MockRepository {
        async fn principal_by_capability_key(
            &self,
            _tenant: &HostedTenantId,
            _public_key_hex: &str,
            _now: u64,
        ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
            Ok(Some(self.principal.clone()))
        }

        async fn principal(
            &self,
            _tenant: &HostedTenantId,
            _principal_id: &str,
        ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
            Ok(Some(self.principal.clone()))
        }

        async fn active_api_key(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _now: u64,
        ) -> Result<Option<HostedApiKeyRecord>, HostedMarketPortError> {
            Ok(Some(self.key.clone()))
        }

        async fn consume_capability_dpop_admission(
            &self,
            _tenant: &HostedTenantId,
            _admission: &HostedCapabilityAdmission<'_>,
        ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError> {
            let mut nonce_fresh = self
                .nonce_fresh
                .lock()
                .map_err(|_| HostedMarketPortError::Unavailable)?;
            if !*nonce_fresh {
                return Ok(HostedCapabilityAdmissionOutcome::Replay);
            }
            let capability_available = self
                .capability_available
                .lock()
                .map_err(|_| HostedMarketPortError::Unavailable)?;
            if !*capability_available {
                return Ok(HostedCapabilityAdmissionOutcome::BudgetExceeded);
            }
            *nonce_fresh = false;
            Ok(HostedCapabilityAdmissionOutcome::Admitted)
        }
    }

    fn tenant() -> HostedTenantId {
        HostedTenantId::new("tenant-a").unwrap_or_else(|_| unreachable!())
    }

    fn repository(pepper: &StaticApiKeyPepper, subject: &PublicKey) -> Arc<MockRepository> {
        let verifier = pepper
            .hmac_verifier(&tenant(), "key-a", &[0_u8; 32])
            .unwrap_or_default();
        Arc::new(MockRepository {
            principal: HostedPrincipal {
                tenant_id: tenant(),
                principal_id: "buyer-a".to_owned(),
                role: HostedPrincipalRole::Buyer,
                capability_public_key_hex: Some(subject.to_hex()),
                enabled: true,
                created_at: 1,
                updated_at: 1,
            },
            key: HostedApiKeyRecord {
                tenant_id: tenant(),
                key_id: "key-a".to_owned(),
                principal_id: "buyer-a".to_owned(),
                verifier_sha256: verifier,
                allowed_actions: ["finding.purchase".to_owned()].into_iter().collect(),
                active_from: 1,
                expires_at: 1_000,
                revoked_at: None,
                rotated_from_key_id: None,
                created_at: 1,
            },
            nonce_fresh: Mutex::new(true),
            capability_available: Mutex::new(true),
        })
    }

    fn config(authority: PublicKey) -> HostedAuthenticatorConfig {
        HostedAuthenticatorConfig {
            deployment_id: "deployment-a".to_owned(),
            public_endpoint: "https://market.example".to_owned(),
            capability_authorities: vec![authority],
            maximum_capability_ttl_secs: 300,
            dpop_proof_ttl_secs: 60,
            dpop_clock_skew_secs: 5,
            dpop_nonce_capacity_per_tenant: 1_000,
            tenant_policies: vec![HostedTenantAuthPolicy {
                tenant_id: tenant(),
                allowed_methods: [HostedAuthMethod::CapabilityDpop, HostedAuthMethod::ApiKey]
                    .into_iter()
                    .collect(),
            }],
        }
    }

    #[test]
    fn endpoint_validation_rejects_origin_and_path_confusion() {
        assert!(parse_public_endpoint("https://market.example/api").is_err());
        let endpoint = parse_public_endpoint("https://market.example");
        assert!(endpoint.is_ok());
        if let Ok(endpoint) = endpoint {
            assert!(target_belongs_to_endpoint(
                "https://market.example/v1/findings?limit=1",
                &endpoint
            ));
            assert!(!target_belongs_to_endpoint(
                "https://market.example.evil/v1/findings",
                &endpoint
            ));
            assert!(!target_belongs_to_endpoint(
                "https://market.example/v1/findings#unsigned",
                &endpoint
            ));
        }
        assert!(parse_public_endpoint("http://market.example").is_err());
        assert!(parse_public_endpoint("https://operator@market.example").is_err());
        assert!(parse_public_endpoint("https://market.example?mode=unsafe").is_err());
    }

    fn base_request(credential: HostedAuthCredential) -> HostedAuthRequest {
        HostedAuthRequest {
            tenant_id: tenant(),
            action: "finding.purchase".to_owned(),
            method: "POST".to_owned(),
            canonical_target: "https://market.example/v1/findings/a/purchases".to_owned(),
            body_sha256: sha256_hex(b"{}"),
            idempotency_key: Some("event-a".to_owned()),
            required_role: HostedPrincipalRole::Buyer,
            credential,
            now_unix_secs: 100,
        }
    }

    #[tokio::test]
    async fn api_key_secret_is_hmac_verified_without_fallback() {
        let authority = Keypair::generate();
        let subject = Keypair::generate();
        let pepper =
            Arc::new(StaticApiKeyPepper::new(vec![7; 32]).unwrap_or_else(|_| unreachable!()));
        let authenticator = HostedAuthenticator::new(
            config(authority.public_key()),
            repository(&pepper, &subject.public_key()),
            pepper,
        );
        assert!(authenticator.is_ok());
        if let Ok(authenticator) = authenticator {
            let accepted = authenticator
                .authenticate(base_request(HostedAuthCredential::ApiKey {
                    key_id: "key-a".to_owned(),
                    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                }))
                .await;
            assert!(accepted.is_ok());
            let rejected = authenticator
                .authenticate(base_request(HostedAuthCredential::ApiKey {
                    key_id: "key-a".to_owned(),
                    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE".to_owned(),
                }))
                .await;
            assert_eq!(rejected, Err(HostedEdgeError::AuthenticationFailed));
        }
    }

    #[tokio::test]
    async fn capability_is_audience_action_body_role_and_replay_bound() {
        let authority = Keypair::generate();
        let subject = Keypair::generate();
        let pepper =
            Arc::new(StaticApiKeyPepper::new(vec![7; 32]).unwrap_or_else(|_| unreachable!()));
        let repository = repository(&pepper, &subject.public_key());
        let auth_repository: Arc<dyn HostedAuthRepository> = repository.clone();
        let authenticator =
            HostedAuthenticator::new(config(authority.public_key()), auth_repository, pepper);
        assert!(authenticator.is_ok());
        if let Ok(authenticator) = authenticator {
            let audience = authenticator.audience(&tenant());
            let capability = CapabilityToken::sign(
                CapabilityTokenBody {
                    id: "capability-a".to_owned(),
                    issuer: authority.public_key(),
                    subject: subject.public_key(),
                    scope: ChioScope {
                        grants: vec![ToolGrant {
                            server_id: audience.clone(),
                            tool_name: "finding.purchase".to_owned(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: Some(1),
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: Some(true),
                        }],
                        resource_grants: vec![],
                        prompt_grants: vec![],
                    },
                    issued_at: 90,
                    expires_at: 200,
                    delegation_chain: vec![],
                    aggregate_invocation_budget: None,
                },
                &authority,
            );
            assert!(capability.is_ok());
            if let Ok(capability) = capability {
                let unsigned = base_request(HostedAuthCredential::ApiKey {
                    key_id: "unused".to_owned(),
                    secret: "unused-unused-unused-unused-unused".to_owned(),
                });
                let action_hash = request_action_hash(&unsigned).unwrap_or_default();
                let proof = DpopProof::sign(
                    DpopProofBody {
                        schema: DPOP_SCHEMA.to_owned(),
                        capability_id: capability.id.clone(),
                        tool_server: audience,
                        tool_name: "finding.purchase".to_owned(),
                        action_hash,
                        nonce: "nonce-0000000001".to_owned(),
                        issued_at: 100,
                        agent_key: subject.public_key(),
                    },
                    &subject,
                );
                assert!(proof.is_ok());
                if let Ok(proof) = proof {
                    let mut wrong_binding = base_request(HostedAuthCredential::CapabilityDpop {
                        capability: Box::new(capability.clone()),
                        proof: Box::new(proof.clone()),
                    });
                    wrong_binding.idempotency_key = Some("event-b".to_owned());
                    let rejected = authenticator.authenticate(wrong_binding).await;
                    assert_eq!(rejected, Err(HostedEdgeError::AuthenticationFailed));
                    assert!(repository
                        .capability_available
                        .lock()
                        .map(|mut available| *available = false)
                        .is_ok());
                    let budget_rejected = authenticator
                        .authenticate(base_request(HostedAuthCredential::CapabilityDpop {
                            capability: Box::new(capability.clone()),
                            proof: Box::new(proof.clone()),
                        }))
                        .await;
                    assert_eq!(budget_rejected, Err(HostedEdgeError::AuthorizationFailed));
                    assert!(repository
                        .capability_available
                        .lock()
                        .map(|mut available| *available = true)
                        .is_ok());
                    let accepted = authenticator
                        .authenticate(base_request(HostedAuthCredential::CapabilityDpop {
                            capability: Box::new(capability.clone()),
                            proof: Box::new(proof.clone()),
                        }))
                        .await;
                    assert!(accepted.is_ok());
                    let replay = authenticator
                        .authenticate(base_request(HostedAuthCredential::CapabilityDpop {
                            capability: Box::new(capability),
                            proof: Box::new(proof),
                        }))
                        .await;
                    assert_eq!(replay, Err(HostedEdgeError::ReplayRejected));
                }
            }
        }
    }
}
