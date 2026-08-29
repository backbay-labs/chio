//! Strict configuration contract for a multi-tenant hosted cognition market.
//!
//! This profile carries references to credentials, never credential values or
//! local signing seeds. Validation closes the production boundary before any
//! listener, database pool, payment rail, or remote signer is contacted.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::{PublicKey, SigningAlgorithm, SigningBackend};
use chio_finding_hosted_edge::{
    HostedAuthMethod, HostedAuthenticatorConfig, HostedTenantAuthPolicy, HostedTlsConfig,
    HostedTlsState, HostedTrustedProxy, HostedTrustedProxyConfig, StaticApiKeyPepper,
};
use chio_finding_market_store_postgres::HostedTenantId;
#[cfg(target_os = "linux")]
use chio_finding_worker::{FirecrackerExecutor, FirecrackerIdentity, FirecrackerWorkerConfig};
use chio_settle::{RemoteFindingBondObservationSource, RemoteFindingBondObservationSourceConfig};
use chio_settle::{RemoteFindingImpairmentPublisher, RemoteFindingImpairmentPublisherConfig};
use chio_signing_remote::{HttpSigningBackend, RemoteSigningKey, VaultTransitSigningBackend};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroize as _;

use super::FindingMarketConfig;

pub const FINDING_HOSTED_PROFILE_SCHEMA: &str = "chio.finding.hosted-operator-profile.v1";
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedProfile {
    pub schema: String,
    pub deployment_id: String,
    pub listen: SocketAddr,
    pub public_endpoint: String,
    pub edge: FindingHostedEdgeProfile,
    pub database: FindingHostedDatabaseProfile,
    pub identity: FindingHostedIdentityProfile,
    pub market: FindingMarketConfig,
    pub kernel_public_key_hex: String,
    pub signers: Vec<FindingHostedSignerProfile>,
    pub payment: FindingHostedAcpProfile,
    pub bond_observer: FindingHostedBondObserverProfile,
    pub impairment_publisher: FindingHostedImpairmentPublisherProfile,
    pub worker_public_key_hex: String,
    pub worker: FindingHostedWorkerProfile,
    pub tenants: Vec<FindingHostedTenantProfile>,
    pub release: FindingHostedReleaseProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FindingHostedEdgeProfile {
    NativeTls {
        certificate_chain_path: String,
        private_key_path: String,
        client_ca_path: Option<String>,
        require_client_certificate: bool,
        minimum_protocol: String,
        reload_interval_secs: u64,
        minimum_remaining_validity_secs: u64,
    },
    TrustedProxy {
        trusted_proxy_ips: Vec<IpAddr>,
        authentication_token_env: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedDatabaseProfile {
    pub url_env: String,
    pub ca_certificate_path: String,
    pub max_connections: u32,
    pub acquire_timeout_millis: u64,
    pub max_jobs_per_tenant: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedIdentityProfile {
    pub capability_authorities: Vec<String>,
    pub maximum_capability_ttl_secs: u64,
    pub dpop_proof_ttl_secs: u64,
    pub dpop_clock_skew_secs: u64,
    pub nonce_capacity: u64,
    pub api_key_pepper_env: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingHostedSigningRole {
    Venue,
    Listing,
    GovernanceRoot,
    AuthorityStatus,
    VerifierReport,
    Collateral,
    Purchase,
    FailedDelivery,
    ChallengeEvaluator,
    VenueFinalization,
    MarketPenalty,
    SettlementObserver,
    AnchorPublisher,
    AuditAuthority,
    AuditRandomnessWitness,
    StatusFeedOperator,
    FeeScheduleOperator,
    Kernel,
    Worker,
}

impl FindingHostedSigningRole {
    pub const ALL: [Self; 19] = [
        Self::Venue,
        Self::Listing,
        Self::GovernanceRoot,
        Self::AuthorityStatus,
        Self::VerifierReport,
        Self::Collateral,
        Self::Purchase,
        Self::FailedDelivery,
        Self::ChallengeEvaluator,
        Self::VenueFinalization,
        Self::MarketPenalty,
        Self::SettlementObserver,
        Self::AnchorPublisher,
        Self::AuditAuthority,
        Self::AuditRandomnessWitness,
        Self::StatusFeedOperator,
        Self::FeeScheduleOperator,
        Self::Kernel,
        Self::Worker,
    ];
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedSignerProfile {
    pub role: FindingHostedSigningRole,
    pub key_handle: String,
    pub key_version: u32,
    pub public_key_hex: String,
    pub timeout_millis: u64,
    pub transport: FindingHostedSignerTransport,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingHostedSignerTransport {
    Http {
        base_url: String,
        bearer_token_env: String,
    },
    VaultTransit {
        base_url: String,
        mount: String,
        token_env: String,
        namespace: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedAcpProfile {
    pub base_url: String,
    pub bearer_token_env: String,
    pub authorize_path: String,
    pub capture_path: String,
    pub release_path: String,
    pub refund_path: String,
    pub settlement_state_path: String,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedImpairmentPublisherProfile {
    pub base_url: String,
    pub bearer_token_env: String,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedBondObserverProfile {
    pub base_url: String,
    pub bearer_token_env: String,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedWorkerProfile {
    pub worker_binary: String,
    pub worker_binary_sha256: String,
    pub firecracker_binary: String,
    pub firecracker_sha256: String,
    pub jailer_binary: String,
    pub jailer_sha256: String,
    pub kernel_image: String,
    pub kernel_sha256: String,
    pub rootfs_image: String,
    pub rootfs_sha256: String,
    pub artifact_store_root: String,
    pub jail_root: String,
    pub identities: Vec<FindingHostedWorkerIdentity>,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub max_instances: u32,
    pub execution_timeout_secs: u64,
    pub lease_duration_secs: u64,
    pub lease_heartbeat_secs: u64,
    pub max_attempts: u32,
    pub max_tenants_per_tick: u32,
    pub max_jobs_per_tick: u32,
    pub tenant_failure_threshold: u32,
    pub shutdown_grace_secs: u64,
    pub max_frame_bytes: u32,
    pub max_file_size_bytes: u64,
    pub max_open_files: u32,
    pub guest_vsock_port: u32,
    pub require_default_seccomp: bool,
    pub network_enabled: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedWorkerIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedTenantProfile {
    pub tenant_id: String,
    pub enabled: bool,
    pub auth_methods: BTreeSet<FindingHostedAuthMethod>,
    pub principals: Vec<FindingHostedPrincipalProfile>,
    pub max_concurrent_jobs: u32,
    pub max_queued_jobs: u64,
    pub max_monthly_spend_units: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingHostedAuthMethod {
    CapabilityDpop,
    ApiKey,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingHostedPrincipalRole {
    Buyer,
    Seller,
    Evaluator,
    Auditor,
    Operator,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedPrincipalProfile {
    pub principal_id: String,
    pub role: FindingHostedPrincipalRole,
    pub capability_public_key_hex: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedReleaseProfile {
    pub environment: String,
    pub artifact_sha256: String,
    pub configuration_revision: String,
    pub minimum_ready_replicas: u32,
    pub canary_percent: u8,
    pub canary_observation_secs: u64,
    pub rollback_window_secs: u64,
    pub max_error_rate_bps: u16,
    pub max_p99_latency_millis: u64,
    pub max_queue_age_secs: u64,
}

pub const FINDING_HOSTED_CANARY_OBSERVATION_SCHEMA: &str =
    "chio.finding.hosted-canary-observation.v1";
const FINDING_HOSTED_CANARY_MAX_AGE_SECS: u64 = 300;
const FINDING_HOSTED_CANARY_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedCanaryObservation {
    pub schema: String,
    pub artifact_sha256: String,
    pub configuration_revision: String,
    pub window_started_at_unix_secs: u64,
    pub window_ended_at_unix_secs: u64,
    pub observed_secs: u64,
    pub ready_replicas: u32,
    pub request_count: u64,
    pub error_count: u64,
    pub p99_latency_millis: u64,
    pub oldest_queue_age_secs: u64,
    pub signature_failures: u64,
    pub payment_ambiguities: u64,
    pub tenant_isolation_violations: u64,
    pub durable_integrity_failures: u64,
    pub worker_isolation_failures: u64,
}

pub type SignedFindingHostedCanaryObservation =
    SignedExportEnvelope<FindingHostedCanaryObservation>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingHostedCanaryDecision {
    Promote,
    Rollback(FindingHostedRollbackReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingHostedRollbackReason {
    Binding,
    ObservationWindow,
    Freshness,
    Availability,
    ErrorRate,
    Latency,
    QueueAge,
    SecurityInvariant,
}

impl FindingHostedProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != FINDING_HOSTED_PROFILE_SCHEMA {
            return Err("unsupported hosted finding profile schema".to_owned());
        }
        validate_identifier(&self.deployment_id, "deployment id")?;
        if self.listen.port() == 0 || self.listen.ip().is_unspecified() {
            return Err("hosted listener must use a concrete address and nonzero port".to_owned());
        }
        validate_https_url(&self.public_endpoint, "public endpoint", true)?;
        self.validate_edge()?;
        self.validate_database()?;
        self.validate_identity()?;
        self.market.validate().map_err(|error| error.to_string())?;
        self.validate_signers()?;
        self.validate_payment()?;
        self.validate_bond_observer()?;
        self.validate_impairment_publisher()?;
        self.validate_worker()?;
        self.validate_tenants()?;
        self.validate_release()?;
        Ok(())
    }

    pub fn authenticator_config(&self) -> Result<HostedAuthenticatorConfig, String> {
        self.validate()?;
        let capability_authorities = self
            .identity
            .capability_authorities
            .iter()
            .map(|key| parse_key(key, "capability authority"))
            .collect::<Result<Vec<_>, _>>()?;
        let tenant_policies = self
            .tenants
            .iter()
            .map(|tenant| {
                Ok(HostedTenantAuthPolicy {
                    tenant_id: HostedTenantId::new(tenant.tenant_id.clone())
                        .map_err(|_| "hosted tenant id is invalid".to_owned())?,
                    allowed_methods: tenant
                        .auth_methods
                        .iter()
                        .map(|method| match method {
                            FindingHostedAuthMethod::CapabilityDpop => {
                                HostedAuthMethod::CapabilityDpop
                            }
                            FindingHostedAuthMethod::ApiKey => HostedAuthMethod::ApiKey,
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(HostedAuthenticatorConfig {
            deployment_id: self.deployment_id.clone(),
            public_endpoint: self.public_endpoint.clone(),
            capability_authorities,
            maximum_capability_ttl_secs: self.identity.maximum_capability_ttl_secs,
            dpop_proof_ttl_secs: self.identity.dpop_proof_ttl_secs,
            dpop_clock_skew_secs: self.identity.dpop_clock_skew_secs,
            dpop_nonce_capacity_per_tenant: self.identity.nonce_capacity,
            tenant_policies,
        })
    }

    pub fn load_api_key_pepper(&self) -> Result<StaticApiKeyPepper, String> {
        self.validate()?;
        let mut encoded = read_secret_environment(&self.identity.api_key_pepper_env)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| "hosted API-key pepper is invalid".to_owned());
        encoded.zeroize();
        StaticApiKeyPepper::new(decoded?).map_err(|_| "hosted API-key pepper is invalid".to_owned())
    }

    pub fn load_tls(&self, now: u64) -> Result<Option<HostedTlsState>, String> {
        self.validate()?;
        let FindingHostedEdgeProfile::NativeTls {
            certificate_chain_path,
            private_key_path,
            client_ca_path,
            require_client_certificate,
            minimum_remaining_validity_secs,
            ..
        } = &self.edge
        else {
            return Ok(None);
        };
        HostedTlsState::load(
            HostedTlsConfig {
                certificate_chain_path: certificate_chain_path.into(),
                private_key_path: private_key_path.into(),
                client_ca_path: client_ca_path.as_ref().map(Into::into),
                require_client_certificate: *require_client_certificate,
                minimum_remaining_validity_secs: *minimum_remaining_validity_secs,
            },
            now,
        )
        .map(Some)
        .map_err(|_| "hosted TLS material is invalid".to_owned())
    }

    pub fn load_trusted_proxy(&self) -> Result<Option<HostedTrustedProxy>, String> {
        self.validate()?;
        let FindingHostedEdgeProfile::TrustedProxy {
            trusted_proxy_ips,
            authentication_token_env,
        } = &self.edge
        else {
            return Ok(None);
        };
        let mut token = read_secret_environment(authentication_token_env)?;
        let token_bytes = token.as_bytes().to_vec();
        token.zeroize();
        HostedTrustedProxy::new(HostedTrustedProxyConfig {
            listen: self.listen,
            trusted_peer_ips: trusted_proxy_ips.iter().copied().collect(),
            public_endpoint: self.public_endpoint.clone(),
            authentication_token: token_bytes,
        })
        .map(Some)
        .map_err(|_| "hosted trusted-proxy configuration is invalid".to_owned())
    }

    /// Load and remotely preflight one custody signer from secret references.
    pub fn load_signer(
        &self,
        role: FindingHostedSigningRole,
    ) -> Result<Arc<dyn SigningBackend>, String> {
        self.validate()?;
        let signer = self
            .signers
            .iter()
            .find(|candidate| candidate.role == role)
            .ok_or_else(|| "hosted signer role is missing".to_owned())?;
        let key = RemoteSigningKey::new(
            signer.key_handle.clone(),
            signer.key_version,
            parse_key(&signer.public_key_hex, "remote signer public key")?,
        )
        .map_err(|_| "remote signer key configuration is invalid".to_owned())?;
        let timeout = Duration::from_millis(signer.timeout_millis);
        match &signer.transport {
            FindingHostedSignerTransport::Http {
                base_url,
                bearer_token_env,
            } => {
                let backend = HttpSigningBackend::new(
                    base_url,
                    key,
                    read_secret_environment(bearer_token_env)?,
                )
                .map_err(|_| "remote HTTP signer configuration is invalid".to_owned())?
                .with_timeout(timeout);
                backend
                    .verify_key()
                    .map_err(|_| "remote HTTP signer preflight failed".to_owned())?;
                Ok(Arc::new(backend))
            }
            FindingHostedSignerTransport::VaultTransit {
                base_url,
                mount,
                token_env,
                namespace,
            } => {
                let mut backend = VaultTransitSigningBackend::new(
                    base_url,
                    mount,
                    key,
                    read_secret_environment(token_env)?,
                )
                .map_err(|_| "Vault Transit signer configuration is invalid".to_owned())?;
                if let Some(namespace) = namespace {
                    backend = backend
                        .with_namespace(namespace)
                        .map_err(|_| "Vault Transit namespace is invalid".to_owned())?;
                }
                backend = backend.with_timeout(timeout);
                backend
                    .verify_key()
                    .map_err(|_| "Vault Transit signer preflight failed".to_owned())?;
                Ok(Arc::new(backend))
            }
        }
    }

    /// Build the bounded Firecracker worker after validating the full profile.
    #[cfg(target_os = "linux")]
    pub fn load_worker_executor(&self) -> Result<FirecrackerExecutor, String> {
        self.validate()?;
        let signer = self.load_signer(FindingHostedSigningRole::Worker)?;
        FirecrackerExecutor::new(
            FirecrackerWorkerConfig {
                worker_binary: self.worker.worker_binary.clone().into(),
                worker_binary_sha256: self.worker.worker_binary_sha256.clone(),
                firecracker_binary: self.worker.firecracker_binary.clone().into(),
                firecracker_sha256: self.worker.firecracker_sha256.clone(),
                jailer_binary: self.worker.jailer_binary.clone().into(),
                jailer_sha256: self.worker.jailer_sha256.clone(),
                kernel_image: self.worker.kernel_image.clone().into(),
                kernel_sha256: self.worker.kernel_sha256.clone(),
                rootfs_image: self.worker.rootfs_image.clone().into(),
                rootfs_sha256: self.worker.rootfs_sha256.clone(),
                artifact_store_root: self.worker.artifact_store_root.clone().into(),
                jail_root: self.worker.jail_root.clone().into(),
                identities: self
                    .worker
                    .identities
                    .iter()
                    .map(|identity| FirecrackerIdentity {
                        uid: identity.uid,
                        gid: identity.gid,
                    })
                    .collect(),
                vcpu_count: self.worker.vcpu_count,
                memory_mib: self.worker.memory_mib,
                execution_timeout: Duration::from_secs(self.worker.execution_timeout_secs),
                max_frame_bytes: self.worker.max_frame_bytes,
                max_file_size_bytes: self.worker.max_file_size_bytes,
                max_open_files: self.worker.max_open_files,
                guest_vsock_port: self.worker.guest_vsock_port,
                capability_authority: parse_key(
                    &self.kernel_public_key_hex,
                    "worker capability authority",
                )?,
            },
            signer,
        )
        .map_err(|_| "hosted Firecracker worker configuration is invalid".to_owned())
    }

    /// Build the strict HTTPS impairment publisher from a secret reference.
    pub fn load_impairment_publisher(&self) -> Result<RemoteFindingImpairmentPublisher, String> {
        self.validate()?;
        let namespace = self.impairment_publisher_namespace()?;
        let config = RemoteFindingImpairmentPublisherConfig::new(
            self.impairment_publisher.base_url.clone(),
            read_secret_environment(&self.impairment_publisher.bearer_token_env)?,
            namespace,
            Duration::from_millis(self.impairment_publisher.timeout_millis),
        )
        .map_err(|_| "remote impairment publisher configuration is invalid".to_owned())?;
        RemoteFindingImpairmentPublisher::new(config)
            .map_err(|_| "remote impairment publisher preflight failed".to_owned())
    }

    /// Build the strict HTTPS live bond observer from a secret reference.
    pub fn load_bond_observer(&self) -> Result<RemoteFindingBondObservationSource, String> {
        self.validate()?;
        let namespace = self.bond_observer_namespace()?;
        let config = RemoteFindingBondObservationSourceConfig::new(
            self.bond_observer.base_url.clone(),
            read_secret_environment(&self.bond_observer.bearer_token_env)?,
            namespace,
            Duration::from_millis(self.bond_observer.timeout_millis),
        )
        .map_err(|_| "remote bond observer configuration is invalid".to_owned())?;
        RemoteFindingBondObservationSource::new(config)
            .map_err(|_| "remote bond observer preflight failed".to_owned())
    }

    /// Evaluate a canary observation with closed rollback reasons.
    pub fn evaluate_canary(
        &self,
        observation: &FindingHostedCanaryObservation,
        evaluated_at_unix_secs: u64,
    ) -> FindingHostedCanaryDecision {
        self.release
            .evaluate_canary(observation, evaluated_at_unix_secs)
    }

    /// Verify one audit-authority-signed observation before evaluating it.
    pub fn evaluate_signed_canary(
        &self,
        observation: &SignedFindingHostedCanaryObservation,
        evaluated_at_unix_secs: u64,
    ) -> FindingHostedCanaryDecision {
        if self.validate().is_err() {
            return FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Binding);
        }
        let pinned_signer = self.market.audit_authority.key().ok();
        let Some(pinned_signer) = pinned_signer else {
            return FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Binding);
        };
        evaluate_signed_canary_observation(
            &self.release,
            observation,
            &pinned_signer,
            evaluated_at_unix_secs,
        )
    }

    fn validate_edge(&self) -> Result<(), String> {
        match &self.edge {
            FindingHostedEdgeProfile::NativeTls {
                certificate_chain_path,
                private_key_path,
                client_ca_path,
                require_client_certificate,
                minimum_protocol,
                reload_interval_secs,
                minimum_remaining_validity_secs,
            } => {
                validate_absolute_path(certificate_chain_path, "TLS certificate chain")?;
                validate_absolute_path(private_key_path, "TLS private key")?;
                if let Some(path) = client_ca_path {
                    validate_absolute_path(path, "TLS client CA")?;
                }
                if minimum_protocol != "TLSv1.3"
                    || *require_client_certificate != client_ca_path.is_some()
                    || !(5..=86_400).contains(reload_interval_secs)
                    || !(300..=2_592_000).contains(minimum_remaining_validity_secs)
                {
                    return Err("hosted native TLS bounds are invalid".to_owned());
                }
            }
            FindingHostedEdgeProfile::TrustedProxy {
                trusted_proxy_ips,
                authentication_token_env,
            } => {
                validate_env_name(
                    authentication_token_env,
                    "trusted-proxy authentication environment variable",
                )?;
                if !self.listen.ip().is_loopback()
                    || trusted_proxy_ips.is_empty()
                    || trusted_proxy_ips.len() > 32
                    || trusted_proxy_ips
                        .iter()
                        .any(|address| !address.is_loopback())
                    || trusted_proxy_ips.iter().collect::<BTreeSet<_>>().len()
                        != trusted_proxy_ips.len()
                {
                    return Err("hosted trusted-proxy boundary is invalid".to_owned());
                }
            }
        }
        Ok(())
    }

    fn validate_database(&self) -> Result<(), String> {
        validate_env_name(&self.database.url_env, "database URL environment variable")?;
        validate_absolute_path(
            &self.database.ca_certificate_path,
            "database CA certificate",
        )?;
        if !(1..=256).contains(&self.database.max_connections)
            || !(100..=30_000).contains(&self.database.acquire_timeout_millis)
            || !(1..=10_000_000).contains(&self.database.max_jobs_per_tenant)
        {
            return Err("hosted database bounds are invalid".to_owned());
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        validate_env_name(
            &self.identity.api_key_pepper_env,
            "API-key pepper environment variable",
        )?;
        if self.identity.capability_authorities.is_empty()
            || self.identity.capability_authorities.len() > 128
            || !(30..=3_600).contains(&self.identity.maximum_capability_ttl_secs)
            || !(5..=300).contains(&self.identity.dpop_proof_ttl_secs)
            || self.identity.dpop_clock_skew_secs > 60
            || !(1_000..=10_000_000).contains(&self.identity.nonce_capacity)
        {
            return Err("hosted identity bounds are invalid".to_owned());
        }
        let mut authorities = BTreeSet::new();
        for authority in &self.identity.capability_authorities {
            let key = parse_key(authority, "capability authority")?;
            if !authorities.insert(key.to_hex()) {
                return Err("capability authorities must be unique".to_owned());
            }
        }
        Ok(())
    }

    fn validate_signers(&self) -> Result<(), String> {
        let kernel_key = parse_key(&self.kernel_public_key_hex, "kernel public key")?;
        let mut roles = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for signer in &self.signers {
            if !roles.insert(signer.role) {
                return Err("hosted signer roles must be unique".to_owned());
            }
            validate_identifier(&signer.key_handle, "remote signing key handle")?;
            if signer.key_version == 0 {
                return Err("remote signing key version must be nonzero".to_owned());
            }
            if !(100..=30_000).contains(&signer.timeout_millis) {
                return Err("remote signing timeout is outside the hosted bound".to_owned());
            }
            let key = parse_key(&signer.public_key_hex, "remote signer public key")?;
            if !public_keys.insert(key.to_hex()) {
                return Err("hosted signing roles must use distinct public keys".to_owned());
            }
            let expected = self.expected_signer_key(signer.role, &kernel_key)?;
            if signer.role == FindingHostedSigningRole::FeeScheduleOperator {
                if !self
                    .market
                    .fee_schedule_operator_keys
                    .iter()
                    .any(|candidate| candidate == &key.to_hex())
                {
                    return Err("fee schedule remote signer does not match its roster".to_owned());
                }
            } else if key != expected {
                return Err("remote signer does not match its market role pin".to_owned());
            }
            validate_signer_transport(&signer.transport)?;
        }
        if roles != FindingHostedSigningRole::ALL.into_iter().collect() {
            return Err("hosted profile must configure every signing role exactly once".to_owned());
        }
        Ok(())
    }

    fn expected_signer_key(
        &self,
        role: FindingHostedSigningRole,
        kernel_key: &PublicKey,
    ) -> Result<PublicKey, String> {
        let pin = match role {
            FindingHostedSigningRole::Venue => &self.market.venue,
            FindingHostedSigningRole::Listing => &self.market.listing,
            FindingHostedSigningRole::GovernanceRoot => &self.market.governance_root,
            FindingHostedSigningRole::AuthorityStatus => &self.market.authority_status,
            FindingHostedSigningRole::VerifierReport => &self.market.verifier_report,
            FindingHostedSigningRole::Collateral => &self.market.collateral,
            FindingHostedSigningRole::Purchase => &self.market.purchase,
            FindingHostedSigningRole::FailedDelivery => &self.market.failed_delivery,
            FindingHostedSigningRole::ChallengeEvaluator => &self.market.challenge_evaluator,
            FindingHostedSigningRole::VenueFinalization => &self.market.venue_finalization,
            FindingHostedSigningRole::MarketPenalty => &self.market.market_penalty,
            FindingHostedSigningRole::SettlementObserver => &self.market.settlement_observer,
            FindingHostedSigningRole::AnchorPublisher => &self.market.anchor_publisher,
            FindingHostedSigningRole::AuditAuthority => &self.market.audit_authority,
            FindingHostedSigningRole::AuditRandomnessWitness => {
                &self.market.audit_randomness_witness
            }
            FindingHostedSigningRole::StatusFeedOperator => {
                &self.market.status_feed_operator.authority
            }
            FindingHostedSigningRole::FeeScheduleOperator => return Ok(kernel_key.clone()),
            FindingHostedSigningRole::Kernel => return Ok(kernel_key.clone()),
            FindingHostedSigningRole::Worker => {
                return parse_key(&self.worker_public_key_hex, "worker public key")
            }
        };
        pin.key().map_err(|error| error.to_string())
    }

    fn validate_payment(&self) -> Result<(), String> {
        validate_https_url(&self.payment.base_url, "ACP base URL", false)?;
        validate_env_name(
            &self.payment.bearer_token_env,
            "ACP token environment variable",
        )?;
        for (path, label) in [
            (&self.payment.authorize_path, "ACP authorize path"),
            (&self.payment.capture_path, "ACP capture path"),
            (&self.payment.release_path, "ACP release path"),
            (&self.payment.refund_path, "ACP refund path"),
            (
                &self.payment.settlement_state_path,
                "ACP settlement state path",
            ),
        ] {
            validate_http_path(path, label)?;
        }
        if !(100..=30_000).contains(&self.payment.timeout_millis) {
            return Err("ACP timeout is outside the hosted bound".to_owned());
        }
        Ok(())
    }

    fn validate_impairment_publisher(&self) -> Result<(), String> {
        validate_https_url(
            &self.impairment_publisher.base_url,
            "impairment publisher base URL",
            true,
        )?;
        validate_env_name(
            &self.impairment_publisher.bearer_token_env,
            "impairment publisher token environment variable",
        )?;
        if !(100..=30_000).contains(&self.impairment_publisher.timeout_millis) {
            return Err("impairment publisher timeout is outside the hosted bound".to_owned());
        }
        self.impairment_publisher_namespace()?;
        Ok(())
    }

    fn validate_bond_observer(&self) -> Result<(), String> {
        validate_https_url(&self.bond_observer.base_url, "bond observer base URL", true)?;
        validate_env_name(
            &self.bond_observer.bearer_token_env,
            "bond observer token environment variable",
        )?;
        if !(100..=30_000).contains(&self.bond_observer.timeout_millis) {
            return Err("bond observer timeout is outside the hosted bound".to_owned());
        }
        self.bond_observer_namespace()?;
        Ok(())
    }

    fn impairment_publisher_namespace(&self) -> Result<String, String> {
        let namespace = format!("finding:{}", self.deployment_id);
        if namespace.len() > 256 {
            return Err(
                "deployment id is too long for the impairment publisher namespace".to_owned(),
            );
        }
        Ok(namespace)
    }

    fn bond_observer_namespace(&self) -> Result<String, String> {
        let namespace = format!("finding-observer:{}", self.deployment_id);
        if namespace.len() > 256 {
            return Err("deployment id is too long for the bond observer namespace".to_owned());
        }
        Ok(namespace)
    }

    fn validate_worker(&self) -> Result<(), String> {
        let worker_files = [
            (&self.worker.worker_binary, "finding worker binary"),
            (&self.worker.firecracker_binary, "Firecracker binary"),
            (&self.worker.jailer_binary, "Firecracker jailer"),
            (&self.worker.kernel_image, "worker kernel image"),
            (&self.worker.rootfs_image, "worker rootfs image"),
        ];
        let mut unique_files = BTreeSet::new();
        for (path, label) in worker_files {
            if !unique_files.insert(path.as_str()) {
                return Err("hosted worker files must have distinct paths".to_owned());
            }
            validate_absolute_path(path, label)?;
        }
        for (path, label) in [
            (
                &self.worker.artifact_store_root,
                "worker artifact store root",
            ),
            (&self.worker.jail_root, "worker jail root"),
        ] {
            validate_absolute_path(path, label)?;
        }
        let artifact_root = Path::new(&self.worker.artifact_store_root);
        let jail_root = Path::new(&self.worker.jail_root);
        if artifact_root.starts_with(jail_root)
            || jail_root.starts_with(artifact_root)
            || unique_files.iter().any(|path| {
                let path = Path::new(path);
                path.starts_with(artifact_root)
                    || artifact_root.starts_with(path)
                    || path.starts_with(jail_root)
                    || jail_root.starts_with(path)
            })
        {
            return Err("hosted worker files, CAS, and jail roots must not overlap".to_owned());
        }
        validate_digest(
            &self.worker.worker_binary_sha256,
            "finding worker binary digest",
        )?;
        validate_digest(&self.worker.firecracker_sha256, "Firecracker binary digest")?;
        validate_digest(&self.worker.jailer_sha256, "Firecracker jailer digest")?;
        validate_digest(&self.worker.kernel_sha256, "worker kernel digest")?;
        validate_digest(&self.worker.rootfs_sha256, "worker rootfs digest")?;
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        if self.worker.identities.len() != self.worker.max_instances as usize
            || self.worker.identities.iter().any(|identity| {
                identity.uid == 0
                    || identity.gid == 0
                    || !uids.insert(identity.uid)
                    || !gids.insert(identity.gid)
            })
            || !(1..=32).contains(&self.worker.vcpu_count)
            || !(128..=131_072).contains(&self.worker.memory_mib)
            || !(1..=1_024).contains(&self.worker.max_instances)
            || !(1..=3_600).contains(&self.worker.execution_timeout_secs)
            || !(5..=3_600).contains(&self.worker.lease_duration_secs)
            || self.worker.lease_heartbeat_secs == 0
            || self.worker.lease_heartbeat_secs >= self.worker.lease_duration_secs
            || !(1..=20).contains(&self.worker.max_attempts)
            || !(1..=1_024).contains(&self.worker.max_tenants_per_tick)
            || !(1..=10_000).contains(&self.worker.max_jobs_per_tick)
            || !(1..=100).contains(&self.worker.tenant_failure_threshold)
            || !(1..=3_600).contains(&self.worker.shutdown_grace_secs)
            || !(1_024..=4_194_304).contains(&self.worker.max_frame_bytes)
            || !(1_048_576..=1_073_741_824).contains(&self.worker.max_file_size_bytes)
            || !(32..=4_096).contains(&self.worker.max_open_files)
            || !(1_024..=65_535).contains(&self.worker.guest_vsock_port)
            || !self.worker.require_default_seccomp
            || self.worker.network_enabled
        {
            return Err("hosted worker isolation or resource bounds are invalid".to_owned());
        }
        if self.worker.lease_duration_secs <= self.worker.execution_timeout_secs {
            return Err("worker lease must outlive the execution timeout".to_owned());
        }
        Ok(())
    }

    fn validate_tenants(&self) -> Result<(), String> {
        if self.tenants.is_empty() || self.tenants.len() > 10_000 {
            return Err("hosted profile requires a bounded tenant roster".to_owned());
        }
        let mut tenant_ids = BTreeSet::new();
        let mut capability_keys = BTreeSet::new();
        let mut any_enabled_tenant = false;
        for tenant in &self.tenants {
            any_enabled_tenant |= tenant.enabled;
            validate_identifier(&tenant.tenant_id, "tenant id")?;
            if !tenant_ids.insert(tenant.tenant_id.as_str())
                || tenant.auth_methods.is_empty()
                || tenant.auth_methods.len() > 2
                || tenant.principals.is_empty()
                || tenant.principals.len() > 10_000
                || !(1..=1_024).contains(&tenant.max_concurrent_jobs)
                || tenant.max_queued_jobs == 0
                || tenant.max_queued_jobs > self.database.max_jobs_per_tenant
                || tenant.max_monthly_spend_units == 0
                || tenant.max_monthly_spend_units > MAX_I_JSON_INTEGER
            {
                return Err("hosted tenant identity or quota is invalid".to_owned());
            }
            let mut principal_ids = BTreeSet::new();
            let mut any_enabled = false;
            for principal in &tenant.principals {
                validate_identifier(&principal.principal_id, "principal id")?;
                if !principal_ids.insert(principal.principal_id.as_str()) {
                    return Err("hosted tenant principal ids must be unique".to_owned());
                }
                any_enabled |= principal.enabled;
                if let Some(key) = principal.capability_public_key_hex.as_deref() {
                    if !tenant
                        .auth_methods
                        .contains(&FindingHostedAuthMethod::CapabilityDpop)
                    {
                        return Err("API-key-only tenant contains a capability key".to_owned());
                    }
                    let key = parse_key(key, "principal capability key")?;
                    if !capability_keys.insert(key.to_hex()) {
                        return Err("principal capability keys must be globally unique".to_owned());
                    }
                }
            }
            if !any_enabled
                || tenant
                    .auth_methods
                    .contains(&FindingHostedAuthMethod::CapabilityDpop)
                    && !tenant
                        .principals
                        .iter()
                        .any(|principal| principal.capability_public_key_hex.is_some())
            {
                return Err("hosted tenant has no usable principal".to_owned());
            }
        }
        if !any_enabled_tenant {
            return Err("hosted profile requires at least one enabled tenant".to_owned());
        }
        Ok(())
    }

    fn validate_release(&self) -> Result<(), String> {
        validate_identifier(&self.release.environment, "release environment")?;
        validate_digest(&self.release.artifact_sha256, "release artifact digest")?;
        validate_identifier(
            &self.release.configuration_revision,
            "configuration revision",
        )?;
        if self.release.minimum_ready_replicas < 2
            || !(1..=25).contains(&self.release.canary_percent)
            || !(60..=86_400).contains(&self.release.canary_observation_secs)
            || self.release.rollback_window_secs < self.release.canary_observation_secs
            || self.release.rollback_window_secs > 604_800
            || self.release.max_error_rate_bps > 1_000
            || !(1..=120_000).contains(&self.release.max_p99_latency_millis)
            || !(1..=86_400).contains(&self.release.max_queue_age_secs)
        {
            return Err("hosted release safety bounds are invalid".to_owned());
        }
        Ok(())
    }
}

impl FindingHostedReleaseProfile {
    pub fn evaluate_canary(
        &self,
        observation: &FindingHostedCanaryObservation,
        evaluated_at_unix_secs: u64,
    ) -> FindingHostedCanaryDecision {
        use FindingHostedCanaryDecision::{Promote, Rollback};
        use FindingHostedRollbackReason::{
            Availability, Binding, ErrorRate, Freshness, Latency, ObservationWindow, QueueAge,
            SecurityInvariant,
        };
        if observation.schema != FINDING_HOSTED_CANARY_OBSERVATION_SCHEMA
            || observation.artifact_sha256 != self.artifact_sha256
            || observation.configuration_revision != self.configuration_revision
        {
            return Rollback(Binding);
        }
        if observation.window_started_at_unix_secs == 0
            || observation.window_ended_at_unix_secs == 0
            || observation
                .window_started_at_unix_secs
                .checked_add(observation.observed_secs)
                != Some(observation.window_ended_at_unix_secs)
            || observation.observed_secs > self.rollback_window_secs
        {
            return Rollback(ObservationWindow);
        }
        if evaluated_at_unix_secs == 0
            || observation.window_ended_at_unix_secs
                > evaluated_at_unix_secs.saturating_add(FINDING_HOSTED_CANARY_CLOCK_SKEW_SECS)
            || evaluated_at_unix_secs.saturating_sub(observation.window_ended_at_unix_secs)
                > FINDING_HOSTED_CANARY_MAX_AGE_SECS
        {
            return Rollback(Freshness);
        }
        if observation.observed_secs < self.canary_observation_secs {
            return Rollback(ObservationWindow);
        }
        if observation.ready_replicas < self.minimum_ready_replicas
            || observation.request_count == 0
            || observation.error_count > observation.request_count
        {
            return Rollback(Availability);
        }
        if observation.error_count.saturating_mul(10_000)
            > observation
                .request_count
                .saturating_mul(u64::from(self.max_error_rate_bps))
        {
            return Rollback(ErrorRate);
        }
        if observation.p99_latency_millis > self.max_p99_latency_millis {
            return Rollback(Latency);
        }
        if observation.oldest_queue_age_secs > self.max_queue_age_secs {
            return Rollback(QueueAge);
        }
        if observation.signature_failures != 0
            || observation.payment_ambiguities != 0
            || observation.tenant_isolation_violations != 0
            || observation.durable_integrity_failures != 0
            || observation.worker_isolation_failures != 0
        {
            return Rollback(SecurityInvariant);
        }
        Promote
    }
}

fn evaluate_signed_canary_observation(
    release: &FindingHostedReleaseProfile,
    observation: &SignedFindingHostedCanaryObservation,
    pinned_signer: &PublicKey,
    evaluated_at_unix_secs: u64,
) -> FindingHostedCanaryDecision {
    if pinned_signer.algorithm() != SigningAlgorithm::Ed25519
        || pinned_signer.is_weak_ed25519()
        || observation.signer_key != *pinned_signer
        || !matches!(
            pinned_signer.verify_canonical_strict(&observation.body, &observation.signature),
            Ok(true)
        )
    {
        return FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Binding);
    }
    release.evaluate_canary(&observation.body, evaluated_at_unix_secs)
}

fn read_secret_environment(name: &str) -> Result<String, String> {
    validate_env_name(name, "hosted secret environment variable")?;
    let value = std::env::var(name).map_err(|_| "hosted secret is unavailable".to_owned())?;
    if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        return Err("hosted secret is invalid".to_owned());
    }
    Ok(value)
}

fn validate_signer_transport(transport: &FindingHostedSignerTransport) -> Result<(), String> {
    match transport {
        FindingHostedSignerTransport::Http {
            base_url,
            bearer_token_env,
        } => {
            validate_https_url(base_url, "remote signer URL", false)?;
            validate_env_name(bearer_token_env, "remote signer token environment variable")
        }
        FindingHostedSignerTransport::VaultTransit {
            base_url,
            mount,
            token_env,
            namespace,
        } => {
            validate_https_url(base_url, "Vault URL", false)?;
            validate_identifier(mount, "Vault Transit mount")?;
            validate_env_name(token_env, "Vault token environment variable")?;
            if let Some(namespace) = namespace {
                validate_text(namespace, "Vault namespace")?;
            }
            Ok(())
        }
    }
}

fn parse_key(value: &str, label: &str) -> Result<PublicKey, String> {
    let key = PublicKey::from_hex(value).map_err(|_| format!("{label} is invalid"))?;
    if key.algorithm() != SigningAlgorithm::Ed25519
        || key.is_weak_ed25519()
        || key.to_hex() != value
    {
        return Err(format!("{label} must be canonical non-weak Ed25519"));
    }
    Ok(key)
}

fn validate_https_url(value: &str, label: &str, public: bool) -> Result<(), String> {
    let parsed = Url::parse(value).map_err(|_| format!("{label} is invalid"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str().trim_end_matches('/') != value
    {
        return Err(format!(
            "{label} must be an HTTPS URL without credentials or selectors"
        ));
    }
    if public && parsed.host_str().is_some_and(is_non_public_host) {
        return Err(format!(
            "{label} must not target a loopback or private address"
        ));
    }
    Ok(())
}

fn is_non_public_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            address.is_loopback() || address.is_unspecified() || address.is_unique_local()
        }
    })
}

fn validate_http_path(value: &str, label: &str) -> Result<(), String> {
    if value.len() < 2
        || value.len() > 256
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_env_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_absolute_path(value: &str, label: &str) -> Result<(), String> {
    validate_text(value, label)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!("{label} must be a normalized absolute path"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_urls_reject_cleartext_credentials_and_private_public_hosts() {
        assert!(validate_https_url("https://market.example/v1", "endpoint", true).is_ok());
        assert!(validate_https_url("http://market.example", "endpoint", true).is_err());
        assert!(validate_https_url("https://user@market.example", "endpoint", true).is_err());
        assert!(validate_https_url("https://127.0.0.1", "endpoint", true).is_err());
        assert!(validate_https_url("https://10.0.0.1", "endpoint", true).is_err());
    }

    #[test]
    fn environment_names_and_worker_paths_are_closed() {
        assert!(validate_env_name("CHIO_MARKET_DATABASE_URL", "env").is_ok());
        assert!(validate_env_name("chio_token", "env").is_err());
        assert!(validate_absolute_path("/srv/chio/kernel", "path").is_ok());
        assert!(validate_absolute_path("/srv/chio/../kernel", "path").is_err());
    }

    #[test]
    fn signing_role_roster_is_closed() {
        let roles: BTreeSet<_> = FindingHostedSigningRole::ALL.into_iter().collect();
        assert_eq!(roles.len(), 19);
        assert!(roles.contains(&FindingHostedSigningRole::ChallengeEvaluator));
        assert!(roles.contains(&FindingHostedSigningRole::Kernel));
        assert!(roles.contains(&FindingHostedSigningRole::Worker));
    }

    #[test]
    fn hosted_edge_and_auth_schemas_are_closed_and_secret_free() {
        let edge: Result<FindingHostedEdgeProfile, _> = serde_json::from_value(serde_json::json!({
            "kind": "trusted_proxy",
            "trustedProxyIps": ["127.0.0.1"],
            "authenticationTokenEnv": "CHIO_PROXY_AUTH_TOKEN"
        }));
        assert!(edge.is_ok());
        let unknown: Result<FindingHostedEdgeProfile, _> =
            serde_json::from_value(serde_json::json!({
                "kind": "trusted_proxy",
                "trustedProxyIps": ["127.0.0.1"],
                "authenticationTokenEnv": "CHIO_PROXY_AUTH_TOKEN",
                "trustAllForwardingHeaders": true
            }));
        assert!(unknown.is_err());

        let identity = FindingHostedIdentityProfile {
            capability_authorities: vec!["a".repeat(64)],
            maximum_capability_ttl_secs: 300,
            dpop_proof_ttl_secs: 60,
            dpop_clock_skew_secs: 5,
            nonce_capacity: 10_000,
            api_key_pepper_env: "CHIO_API_KEY_PEPPER".to_owned(),
        };
        let encoded = serde_json::to_string(&identity);
        assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            assert!(!encoded.contains("secret"));
            assert!(!encoded.contains("oidc"));
            assert!(encoded.contains("CHIO_API_KEY_PEPPER"));
        }
    }

    #[test]
    fn impairment_publisher_profile_is_closed_and_secret_free() {
        let profile: Result<FindingHostedImpairmentPublisherProfile, _> =
            serde_json::from_value(serde_json::json!({
                "baseUrl": "https://impairment.example/v1",
                "bearerTokenEnv": "CHIO_IMPAIRMENT_PUBLISHER_TOKEN",
                "timeoutMillis": 5_000
            }));
        let profile = match profile {
            Ok(profile) => profile,
            Err(error) => panic!("valid impairment publisher profile was rejected: {error}"),
        };
        let encoded = serde_json::to_string(&profile);
        assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            assert!(!encoded.contains("secret-value"));
            assert!(encoded.contains("CHIO_IMPAIRMENT_PUBLISHER_TOKEN"));
        }

        let unknown: Result<FindingHostedImpairmentPublisherProfile, _> =
            serde_json::from_value(serde_json::json!({
                "baseUrl": "https://impairment.example/v1",
                "bearerTokenEnv": "CHIO_IMPAIRMENT_PUBLISHER_TOKEN",
                "timeoutMillis": 5_000,
                "allowHttp": true
            }));
        assert!(unknown.is_err());
    }

    #[test]
    fn impairment_publisher_boundary_rejects_unsafe_values() {
        assert!(validate_https_url("https://impairment.example/v1", "publisher", true).is_ok());
        assert!(validate_https_url("http://impairment.example", "publisher", true).is_err());
        assert!(validate_https_url("https://127.0.0.1", "publisher", true).is_err());
        assert!(validate_env_name("CHIO_IMPAIRMENT_PUBLISHER_TOKEN", "token").is_ok());
        assert!(validate_env_name("publisher-token", "token").is_err());
    }

    #[test]
    fn bond_observer_profile_is_closed_and_secret_free() {
        let profile: Result<FindingHostedBondObserverProfile, _> =
            serde_json::from_value(serde_json::json!({
                "baseUrl": "https://observer.example/v1",
                "bearerTokenEnv": "CHIO_BOND_OBSERVER_TOKEN",
                "timeoutMillis": 5_000
            }));
        assert!(profile.is_ok());
        if let Ok(profile) = profile {
            let encoded = serde_json::to_string(&profile).unwrap_or_default();
            assert!(!encoded.contains("secret-value"));
            assert!(encoded.contains("CHIO_BOND_OBSERVER_TOKEN"));
        }
        let unknown: Result<FindingHostedBondObserverProfile, _> =
            serde_json::from_value(serde_json::json!({
                "baseUrl": "https://observer.example/v1",
                "bearerTokenEnv": "CHIO_BOND_OBSERVER_TOKEN",
                "timeoutMillis": 5_000,
                "trustResponseWithoutDigest": true
            }));
        assert!(unknown.is_err());
    }

    #[test]
    fn canary_security_invariant_forces_rollback() {
        let release = FindingHostedReleaseProfile {
            environment: "production".to_owned(),
            artifact_sha256: "a".repeat(64),
            configuration_revision: "revision-1".to_owned(),
            minimum_ready_replicas: 2,
            canary_percent: 5,
            canary_observation_secs: 300,
            rollback_window_secs: 3_600,
            max_error_rate_bps: 100,
            max_p99_latency_millis: 2_000,
            max_queue_age_secs: 60,
        };
        let mut observation = FindingHostedCanaryObservation {
            schema: FINDING_HOSTED_CANARY_OBSERVATION_SCHEMA.to_owned(),
            artifact_sha256: "a".repeat(64),
            configuration_revision: "revision-1".to_owned(),
            window_started_at_unix_secs: 1_699_999_700,
            window_ended_at_unix_secs: 1_700_000_000,
            observed_secs: 300,
            ready_replicas: 2,
            request_count: 1_000,
            error_count: 1,
            p99_latency_millis: 500,
            oldest_queue_age_secs: 5,
            signature_failures: 0,
            payment_ambiguities: 0,
            tenant_isolation_violations: 0,
            durable_integrity_failures: 0,
            worker_isolation_failures: 0,
        };
        assert_eq!(
            release.evaluate_canary(&observation, 1_700_000_001),
            FindingHostedCanaryDecision::Promote
        );
        observation.tenant_isolation_violations = 1;
        assert_eq!(
            release.evaluate_canary(&observation, 1_700_000_001),
            FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::SecurityInvariant)
        );
        observation.tenant_isolation_violations = 0;
        assert_eq!(
            release.evaluate_canary(&observation, 1_700_000_301),
            FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Freshness)
        );
        observation.window_ended_at_unix_secs = 1_700_000_302;
        assert_eq!(
            release.evaluate_canary(&observation, 1_700_000_301),
            FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::ObservationWindow)
        );

        observation.window_ended_at_unix_secs = 1_700_000_000;
        let signer = chio_core::Keypair::generate();
        let signed = SignedExportEnvelope::sign(observation.clone(), &signer);
        assert!(signed.is_ok());
        if let Ok(mut signed) = signed {
            assert_eq!(
                evaluate_signed_canary_observation(
                    &release,
                    &signed,
                    &signer.public_key(),
                    1_700_000_001,
                ),
                FindingHostedCanaryDecision::Promote
            );
            signed.body.request_count = 999;
            assert_eq!(
                evaluate_signed_canary_observation(
                    &release,
                    &signed,
                    &signer.public_key(),
                    1_700_000_001,
                ),
                FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Binding)
            );
            let wrong_signer = chio_core::Keypair::generate();
            let wrong = SignedExportEnvelope::sign(observation, &wrong_signer)
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(
                evaluate_signed_canary_observation(
                    &release,
                    &wrong,
                    &signer.public_key(),
                    1_700_000_001,
                ),
                FindingHostedCanaryDecision::Rollback(FindingHostedRollbackReason::Binding)
            );
        }
    }
}
