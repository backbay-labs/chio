//! Strict configuration contract for a multi-tenant hosted cognition market.
//!
//! This profile carries references to credentials, never credential values or
//! local signing seeds. Validation closes the production boundary before any
//! listener, database pool, payment rail, or remote signer is contacted.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path};

use chio_core::{PublicKey, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use url::Url;

use super::FindingMarketConfig;

pub const FINDING_HOSTED_PROFILE_SCHEMA: &str = "chio.finding.hosted-profile.v1";
const MAX_I_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedProfile {
    pub schema: String,
    pub deployment_id: String,
    pub listen: SocketAddr,
    pub public_endpoint: String,
    pub tls: FindingHostedTlsProfile,
    pub database: FindingHostedDatabaseProfile,
    pub identity: FindingHostedIdentityProfile,
    pub market: FindingMarketConfig,
    pub kernel_public_key_hex: String,
    pub signers: Vec<FindingHostedSignerProfile>,
    pub payment: FindingHostedAcpProfile,
    pub worker: FindingHostedWorkerProfile,
    pub tenants: Vec<FindingHostedTenantProfile>,
    pub release: FindingHostedReleaseProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedTlsProfile {
    pub certificate_chain_path: String,
    pub private_key_path: String,
    pub client_ca_path: String,
    pub minimum_protocol: String,
    pub require_client_certificate: bool,
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
    pub issuer: String,
    pub jwks_uri: String,
    pub audiences: Vec<String>,
    pub required_scopes: Vec<String>,
    pub require_dpop: bool,
    pub dpop_proof_ttl_secs: u64,
    pub dpop_clock_skew_secs: u64,
    pub nonce_capacity: u64,
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
}

impl FindingHostedSigningRole {
    const ALL: [Self; 18] = [
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
    ];
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedSignerProfile {
    pub role: FindingHostedSigningRole,
    pub key_handle: String,
    pub key_version: u32,
    pub public_key_hex: String,
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
pub struct FindingHostedWorkerProfile {
    pub firecracker_binary: String,
    pub jailer_binary: String,
    pub kernel_image: String,
    pub kernel_sha256: String,
    pub rootfs_image: String,
    pub rootfs_sha256: String,
    pub jail_root: String,
    pub uid: u32,
    pub gid: u32,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub max_instances: u32,
    pub execution_timeout_secs: u64,
    pub lease_duration_secs: u64,
    pub max_attempts: u32,
    pub seccomp_level: u8,
    pub network_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingHostedTenantProfile {
    pub tenant_id: String,
    pub oidc_subject: String,
    pub enabled: bool,
    pub max_concurrent_jobs: u32,
    pub max_queued_jobs: u64,
    pub max_monthly_spend_units: u64,
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
        self.validate_tls()?;
        self.validate_database()?;
        self.validate_identity()?;
        self.market.validate().map_err(|error| error.to_string())?;
        self.validate_signers()?;
        self.validate_payment()?;
        self.validate_worker()?;
        self.validate_tenants()?;
        self.validate_release()?;
        Ok(())
    }

    fn validate_tls(&self) -> Result<(), String> {
        for (path, label) in [
            (&self.tls.certificate_chain_path, "TLS certificate chain"),
            (&self.tls.private_key_path, "TLS private key"),
            (&self.tls.client_ca_path, "TLS client CA"),
        ] {
            validate_absolute_path(path, label)?;
        }
        if self.tls.minimum_protocol != "TLSv1.3" || !self.tls.require_client_certificate {
            return Err("hosted TLS must require TLS 1.3 and client certificates".to_owned());
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
        validate_https_url(&self.identity.issuer, "OIDC issuer", false)?;
        validate_https_url(&self.identity.jwks_uri, "OIDC JWKS URI", false)?;
        validate_unique_text(&self.identity.audiences, "OIDC audience")?;
        validate_unique_text(&self.identity.required_scopes, "OIDC required scope")?;
        if !self.identity.require_dpop
            || !(5..=300).contains(&self.identity.dpop_proof_ttl_secs)
            || self.identity.dpop_clock_skew_secs > 60
            || !(1_000..=10_000_000).contains(&self.identity.nonce_capacity)
        {
            return Err("hosted identity must require bounded DPoP replay protection".to_owned());
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

    fn validate_worker(&self) -> Result<(), String> {
        for (path, label) in [
            (&self.worker.firecracker_binary, "Firecracker binary"),
            (&self.worker.jailer_binary, "Firecracker jailer"),
            (&self.worker.kernel_image, "worker kernel image"),
            (&self.worker.rootfs_image, "worker rootfs image"),
            (&self.worker.jail_root, "worker jail root"),
        ] {
            validate_absolute_path(path, label)?;
        }
        validate_digest(&self.worker.kernel_sha256, "worker kernel digest")?;
        validate_digest(&self.worker.rootfs_sha256, "worker rootfs digest")?;
        if self.worker.uid == 0
            || self.worker.gid == 0
            || !(1..=32).contains(&self.worker.vcpu_count)
            || !(128..=131_072).contains(&self.worker.memory_mib)
            || !(1..=1_024).contains(&self.worker.max_instances)
            || !(1..=3_600).contains(&self.worker.execution_timeout_secs)
            || !(5..=3_600).contains(&self.worker.lease_duration_secs)
            || !(1..=20).contains(&self.worker.max_attempts)
            || self.worker.seccomp_level != 2
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
        let mut subjects = BTreeSet::new();
        for tenant in &self.tenants {
            validate_identifier(&tenant.tenant_id, "tenant id")?;
            validate_text(&tenant.oidc_subject, "tenant OIDC subject")?;
            if !tenant_ids.insert(tenant.tenant_id.as_str())
                || !subjects.insert(tenant.oidc_subject.as_str())
                || !(1..=1_024).contains(&tenant.max_concurrent_jobs)
                || tenant.max_queued_jobs == 0
                || tenant.max_queued_jobs > self.database.max_jobs_per_tenant
                || tenant.max_monthly_spend_units == 0
                || tenant.max_monthly_spend_units > MAX_I_JSON_INTEGER
            {
                return Err("hosted tenant identity or quota is invalid".to_owned());
            }
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
        {
            return Err("hosted release safety bounds are invalid".to_owned());
        }
        Ok(())
    }
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

fn validate_unique_text(values: &[String], label: &str) -> Result<(), String> {
    if values.is_empty() || values.len() > 128 {
        return Err(format!("{label} list is invalid"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, label)?;
        if !unique.insert(value.as_str()) {
            return Err(format!("{label} values must be unique"));
        }
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
        assert_eq!(roles.len(), 18);
        assert!(roles.contains(&FindingHostedSigningRole::ChallengeEvaluator));
        assert!(roles.contains(&FindingHostedSigningRole::Kernel));
    }
}
