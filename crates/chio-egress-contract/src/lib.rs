//! Typed HTTP egress contracts for substrate adapters.
//!
//! Kernel, guard, and adapter code paths that initiate outbound HTTP must
//! declare one of these contracts before a target URL is accepted. Missing or
//! malformed contract state fails closed.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Typed egress policy that must be declared before substrate HTTP egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEgressContract {
    /// Tenant-scoped namespace used by callers to bind egress receipts and
    /// deployment policy to one authority domain.
    pub tenant_egress_namespace: String,
    /// Lowercase HTTP URL schemes allowed by this contract: `http` or `https`.
    #[serde(default)]
    pub allowed_schemes: BTreeSet<String>,
    /// Exact normalized URL authorities allowed by this contract.
    ///
    /// Domain authorities are lowercase. IPv6 authorities use brackets, for
    /// example `[2001:db8::10]:443`.
    #[serde(default)]
    pub allowed_authority_set: BTreeSet<String>,
    /// Reject loopback address literals and localhost names even if an
    /// authority entry was configured.
    pub deny_loopback: bool,
    /// Reject IPv4 and IPv6 link-local address literals.
    pub deny_link_local: bool,
    /// Reject IPv6 unique-local address literals.
    pub deny_ipv6_ula: bool,
    /// Maximum redirect hop count accepted for a request chain.
    pub max_redirect_chain: u8,
    /// Maximum response bytes accepted before the substrate must abort.
    pub max_response_bytes: u64,
}

/// A target URL that survived [`HttpEgressContract`] enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHttpEgressTarget {
    pub tenant_egress_namespace: String,
    pub scheme: String,
    pub authority: String,
}

/// Immutable egress contract that has passed shape validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedHttpEgressContract {
    contract: HttpEgressContract,
    tenant_egress_namespace: String,
}

/// Fail-closed reasons returned by HTTP egress contract enforcement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpEgressError {
    #[error("outbound HTTP egress requires a declared HttpEgressContract")]
    MissingContract,
    #[error("invalid HttpEgressContract: {0}")]
    InvalidContract(String),
    #[error("invalid egress URL: {0}")]
    InvalidUrl(String),
    #[error("egress URL is missing an authority")]
    MissingAuthority,
    #[error("egress URL must not include userinfo")]
    UserinfoDenied,
    #[error("scheme {scheme:?} is not allowed by the HttpEgressContract")]
    SchemeDenied { scheme: String },
    #[error("authority {authority:?} is not allowed by the HttpEgressContract")]
    AuthorityDenied { authority: String },
    #[error("loopback egress target denied: {host}")]
    LoopbackDenied { host: String },
    #[error("link-local egress target denied: {host}")]
    LinkLocalDenied { host: String },
    #[error("IPv6 unique-local egress target denied: {host}")]
    Ipv6UlaDenied { host: String },
    #[error("private network egress target denied: {host}")]
    PrivateNetworkDenied { host: String },
    #[error("failed to resolve egress target {host}: {details}")]
    DnsResolutionFailed { host: String, details: String },
    #[error("redirect chain length {observed} exceeds maximum {max}")]
    RedirectLimitExceeded { observed: u8, max: u8 },
    #[error("response size {observed} exceeds maximum {max}")]
    ResponseTooLarge { observed: u64, max: u64 },
}

impl HttpEgressContract {
    /// Enforce a required contract. `None` is a fail-closed denial.
    pub fn enforce_required(
        contract: Option<&Self>,
        target_url: &str,
        redirect_chain_len: u8,
        observed_response_bytes: Option<u64>,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let contract = contract.ok_or(HttpEgressError::MissingContract)?;
        contract.enforce_attempt(target_url, redirect_chain_len, observed_response_bytes)
    }

    /// Enforce target, redirect, and optional response-size bounds.
    pub fn enforce_attempt(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
        observed_response_bytes: Option<u64>,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.prepare()?
            .enforce_attempt(target_url, redirect_chain_len, observed_response_bytes)
    }

    /// Enforce target URL and redirect hop constraints.
    pub fn enforce_url(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.prepare()?.enforce_url(target_url, redirect_chain_len)
    }

    /// Enforce target URL, redirect hop constraints, and DNS safety.
    ///
    /// Literal IPs and localhost names are enforced directly. Domain names are
    /// resolved here and every resolved IP is checked against the address-class
    /// policy before the caller opens a socket.
    pub fn enforce_url_with_dns(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.prepare()?
            .enforce_url_with_dns(target_url, redirect_chain_len)
    }

    /// Enforce the response-byte ceiling after headers or streaming counters
    /// expose the observed size.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        self.prepare()?.enforce_response_bytes(observed)
    }

    /// Validate the contract shape before use.
    pub fn validate(&self) -> Result<(), HttpEgressError> {
        if self.tenant_egress_namespace.trim().is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "tenant_egress_namespace must be non-empty".to_string(),
            ));
        }
        if self.allowed_schemes.is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "allowed_schemes must be non-empty".to_string(),
            ));
        }
        if self.allowed_authority_set.is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "allowed_authority_set must be non-empty".to_string(),
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(HttpEgressError::InvalidContract(
                "max_response_bytes must be greater than zero".to_string(),
            ));
        }
        for scheme in &self.allowed_schemes {
            validate_scheme_token(scheme)?;
        }
        for authority in &self.allowed_authority_set {
            validate_authority_token(authority)?;
        }
        Ok(())
    }

    /// Validate this raw contract and return an immutable enforcement handle.
    pub fn prepare(&self) -> Result<PreparedHttpEgressContract, HttpEgressError> {
        self.validate()?;
        Ok(PreparedHttpEgressContract {
            contract: self.clone(),
            tenant_egress_namespace: self.tenant_egress_namespace.trim().to_string(),
        })
    }

    /// Validate that this contract can be used by the reqwest-backed
    /// dispatcher whose resolver enforces address-class policy at connect
    /// time.
    pub fn validate_dispatchable_with_pinned_dns(&self) -> Result<(), HttpEgressError> {
        self.validate()?;
        for authority in &self.allowed_authority_set {
            validate_dispatchable_authority(authority)?;
        }
        Ok(())
    }

    fn enforce_host_class(&self, host: &Host<&str>) -> Result<(), HttpEgressError> {
        match host {
            Host::Domain(domain) => {
                let normalized = normalize_domain_name(domain);
                self.enforce_loopback_hostname(&normalized)?;
            }
            Host::Ipv4(address) => self.enforce_ipv4_class(*address)?,
            Host::Ipv6(address) => self.enforce_ipv6_class(*address)?,
        }
        Ok(())
    }

    fn enforce_loopback_hostname(&self, normalized: &str) -> Result<(), HttpEgressError> {
        if self.deny_loopback && matches!(normalized, "localhost" | "localhost.localdomain") {
            return Err(HttpEgressError::LoopbackDenied {
                host: normalized.to_string(),
            });
        }
        Ok(())
    }

    fn enforce_ipv4_class(&self, address: Ipv4Addr) -> Result<(), HttpEgressError> {
        self.enforce_ip_address_class(address.to_string(), classify_ipv4_address(&address))
    }

    fn enforce_ipv6_class(&self, address: Ipv6Addr) -> Result<(), HttpEgressError> {
        if let Some(mapped) = address.to_ipv4_mapped() {
            return self.enforce_ipv4_class(mapped);
        }
        self.enforce_ip_address_class(address.to_string(), classify_ipv6_address(&address))
    }

    /// Enforce address-class denials after a domain has resolved to an IP.
    pub fn enforce_resolved_ip(&self, host: &str, address: IpAddr) -> Result<(), HttpEgressError> {
        match address {
            IpAddr::V4(address) => {
                self.enforce_ip_address_class(
                    format!("{host} resolved to {address}"),
                    classify_ipv4_address(&address),
                )?;
            }
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    return self.enforce_resolved_ip(host, IpAddr::V4(mapped));
                }
                self.enforce_ip_address_class(
                    format!("{host} resolved to {address}"),
                    classify_ipv6_address(&address),
                )?;
            }
        }
        Ok(())
    }

    fn enforce_ip_address_class(
        &self,
        host: String,
        class: IpAddressClass,
    ) -> Result<(), HttpEgressError> {
        match class {
            IpAddressClass::Global => Ok(()),
            IpAddressClass::Loopback => {
                if self.deny_loopback {
                    return Err(HttpEgressError::LoopbackDenied { host });
                }
                Ok(())
            }
            IpAddressClass::LinkLocal => {
                if self.deny_link_local {
                    return Err(HttpEgressError::LinkLocalDenied { host });
                }
                Ok(())
            }
            IpAddressClass::Ipv6Ula => {
                if self.deny_ipv6_ula {
                    return Err(HttpEgressError::Ipv6UlaDenied { host });
                }
                Ok(())
            }
            IpAddressClass::PrivateOrSpecialUse => {
                Err(HttpEgressError::PrivateNetworkDenied { host })
            }
        }
    }

    fn enforce_domain_resolution(&self, url: &Url) -> Result<(), HttpEgressError> {
        let Some(Host::Domain(domain)) = url.host() else {
            return Ok(());
        };
        let normalized = normalize_domain_name(domain);
        self.enforce_loopback_hostname(&normalized)?;
        let port = url.port_or_known_default().ok_or_else(|| {
            HttpEgressError::InvalidUrl(format!(
                "egress URL {url} has no explicit port or known default port"
            ))
        })?;
        let addrs = (normalized.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| HttpEgressError::DnsResolutionFailed {
                host: normalized.clone(),
                details: error.to_string(),
            })?;
        let mut saw_addr = false;
        for addr in addrs {
            saw_addr = true;
            self.enforce_resolved_ip(&normalized, addr.ip())?;
        }
        if !saw_addr {
            return Err(HttpEgressError::DnsResolutionFailed {
                host: normalized,
                details: "resolver returned no addresses".to_string(),
            });
        }
        Ok(())
    }

    fn authority_is_allowed(&self, url: &Url, authority: &str) -> Result<bool, HttpEgressError> {
        if self.allowed_authority_set.contains(authority) {
            return Ok(true);
        }
        let host_authority = normalized_url_host_authority(url)?;
        if url.port().is_some()
            && url.port() == url.port_or_known_default()
            && self.allowed_authority_set.contains(&host_authority)
        {
            return Ok(true);
        }
        if let Some(default_port) = url.port_or_known_default() {
            let default_port_authority = format!("{host_authority}:{default_port}");
            return Ok(self.allowed_authority_set.contains(&default_port_authority));
        }
        Ok(false)
    }

    #[cfg(feature = "reqwest-egress")]
    fn enforce_resolver_hostname(&self, host: &str) -> Result<(), HttpEgressError> {
        self.prepare()?.enforce_resolver_hostname(host)
    }
}

impl PreparedHttpEgressContract {
    /// Return the validated raw contract that backs this prepared handle.
    #[must_use]
    pub fn contract(&self) -> &HttpEgressContract {
        &self.contract
    }

    /// Return the normalized tenant namespace captured during preparation.
    #[must_use]
    pub fn tenant_egress_namespace(&self) -> &str {
        &self.tenant_egress_namespace
    }

    /// Return the prepared redirect-hop ceiling.
    #[must_use]
    pub fn max_redirect_chain(&self) -> u8 {
        self.contract.max_redirect_chain
    }

    /// Return the prepared response-byte ceiling.
    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.contract.max_response_bytes
    }

    /// Enforce target, redirect, and optional response-size bounds.
    pub fn enforce_attempt(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
        observed_response_bytes: Option<u64>,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        if let Some(observed) = observed_response_bytes {
            self.enforce_response_bytes(observed)?;
        }
        Ok(target)
    }

    /// Enforce target URL and redirect hop constraints.
    pub fn enforce_url(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        if redirect_chain_len > self.contract.max_redirect_chain {
            return Err(HttpEgressError::RedirectLimitExceeded {
                observed: redirect_chain_len,
                max: self.contract.max_redirect_chain,
            });
        }

        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpEgressError::UserinfoDenied);
        }

        let scheme = url.scheme().to_ascii_lowercase();
        if !self.contract.allowed_schemes.contains(&scheme) {
            return Err(HttpEgressError::SchemeDenied { scheme });
        }

        let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
        self.contract.enforce_host_class(&host)?;

        let authority = normalized_url_authority(&url)?;
        if !self.contract.authority_is_allowed(&url, &authority)? {
            return Err(HttpEgressError::AuthorityDenied { authority });
        }

        Ok(ValidatedHttpEgressTarget {
            tenant_egress_namespace: self.tenant_egress_namespace.clone(),
            scheme,
            authority,
        })
    }

    /// Enforce target URL, redirect hop constraints, and DNS safety.
    pub fn enforce_url_with_dns(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        self.contract.enforce_domain_resolution(&url)?;
        Ok(target)
    }

    /// Enforce the response-byte ceiling.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        if observed > self.contract.max_response_bytes {
            return Err(HttpEgressError::ResponseTooLarge {
                observed,
                max: self.contract.max_response_bytes,
            });
        }
        Ok(())
    }

    /// Validate that this prepared contract can be used by the reqwest-backed
    /// dispatcher whose resolver enforces address-class policy at connect time.
    pub fn validate_dispatchable_with_pinned_dns(&self) -> Result<(), HttpEgressError> {
        for authority in &self.contract.allowed_authority_set {
            validate_dispatchable_authority(authority)?;
        }
        Ok(())
    }

    #[cfg(feature = "reqwest-egress")]
    fn enforce_resolver_hostname(&self, host: &str) -> Result<(), HttpEgressError> {
        self.validate_dispatchable_with_pinned_dns()?;
        let normalized = normalize_domain_name(host);
        if normalized.is_empty() {
            return Err(HttpEgressError::MissingAuthority);
        }
        self.contract.enforce_loopback_hostname(&normalized)?;
        for authority in &self.contract.allowed_authority_set {
            if normalized_authority_host(authority)? == normalized {
                return Ok(());
            }
        }
        Err(HttpEgressError::AuthorityDenied {
            authority: normalized,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

fn validate_scheme_token(scheme: &str) -> Result<(), HttpEgressError> {
    let bytes = scheme.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed scheme {scheme:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed scheme {scheme:?}"
        )));
    }
    if !matches!(scheme, "http" | "https") {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid HTTP egress scheme {scheme:?}; expected \"http\" or \"https\""
        )));
    }
    Ok(())
}

fn validate_authority_token(authority: &str) -> Result<(), HttpEgressError> {
    if authority.trim().is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority != authority.trim()
        || authority != authority.to_ascii_lowercase()
        || authority.ends_with(':')
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}"
        )));
    }
    validate_dispatchable_authority(authority)?;
    let normalized = normalize_authority_token(authority)?;
    if normalized != authority {
        return Err(HttpEgressError::InvalidContract(format!(
            "allowed authority {authority:?} must be normalized as {normalized:?}"
        )));
    }
    Ok(())
}

fn validate_dispatchable_authority(authority: &str) -> Result<(), HttpEgressError> {
    let _ = normalized_authority_host(authority)?;
    Ok(())
}

fn normalize_authority_token(authority: &str) -> Result<String, HttpEgressError> {
    let parsed = Url::parse(&format!("http://{authority}/")).map_err(|error| {
        HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}: {error}"
        ))
    })?;
    let host = parsed.host().ok_or_else(|| {
        HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
    })?;
    let normalized_host = match host {
        Host::Domain(domain) => normalize_domain_name(domain),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    if authority_has_explicit_port(authority) {
        let port = parsed.port_or_known_default().ok_or_else(|| {
            HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
        })?;
        return Ok(format!("{normalized_host}:{port}"));
    }
    Ok(normalized_host)
}

fn authority_has_explicit_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        return authority
            .rsplit_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':'));
    }
    authority
        .rsplit_once(':')
        .is_some_and(|(host, _)| !host.contains(':'))
}

fn normalized_authority_host(authority: &str) -> Result<String, HttpEgressError> {
    let parsed = Url::parse(&format!("http://{authority}/")).map_err(|error| {
        HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}: {error}"
        ))
    })?;
    let host = parsed.host().ok_or_else(|| {
        HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
    })?;
    Ok(match host {
        Host::Domain(domain) => normalize_domain_name(domain),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn normalize_domain_name(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpAddressClass {
    Global,
    Loopback,
    LinkLocal,
    Ipv6Ula,
    PrivateOrSpecialUse,
}

fn classify_ipv4_address(address: &Ipv4Addr) -> IpAddressClass {
    if address.is_loopback() {
        return IpAddressClass::Loopback;
    }
    if address.is_link_local() {
        return IpAddressClass::LinkLocal;
    }
    if is_ipv4_private_or_special_use(address) {
        return IpAddressClass::PrivateOrSpecialUse;
    }
    IpAddressClass::Global
}

fn classify_ipv6_address(address: &Ipv6Addr) -> IpAddressClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4_address(&mapped);
    }
    if address.is_loopback() {
        return IpAddressClass::Loopback;
    }
    if is_ipv6_unicast_link_local(address) {
        return IpAddressClass::LinkLocal;
    }
    if is_ipv6_unique_local(address) {
        return IpAddressClass::Ipv6Ula;
    }
    if is_ipv6_private_or_special_use(address) {
        return IpAddressClass::PrivateOrSpecialUse;
    }
    IpAddressClass::Global
}

fn normalized_url_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = normalized_url_host_authority(url)?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn normalized_url_host_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
    Ok(match host {
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    })
}

fn is_ipv6_unicast_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_ipv4_private_or_special_use(address: &Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_broadcast()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

fn is_ipv6_private_or_special_use(address: &Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_ipv4_private_or_special_use(&mapped);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// Optional helper that pairs a `reqwest::Client` dispatch with
/// `HttpEgressContract` enforcement. Behind the `reqwest-egress` feature so
/// callers that already depend on `reqwest` get a single fail-closed entry
/// point and substrate adapters can keep their existing client builder.
#[cfg(feature = "reqwest-egress")]
pub mod reqwest_helper;

#[cfg(feature = "reqwest-egress")]
#[allow(unused_imports)]
pub use reqwest_helper::{
    client_builder_with_contract, send_with_contract, ContractClientBuilder, ContractResponse,
};

impl HttpEgressContract {
    /// Construct a permissive contract suitable for tests that exercise a
    /// wiremock or other local loopback HTTP server. Production code MUST NOT
    /// use this; production always builds a contract from tenant-scoped
    /// substrate config.
    ///
    /// Loopback, link-local and IPv6 ULA denials are disabled so wiremock's
    /// `127.0.0.1:<port>` URL is accepted. Authority allow-list is wildcard
    /// per `allowed_authority_set` semantics: caller supplies the wiremock
    /// authority. Schemes default to `http` and `https`.
    pub fn permissive_for_tests(authority: &str) -> Self {
        let mut allowed_schemes = BTreeSet::new();
        allowed_schemes.insert("http".to_string());
        allowed_schemes.insert("https".to_string());
        let mut allowed_authority_set = BTreeSet::new();
        allowed_authority_set.insert(authority.to_ascii_lowercase());
        Self {
            tenant_egress_namespace: "tests".to_string(),
            allowed_schemes,
            allowed_authority_set,
            deny_loopback: false,
            deny_link_local: false,
            deny_ipv6_ula: false,
            max_redirect_chain: 4,
            max_response_bytes: 64 * 1024 * 1024,
        }
    }
}
