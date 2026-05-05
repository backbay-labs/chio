//! Typed HTTP egress contracts for substrate adapters.
//!
//! Kernel, guard, and adapter code paths that initiate outbound HTTP must
//! declare one of these contracts before a target URL is accepted. Missing or
//! malformed contract state fails closed.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Typed egress policy that must be declared before substrate HTTP egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEgressContract {
    /// Tenant-scoped namespace used by callers to bind egress receipts and
    /// deployment policy to one authority domain.
    pub tenant_egress_namespace: String,
    /// Lowercase URL schemes allowed by this contract, for example `https`.
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
        self.validate()?;
        if redirect_chain_len > self.max_redirect_chain {
            return Err(HttpEgressError::RedirectLimitExceeded {
                observed: redirect_chain_len,
                max: self.max_redirect_chain,
            });
        }

        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpEgressError::UserinfoDenied);
        }

        let scheme = url.scheme().to_ascii_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(HttpEgressError::SchemeDenied { scheme });
        }

        let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
        self.enforce_host_class(&host)?;

        let authority = normalized_url_authority(&url)?;
        if !self.allowed_authority_set.contains(&authority) {
            return Err(HttpEgressError::AuthorityDenied { authority });
        }

        Ok(ValidatedHttpEgressTarget {
            tenant_egress_namespace: self.tenant_egress_namespace.trim().to_string(),
            scheme,
            authority,
        })
    }

    /// Enforce the response-byte ceiling after headers or streaming counters
    /// expose the observed size.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        self.validate()?;
        if observed > self.max_response_bytes {
            return Err(HttpEgressError::ResponseTooLarge {
                observed,
                max: self.max_response_bytes,
            });
        }
        Ok(())
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

    fn enforce_host_class(&self, host: &Host<&str>) -> Result<(), HttpEgressError> {
        match host {
            Host::Domain(domain) => {
                let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                if self.deny_loopback
                    && matches!(normalized.as_str(), "localhost" | "localhost.localdomain")
                {
                    return Err(HttpEgressError::LoopbackDenied { host: normalized });
                }
            }
            Host::Ipv4(address) => self.enforce_ipv4_class(*address)?,
            Host::Ipv6(address) => self.enforce_ipv6_class(*address)?,
        }
        Ok(())
    }

    fn enforce_ipv4_class(&self, address: Ipv4Addr) -> Result<(), HttpEgressError> {
        if self.deny_loopback && address.is_loopback() {
            return Err(HttpEgressError::LoopbackDenied {
                host: address.to_string(),
            });
        }
        if self.deny_link_local && address.is_link_local() {
            return Err(HttpEgressError::LinkLocalDenied {
                host: address.to_string(),
            });
        }
        Ok(())
    }

    fn enforce_ipv6_class(&self, address: Ipv6Addr) -> Result<(), HttpEgressError> {
        if let Some(mapped) = address.to_ipv4_mapped() {
            return self.enforce_ipv4_class(mapped);
        }
        if self.deny_loopback && address.is_loopback() {
            return Err(HttpEgressError::LoopbackDenied {
                host: address.to_string(),
            });
        }
        if self.deny_link_local && is_ipv6_unicast_link_local(&address) {
            return Err(HttpEgressError::LinkLocalDenied {
                host: address.to_string(),
            });
        }
        if self.deny_ipv6_ula && is_ipv6_unique_local(&address) {
            return Err(HttpEgressError::Ipv6UlaDenied {
                host: address.to_string(),
            });
        }
        Ok(())
    }
}

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
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}"
        )));
    }
    Ok(())
}

fn normalized_url_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
    let host = match host {
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn is_ipv6_unicast_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}
