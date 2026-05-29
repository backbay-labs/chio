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
        if !self.authority_is_allowed(&url, &authority)? {
            return Err(HttpEgressError::AuthorityDenied { authority });
        }

        Ok(ValidatedHttpEgressTarget {
            tenant_egress_namespace: self.tenant_egress_namespace.trim().to_string(),
            scheme,
            authority,
        })
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
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        self.enforce_domain_resolution(&url)?;
        Ok(target)
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

    /// Enforce address-class denials after a domain has resolved to an IP.
    pub fn enforce_resolved_ip(&self, host: &str, address: IpAddr) -> Result<(), HttpEgressError> {
        match address {
            IpAddr::V4(address) => {
                if address.is_loopback() {
                    if self.deny_loopback {
                        return Err(HttpEgressError::LoopbackDenied {
                            host: format!("{host} resolved to {address}"),
                        });
                    }
                    return Ok(());
                }
                if address.is_link_local() {
                    if self.deny_link_local {
                        return Err(HttpEgressError::LinkLocalDenied {
                            host: format!("{host} resolved to {address}"),
                        });
                    }
                    return Ok(());
                }
                if is_ipv4_private_or_special_use(&address) {
                    return Err(HttpEgressError::PrivateNetworkDenied {
                        host: format!("{host} resolved to {address}"),
                    });
                }
            }
            IpAddr::V6(address) => {
                if let Some(mapped) = address.to_ipv4_mapped() {
                    return self.enforce_resolved_ip(host, IpAddr::V4(mapped));
                }
                if address.is_loopback() {
                    if self.deny_loopback {
                        return Err(HttpEgressError::LoopbackDenied {
                            host: format!("{host} resolved to {address}"),
                        });
                    }
                    return Ok(());
                }
                if is_ipv6_unicast_link_local(&address) {
                    if self.deny_link_local {
                        return Err(HttpEgressError::LinkLocalDenied {
                            host: format!("{host} resolved to {address}"),
                        });
                    }
                    return Ok(());
                }
                if is_ipv6_unique_local(&address) {
                    if self.deny_ipv6_ula {
                        return Err(HttpEgressError::Ipv6UlaDenied {
                            host: format!("{host} resolved to {address}"),
                        });
                    }
                    return Ok(());
                }
                if is_ipv6_private_or_special_use(&address) {
                    return Err(HttpEgressError::PrivateNetworkDenied {
                        host: format!("{host} resolved to {address}"),
                    });
                }
            }
        }
        Ok(())
    }

    fn enforce_domain_resolution(&self, url: &Url) -> Result<(), HttpEgressError> {
        let Some(Host::Domain(domain)) = url.host() else {
            return Ok(());
        };
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        if self.deny_loopback
            && matches!(normalized.as_str(), "localhost" | "localhost.localdomain")
        {
            return Err(HttpEgressError::LoopbackDenied { host: normalized });
        }
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

    fn enforce_resolver_hostname(&self, host: &str) -> Result<(), HttpEgressError> {
        self.validate_dispatchable_with_pinned_dns()?;
        let normalized = normalize_domain_name(host);
        if normalized.is_empty() {
            return Err(HttpEgressError::MissingAuthority);
        }
        if self.deny_loopback
            && matches!(normalized.as_str(), "localhost" | "localhost.localdomain")
        {
            return Err(HttpEgressError::LoopbackDenied { host: normalized });
        }
        for authority in &self.allowed_authority_set {
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
mod tests {
    use super::{HttpEgressContract, HttpEgressError};
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn strict_contract(authority: &str) -> HttpEgressContract {
        let mut allowed_schemes = BTreeSet::new();
        allowed_schemes.insert("https".to_string());
        let mut allowed_authority_set = BTreeSet::new();
        allowed_authority_set.insert(authority.to_string());
        HttpEgressContract {
            tenant_egress_namespace: "tenant-a".to_string(),
            allowed_schemes,
            allowed_authority_set,
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 3,
            max_response_bytes: 1024,
        }
    }

    #[test]
    fn explicit_default_port_matches_no_port_allowlist_entry() {
        strict_contract("api.example.com")
            .enforce_url("https://api.example.com:443/v1", 0)
            .expect("explicit default port should match no-port authority");
    }

    #[test]
    fn no_port_url_matches_explicit_default_port_allowlist_entry() {
        strict_contract("api.example.com:443")
            .enforce_url("https://api.example.com/v1", 0)
            .expect("no-port URL should match explicit default-port authority");
    }

    #[test]
    fn resolved_loopback_respects_loopback_allowance() {
        let contract = HttpEgressContract::permissive_for_tests("localhost:80");
        contract
            .enforce_resolved_ip("localhost", IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("loopback may be explicitly allowed for local test contracts");

        let mut denied = contract;
        denied.deny_loopback = true;
        let error = denied
            .enforce_resolved_ip("localhost", IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect_err("loopback should fail when the flag is enabled");
        assert!(matches!(error, HttpEgressError::LoopbackDenied { .. }));
    }

    #[test]
    fn resolved_ipv6_ula_respects_ula_allowance() {
        let contract = HttpEgressContract::permissive_for_tests("[fc00::1]:80");
        contract
            .enforce_resolved_ip("ula.test", IpAddr::V6("fc00::1".parse().unwrap()))
            .expect("ULA may be explicitly allowed for local test contracts");

        let mut denied = contract;
        denied.deny_ipv6_ula = true;
        let error = denied
            .enforce_resolved_ip("ula.test", IpAddr::V6("fc00::1".parse().unwrap()))
            .expect_err("ULA should fail when the flag is enabled");
        assert!(matches!(error, HttpEgressError::Ipv6UlaDenied { .. }));
    }

    #[test]
    fn resolved_public_ip_is_allowed() {
        strict_contract("example.com")
            .enforce_resolved_ip(
                "example.com",
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0, 0, 0, 0)),
            )
            .expect("global resolved addresses remain allowed");
    }
}

#[cfg(all(test, feature = "reqwest-egress"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod reqwest_egress_tests {
    use super::reqwest_helper::{client_builder_with_contract, send_with_contract};
    use super::{HttpEgressContract, HttpEgressError};
    use std::io::{ErrorKind, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    fn authority(addr: SocketAddr) -> String {
        format!("{}:{}", addr.ip(), addr.port())
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn spawn_single_response_server<F>(
        response_for_request: F,
    ) -> (SocketAddr, Receiver<String>, JoinHandle<()>)
    where
        F: FnOnce(String) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("read local addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            tx.send(request.clone()).expect("send captured request");
            let response = response_for_request(request);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (addr, rx, handle)
    }

    fn spawn_single_localhost_response_server<F>(
        response_for_request: F,
    ) -> (SocketAddr, Receiver<String>, JoinHandle<()>)
    where
        F: FnOnce(String) -> String + Send + 'static,
    {
        let bind_ip = ("localhost", 0)
            .to_socket_addrs()
            .expect("resolve localhost")
            .next()
            .map(|addr| addr.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0)).expect("bind test server");
        let addr = listener.local_addr().expect("read local addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            tx.send(request.clone()).expect("send captured request");
            let response = response_for_request(request);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (addr, rx, handle)
    }

    fn spawn_optional_response_server<F>(
        response_for_request: F,
    ) -> (SocketAddr, Receiver<Option<String>>, JoinHandle<()>)
    where
        F: FnOnce(String) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("configure nonblocking test server");
        let addr = listener.local_addr().expect("read local addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_http_request(&mut stream);
                        tx.send(Some(request.clone()))
                            .expect("send captured request");
                        let response = response_for_request(request);
                        stream
                            .write_all(response.as_bytes())
                            .expect("write response");
                        return;
                    }
                    Err(error)
                        if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        tx.send(None).expect("send no request observation");
                        return;
                    }
                    Err(error) => panic!("accept request: {error}"),
                }
            }
        });
        (addr, rx, handle)
    }

    #[tokio::test]
    async fn send_with_contract_validates_redirect_before_following() {
        let denied_target = "http://127.0.0.1:9/final";
        let (start_addr, _start_rx, start_handle) = spawn_single_response_server({
            let denied_target = denied_target.to_string();
            move |_| {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {denied_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });
        let contract = HttpEgressContract::permissive_for_tests(&authority(start_addr));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/start", authority(start_addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("redirect target should be denied before follow");
        assert!(matches!(error, HttpEgressError::AuthorityDenied { .. }));
        start_handle.join().expect("join start server");
    }

    #[tokio::test]
    async fn send_with_contract_strips_sensitive_headers_on_cross_origin_redirect() {
        let (final_addr, final_rx, final_handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        });
        let final_url = format!("http://{}/final", authority(final_addr));
        let (start_addr, _start_rx, start_handle) = spawn_single_response_server({
            let final_url = final_url.clone();
            move |_| {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {final_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });

        let mut contract = HttpEgressContract::permissive_for_tests(&authority(start_addr));
        contract.allowed_authority_set.insert(authority(final_addr));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/start", authority(start_addr)))
            .header(reqwest::header::AUTHORIZATION, "Bearer secret")
            .header(reqwest::header::COOKIE, "sid=secret")
            .build()
            .expect("build request");

        let response = send_with_contract(&contract, &client, request)
            .await
            .expect("follow redirect");
        assert_eq!(response.body(), b"ok");

        let final_request = final_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("capture final request");
        let final_request = final_request.to_ascii_lowercase();
        assert!(!final_request.contains("authorization:"));
        assert!(!final_request.contains("cookie:"));

        start_handle.join().expect("join start server");
        final_handle.join().expect("join final server");
    }

    async fn assert_cross_origin_post_preserving_redirect_is_denied(status_line: &str) {
        let (final_addr, final_rx, final_handle) = spawn_optional_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        });
        let final_url = format!("http://{}/final", authority(final_addr));
        let (start_addr, _start_rx, start_handle) = spawn_single_response_server({
            let final_url = final_url.clone();
            let status_line = status_line.to_string();
            move |_| {
                format!(
                    "HTTP/1.1 {status_line}\r\nLocation: {final_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });

        let mut contract = HttpEgressContract::permissive_for_tests(&authority(start_addr));
        contract.allowed_authority_set.insert(authority(final_addr));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .post(format!("http://{}/start", authority(start_addr)))
            .body("mutation=true")
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("cross-origin POST redirect preserving body should be denied");
        assert!(
            error
                .to_string()
                .contains("cross-origin redirect method/body denied"),
            "unexpected redirect denial: {error}"
        );

        let observed = final_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("final server observation");
        assert!(observed.is_none(), "forbidden redirect target was reached");

        start_handle.join().expect("join start server");
        final_handle.join().expect("join final server");
    }

    #[tokio::test]
    async fn send_with_contract_denies_cross_origin_post_301_before_rewrite() {
        assert_cross_origin_post_preserving_redirect_is_denied("301 Moved Permanently").await;
    }

    #[tokio::test]
    async fn send_with_contract_denies_cross_origin_post_302_before_rewrite() {
        assert_cross_origin_post_preserving_redirect_is_denied("302 Found").await;
    }

    #[tokio::test]
    async fn send_with_contract_denies_cross_origin_post_303_before_rewrite() {
        assert_cross_origin_post_preserving_redirect_is_denied("303 See Other").await;
    }

    #[tokio::test]
    async fn send_with_contract_denies_cross_origin_post_307_before_replay() {
        assert_cross_origin_post_preserving_redirect_is_denied("307 Temporary Redirect").await;
    }

    #[tokio::test]
    async fn send_with_contract_denies_cross_origin_post_308_before_replay() {
        assert_cross_origin_post_preserving_redirect_is_denied("308 Permanent Redirect").await;
    }

    #[tokio::test]
    async fn send_with_contract_denies_oversized_response_body() {
        let (addr, _rx, handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef".to_string()
        });
        let mut contract = HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = 5;
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/body", authority(addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("oversized response should be rejected");
        assert!(matches!(
            error,
            HttpEgressError::ResponseTooLarge {
                observed: 6,
                max: 5
            }
        ));
        handle.join().expect("join server");
    }

    #[tokio::test]
    async fn send_with_contract_denies_oversized_response_without_content_length() {
        let (addr, _rx, handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_string()
        });
        let mut contract = HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = 5;
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/body", authority(addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("streamed response should be capped");
        assert!(matches!(error, HttpEgressError::ResponseTooLarge { .. }));
        handle.join().expect("join server");
    }

    #[test]
    fn validate_dispatchable_accepts_production_domain_hostnames_for_pinned_resolver() {
        let mut contract = HttpEgressContract::permissive_for_tests("rebind.test:80");
        contract.deny_loopback = true;
        contract.deny_link_local = true;
        contract.deny_ipv6_ula = true;

        contract
            .validate_dispatchable_with_pinned_dns()
            .expect("domain hostnames are dispatchable through the pinned resolver");
        client_builder_with_contract(&contract)
            .build()
            .expect("hostname contract builds a resolver-backed reqwest client");
    }

    #[test]
    fn resolved_hostname_private_address_fails_closed() {
        let mut contract = HttpEgressContract::permissive_for_tests("rebind.test:80");
        contract.deny_loopback = true;
        contract.deny_link_local = true;
        contract.deny_ipv6_ula = true;

        let error = contract
            .enforce_resolved_ip("rebind.test", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)))
            .expect_err("private DNS answers must fail closed");
        assert!(matches!(
            error,
            HttpEgressError::PrivateNetworkDenied { .. }
        ));
    }

    #[test]
    fn resolved_hostname_special_use_addresses_fail_closed() {
        let mut contract = HttpEgressContract::permissive_for_tests("rebind.test:80");
        contract.deny_loopback = true;
        contract.deny_link_local = true;
        contract.deny_ipv6_ula = true;

        for address in [
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("fe80::1".parse().expect("parse link-local")),
            IpAddr::V6("fc00::1".parse().expect("parse unique-local")),
            IpAddr::V6("::ffff:10.0.0.8".parse().expect("parse mapped private")),
            IpAddr::V6("::ffff:0.0.0.0".parse().expect("parse mapped zero")),
            IpAddr::V6(
                "::ffff:255.255.255.255"
                    .parse()
                    .expect("parse mapped broadcast"),
            ),
        ] {
            let error = contract
                .enforce_resolved_ip("rebind.test", address)
                .expect_err("special-use DNS answers must fail closed");
            assert!(
                matches!(
                    error,
                    HttpEgressError::LoopbackDenied { .. }
                        | HttpEgressError::LinkLocalDenied { .. }
                        | HttpEgressError::Ipv6UlaDenied { .. }
                        | HttpEgressError::PrivateNetworkDenied { .. }
                ),
                "unexpected special-use denial for {address}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn send_with_contract_dispatches_localhost_through_contract_resolver() {
        let (addr, _rx, handle) = spawn_single_localhost_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        });
        let contract =
            HttpEgressContract::permissive_for_tests(&format!("localhost:{}", addr.port()));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://localhost:{}/health", addr.port()))
            .build()
            .expect("build request");

        let response = send_with_contract(&contract, &client, request)
            .await
            .expect("localhost dispatch goes through contract resolver");
        assert_eq!(response.body(), b"ok");
        handle.join().expect("join server");
    }

    #[test]
    fn enforce_url_with_dns_preserves_localhost_when_loopback_is_allowed() {
        let contract = HttpEgressContract::permissive_for_tests("localhost:8080");
        contract
            .enforce_url_with_dns("http://localhost:8080/health", 0)
            .expect("localhost remains available for explicit loopback contracts");
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

fn validate_dispatchable_authority(authority: &str) -> Result<(), HttpEgressError> {
    let _ = normalized_authority_host(authority)?;
    Ok(())
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
pub mod reqwest_helper {
    use super::{HttpEgressContract, HttpEgressError};
    use reqwest::header::{
        HeaderMap, HeaderName, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
        PROXY_AUTHORIZATION,
    };
    use reqwest::{Method, StatusCode, Url};
    use serde::de::DeserializeOwned;
    use std::error::Error;
    use std::sync::Arc;

    /// Response returned by [`send_with_contract`] after the full response body
    /// has been read under the contract byte ceiling.
    #[derive(Debug, Clone)]
    pub struct ContractResponse {
        status: StatusCode,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl ContractResponse {
        #[must_use]
        pub fn status(&self) -> StatusCode {
            self.status
        }

        #[must_use]
        pub fn url(&self) -> &Url {
            &self.url
        }

        #[must_use]
        pub fn headers(&self) -> &HeaderMap {
            &self.headers
        }

        #[must_use]
        pub fn body(&self) -> &[u8] {
            &self.body
        }

        pub async fn text(self) -> Result<String, std::string::FromUtf8Error> {
            String::from_utf8(self.body)
        }

        pub async fn json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
            serde_json::from_slice(&self.body)
        }
    }

    /// Wrap a `reqwest::Client::execute` call with [`HttpEgressContract`]
    /// enforcement before each network hop and while reading the response body.
    /// The supplied client must be built with [`client_builder_with_contract`],
    /// which disables reqwest's automatic redirect following so this helper can
    /// validate each `Location` target before issuing the next request.
    pub async fn send_with_contract(
        contract: &HttpEgressContract,
        client: &reqwest::Client,
        request: reqwest::Request,
    ) -> Result<ContractResponse, HttpEgressError> {
        let mut request = request;
        let mut redirect_chain_len = 0_u8;

        loop {
            let request_url = request.url().clone();
            contract.enforce_url_with_dns(request_url.as_str(), redirect_chain_len)?;
            let reusable_request = request.try_clone();
            let redirect_request = RedirectRequestParts {
                method: request.method().clone(),
                headers: request.headers().clone(),
                has_body: request.body().is_some(),
            };

            let response = client.execute(request).await.map_err(map_reqwest_error)?;
            if response.url() != &request_url {
                return Err(HttpEgressError::InvalidUrl(
                    "reqwest client followed a redirect internally; build it with client_builder_with_contract"
                        .to_string(),
                ));
            }

            let status = response.status();
            if is_redirect_status(status) {
                if let Some(location) = response.headers().get(LOCATION).cloned() {
                    if redirect_chain_len >= contract.max_redirect_chain {
                        return Err(HttpEgressError::RedirectLimitExceeded {
                            observed: redirect_chain_len.saturating_add(1),
                            max: contract.max_redirect_chain,
                        });
                    }
                    let location = location.to_str().map_err(|error| {
                        HttpEgressError::InvalidUrl(format!(
                            "invalid redirect Location header from {request_url}: {error}"
                        ))
                    })?;
                    let next_url = request_url.join(location).map_err(|error| {
                        HttpEgressError::InvalidUrl(format!(
                            "invalid redirect target `{location}` from {request_url}: {error}"
                        ))
                    })?;
                    let next_chain_len = redirect_chain_len.saturating_add(1);
                    contract.enforce_url_with_dns(next_url.as_str(), next_chain_len)?;
                    let cross_origin = !same_origin(&request_url, &next_url);
                    request = build_redirect_request(
                        client,
                        reusable_request,
                        redirect_request,
                        status,
                        next_url,
                        cross_origin,
                    )?;
                    redirect_chain_len = next_chain_len;
                    continue;
                }
            }

            return collect_capped_response(contract, response).await;
        }
    }

    fn is_redirect_status(status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        )
    }

    /// Builder for a contract-backed reqwest client. It deliberately exposes
    /// only safe tuning knobs so callers cannot override the DNS resolver,
    /// proxy policy, or redirect policy after contract protections are applied.
    pub struct ContractClientBuilder {
        inner: reqwest::ClientBuilder,
    }

    impl ContractClientBuilder {
        #[must_use]
        pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
            self.inner = self.inner.timeout(timeout);
            self
        }

        pub fn build(self) -> Result<reqwest::Client, reqwest::Error> {
            self.inner.build()
        }
    }

    /// Build a contract-backed reqwest client builder. [`send_with_contract`]
    /// manually follows redirects after validating each hop and stripping
    /// sensitive headers on cross-origin hops.
    pub fn client_builder_with_contract(contract: &HttpEgressContract) -> ContractClientBuilder {
        ContractClientBuilder {
            inner: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .dns_resolver(Arc::new(ContractDnsResolver::new(contract.clone()))),
        }
    }

    #[derive(Clone)]
    struct ContractDnsResolver {
        contract: HttpEgressContract,
    }

    impl ContractDnsResolver {
        fn new(contract: HttpEgressContract) -> Self {
            Self { contract }
        }
    }

    impl reqwest::dns::Resolve for ContractDnsResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let contract = self.contract.clone();
            let host = name.as_str().to_string();
            Box::pin(async move {
                if let Err(error) = contract.enforce_resolver_hostname(&host) {
                    return Err(boxed_egress_error(error));
                }

                let lookup = match tokio::net::lookup_host((host.as_str(), 0)).await {
                    Ok(lookup) => lookup,
                    Err(error) => {
                        return Err(boxed_egress_error(HttpEgressError::DnsResolutionFailed {
                            host: host.clone(),
                            details: error.to_string(),
                        }));
                    }
                };

                let mut addrs = Vec::new();
                for mut addr in lookup {
                    if let Err(error) = contract.enforce_resolved_ip(&host, addr.ip()) {
                        return Err(boxed_egress_error(error));
                    }
                    addr.set_port(0);
                    addrs.push(addr);
                }

                if addrs.is_empty() {
                    return Err(boxed_egress_error(HttpEgressError::DnsResolutionFailed {
                        host: host.clone(),
                        details: "resolver returned no addresses".to_string(),
                    }));
                }

                Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
            })
        }
    }

    fn boxed_egress_error(error: HttpEgressError) -> Box<dyn Error + Send + Sync> {
        Box::new(error)
    }

    struct RedirectRequestParts {
        method: Method,
        headers: HeaderMap,
        has_body: bool,
    }

    fn build_redirect_request(
        client: &reqwest::Client,
        reusable_request: Option<reqwest::Request>,
        original: RedirectRequestParts,
        status: StatusCode,
        next_url: Url,
        cross_origin: bool,
    ) -> Result<reqwest::Request, HttpEgressError> {
        if cross_origin && (original.has_body || !is_idempotent_method(&original.method)) {
            return Err(HttpEgressError::InvalidUrl(format!(
                "cross-origin redirect method/body denied for {} {status} to {next_url}",
                original.method
            )));
        }

        let rewrite_to_get = status == StatusCode::SEE_OTHER && original.method != Method::HEAD
            || matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
                && original.method == Method::POST;
        if rewrite_to_get {
            let mut builder = client.request(Method::GET, next_url);
            for (name, value) in &original.headers {
                if should_drop_redirect_header(name, cross_origin, true) {
                    continue;
                }
                builder = builder.header(name, value);
            }
            return builder.build().map_err(map_reqwest_error);
        }

        let mut request = reusable_request.ok_or_else(|| {
            HttpEgressError::InvalidUrl(
                "redirect requires a cloneable request body to replay safely".to_string(),
            )
        })?;
        *request.url_mut() = next_url;
        strip_redirect_headers(request.headers_mut(), cross_origin, false);
        Ok(request)
    }

    fn is_idempotent_method(method: &Method) -> bool {
        matches!(
            *method,
            Method::GET
                | Method::HEAD
                | Method::PUT
                | Method::DELETE
                | Method::OPTIONS
                | Method::TRACE
        )
    }

    fn should_drop_redirect_header(
        name: &HeaderName,
        cross_origin: bool,
        body_was_dropped: bool,
    ) -> bool {
        *name == HOST
            || body_was_dropped && (*name == CONTENT_LENGTH || *name == CONTENT_TYPE)
            || cross_origin && is_sensitive_request_header(name)
    }

    fn strip_redirect_headers(headers: &mut HeaderMap, cross_origin: bool, body_was_dropped: bool) {
        let names = headers.keys().cloned().collect::<Vec<_>>();
        for name in names {
            if should_drop_redirect_header(&name, cross_origin, body_was_dropped) {
                headers.remove(name);
            }
        }
    }

    fn is_sensitive_request_header(name: &HeaderName) -> bool {
        *name == AUTHORIZATION || *name == COOKIE || *name == PROXY_AUTHORIZATION
    }

    fn same_origin(left: &Url, right: &Url) -> bool {
        left.scheme() == right.scheme()
            && left.host_str().map(str::to_ascii_lowercase)
                == right.host_str().map(str::to_ascii_lowercase)
            && left.port_or_known_default() == right.port_or_known_default()
    }

    async fn collect_capped_response(
        contract: &HttpEgressContract,
        mut response: reqwest::Response,
    ) -> Result<ContractResponse, HttpEgressError> {
        if let Some(content_length) = response.content_length() {
            contract.enforce_response_bytes(content_length)?;
        }

        let status = response.status();
        let url = response.url().clone();
        let headers = response.headers().clone();
        let mut observed = 0_u64;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            observed = observed.checked_add(chunk.len() as u64).ok_or(
                HttpEgressError::ResponseTooLarge {
                    observed: u64::MAX,
                    max: contract.max_response_bytes,
                },
            )?;
            contract.enforce_response_bytes(observed)?;
            body.extend_from_slice(&chunk);
        }

        Ok(ContractResponse {
            status,
            url,
            headers,
            body,
        })
    }

    fn map_reqwest_error(err: reqwest::Error) -> HttpEgressError {
        let kind = if err.is_timeout() {
            "timeout"
        } else if err.is_connect() {
            "connect error"
        } else if err.is_request() {
            "request error"
        } else if err.is_body() {
            "body error"
        } else if err.is_decode() {
            "decode error"
        } else {
            "transport error"
        };
        HttpEgressError::InvalidUrl(format!("dispatch failed ({kind}): {err}"))
    }
}

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
