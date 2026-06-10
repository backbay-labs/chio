use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use url::Url;

use super::ExternalGuardError;

pub fn validate_external_guard_url(field: &str, value: &str) -> Result<(), ExternalGuardError> {
    validate_external_guard_url_with_resolver(field, value, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
            .map_err(|error| error.to_string())
    })
}

pub fn validate_external_guard_url_without_dns(
    field: &str,
    value: &str,
) -> Result<(), ExternalGuardError> {
    let parsed = Url::parse(value).map_err(|error| {
        ExternalGuardError::Permanent(format!("{field} must be a valid URL: {error}"))
    })?;
    if is_localhost_http_url(&parsed) {
        return Ok(());
    }
    if parsed.scheme() != "https" {
        return Err(ExternalGuardError::Permanent(format!(
            "{field} must use https or localhost-only http"
        )));
    }
    if host_is_denied(&parsed) {
        return Err(ExternalGuardError::Permanent(format!(
            "{field} must not target localhost, link-local, or private-network hosts"
        )));
    }
    Ok(())
}

pub fn validate_external_guard_url_with_resolver<F>(
    field: &str,
    value: &str,
    resolver: F,
) -> Result<(), ExternalGuardError>
where
    F: FnOnce(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    let parsed = Url::parse(value).map_err(|error| {
        ExternalGuardError::Permanent(format!("{field} must be a valid URL: {error}"))
    })?;
    if is_localhost_http_url(&parsed) {
        return Ok(());
    }
    if parsed.scheme() != "https" {
        return Err(ExternalGuardError::Permanent(format!(
            "{field} must use https or localhost-only http"
        )));
    }
    if host_is_denied(&parsed) {
        return Err(ExternalGuardError::Permanent(format!(
            "{field} must not target localhost, link-local, or private-network hosts"
        )));
    }
    validate_dns_resolution(field, &parsed, resolver)
}

fn validate_dns_resolution<F>(
    field: &str,
    parsed: &Url,
    resolver: F,
) -> Result<(), ExternalGuardError>
where
    F: FnOnce(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    let Some(url::Host::Domain(host)) = parsed.host() else {
        return Ok(());
    };
    let port = parsed.port_or_known_default().ok_or_else(|| {
        ExternalGuardError::Permanent(format!("{field} must include a resolvable port"))
    })?;
    let addrs = resolver(host, port).map_err(|error| {
        ExternalGuardError::Transient(format!(
            "{field} host `{host}` could not be resolved: {error}"
        ))
    })?;
    if addrs.is_empty() {
        return Err(ExternalGuardError::Transient(format!(
            "{field} host `{host}` did not resolve to any addresses"
        )));
    }
    for addr in addrs {
        if denied_ip(addr) {
            return Err(ExternalGuardError::Permanent(format!(
                "{field} host `{host}` resolved to disallowed address `{addr}`"
            )));
        }
    }
    Ok(())
}

fn is_localhost_http_url(parsed: &Url) -> bool {
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn host_is_denied(parsed: &Url) -> bool {
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            host == "localhost" || host.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(address)) => denied_ip(IpAddr::V4(address)),
        Some(url::Host::Ipv6(address)) => denied_ip(IpAddr::V6(address)),
        None => true,
    }
}

pub fn denied_external_guard_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = ipv4_mapped_ipv6(address) {
                return denied_ip(IpAddr::V4(mapped));
            }
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_multicast()
                || address.is_unicast_link_local()
        }
    }
}

fn ipv4_mapped_ipv6(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = address.octets();
    if octets[0..10].iter().all(|octet| *octet == 0) && octets[10] == 0xff && octets[11] == 0xff {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

fn denied_ip(address: IpAddr) -> bool {
    denied_external_guard_ip(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn runtime_endpoint_validation_rejects_rebound_private_dns_answers() {
        let error = validate_external_guard_url_with_resolver(
            "external guard endpoint",
            "https://guard.example.test/moderate",
            |_host, _port| Ok(vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))]),
        )
        .expect_err("private DNS answers should fail closed");
        assert!(error.to_string().contains("resolved to disallowed address"));
    }

    #[test]
    fn runtime_endpoint_validation_rejects_ipv6_ula_literals() {
        let error =
            validate_external_guard_url("external guard endpoint", "https://[fd00::1]/moderate")
                .expect_err("IPv6 ULA should fail closed");
        assert!(error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"));
    }

    #[test]
    fn runtime_endpoint_validation_rejects_ipv4_multicast_literals() {
        let error =
            validate_external_guard_url("external guard endpoint", "https://224.0.0.1/moderate")
                .expect_err("IPv4 multicast should fail closed");
        assert!(error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"));
    }

    #[test]
    fn static_endpoint_validation_does_not_require_dns_resolution() {
        validate_external_guard_url_without_dns(
            "external guard endpoint",
            "https://guard.example.test/moderate",
        )
        .expect("domain-only static validation should not resolve DNS");

        let error = validate_external_guard_url_without_dns(
            "external guard endpoint",
            "http://example.com",
        )
        .expect_err("non-HTTPS static endpoint should fail closed");
        assert!(error
            .to_string()
            .contains("must use https or localhost-only http"));
    }

    #[test]
    fn runtime_endpoint_validation_rejects_ipv4_mapped_ipv6_private_literals() {
        let error = validate_external_guard_url(
            "external guard endpoint",
            "https://[::ffff:169.254.169.254]/moderate",
        )
        .expect_err("IPv4-mapped IPv6 private endpoint should fail closed");
        assert!(error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"));
    }

    #[test]
    fn runtime_endpoint_validation_rejects_ipv6_multicast_literals() {
        let error =
            validate_external_guard_url("external guard endpoint", "https://[ff02::1]/moderate")
                .expect_err("IPv6 multicast should fail closed");
        assert!(error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"));
    }

    #[test]
    fn runtime_endpoint_validation_allows_loopback_http_for_tests() {
        validate_external_guard_url(
            "external guard endpoint",
            &format!("http://{}:8080/moderate", Ipv4Addr::LOCALHOST),
        )
        .expect("loopback HTTP remains allowed for local test guards");
        validate_external_guard_url(
            "external guard endpoint",
            &format!("http://[{}]:8080/moderate", Ipv6Addr::LOCALHOST),
        )
        .expect("IPv6 loopback HTTP remains allowed for local test guards");
    }
}
