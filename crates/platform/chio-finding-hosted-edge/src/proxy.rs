use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use subtle::ConstantTimeEq as _;
use url::Url;
use zeroize::Zeroizing;

use crate::HostedEdgeError;

const MAX_FORWARDED_BYTES: usize = 1_024;

/// The raw forwarding headers as received, kept separate so parsing
/// happens under the trusted-proxy rules only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostedForwardingHeaders {
    pub forwarded: Vec<String>,
    pub x_forwarded_for: Vec<String>,
    pub x_forwarded_host: Vec<String>,
    pub x_forwarded_proto: Vec<String>,
}

/// The client identity the trusted proxy attests: originating IP and
/// the external scheme and host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedRequestContext {
    pub client_ip: IpAddr,
    pub external_scheme: String,
    pub external_host: String,
}

/// Trusted-proxy contract: the loopback listen address, the exact
/// peer IPs allowed to speak for clients, and the shared
/// proxy-authentication secret.
pub struct HostedTrustedProxyConfig {
    pub listen: SocketAddr,
    pub trusted_peer_ips: BTreeSet<IpAddr>,
    pub public_endpoint: String,
    pub authentication_token: Vec<u8>,
}

impl fmt::Debug for HostedTrustedProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostedTrustedProxyConfig")
            .field("listen", &self.listen)
            .field("trusted_peer_ips", &self.trusted_peer_ips)
            .field("public_endpoint", &self.public_endpoint)
            .field("authentication_token", &"[REDACTED]")
            .finish()
    }
}

/// Reconstructs the client context from forwarding headers, but only
/// for authenticated peers on the trusted list; everything else is
/// rejected before routing.
pub struct HostedTrustedProxy {
    trusted_peer_ips: BTreeSet<IpAddr>,
    endpoint: Url,
    authentication_token: Zeroizing<Vec<u8>>,
}

impl HostedTrustedProxy {
    /// Fail closed on an invalid listen address, empty peer list, or
    /// weak shared secret.
    pub fn new(mut config: HostedTrustedProxyConfig) -> Result<Self, HostedEdgeError> {
        let endpoint =
            Url::parse(&config.public_endpoint).map_err(|_| HostedEdgeError::Configuration)?;
        if !config.listen.ip().is_loopback()
            || config.listen.port() == 0
            || config.trusted_peer_ips.is_empty()
            || config.trusted_peer_ips.len() > 32
            || !(43..=128).contains(&config.authentication_token.len())
            || !config
                .authentication_token
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || config
                .trusted_peer_ips
                .iter()
                .any(|address| !address.is_loopback())
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(Self {
            trusted_peer_ips: config.trusted_peer_ips,
            endpoint,
            authentication_token: Zeroizing::new(std::mem::take(&mut config.authentication_token)),
        })
    }

    /// Reconstruct the external request context only from one trusted proxy.
    /// Legacy forwarding headers and multi-hop chains are deliberately refused.
    pub fn reconstruct(
        &self,
        peer_ip: IpAddr,
        headers: &HostedForwardingHeaders,
        presented_authentication: Option<&str>,
    ) -> Result<HostedRequestContext, HostedEdgeError> {
        let presented_authentication = presented_authentication
            .filter(|value| {
                value.len() == self.authentication_token.len()
                    && !value.chars().any(char::is_control)
            })
            .ok_or(HostedEdgeError::AuthenticationFailed)?;
        if !bool::from(
            self.authentication_token
                .as_slice()
                .ct_eq(presented_authentication.as_bytes()),
        ) {
            return Err(HostedEdgeError::AuthenticationFailed);
        }
        if !self.trusted_peer_ips.contains(&peer_ip)
            || headers.forwarded.len() != 1
            || !headers.x_forwarded_for.is_empty()
            || !headers.x_forwarded_host.is_empty()
            || !headers.x_forwarded_proto.is_empty()
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let value = &headers.forwarded[0];
        if value.is_empty()
            || value.len() > MAX_FORWARDED_BYTES
            || !value.is_ascii()
            || value.contains(',')
            || value
                .chars()
                .any(|character| character.is_control() && character != '\t')
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let mut forwarded_for = None;
        let mut forwarded_proto = None;
        let mut forwarded_host = None;
        let mut seen_for = false;
        let mut seen_proto = false;
        let mut seen_host = false;
        for (name, raw_value) in parse_forwarded_parameters(value)? {
            match name.to_ascii_lowercase().as_str() {
                "for" if !seen_for => {
                    seen_for = true;
                    forwarded_for = parse_forwarded_ip(&raw_value);
                }
                "proto" if !seen_proto => {
                    seen_proto = true;
                    forwarded_proto = Some(raw_value.to_ascii_lowercase())
                }
                "host" if !seen_host => {
                    seen_host = true;
                    forwarded_host = Some(raw_value.to_owned());
                }
                _ => return Err(HostedEdgeError::InvalidRequest),
            }
        }
        let client_ip = forwarded_for.ok_or(HostedEdgeError::InvalidRequest)?;
        if forwarded_proto.as_deref() != Some("https") {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let host = forwarded_host.ok_or(HostedEdgeError::InvalidRequest)?;
        if !host_matches_endpoint(&host, &self.endpoint) {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(HostedRequestContext {
            client_ip,
            external_scheme: "https".to_owned(),
            external_host: host,
        })
    }
}

fn parse_forwarded_parameters(value: &str) -> Result<Vec<(&str, String)>, HostedEdgeError> {
    let bytes = value.as_bytes();
    let mut cursor = 0;
    let mut parameters = Vec::with_capacity(3);
    while cursor < bytes.len() {
        skip_optional_whitespace(bytes, &mut cursor);
        if cursor == bytes.len() {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let name_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| is_forwarded_token_byte(*byte))
        {
            cursor += 1;
        }
        if cursor == name_start {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let name = &value[name_start..cursor];
        skip_optional_whitespace(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'=') {
            return Err(HostedEdgeError::InvalidRequest);
        }
        cursor += 1;
        skip_optional_whitespace(bytes, &mut cursor);
        let parsed_value = parse_forwarded_value(value, &mut cursor)?;
        skip_optional_whitespace(bytes, &mut cursor);
        parameters.push((name, parsed_value));
        if parameters.len() > 3 {
            return Err(HostedEdgeError::InvalidRequest);
        }
        if cursor == bytes.len() {
            break;
        }
        if bytes.get(cursor) != Some(&b';') {
            return Err(HostedEdgeError::InvalidRequest);
        }
        cursor += 1;
    }
    Ok(parameters)
}

fn parse_forwarded_value(value: &str, cursor: &mut usize) -> Result<String, HostedEdgeError> {
    let bytes = value.as_bytes();
    if bytes.get(*cursor) != Some(&b'"') {
        let start = *cursor;
        while bytes.get(*cursor).is_some_and(|byte| {
            byte.is_ascii_graphic() && !matches!(*byte, b'"' | b'\\' | b';' | b',')
        }) {
            *cursor += 1;
        }
        if *cursor == start {
            return Err(HostedEdgeError::InvalidRequest);
        }
        return Ok(value[start..*cursor].to_owned());
    }

    *cursor += 1;
    let mut decoded = Vec::new();
    loop {
        let byte = *bytes.get(*cursor).ok_or(HostedEdgeError::InvalidRequest)?;
        *cursor += 1;
        match byte {
            b'"' => break,
            b'\\' => {
                let escaped = *bytes.get(*cursor).ok_or(HostedEdgeError::InvalidRequest)?;
                if escaped != b'\t' && !(b' '..=b'~').contains(&escaped) {
                    return Err(HostedEdgeError::InvalidRequest);
                }
                decoded.push(escaped);
                *cursor += 1;
            }
            b'\t' | b' ' | b'!' => decoded.push(byte),
            b'#'..=b'[' | b']'..=b'~' => decoded.push(byte),
            _ => return Err(HostedEdgeError::InvalidRequest),
        }
    }
    if decoded.is_empty() {
        return Err(HostedEdgeError::InvalidRequest);
    }
    String::from_utf8(decoded).map_err(|_| HostedEdgeError::InvalidRequest)
}

fn skip_optional_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn is_forwarded_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    if value.is_empty() || value.starts_with('_') {
        return None;
    }
    value.parse::<IpAddr>().ok().or_else(|| {
        value
            .parse::<SocketAddr>()
            .ok()
            .map(|address| address.ip())
            .or_else(|| {
                value
                    .strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|address| address.parse().ok())
            })
    })
}

fn host_matches_endpoint(value: &str, endpoint: &Url) -> bool {
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '/' | '@' | '?' | '#'))
        || value.chars().any(char::is_whitespace)
    {
        return false;
    }
    let Ok(candidate) = Url::parse(&format!("https://{value}")) else {
        return false;
    };
    candidate.host_str() == endpoint.host_str()
        && candidate.port_or_known_default() == endpoint.port_or_known_default()
        && candidate.path() == "/"
        && candidate.query().is_none()
        && candidate.fragment().is_none()
        && candidate.username().is_empty()
        && candidate.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789A";

    fn proxy() -> Result<HostedTrustedProxy, HostedEdgeError> {
        proxy_for_endpoint("https://market.example")
    }

    fn proxy_for_endpoint(public_endpoint: &str) -> Result<HostedTrustedProxy, HostedEdgeError> {
        HostedTrustedProxy::new(HostedTrustedProxyConfig {
            listen: "127.0.0.1:9443"
                .parse()
                .map_err(|_| HostedEdgeError::Configuration)?,
            trusted_peer_ips: [IpAddr::from([127, 0, 0, 1])].into_iter().collect(),
            public_endpoint: public_endpoint.to_owned(),
            authentication_token: PROXY_TOKEN.as_bytes().to_vec(),
        })
    }

    #[test]
    fn proxy_token_is_safe_for_deployment_configuration() {
        for token in [vec![b'p'; 42], vec![b'p'; 129], {
            let mut token = vec![b'p'; 43];
            token[20] = b'"';
            token
        }] {
            assert!(HostedTrustedProxy::new(HostedTrustedProxyConfig {
                listen: "127.0.0.1:9443"
                    .parse()
                    .unwrap_or_else(|error| panic!("test listener failed: {error}")),
                trusted_peer_ips: [IpAddr::from([127, 0, 0, 1])].into_iter().collect(),
                public_endpoint: "https://market.example".to_owned(),
                authentication_token: token,
            })
            .is_err());
        }
    }

    #[test]
    fn trusted_proxy_accepts_quoted_ipv6_and_nondefault_port() {
        let proxy = proxy_for_endpoint("https://market.example:8443");
        assert!(proxy.is_ok());
        if let Ok(proxy) = proxy {
            let context = proxy.reconstruct(
                IpAddr::from([127, 0, 0, 1]),
                &HostedForwardingHeaders {
                    forwarded: vec![
                        r#"for="[2001:db8::1]";proto="ht\tps";host="market.example:8443""#
                            .to_owned(),
                    ],
                    ..HostedForwardingHeaders::default()
                },
                Some(PROXY_TOKEN),
            );
            assert_eq!(
                context,
                Ok(HostedRequestContext {
                    client_ip: IpAddr::V6(std::net::Ipv6Addr::new(
                        0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
                    )),
                    external_scheme: "https".to_owned(),
                    external_host: "market.example:8443".to_owned(),
                })
            );
        }
    }

    #[test]
    fn malformed_quoted_forwarded_values_fail_closed() {
        let proxy = proxy();
        assert!(proxy.is_ok());
        if let Ok(proxy) = proxy {
            for forwarded in [
                r#"for="[2001:db8::1];proto=https;host=market.example"#,
                r#"for="[2001:db8::1]"junk;proto=https;host=market.example"#,
                r#"for="[2001:db8::1]\"#,
            ] {
                assert!(proxy
                    .reconstruct(
                        IpAddr::from([127, 0, 0, 1]),
                        &HostedForwardingHeaders {
                            forwarded: vec![forwarded.to_owned()],
                            ..HostedForwardingHeaders::default()
                        },
                        Some(PROXY_TOKEN),
                    )
                    .is_err());
            }
        }
    }

    #[test]
    fn trusted_proxy_accepts_one_exact_forwarded_context() {
        let proxy = proxy();
        assert!(proxy.is_ok());
        if let Ok(proxy) = proxy {
            let context = proxy.reconstruct(
                IpAddr::from([127, 0, 0, 1]),
                &HostedForwardingHeaders {
                    forwarded: vec!["for=192.0.2.44;proto=https;host=market.example".to_owned()],
                    ..HostedForwardingHeaders::default()
                },
                Some(PROXY_TOKEN),
            );
            assert!(context.is_ok());
            assert_eq!(
                context.map(|value| value.client_ip),
                Ok(IpAddr::from([192, 0, 2, 44]))
            );
        }
    }

    #[test]
    fn proxy_spoofing_and_ambiguous_headers_fail_closed() {
        let proxy = proxy();
        assert!(proxy.is_ok());
        if let Ok(proxy) = proxy {
            let valid = HostedForwardingHeaders {
                forwarded: vec!["for=192.0.2.44;proto=https;host=market.example".to_owned()],
                ..HostedForwardingHeaders::default()
            };
            assert!(proxy
                .reconstruct(IpAddr::from([192, 0, 2, 1]), &valid, Some(PROXY_TOKEN))
                .is_err());
            let ambiguous = HostedForwardingHeaders {
                x_forwarded_for: vec!["192.0.2.99".to_owned()],
                ..valid
            };
            assert!(proxy
                .reconstruct(IpAddr::from([127, 0, 0, 1]), &ambiguous, Some(PROXY_TOKEN))
                .is_err());
            assert_eq!(
                proxy.reconstruct(
                    IpAddr::from([127, 0, 0, 1]),
                    &HostedForwardingHeaders {
                        forwarded: vec![
                            "for=192.0.2.44;proto=https;host=market.example".to_owned(),
                        ],
                        ..HostedForwardingHeaders::default()
                    },
                    Some("wrong-wrong-wrong-wrong-wrong-wr")
                ),
                Err(HostedEdgeError::AuthenticationFailed)
            );
        }
    }
}
