use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use subtle::ConstantTimeEq as _;
use url::Url;
use zeroize::Zeroizing;

use crate::HostedEdgeError;

const MAX_FORWARDED_BYTES: usize = 1_024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostedForwardingHeaders {
    pub forwarded: Vec<String>,
    pub x_forwarded_for: Vec<String>,
    pub x_forwarded_host: Vec<String>,
    pub x_forwarded_proto: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedRequestContext {
    pub client_ip: IpAddr,
    pub external_scheme: String,
    pub external_host: String,
}

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

pub struct HostedTrustedProxy {
    trusted_peer_ips: BTreeSet<IpAddr>,
    endpoint: Url,
    authentication_token: Zeroizing<Vec<u8>>,
}

impl HostedTrustedProxy {
    pub fn new(mut config: HostedTrustedProxyConfig) -> Result<Self, HostedEdgeError> {
        let endpoint =
            Url::parse(&config.public_endpoint).map_err(|_| HostedEdgeError::Configuration)?;
        if !config.listen.ip().is_loopback()
            || config.listen.port() == 0
            || config.trusted_peer_ips.is_empty()
            || config.trusted_peer_ips.len() > 32
            || !(32..=4_096).contains(&config.authentication_token.len())
            || config
                .trusted_peer_ips
                .iter()
                .any(|address| !address.is_loopback())
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
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
            || value.contains(',')
            || value.chars().any(char::is_control)
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let mut forwarded_for = None;
        let mut forwarded_proto = None;
        let mut forwarded_host = None;
        let mut seen_for = false;
        let mut seen_proto = false;
        let mut seen_host = false;
        for component in value.split(';') {
            let (name, raw_value) = component
                .trim()
                .split_once('=')
                .ok_or(HostedEdgeError::InvalidRequest)?;
            let raw_value = raw_value.trim();
            if raw_value.contains('"') {
                return Err(HostedEdgeError::InvalidRequest);
            }
            match name.trim().to_ascii_lowercase().as_str() {
                "for" if !seen_for => {
                    seen_for = true;
                    forwarded_for = parse_forwarded_ip(raw_value);
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

    fn proxy() -> Result<HostedTrustedProxy, HostedEdgeError> {
        HostedTrustedProxy::new(HostedTrustedProxyConfig {
            listen: "127.0.0.1:9443"
                .parse()
                .map_err(|_| HostedEdgeError::Configuration)?,
            trusted_peer_ips: [IpAddr::from([127, 0, 0, 1])].into_iter().collect(),
            public_endpoint: "https://market.example".to_owned(),
            authentication_token: vec![b'p'; 32],
        })
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
                Some("pppppppppppppppppppppppppppppppp"),
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
                .reconstruct(
                    IpAddr::from([192, 0, 2, 1]),
                    &valid,
                    Some("pppppppppppppppppppppppppppppppp")
                )
                .is_err());
            let ambiguous = HostedForwardingHeaders {
                x_forwarded_for: vec!["192.0.2.99".to_owned()],
                ..valid
            };
            assert!(proxy
                .reconstruct(
                    IpAddr::from([127, 0, 0, 1]),
                    &ambiguous,
                    Some("pppppppppppppppppppppppppppppppp")
                )
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
