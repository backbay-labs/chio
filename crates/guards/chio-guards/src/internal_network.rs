//! Internal network guard -- blocks SSRF targeting private/reserved addresses.
//!
//! This guard prevents Server-Side Request Forgery (SSRF) by blocking
//! network egress to:
//! - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//! - Loopback addresses (127.0.0.0/8, ::1)
//! - Link-local addresses (169.254.0.0/16, fe80::/10)
//! - Cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
//! - DNS rebinding detection via suspicious hostname patterns
//!
//! The guard fails closed: any parse error or ambiguous address is denied.

use std::net::IpAddr;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Guard that blocks SSRF targeting internal/private network addresses.
///
/// Inspects network egress actions and denies requests to private, loopback,
/// link-local, and cloud metadata addresses.
pub struct InternalNetworkGuard {
    /// Additional hostnames to block (beyond the built-in list).
    extra_blocked_hosts: Vec<String>,
    /// Enable DNS rebinding detection heuristics.
    dns_rebinding_detection: bool,
}

impl InternalNetworkGuard {
    /// Create a new guard with default settings.
    pub fn new() -> Self {
        Self {
            extra_blocked_hosts: Vec::new(),
            dns_rebinding_detection: true,
        }
    }

    /// Create a new guard with additional blocked hostnames and DNS rebinding
    /// detection toggle.
    pub fn with_config(extra_blocked_hosts: Vec<String>, dns_rebinding_detection: bool) -> Self {
        Self {
            extra_blocked_hosts,
            dns_rebinding_detection,
        }
    }

    /// Check whether a host string targets an internal/private address.
    ///
    /// Returns `Some(reason)` if blocked, `None` if allowed.
    pub fn check_host(&self, host: &str) -> Option<String> {
        let host_lower = host.to_lowercase();

        // Check cloud metadata hostnames.
        if is_cloud_metadata_host(&host_lower) {
            return Some(format!("cloud metadata endpoint: {host}"));
        }

        // Check extra blocked hosts.
        for blocked in &self.extra_blocked_hosts {
            if host_lower == blocked.to_lowercase() {
                return Some(format!("blocked host: {host}"));
            }
        }

        // DNS rebinding detection: suspicious patterns in hostnames.
        if self.dns_rebinding_detection && is_dns_rebinding_suspect(&host_lower) {
            return Some(format!("DNS rebinding suspect: {host}"));
        }

        // Try to parse as IP address directly.
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Some(format!("private/reserved IP: {ip}"));
            }
            return None;
        }

        // For hostnames, check if they resolve to numeric-looking patterns
        // that could bypass DNS resolution. Accept non-IP hostnames.
        if looks_like_encoded_ip(&host_lower) {
            return Some(format!("encoded IP pattern in hostname: {host}"));
        }

        None
    }
}

impl Default for InternalNetworkGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for InternalNetworkGuard {
    fn name(&self) -> &str {
        "internal-network"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let host = match &action {
            ToolAction::NetworkEgress(h, _) => h.as_str(),
            _ => return Ok(GuardDecision::allow()),
        };

        match self.check_host(host) {
            Some(_reason) => Ok(GuardDecision::deny(Vec::new())),
            None => Ok(GuardDecision::allow()),
        }
    }
}

/// Check whether an IP address is in a private/reserved range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Loopback: 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // RFC 1918: 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // RFC 1918: 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // RFC 1918: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // Link-local: 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // Broadcast
            if octets == [255, 255, 255, 255] {
                return true;
            }
            // 0.0.0.0/8 (current network)
            if octets[0] == 0 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // Loopback: ::1
            if v6.is_loopback() {
                return true;
            }
            let segments = v6.segments();
            // Link-local: fe80::/10
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // Unique local: fc00::/7
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // Unspecified: ::
            if v6.is_unspecified() {
                return true;
            }
            // IPv4-mapped IPv6 addresses: check the mapped v4 portion.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Check whether a hostname is a well-known cloud metadata endpoint.
fn is_cloud_metadata_host(host: &str) -> bool {
    // AWS/GCP/Azure metadata endpoint IP
    if host == "169.254.169.254" {
        return true;
    }
    // GCP metadata hostname
    if host == "metadata.google.internal" {
        return true;
    }
    // Azure metadata hostname
    if host == "metadata.azure.com" {
        return true;
    }
    // AWS EC2 metadata via hostname
    if host == "instance-data" || host.ends_with(".internal") {
        return true;
    }
    // Kubernetes metadata
    if host == "kubernetes.default.svc" || host == "kubernetes.default" {
        return true;
    }
    false
}

/// DNS rebinding detection: check for suspicious hostname patterns.
///
/// This catches hostnames that embed IP-like octets or use tricks to
/// resolve to private addresses.
fn is_dns_rebinding_suspect(host: &str) -> bool {
    // Hostnames containing raw IP octets separated by dashes or dots
    // that look like private ranges.
    let suspicious_patterns = [
        "127-0-0-1",
        "127.0.0.1",
        "10-0-",
        "10.0.",
        "192-168-",
        "192.168.",
        "172-16-",
        "172.16.",
        "169-254-",
        "169.254.",
        "0x7f",  // hex-encoded 127
        "0177.", // octal 127
    ];

    for pattern in &suspicious_patterns {
        if host.contains(pattern) {
            // But don't flag if the host itself IS an IP (already handled).
            if host.parse::<IpAddr>().is_ok() {
                return false;
            }
            return true;
        }
    }

    false
}

/// Check if a hostname looks like an encoded/obfuscated IP address.
///
/// Catches hex (0x7f000001), octal (0177.0.0.1), and decimal (2130706433)
/// representations of IP addresses.
fn looks_like_encoded_ip(host: &str) -> bool {
    // Hex-encoded IP: 0x followed by hex digits
    if host.starts_with("0x") && host[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Decimal-encoded IP: pure digits that could be an IP
    if host.chars().all(|c| c.is_ascii_digit()) && host.len() >= 7 && host.len() <= 10 {
        return true;
    }
    // Octal components: starts with 0 followed by octal digits and dots
    if host.starts_with('0')
        && host.len() > 1
        && host.chars().all(|c| c.is_ascii_digit() || c == '.')
        && host.contains('.')
    {
        // Could be octal IP notation like 0177.0.0.1
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 && parts.iter().any(|p| p.starts_with('0') && p.len() > 1) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("127.0.0.1").is_some());
        assert!(guard.check_host("127.0.0.2").is_some());
        assert!(guard.check_host("127.255.255.255").is_some());
    }

    #[test]
    fn blocks_rfc_1918() {
        let guard = InternalNetworkGuard::new();
        // 10.0.0.0/8
        assert!(guard.check_host("10.0.0.1").is_some());
        assert!(guard.check_host("10.255.255.255").is_some());
        // 172.16.0.0/12
        assert!(guard.check_host("172.16.0.1").is_some());
        assert!(guard.check_host("172.31.255.255").is_some());
        // 192.168.0.0/16
        assert!(guard.check_host("192.168.0.1").is_some());
        assert!(guard.check_host("192.168.255.255").is_some());
    }

    #[test]
    fn allows_public_ips() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("8.8.8.8").is_none());
        assert!(guard.check_host("1.1.1.1").is_none());
        assert!(guard.check_host("203.0.113.1").is_none());
    }

    #[test]
    fn blocks_link_local() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("169.254.1.1").is_some());
        assert!(guard.check_host("169.254.169.254").is_some());
    }

    #[test]
    fn blocks_cloud_metadata() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("169.254.169.254").is_some());
        assert!(guard.check_host("metadata.google.internal").is_some());
    }

    #[test]
    fn blocks_ipv6_loopback() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("::1").is_some());
    }

    #[test]
    fn blocks_ipv6_link_local() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("fe80::1").is_some());
    }

    #[test]
    fn blocks_ipv6_unique_local() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("fc00::1").is_some());
        assert!(guard.check_host("fd00::1").is_some());
    }

    #[test]
    fn blocks_hex_encoded_ip() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("0x7f000001").is_some());
    }

    #[test]
    fn blocks_decimal_encoded_ip() {
        let guard = InternalNetworkGuard::new();
        // 2130706433 == 127.0.0.1
        assert!(guard.check_host("2130706433").is_some());
    }

    #[test]
    fn allows_normal_hostnames() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("api.example.com").is_none());
        assert!(guard.check_host("github.com").is_none());
    }

    #[test]
    fn blocks_dns_rebinding_patterns() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("evil.127-0-0-1.example.com").is_some());
        assert!(guard.check_host("evil.192-168-1.attacker.com").is_some());
    }

    #[test]
    fn dns_rebinding_detection_can_be_disabled() {
        let guard = InternalNetworkGuard::with_config(vec![], false);
        // Without rebinding detection, suspicious hostnames are allowed
        // (they're not actual IPs).
        assert!(guard.check_host("evil.127-0-0-1.example.com").is_none());
    }

    #[test]
    fn extra_blocked_hosts() {
        let guard = InternalNetworkGuard::with_config(vec!["evil.internal".to_string()], true);
        assert!(guard.check_host("evil.internal").is_some());
        assert!(guard.check_host("safe.external.com").is_none());
    }

    #[test]
    fn blocks_broadcast() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("255.255.255.255").is_some());
    }

    #[test]
    fn blocks_zero_network() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("0.0.0.0").is_some());
    }

    #[test]
    fn blocks_kubernetes_metadata() {
        let guard = InternalNetworkGuard::new();
        assert!(guard.check_host("kubernetes.default.svc").is_some());
        assert!(guard.check_host("kubernetes.default").is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        let guard = InternalNetworkGuard::new();
        // ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address
        assert!(guard.check_host("::ffff:127.0.0.1").is_some());
    }

    #[test]
    fn guard_name() {
        let guard = InternalNetworkGuard::new();
        assert_eq!(guard.name(), "internal-network");
    }

    #[test]
    fn non_network_actions_pass() {
        let guard = InternalNetworkGuard::new();

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent = kp.public_key().to_hex();
        let server = "srv".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: server.clone(),
            agent_id: agent.clone(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent,
            server_id: &server,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("should not error");
        assert_eq!(result, Verdict::Allow, "non-network action should pass");
    }
}
