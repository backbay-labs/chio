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
fn loopback_hostname_policy_respects_contract_flag() {
    let contract = HttpEgressContract::permissive_for_tests("localhost:80");
    contract
        .enforce_loopback_hostname("localhost")
        .expect("loopback hostname remains allowed when loopback denial is disabled");

    let mut denied = contract;
    denied.deny_loopback = true;
    let error = denied
        .enforce_loopback_hostname("localhost.localdomain")
        .expect_err("known loopback hostname should be denied when flag is enabled");
    assert!(matches!(
        error,
        HttpEgressError::LoopbackDenied { host } if host == "localhost.localdomain"
    ));
    denied
        .enforce_loopback_hostname("api.example.com")
        .expect("non-loopback hostname remains allowed");
}

#[test]
fn validate_rejects_allowed_authority_with_empty_port() {
    let error = strict_contract("api.example.com:")
        .validate()
        .expect_err("empty authority port must fail contract validation");

    assert!(matches!(error, HttpEgressError::InvalidContract(_)));
    assert!(error.to_string().contains("invalid allowed authority"));
}

#[test]
fn validate_rejects_non_canonical_allowed_authorities() {
    for authority in ["api.example.com.", "api.example.com:0443", "[2001:0db8::1]"] {
        let error = strict_contract(authority)
            .validate()
            .expect_err("non-canonical authority should be rejected");
        assert!(matches!(error, HttpEgressError::InvalidContract(_)));
        assert!(
            error.to_string().contains("must be normalized"),
            "unexpected canonicalization error for {authority:?}: {error}"
        );
    }
}

#[test]
fn validate_accepts_explicit_default_port_authority() {
    strict_contract("api.example.com:443")
        .validate()
        .expect("explicit default ports remain valid authority entries");
}

#[test]
fn validate_rejects_non_http_allowed_schemes() {
    for scheme in ["ftp", "ws", "custom+scheme"] {
        let mut contract = strict_contract("api.example.com");
        contract.allowed_schemes = BTreeSet::from([scheme.to_string()]);

        let error = contract
            .validate()
            .expect_err("non-HTTP schemes must fail HTTP egress contract validation");
        assert!(matches!(error, HttpEgressError::InvalidContract(_)));
        assert!(
            error.to_string().contains("invalid HTTP egress scheme"),
            "unexpected scheme validation error for {scheme:?}: {error}"
        );
    }
}

#[test]
fn validate_accepts_http_allowed_schemes() {
    let mut contract = strict_contract("api.example.com");
    contract.allowed_schemes = BTreeSet::from(["http".to_string(), "https".to_string()]);

    contract
        .validate()
        .expect("http and https remain valid HTTP egress schemes");
}

#[test]
fn prepare_rejects_invalid_contract_shape() {
    let mut contract = strict_contract("api.example.com");
    contract.allowed_schemes.clear();

    let error = contract
        .prepare()
        .expect_err("prepared contracts must reject invalid raw policy shape");
    assert!(matches!(error, HttpEgressError::InvalidContract(_)));
}

#[test]
fn prepared_contract_normalizes_tenant_namespace() {
    let mut contract = strict_contract("api.example.com");
    contract.tenant_egress_namespace = " tenant-a ".to_string();

    let prepared = contract.prepare().expect("prepare valid contract");
    assert_eq!(prepared.tenant_egress_namespace(), "tenant-a");

    let target = prepared
        .enforce_url("https://api.example.com/v1", 0)
        .expect("prepared contract should enforce allowed target");
    assert_eq!(target.tenant_egress_namespace, "tenant-a");
}

#[test]
fn prepared_contract_keeps_validated_snapshot_after_raw_mutation() {
    let mut contract = strict_contract("api.example.com");
    let prepared = contract.prepare().expect("prepare valid contract");

    contract.allowed_schemes.clear();
    contract.max_response_bytes = 1;

    prepared
        .enforce_attempt("https://api.example.com/v1", 0, Some(1024))
        .expect("prepared snapshot should retain original valid policy");
    let error = contract
        .enforce_attempt("https://api.example.com/v1", 0, Some(2))
        .expect_err("mutated raw contract should be rejected when reused");
    assert!(matches!(error, HttpEgressError::InvalidContract(_)));
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

#[test]
fn private_ipv4_literal_fails_closed_even_when_declared() {
    let error = strict_contract("10.0.0.5")
        .enforce_url("https://10.0.0.5/admin", 0)
        .expect_err("private IPv4 literals must fail closed even when allow-listed");

    assert!(matches!(
        error,
        HttpEgressError::PrivateNetworkDenied { host } if host == "10.0.0.5"
    ));
}

#[test]
fn ipv4_mapped_private_literal_fails_closed_even_when_declared() {
    let error = strict_contract("[::ffff:10.0.0.5]")
        .enforce_url("https://[::ffff:10.0.0.5]/admin", 0)
        .expect_err("IPv4-mapped private literals must fail closed even when allow-listed");

    assert!(matches!(
        error,
        HttpEgressError::PrivateNetworkDenied { host } if host == "10.0.0.5"
    ));
}

#[cfg(all(test, feature = "reqwest-egress"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod reqwest_egress_tests {
    use crate::reqwest_helper::{client_builder_with_contract, send_with_contract};
    use crate::{HttpEgressContract, HttpEgressError};
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

    // Regression (DNS rebinding / TOCTOU): a host whose resolution yields a
    // loopback address must be refused by the pinned egress path before any
    // socket is opened. The address-class check and the connect share one
    // resolution, so a rebinding answer cannot pass the check with a global IP
    // and then connect to a loopback/private target. deny_loopback stays on;
    // the production denial is never weakened.
    #[tokio::test]
    async fn send_with_contract_refuses_loopback_resolving_host_before_connect() {
        let (addr, observation_rx, handle) = spawn_optional_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        });
        let mut contract =
            HttpEgressContract::permissive_for_tests(&format!("localhost:{}", addr.port()));
        contract.deny_loopback = true;
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://localhost:{}/head", addr.port()))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("loopback-resolving host must fail closed");
        assert!(
            matches!(error, HttpEgressError::LoopbackDenied { .. }),
            "unexpected error: {error}"
        );

        let observation = observation_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server observation");
        assert!(
            observation.is_none(),
            "pinned egress path opened a socket to a loopback target"
        );
        handle.join().expect("join server");
    }

    // Regression (response byte cap): a chunked response with no Content-Length
    // must be capped while streaming. The running byte counter aborts shortly
    // after the ceiling is crossed rather than buffering the whole body, so an
    // oversized (or effectively unbounded) response cannot exhaust memory.
    #[tokio::test]
    async fn send_with_contract_aborts_oversized_chunked_body_mid_stream() {
        const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
        const CHUNK_BYTES: usize = 16 * 1024;
        // The server intends to stream 4 MiB with no Content-Length; the cap
        // must fire on a small prefix and never buffer the whole body.
        const TOTAL_CHUNKS: usize = 256;
        let total_body_bytes = (CHUNK_BYTES * TOTAL_CHUNKS) as u64;

        let addr = spawn_streaming_chunked_server(CHUNK_BYTES, TOTAL_CHUNKS);
        let mut contract = HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = MAX_RESPONSE_BYTES;
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/stream", authority(addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("oversized chunked body must be rejected");
        let HttpEgressError::ResponseTooLarge { observed, max } = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(max, MAX_RESPONSE_BYTES);
        assert!(
            observed > MAX_RESPONSE_BYTES,
            "observed {observed} should exceed the ceiling"
        );
        // The read aborts on a bounded prefix (a handful of chunks past the
        // ceiling), not after the whole 4 MiB body is buffered into memory.
        assert!(
            observed < total_body_bytes / 8,
            "observed {observed} indicates the whole {total_body_bytes}-byte body was buffered before the cap fired"
        );
        // The server thread is intentionally detached: it blocks writing the
        // remaining body once the client aborts, and unblocks when the runtime
        // drops the connection at test teardown. Joining it here would block the
        // current-thread reactor and deadlock.
    }

    // Streams a chunked response (no Content-Length) of `total_chunks` chunks.
    // The thread is detached and tolerates the client closing the connection
    // once the byte ceiling fires, so an oversized body never requires the test
    // to read the whole stream.
    fn spawn_streaming_chunked_server(chunk_bytes: usize, total_chunks: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("read local addr");
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = read_http_request(&mut stream);
            let headers =
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            if stream.write_all(headers.as_bytes()).is_err() {
                return;
            }
            let chunk = format!("{:x}\r\n{}\r\n", chunk_bytes, "a".repeat(chunk_bytes));
            for _ in 0..total_chunks {
                if stream.write_all(chunk.as_bytes()).is_err() {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        addr
    }
}
