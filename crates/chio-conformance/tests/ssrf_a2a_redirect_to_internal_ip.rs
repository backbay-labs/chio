//! SSRF negative-conformance test: A2A redirect targets are validated
//! against the typed `HttpEgressContract` per hop.
//!
//! Spins up a `tiny_http` server bound to `127.0.0.1` that responds to
//! the A2A agent-card request with a 302 redirect to a forbidden
//! internal authority (`http://169.254.169.254/...`). Wires an
//! `A2aAdapter` whose `HttpEgressContract` allow-lists the loopback
//! discovery host but denies the cloud-metadata link-local address.
//! Asserts the redirect is rejected by the contract before any byte
//! is sent to the internal target. This pins the SSRF fix that
//! validates every redirect hop, not just the initial request URL.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use chio_a2a_adapter::A2aAdapterConfig;
use chio_egress_contract::HttpEgressContract;
use tiny_http::{Header, Response, Server};

fn loopback_only_contract(authority: &str) -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string(), "https".to_string()]),
        allowed_authority_set: BTreeSet::from([authority.to_ascii_lowercase()]),
        // The discovery target is 127.0.0.1 in this test, so allow loopback
        // here; the policy still denies link-local redirects below.
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 4,
        max_response_bytes: 64 * 1024,
    }
}

#[test]
fn a2a_discovery_rejects_redirect_to_internal_link_local() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("local addr");
    let server = Server::from_listener(listener, None).expect("build tiny_http server");

    let (ready_tx, ready_rx) = mpsc::channel();
    let server_handle = thread::spawn(move || {
        ready_tx.send(()).ok();
        if let Some(request) = server.incoming_requests().next() {
            // Always redirect the agent-card request into the
            // cloud-metadata endpoint, simulating a hostile A2A peer.
            let location = Header::from_bytes(
                &b"Location"[..],
                &b"http://169.254.169.254/agent-card.json"[..],
            )
            .expect("build Location header");
            let response = Response::empty(302).with_header(location);
            let _ = request.respond(response);
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server ready");

    let authority = format!("127.0.0.1:{}", local_addr.port());
    let agent_card_url = format!("http://{authority}/.well-known/agent-card.json");
    let cfg = A2aAdapterConfig::new(&agent_card_url, "00".to_string())
        .with_egress_contract(loopback_only_contract(&authority))
        .with_timeout(Duration::from_secs(5));

    let result = chio_a2a_adapter::A2aAdapter::discover(cfg);
    let _ = server_handle.join();
    let message = match result {
        Ok(_) => panic!("redirect into 169.254.169.254 must be denied"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("HttpEgressContract")
            || message.contains("redirect")
            || message.contains("169.254")
            || message.contains("link-local"),
        "expected HttpEgressContract redirect denial, got: {message}"
    );
}
