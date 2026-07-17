use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::{
    apply_server_hygiene, run_until_drained, DrainOutcome, MaxConnListener, ServeError,
    ServeHygieneConfig, ShutdownController,
};

/// Send one HTTP/1.1 request with `Connection: close` and return the status code
/// and full response text. The connection close lets `read_to_end` terminate
/// once the server has written the whole response.
async fn http_request(addr: SocketAddr, request: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok((parse_status(&text), text))
}

fn parse_status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn get_request(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
}

async fn bind_ephemeral() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[tokio::test]
async fn sigterm_drains_in_flight_request_before_exit() {
    // A handler that takes a beat and then records a durable side effect stands
    // in for the receipt commit that the drain must not sever.
    let receipt_written = Arc::new(AtomicBool::new(false));
    let handler_receipt = Arc::clone(&receipt_written);
    let router = Router::new().route(
        "/work",
        get(move || {
            let receipt = Arc::clone(&handler_receipt);
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                receipt.store(true, Ordering::SeqCst);
                "done"
            }
        }),
    );

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());

    let flush_receipt = Arc::clone(&receipt_written);
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_secs(5),
        async move {
            // The drain must have completed the in-flight write before the flush
            // hook runs.
            assert!(
                flush_receipt.load(Ordering::SeqCst),
                "in-flight receipt was not written before the flush hook ran"
            );
            Ok::<(), String>(())
        },
    ));

    let request = tokio::spawn(async move { http_request(addr, &get_request("/work")).await });

    // Fire the stop signal while the request is still in flight.
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.trigger();

    let (status, _) = request.await.unwrap().unwrap();
    assert_eq!(status, 200, "in-flight request did not complete on drain");
    assert!(receipt_written.load(Ordering::SeqCst));

    let outcome = serve.await.unwrap().unwrap();
    assert_eq!(outcome, DrainOutcome::Clean);
}

#[tokio::test]
async fn drain_deadline_forces_close_and_still_flushes() {
    // A handler that never returns forces the drain deadline to elapse.
    let router = Router::new().route(
        "/hang",
        get(|| async {
            std::future::pending::<()>().await;
            "unreachable"
        }),
    );

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());

    let flush_ran = Arc::new(AtomicBool::new(false));
    let flush_flag = Arc::clone(&flush_ran);
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_millis(150),
        async move {
            flush_flag.store(true, Ordering::SeqCst);
            Ok::<(), String>(())
        },
    ));

    // Hold a connection open in the never-returning handler.
    let _stuck = tokio::spawn(async move { http_request(addr, &get_request("/hang")).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.trigger();

    let outcome = serve.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        DrainOutcome::Forced,
        "a stuck request should force the drain deadline"
    );
    assert!(
        flush_ran.load(Ordering::SeqCst),
        "the flush hook must run even when the drain is forced"
    );
}

#[tokio::test]
async fn manual_controller_does_not_signal_until_triggered() {
    // The shutdown future must never resolve spuriously: absent a trigger it
    // stays pending, which is the property that keeps a failed handler install
    // from crash-looping the process at startup.
    let ctrl = ShutdownController::manual();
    assert!(!ctrl.is_shutdown());

    let early = tokio::time::timeout(Duration::from_millis(100), ctrl.signalled()).await;
    assert!(early.is_err(), "shutdown resolved without a signal");

    ctrl.trigger();
    let after = tokio::time::timeout(Duration::from_millis(100), ctrl.signalled()).await;
    assert!(after.is_ok(), "shutdown did not resolve after trigger");
    assert!(ctrl.is_shutdown());
}

#[tokio::test]
async fn flush_error_surfaces_as_serve_error() {
    let router = Router::new().route("/", get(|| async { "ok" }));
    let (listener, _addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());

    ctrl.trigger();
    let result = run_until_drained(server, ctrl.subscribe(), Duration::from_secs(1), async {
        Err::<(), String>("wedged commit actor".to_string())
    })
    .await;

    match result {
        Err(ServeError::Flush(message)) => assert!(message.contains("wedged commit actor")),
        other => panic!("expected a flush error, got {other:?}"),
    }
}

#[tokio::test]
async fn request_timeout_returns_408() {
    let router = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "unreachable"
        }),
    );
    let config = ServeHygieneConfig {
        request_timeout: Some(Duration::from_millis(100)),
        max_concurrent_requests: None,
        max_connections: None,
        max_body_bytes: None,
        ..ServeHygieneConfig::default()
    };
    let router = apply_server_hygiene(router, &config);

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_secs(2),
        async { Ok::<(), String>(()) },
    ));

    let (status, _) = http_request(addr, &get_request("/slow")).await.unwrap();
    assert_eq!(status, 408, "slow request should time out with 408");

    ctrl.trigger();
    let _ = serve.await.unwrap();
}

#[tokio::test]
async fn body_limit_returns_413() {
    let router = Router::new().route("/echo", post(|body: String| async move { body }));
    let config = ServeHygieneConfig {
        request_timeout: None,
        max_concurrent_requests: None,
        max_connections: None,
        max_body_bytes: Some(16),
        ..ServeHygieneConfig::default()
    };
    let router = apply_server_hygiene(router, &config);

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_secs(2),
        async { Ok::<(), String>(()) },
    ));

    let oversized = "x".repeat(64);
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{oversized}",
        oversized.len()
    );
    let (status, _) = http_request(addr, &request).await.unwrap();
    assert_eq!(status, 413, "oversized body should be rejected with 413");

    ctrl.trigger();
    let _ = serve.await.unwrap();
}

#[tokio::test]
async fn load_shed_returns_503_over_concurrency_limit() {
    // The first request parks in the handler holding the single concurrency
    // permit; the second must shed with 503 rather than queue behind it.
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let handler_entered = Arc::clone(&entered);
    let handler_release = Arc::clone(&release);
    let router = Router::new().route(
        "/park",
        get(move || {
            let entered = Arc::clone(&handler_entered);
            let release = Arc::clone(&handler_release);
            async move {
                entered.notify_one();
                release.notified().await;
                "released"
            }
        }),
    );
    let config = ServeHygieneConfig {
        request_timeout: None,
        max_concurrent_requests: Some(1),
        max_connections: None,
        max_body_bytes: None,
        ..ServeHygieneConfig::default()
    };
    let router = apply_server_hygiene(router, &config);

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_secs(2),
        async { Ok::<(), String>(()) },
    ));

    let first = tokio::spawn(async move { http_request(addr, &get_request("/park")).await });
    // Wait until the first request holds the permit inside the handler.
    entered.notified().await;

    let (second_status, _) = http_request(addr, &get_request("/park")).await.unwrap();
    assert_eq!(
        second_status, 503,
        "a request over the concurrency limit should shed with 503"
    );

    release.notify_waiters();
    let (first_status, _) = first.await.unwrap().unwrap();
    assert_eq!(
        first_status, 200,
        "the admitted request should still succeed"
    );

    ctrl.trigger();
    let _ = serve.await.unwrap();
}

#[tokio::test]
async fn max_conn_listener_caps_concurrent_connections() {
    let (listener, addr) = bind_ephemeral().await;
    let mut capped = MaxConnListener::new(listener, 1);

    // First connection consumes the only permit.
    let _client_one = TcpStream::connect(addr).await.unwrap();
    let (io_one, _) = accept_once(&mut capped).await;

    // A second connection is established at the TCP level but must not be
    // accepted by the app while the permit is held.
    let _client_two = TcpStream::connect(addr).await.unwrap();
    let blocked = tokio::time::timeout(Duration::from_millis(200), accept_once(&mut capped)).await;
    assert!(
        blocked.is_err(),
        "the second connection was accepted despite an exhausted cap"
    );

    // Releasing the first connection frees the permit for the second.
    drop(io_one);
    let accepted = tokio::time::timeout(Duration::from_millis(500), accept_once(&mut capped)).await;
    assert!(
        accepted.is_ok(),
        "the second connection was not accepted after the permit freed"
    );
}

/// Drive one `axum::serve::Listener::accept` on the capped listener.
async fn accept_once(
    listener: &mut MaxConnListener<TcpListener>,
) -> (crate::PermittedIo<TcpStream>, SocketAddr) {
    use axum::serve::Listener;
    listener.accept().await
}

#[tokio::test]
async fn capped_listener_still_serves_connect_info() {
    // Capping connections changes the accepted IO type, which drops it out of
    // axum's built-in `SocketAddr` connect-info. `CappedPeerAddr` restores the
    // peer address, so a site keeps both the accept ceiling and per-connection
    // context. A handler that echoes the peer address proves the binding resolves.
    use axum::extract::ConnectInfo;
    let router =
        Router::new().route(
            "/whoami",
            get(
                |ConnectInfo(peer): ConnectInfo<crate::CappedPeerAddr>| async move {
                    peer.ip().to_string()
                },
            ),
        );
    let (listener, addr) = bind_ephemeral().await;
    let capped = MaxConnListener::new(listener, 8);
    let ctrl = ShutdownController::manual();
    let server = axum::serve(
        capped,
        router.into_make_service_with_connect_info::<crate::CappedPeerAddr>(),
    )
    .with_graceful_shutdown(ctrl.signalled());
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        Duration::from_secs(2),
        async { Ok::<(), String>(()) },
    ));

    let (status, response) = http_request(addr, &get_request("/whoami")).await.unwrap();
    assert_eq!(status, 200);
    assert!(
        response.contains("127.0.0.1"),
        "the handler must observe the loopback peer address, got: {response}"
    );

    ctrl.trigger();
    let _ = serve.await.unwrap();
}

#[test]
fn default_request_timeout_stays_within_drain_window() {
    // The forced-drain timer starts at the stop signal and force-closes at
    // `DEFAULT_DRAIN_TIMEOUT`. A request admitted just before the signal must be
    // able to reach its own 408 and complete cleanly first, so the per-request
    // ceiling must be strictly below the drain window. If this ever inverts, a
    // routine deploy severs requests that were still inside their allotted time.
    assert!(
        crate::DEFAULT_REQUEST_TIMEOUT < crate::DEFAULT_DRAIN_TIMEOUT,
        "request timeout {:?} must stay below the drain window {:?}",
        crate::DEFAULT_REQUEST_TIMEOUT,
        crate::DEFAULT_DRAIN_TIMEOUT,
    );
}

#[tokio::test]
async fn slow_request_times_out_cleanly_inside_the_drain_window() {
    // With the request timeout below the drain window, a request that outlives
    // both is denied with 408 by the timeout layer and its connection completes,
    // so the drain observes a clean shutdown rather than force-closing it. This is
    // the behavioral guarantee the default ordering exists to provide.
    let router = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "unreachable"
        }),
    );
    let config = ServeHygieneConfig {
        request_timeout: Some(Duration::from_millis(100)),
        drain_timeout: Duration::from_millis(600),
        max_concurrent_requests: None,
        max_connections: None,
        max_body_bytes: None,
    };
    let router = apply_server_hygiene(router, &config);

    let (listener, addr) = bind_ephemeral().await;
    let ctrl = ShutdownController::manual();
    let server = axum::serve(listener, router).with_graceful_shutdown(ctrl.signalled());
    let serve = tokio::spawn(run_until_drained(
        server,
        ctrl.subscribe(),
        config.drain_timeout,
        async { Ok::<(), String>(()) },
    ));

    let request = tokio::spawn(async move { http_request(addr, &get_request("/slow")).await });
    // Admit the request, then stop the server while it is still parked in the
    // handler and inside its own request-timeout budget.
    tokio::time::sleep(Duration::from_millis(20)).await;
    ctrl.trigger();

    let (status, _) = request.await.unwrap().unwrap();
    assert_eq!(status, 408, "the slow request should be denied with 408");

    let outcome = serve.await.unwrap().unwrap();
    assert_eq!(
        outcome,
        DrainOutcome::Clean,
        "the request timeout must fire before the drain deadline force-closes"
    );
}

#[test]
fn hygiene_defaults_are_conservative() {
    let config = ServeHygieneConfig::default();
    assert_eq!(config.drain_timeout, crate::DEFAULT_DRAIN_TIMEOUT);
    assert_eq!(
        config.request_timeout,
        Some(crate::DEFAULT_REQUEST_TIMEOUT),
        "requests should time out by default"
    );
    assert_eq!(
        config.max_concurrent_requests,
        Some(crate::DEFAULT_MAX_CONCURRENT_REQUESTS)
    );
    assert_eq!(config.max_connections, Some(crate::DEFAULT_MAX_CONNECTIONS));
    assert_eq!(
        config.max_body_bytes, None,
        "the global body cap is opt-in so it cannot clobber a route-local limit"
    );
}
