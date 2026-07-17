//! Minimal Prometheus scrape endpoint for the `chio-wall siem-export` serve
//! process.
//!
//! The SIEM serve process records SOC-export, DLQ-depth, alert-dispatch, lag,
//! and receipt-checkpoint metrics into the process-global chio-metrics-spec
//! registry via `RegistryMetricsSink`. But when `siem-export` runs as its own
//! process, nothing else binds an HTTP surface, so a co-located Prometheus agent
//! could never scrape those families and the metrics would be unobservable. This
//! module serves the registry over a small HTTP/1.1 `GET /metrics` endpoint.
//!
//! It is intentionally dependency-free (tokio only): chio-wall is a CLI and does
//! not carry axum/hyper. The endpoint composes, never fabricates, values (it
//! renders the same runtime families every other serving surface renders).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Environment key overriding the scrape bind address.
const METRICS_ADDR_ENV: &str = "CHIO_SIEM_METRICS_ADDR";
/// Localhost-only default: a co-located Prometheus agent scrapes over the shared
/// pod network namespace. Operators running a cross-container sidecar set
/// `CHIO_SIEM_METRICS_ADDR=0.0.0.0:9090`.
const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9090";
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// Bounded read for the request line/headers. A Prometheus scrape is a tiny GET;
/// this caps per-connection memory and never blocks on a body.
const REQUEST_READ_LIMIT: usize = 2048;

/// Resolve the configured scrape bind address, defaulting to localhost:9090.
pub(crate) fn configured_metrics_addr() -> String {
    match std::env::var(METRICS_ADDR_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => DEFAULT_METRICS_ADDR.to_string(),
    }
}

/// Render the SIEM serve-mode Prometheus body from the runtime families this
/// process produces: the alert-pack families (SOC export, DLQ depth, alert
/// dispatch, lag) plus the receipt-log watchdog gauges. Composes, never
/// fabricates.
#[must_use]
pub(crate) fn render_siem_metrics_body() -> String {
    let alert_pack = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut out);
        out
    };
    let watchdog = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_receipt_watchdog_gauges(&mut out);
        out
    };
    chio_metrics_spec::runtime::compose_metrics_body(&[&alert_pack, &watchdog])
}

/// Format the HTTP/1.1 response for a parsed request line. `GET /metrics`
/// renders the registry; anything else is 404. Kept pure so routing and
/// rendering are unit-testable without a socket.
fn http_response(request_line: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or(target);
    if method == "GET" && path == "/metrics" {
        let body = render_siem_metrics_body();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {PROMETHEUS_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        let body = "not found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
}

async fn serve_connection(mut stream: TcpStream) {
    // A single TcpStream::read is not guaranteed to contain the complete HTTP
    // request line, so a fragmented scrape could parse a partial target like
    // "GET /met" and 404, causing intermittent Prometheus scrape failures. Read
    // until the request line terminates (the first `\n`), bounded by the 2 KiB
    // REQUEST_READ_LIMIT, before routing.
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let remaining = REQUEST_READ_LIMIT.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        match stream.read(&mut chunk[..take]).await {
            Ok(0) => break,
            Ok(read) => {
                buf.extend_from_slice(&chunk[..read]);
                // The request line ends at the first newline; once we have it the
                // full target is present and further bytes are headers/body.
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    if buf.is_empty() {
        return;
    }
    let request = String::from_utf8_lossy(&buf);
    let request_line = request.lines().next().unwrap_or("");
    let response = http_response(request_line);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Bind the scrape endpoint. Separated from the serve loop so callers (and
/// tests) can bind an ephemeral port and read back the assigned address.
pub(crate) async fn bind_metrics_endpoint(addr: &str) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Serve `listener` until `cancel` flips true, spawning one task per scrape.
/// Never fabricates: each response renders the live registry.
pub(crate) fn spawn_metrics_endpoint(
    listener: TcpListener,
    mut cancel: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((stream, _peer)) = accepted {
                        tokio::spawn(serve_connection(stream));
                    }
                }
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn non_metrics_paths_are_404() {
        assert!(http_response("GET /healthz HTTP/1.1").starts_with("HTTP/1.1 404"));
        assert!(http_response("POST /metrics HTTP/1.1").starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn configured_addr_defaults_to_localhost_9090() {
        // The env is process-global; only assert the default when it is unset.
        if std::env::var(METRICS_ADDR_ENV).is_err() {
            assert_eq!(configured_metrics_addr(), DEFAULT_METRICS_ADDR);
        }
    }

    #[tokio::test]
    async fn fragmented_request_line_is_routed_correctly() {
        // A scrape whose request line arrives in two TCP reads must not be
        // misrouted as a partial target ("GET /met" -> 404). The server reads
        // until the request line is complete before routing.
        let listener = bind_metrics_endpoint("127.0.0.1:0")
            .await
            .expect("bind ephemeral scrape port");
        let addr = listener.local_addr().expect("resolve bound address");
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let handle = spawn_metrics_endpoint(listener, cancel_rx);

        let mut stream = TcpStream::connect(addr).await.expect("connect to endpoint");
        // Send the request line split across the target, with a delay so the
        // server's first read observes only the partial prefix.
        stream
            .write_all(b"GET /met")
            .await
            .expect("send partial request line");
        stream.flush().await.expect("flush partial");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        stream
            .write_all(b"rics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("send remainder");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read scrape response");
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "a fragmented GET /metrics must still route to 200, not 404: {text}"
        );

        let _ = cancel_tx.send(true);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_recorded_families() {
        // Record a distinctive SOC export so the endpoint has a real family to
        // render out of the process-global registry (unique label avoids sharing
        // with other tests in this binary).
        let exporter = "chio-wall-metrics-endpoint-test-exporter";
        chio_metrics_spec::runtime::families::SOC_EXPORT_TOTAL.incr(&[exporter, "success"]);

        let listener = bind_metrics_endpoint("127.0.0.1:0")
            .await
            .expect("bind ephemeral scrape port");
        let addr = listener.local_addr().expect("resolve bound address");
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let handle = spawn_metrics_endpoint(listener, cancel_rx);

        let mut stream = TcpStream::connect(addr).await.expect("connect to endpoint");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("send scrape request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read scrape response");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"), "status line: {text}");
        assert!(
            text.contains("text/plain; version=0.0.4"),
            "prometheus content-type: {text}"
        );
        assert!(
            text.contains(&format!(
                "chio_soc_export_total{{exporter=\"{exporter}\",outcome=\"success\"}}"
            )),
            "the endpoint must render the recorded registry family: {text}"
        );

        let _ = cancel_tx.send(true);
        let _ = handle.await;
    }
}
