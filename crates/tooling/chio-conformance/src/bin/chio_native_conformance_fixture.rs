use std::io::Write;
use std::net::SocketAddr;

use chio_conformance::{fixture_messages_for_request, NativeFixtureRequest, NativeFixtureResponse};
use chio_kernel::transport::{read_frame, write_frame, TransportError};
use tiny_http::{Method, Response, Server, StatusCode};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut http_listen = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--http-listen" => {
                http_listen = Some(
                    args.next()
                        .ok_or_else(|| "missing value for --http-listen".to_string())?
                        .parse::<SocketAddr>()?,
                );
            }
            other => return Err(format!("unexpected flag: {other}").into()),
        }
    }

    if let Some(listen) = http_listen {
        run_http_fixture(listen)
    } else {
        run_stdio_fixture()
    }
}

fn run_stdio_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    let frame = match read_frame(&mut stdin) {
        Ok(frame) => frame,
        Err(TransportError::ConnectionClosed) => return Ok(()),
        Err(error) => return Err(Box::new(error)),
    };
    let request: chio_core::message::AgentMessage = serde_json::from_slice(&frame)?;
    for message in fixture_messages_for_request(&request) {
        let bytes = chio_core::canonical::canonical_json_bytes(&message)?;
        write_frame(&mut stdout, &bytes)?;
        stdout.flush()?;
    }
    Ok(())
}

fn run_http_fixture(listen: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let server = Server::http(listen).map_err(|error| error.to_string())?;
    for mut request in server.incoming_requests() {
        if request.method() != &Method::Post || request.url() != "/chio-conformance/v1/invoke" {
            let response = Response::empty(StatusCode(404));
            let _ = request.respond(response);
            continue;
        }

        let mut body = String::new();
        request.as_reader().read_to_string(&mut body)?;
        let fixture_request: NativeFixtureRequest = serde_json::from_str(&body)?;
        let response = NativeFixtureResponse {
            messages: fixture_messages_for_request(&fixture_request.request),
        };
        let response_body = serde_json::to_string(&response)?;
        let http_response = Response::from_string(response_body)
            .with_status_code(StatusCode(200))
            .with_header(
                tiny_http::Header::from_bytes("Content-Type", "application/json")
                    .map_err(|_| "failed to build content-type header")?,
            );
        let _ = request.respond(http_response);
    }
    Ok(())
}
