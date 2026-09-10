//! Run the Envoy ext_authz service with a pinned Chio authority.
use chio_core_types::crypto::PublicKey;
use chio_envoy_ext_authz::{
    proto::envoy::service::auth::v3::authorization_server::AuthorizationServer,
    runtime::HttpAuthorityKernel, ChioExtAuthzService, EnvoyKernel,
};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
#[command(about = "Authorize Envoy requests through a pinned, durable Chio authority")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9091")]
    listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:9092")]
    health_listen: SocketAddr,
    #[arg(long)]
    authority_url: String,
    #[arg(long)]
    trusted_kernel_key_file: PathBuf,
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
}

struct Shared(Arc<HttpAuthorityKernel>);
#[async_trait::async_trait]
impl EnvoyKernel for Shared {
    async fn evaluate(
        &self,
        request: chio_envoy_ext_authz::ToolCallRequest,
    ) -> Result<chio_envoy_ext_authz::Verdict, chio_envoy_ext_authz::KernelError> {
        self.0.evaluate(request).await
    }
    async fn evaluate_with_receipt(
        &self,
        request: chio_envoy_ext_authz::ToolCallRequest,
    ) -> Result<(chio_envoy_ext_authz::Verdict, Option<String>), chio_envoy_ext_authz::KernelError>
    {
        self.0.evaluate_with_receipt(request).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .map_err(|error| error.to_string())?;
    if args.timeout_ms == 0 || args.timeout_ms > 30_000 {
        return Err("timeout-ms must be between 1 and 30000".into());
    }
    let key = std::fs::read_to_string(args.trusted_kernel_key_file)?;
    let authority = Arc::new(HttpAuthorityKernel::new(
        &args.authority_url,
        PublicKey::from_hex(key.trim())?,
        Duration::from_millis(args.timeout_ms),
    )?);
    let ready = authority.clone();
    let health = axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok\n" }))
        .route(
            "/readyz",
            axum::routing::get(move || {
                let ready = ready.clone();
                async move {
                    if ready.ready().await {
                        (axum::http::StatusCode::OK, "ready\n")
                    } else {
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "authority unavailable\n",
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind(args.health_listen).await?;
    let grpc = tonic::transport::Server::builder()
        .add_service(
            AuthorizationServer::new(ChioExtAuthzService::new(Shared(authority)))
                .max_decoding_message_size(1_048_576),
        )
        .serve(args.listen);
    eprintln!(
        "Chio ext_authz listening on {}; health on {}",
        args.listen, args.health_listen
    );
    tokio::select! {
        result = grpc => result?,
        result = axum::serve(listener, health) => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}
