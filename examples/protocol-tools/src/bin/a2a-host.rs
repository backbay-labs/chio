#[path = "../host.rs"]
mod host;
#[path = "../service.rs"]
mod service;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_a2a_edge::{A2aEdgeConfig, A2aKernelExecutionContext, ChioA2aEdge};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct App {
    edge: Mutex<ChioA2aEdge>,
    kernel: chio_kernel::ChioKernel,
    execution: A2aKernelExecutionContext,
    token: String,
    card: Value,
}

async fn invoke(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(message): Json<Value>,
) -> Result<Json<Value>, (StatusCode, &'static str)> {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        != Some(app.token.as_str())
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "A valid application credential is required",
        ));
    }
    let response = tokio::task::spawn_blocking(move || {
        let mut edge = app
            .edge
            .lock()
            .map_err(|_| "Protocol state is unavailable")?;
        Ok::<_, &'static str>(
            edge.handle_v1_jsonrpc(message, &app.kernel, &app.execution)
                .into_value(),
        )
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Protocol execution failed",
        )
    })?
    .map_err(|reason| (StatusCode::SERVICE_UNAVAILABLE, reason))?;
    response
        .map(Json)
        .ok_or((StatusCode::BAD_REQUEST, "A2A requests require an ID"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Usage: a2a-host NEW_SESSION_DIRECTORY"))?,
    );
    let host = host::boot(&directory)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let edge = ChioA2aEdge::new(
        A2aEdgeConfig {
            agent_name: "Chio document analyst".into(),
            agent_description: "Count caller-provided text under a bounded signed grant".into(),
            endpoint_url: endpoint.clone(),
            ..A2aEdgeConfig::default()
        },
        vec![host.manifest],
    )?;
    let token = chio_core::crypto::Keypair::generate().public_key().to_hex();
    std::fs::write(directory.join("client-token.txt"), &token)?;
    let execution = A2aKernelExecutionContext {
        agent_id: host.capability.subject.to_hex(),
        capability: host.capability,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let app = Arc::new(App {
        card: edge.agent_card_v1(),
        edge: Mutex::new(edge),
        kernel: host.kernel,
        execution,
        token,
    });
    let router = Router::new()
        .route("/", post(invoke))
        .route(
            "/.well-known/agent-card.json",
            get(|State(app): State<Arc<App>>| async move { Json(app.card.clone()) }),
        )
        .layer(DefaultBodyLimit::max(65_536))
        .with_state(app);
    std::fs::write(
        directory.join("server.json"),
        serde_json::to_vec_pretty(&json!({"endpoint":endpoint}))?,
    )?;
    eprintln!(
        "A2A 1.0 listening at {endpoint}; credential: {}",
        directory.join("client-token.txt").display()
    );
    axum::serve(listener, router).await?;
    Ok(())
}
