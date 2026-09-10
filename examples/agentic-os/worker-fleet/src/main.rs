use anyhow::Context;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--host") => {
            chio_worker_fleet::server::serve(serde_json::from_slice(&std::fs::read(
                args.get(1)
                    .context("Host requires its configuration file")?,
            )?)?)
            .await
        }
        Some("--worker") => chio_worker_fleet::worker().await,
        _ => chio_agent_os_shared::web::main(chio_worker_fleet::Fleet).await,
    }
}
