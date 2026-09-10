use anyhow::Context;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("--host") => {
            chio_worker_fleet::server::serve(serde_json::from_slice(&std::fs::read(
                args.get(1).context("Provide host configuration")?,
            )?)?)
            .await
        }
        Some("--worker") => chio_worker_fleet::worker().await,
        Some("--node") => {
            chio_personal_network::node::serve(serde_json::from_slice(&std::fs::read(
                args.get(1).context("Provide node configuration")?,
            )?)?)
            .await
        }
        _ => chio_agent_os_shared::web::main(chio_operations::Operations).await,
    }
}
