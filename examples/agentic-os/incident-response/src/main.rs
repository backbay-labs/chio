use anyhow::Context;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--organization") {
        chio_incident_response::organization::serve(serde_json::from_slice(&std::fs::read(
            args.get(1).context("Provide organization configuration")?,
        )?)?)
        .await
    } else {
        chio_agent_os_shared::web::main(chio_incident_response::Incident).await
    }
}
