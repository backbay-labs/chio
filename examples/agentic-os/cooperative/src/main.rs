use anyhow::Context;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--node") {
        chio_personal_network::node::serve(serde_json::from_slice(&std::fs::read(
            args.get(1).context("Provide a member configuration file")?,
        )?)?)
        .await
    } else if args.first().map(String::as_str) == Some("--threshold-member") {
        chio_cooperative::threshold::member::serve(serde_json::from_slice(&std::fs::read(
            args.get(1).context("Provide member configuration")?,
        )?)?)
        .await
    } else if args.first().map(String::as_str) == Some("--threshold-authority") {
        chio_cooperative::threshold::authority::serve(serde_json::from_slice(&std::fs::read(
            args.get(1).context("Provide authority configuration")?,
        )?)?)
        .await
    } else {
        chio_agent_os_shared::web::main(chio_cooperative::Cooperative).await
    }
}
