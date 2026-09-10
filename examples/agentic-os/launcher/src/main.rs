use anyhow::Context;
fn config<T: serde::de::DeserializeOwned>(args: &[String]) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(
        args.get(1)
            .context("Provide the process configuration file")?,
    )?)?)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("--host") => return chio_worker_fleet::server::serve(config(&args)?).await,
        Some("--worker") => return chio_worker_fleet::worker().await,
        Some("--node") => return chio_personal_network::node::serve(config(&args)?).await,
        Some("--organization") => {
            return chio_incident_response::organization::serve(config(&args)?).await
        }
        Some("--threshold-member") => {
            return chio_cooperative::threshold::member::serve(config(&args)?).await
        }
        Some("--threshold-authority") => {
            return chio_cooperative::threshold::authority::serve(config(&args)?).await
        }
        _ => {}
    }
    let binary = std::env::args().next().context("No executable name")?;
    let binary = std::path::Path::new(&binary)
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid executable name")?;
    let selected = std::env::var("CHIO_APPLICATION").unwrap_or_else(|_| {
        binary
            .strip_prefix("chio-")
            .unwrap_or("mission-host")
            .into()
    });
    use chio_agent_os_shared::web::main;
    match selected.as_str(){
 "mission-host"|"agent-os"=>main(chio_mission_host::Mission).await,
 "worker-fleet"=>main(chio_worker_fleet::Fleet).await,
 "knowledge-network"=>main(chio_knowledge_network::Knowledge).await,
 "research-swarm"=>main(chio_research_swarm::Research).await,
 "software-factory"=>main(chio_software_factory::Factory).await,
 "personal-network"=>main(chio_personal_network::Personal).await,
 "cooperative"=>main(chio_cooperative::Cooperative).await,
 "incident-response"=>main(chio_incident_response::Incident).await,
 "cognition-marketplace"=>main(chio_cognition_marketplace::Marketplace).await,
 "operations"=>main(chio_operations::Operations).await,
 "suite"=>main(chio_suite::Suite).await,
 _=>anyhow::bail!("Choose a downloaded Chio application executable or set CHIO_APPLICATION to a chapter application ID"),
 }
}
