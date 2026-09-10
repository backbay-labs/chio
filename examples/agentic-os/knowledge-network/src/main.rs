#[tokio::main]
async fn main() -> anyhow::Result<()> {
    chio_agent_os_shared::web::main(chio_knowledge_network::Knowledge).await
}
