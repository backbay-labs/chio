#[path = "../host.rs"]
mod host;
#[path = "../service.rs"]
mod service;

use chio_acp_edge::{AcpAgentConnection, AcpEdgeConfig, AcpKernelExecutionContext, ChioAcpEdge};
use std::{
    io::{BufRead, Read, Write},
    path::PathBuf,
};

fn main() -> anyhow::Result<()> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Usage: acp-host NEW_SESSION_DIRECTORY"))?,
    );
    let host = host::boot(&directory)?;
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![host.manifest])?;
    let mut connection = AcpAgentConnection::new(edge, service::TOOL.into(), "text".into())?;
    let execution = AcpKernelExecutionContext {
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
    let mut reader = std::io::stdin().lock();
    let mut writer = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        if (&mut reader).take(1_048_577).read_until(b'\n', &mut line)? == 0 {
            break;
        }
        anyhow::ensure!(line.len() <= 1_048_576, "ACP message exceeds one MiB");
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: serde_json::Value = serde_json::from_slice(&line)?;
        for response in connection.handle_jsonrpc(message, &host.kernel, &execution) {
            serde_json::to_writer(&mut writer, &response)?;
            writeln!(&mut writer)?;
        }
        writer.flush()?;
    }
    Ok(())
}
