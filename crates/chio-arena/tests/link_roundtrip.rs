use chio_arena::link::KernelLink;
use serde_json::json;

#[tokio::test]
async fn sends_envelope_between_paired_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let (agent_a, agent_b) = KernelLink::pair("agent-a", "agent-b").into_endpoints();

    agent_a
        .send("step-1", json!({ "tool": "read_file" }))
        .await?;
    let received = agent_b
        .recv()
        .await
        .ok_or("expected one envelope from agent-a")?;

    assert_eq!(received.from_agent, "agent-a");
    assert_eq!(received.to_agent, "agent-b");
    assert_eq!(received.step_id, "step-1");
    assert_eq!(received.payload, json!({ "tool": "read_file" }));
    Ok(())
}

#[tokio::test]
async fn sends_in_both_directions() -> Result<(), Box<dyn std::error::Error>> {
    let (agent_a, agent_b) = KernelLink::pair("agent-a", "agent-b").into_endpoints();

    agent_b.send("step-2", json!({ "ok": true })).await?;
    let received = agent_a
        .recv()
        .await
        .ok_or("expected one envelope from agent-b")?;

    assert_eq!(received.from_agent, "agent-b");
    assert_eq!(received.to_agent, "agent-a");
    assert_eq!(received.step_id, "step-2");
    assert_eq!(received.payload, json!({ "ok": true }));
    Ok(())
}
