use anyhow::Result;
use chio_agent_os_shared::{json, Application, Run};
#[tokio::test]
async fn independent_organizations_enforce_approval_and_verify_actual_recovery() -> Result<()> {
    for (approve, backend, status, effects) in [
        (true, false, "resolved", 1),
        (false, false, "awaiting_approval", 0),
        (true, true, "open", 1),
    ] {
        let app = chio_incident_response::Incident;
        let mut input = app.sample();
        input["approve_repair"] = json!(approve);
        input["backend_failed"] = json!(backend);
        input["customer_records"] = json!("PRIVATE-CUSTOMER-SENTINEL");
        let run = Run::create(
            &std::env::temp_dir().join("chio-incident-tests"),
            app.name(),
            &input,
        )?;
        let output = chio_incident_response::resolve(
            input,
            run,
            env!("CARGO_BIN_EXE_chio-incident-response").into(),
        )
        .await?;
        assert_eq!(output["status"], status);
        assert_eq!(output["organization_records"][1]["repairs"], effects);
        assert_eq!(output["denials"]["repairs_after_refusals"], 0);
        assert!(!serde_json::to_string(&output["organization_records"][2])?
            .contains("PRIVATE-CUSTOMER-SENTINEL"));
        let pids = output["organizations"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("No organizations"))?
            .iter()
            .map(|o| o["pid"].as_u64())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(pids.len(), 3);
    }
    Ok(())
}
