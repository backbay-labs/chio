use anyhow::Result;
use chio_agent_os_shared::{json, Application, Run};
use chio_software_factory::Factory;
#[tokio::test]
async fn real_candidate_passes_tests_and_needs_exact_publication_approval() -> Result<()> {
    let root = std::env::temp_dir().join("chio-factory-tests");
    let app = Factory;
    let input = app.sample();
    let run = Run::create(&root, app.name(), &input)?;
    let result = app.execute(input, run.clone()).await?;
    run.finish(&Ok(result.clone()))?;
    assert_eq!(result["baseline"]["passed"], false);
    assert_eq!(result["tests"]["passed"], true);
    assert_eq!(result["review"]["approved"], true);
    assert_eq!(result["published"], false);
    assert!(!run.directory()?.join("release").exists());
    let decision = json!({
        "action":"decide",
        "decision":"approve",
        "source_run":run.id()?,
        "candidate_sha256":result["candidate_sha256"],
        "proposal_sha256":result["approval"][
            "proposal_sha256"
        ]
    });
    let mut stale = decision.clone();
    stale["candidate_sha256"] = json!("changed");
    let rejected = Run::create(&root, app.name(), &stale)?;
    assert!(app.execute(stale, rejected).await.is_err());
    assert!(!run.directory()?.join("release").exists());
    let publish = Run::create(&root, app.name(), &decision)?;
    let published = app.execute(decision.clone(), publish).await?;
    assert_eq!(published["published"], true, "{published}");
    let again = Run::create(&root, app.name(), &decision)?;
    let repeated = app.execute(decision, again).await?;
    assert_eq!(published["receipt_id"], repeated["receipt_id"]);
    let check = chio_software_factory::repository::isolated_python(
        &run.directory()?.join("release"),
        "test_analysis.py",
    )
    .await?;
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    Ok(())
}
