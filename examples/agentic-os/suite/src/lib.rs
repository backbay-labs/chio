use anyhow::{Context, Result};
use chio_agent_os_shared::{async_trait, host::text, json, Application, Run, Value};
use chio_knowledge_network::Knowledge;
use chio_research_swarm::Research;
use chio_software_factory::Factory;
pub struct Suite;
#[async_trait]
impl Application for Suite {
    fn name(&self) -> &'static str {
        "suite"
    }
    fn title(&self) -> &'static str {
        "An operating system for a research-to-repair mission"
    }
    fn description(&self) -> &'static str {
        "Retrieve an operating procedure, assign research, obtain joint compute approval, repair the analysis program, and publish only its reviewed candidate."
    }
    fn sample(&self) -> Value {
        json!({
            "question":"How should the team compare latency measurements and retain evidence for a repair?",
            "issue":Factory.sample()[
                "issue"
            ],
            "mode":"deterministic",
            "member_budget":12,
            "approve_publication":true
        })
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        compose(input, run, std::env::current_exe()?).await
    }
}
async fn stage(app: &dyn Application, input: Value, parent: &Run) -> Result<(Value, Run)> {
    let child = Run::create(&parent.directory()?.join("stages"), app.name(), &input)?;
    let result = app.execute(input, child.clone()).await;
    child.finish(&result)?;
    parent.emit("suite.stage", app.name(), app.title(), child.snapshot()?)?;
    Ok((result?, child))
}
pub async fn compose(input: Value, run: Run, executable: std::path::PathBuf) -> Result<Value> {
    let question = text(&input, "question", 2000)?;
    let issue = text(&input, "issue", 2000)?;
    let mode = input["mode"].as_str().unwrap_or("deterministic");
    anyhow::ensure!(
        ["deterministic", "model"].contains(&mode),
        "Choose deterministic or model execution"
    );
    let (knowledge, _) = stage(
        &Knowledge,
        json!({
            "question":question,
            "caller":"engineer",
            "mode":if mode=="model"{
                "model"
            }else{
                "retrieve"
            },
            "exercise_denials":true
        }),
        &run,
    )
    .await?;
    let mut research_input = Research.sample();
    research_input["question"] = json!(question);
    research_input["allowance"] = json!(9);
    let passages = knowledge["evidence"]
        .as_array()
        .context("Knowledge returned no evidence list")?;
    let reference = passages
        .iter()
        .filter_map(|p| p["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if !reference.is_empty() {
        research_input["sources"].as_array_mut().context("Research has no corpus")?.push(json!({"id":"retrieved-procedure","title":"Retrieved operating procedure","text":reference}));
    }
    let (research, _) = stage(&Research, research_input, &run).await?;
    // Compute over the actual measurements supplied to the research application.
    let samples = research["sources"]
        .as_array()
        .context("No research sources")?
        .iter()
        .filter_map(|s| s["text"].as_str())
        .flat_map(|t| t.lines())
        .filter_map(|line| line.strip_prefix("samples:"))
        .flat_map(|values| values.split(','))
        .map(|v| v.trim().parse::<f64>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !samples.is_empty(),
        "The research did not supply a numerical workload"
    );
    let joint_input = json!({"values":samples,"member_budget":input["member_budget"],"member_accepts":true,"exercise_denials":true});
    let joint_run = Run::create(
        &run.directory()?.join("stages"),
        "cooperative",
        &joint_input,
    )?;
    let joint =
        chio_cooperative::execute_bilateral(joint_input, joint_run.clone(), executable).await;
    joint_run.finish(&joint)?;
    run.emit(
        "suite.stage",
        "cooperative",
        "Jointly authorize computation over the investigated samples",
        joint_run.snapshot()?,
    )?;
    let joint = joint?;
    if joint["status"] != "completed" {
        return Ok(json!({
            "status":"awaiting_joint_authority",
            "knowledge":knowledge,
            "research":research,
            "cooperative":joint,
            "published":false
        }));
    }
    let (factory, factory_run) = stage(
        &Factory,
        json!({"issue":issue,"mode":mode,"exercise_denials":true}),
        &run,
    )
    .await?;
    let approval = &factory["approval"];
    let decision = json!({
        "action":"decide",
        "source_run":factory_run.id()?,
        "candidate_sha256":approval["candidate_sha256"],
        "proposal_sha256":approval["proposal_sha256"],
        "decision":if input["approve_publication"]==true{
            "approve"
        }else{
            "reject"
        }
    });
    let (publication, _) = stage(&Factory, decision, &run).await?;
    let source_versions = passages
        .iter()
        .map(|p| json!({"source":p["source_id"],"sha256":p["version_sha256"]}))
        .collect::<Vec<_>>();
    Ok(json!({
        "status":if publication["published"]==true{
            "completed"
        }else{
            "publication_declined"
        },
        "knowledge":knowledge,
        "research":research,
        "cooperative":joint,
        "factory":factory,
        "publication":publication,
        "source_versions":source_versions,
        "published":publication["published"],
        "composition":"The same chapter applications run sequentially. Retrieved text enters the research corpus; its numerical workload requires bilateral approval. The factory produces and tests the requested repair; the release owner decides the exact candidate."
    }))
}
