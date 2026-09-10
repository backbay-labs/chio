pub mod signals;
pub mod work;
use anyhow::Result;
use chio_agent_os_shared::{async_trait, host::text, json, Application, Run, Value};
use std::sync::atomic::AtomicUsize;
use work::{Job, ResearchTools, Source};
pub struct Research;
pub fn sources() -> Vec<Source> {
    vec![
    Source{id:"trial-a".into(),title:"Latency trial A".into(),text:"# Latency trial A\nCache enabled. The reported mean latency is 20 ms.\nsamples: 10, 20, 30\nUse operation IDs to reconcile requests after connection loss.\n".into()},
    Source{id:"trial-b".into(),title:"Latency trial B".into(),text:"# Latency trial B\nCache disabled. The reported mean latency is 35 ms.\nsamples: 20, 40, 45\nRetain completed operation results before returning an acknowledgement.\n".into()},
    Source{id:"runbook".into(),title:"Experiment runbook".into(),text:"# Experiment runbook\nLatency comparisons must state whether the cache was enabled.\nsamples: 10, 15, 20\nA missing acknowledgement does not prove the operation failed.\n".into()},
]
}
#[async_trait]
impl Application for Research {
    fn name(&self) -> &'static str {
        "research-swarm"
    }
    fn title(&self) -> &'static str {
        "Research that follows the evidence"
    }
    fn description(&self) -> &'static str {
        "Signed observations influence a real assignment queue. Chio still admits every selected tool call independently."
    }
    fn sample(&self) -> Value {
        json!({
            "question":"What explains the reported latency difference, and can the means be reproduced?",
            "sources":sources(),
            "allowance":4,
            "query_after_seconds":0,
            "observer_weight":1.0,
            "observation_age_seconds":{
                "discover":0,
                "contradiction":0,
                "reproduce":0
            },
            "remove_worker":null,
            "exercise_denials":true
        })
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        let question = text(&input, "question", 2000)?;
        let sources: Vec<Source> = if input["sources"].is_array() {
            serde_json::from_value(input["sources"].clone())?
        } else {
            sources()
        };
        anyhow::ensure!(
            !sources.is_empty()
                && sources.len() <= 8
                && sources.iter().map(|s| s.text.len()).sum::<usize>() <= 80_000,
            "Supply 1 to 8 sources totaling at most 80000 bytes"
        );
        let ids = sources
            .iter()
            .map(|s| &s.id)
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            ids.len() == sources.len() && sources.iter().all(|s| !s.id.is_empty()),
            "Source IDs must be nonempty and distinct"
        );
        let allowance = input["allowance"].as_u64().unwrap_or(4) as usize;
        anyhow::ensure!((1..=24).contains(&allowance), "Choose 1 to 24 work units");
        let query_after = input["query_after_seconds"].as_u64().unwrap_or(0);
        anyhow::ensure!(
            query_after <= 3600,
            "Explore up to 3600 seconds after admission"
        );
        let weight = input["observer_weight"].as_f64().unwrap_or(1.0);
        anyhow::ensure!(
            weight.is_finite() && (0.0..=1.0).contains(&weight),
            "Observer weight must be between 0 and 1"
        );
        let removed = input["remove_worker"].as_str();
        anyhow::ensure!(
            removed.is_none_or(|v| signals::CLASSES.contains(&v)),
            "Choose a known worker to remove"
        );
        let directory = run.directory()?;
        let observer = ResearchTools {
            sources: sources.clone(),
            effects: AtomicUsize::new(0),
        };
        let host = chio_agent_os_shared::host::Host::open(
            &directory.join("observer-host"),
            "research-observation-production-v1",
            vec![Box::new(work::ToolServer(std::sync::Arc::new(observer)))],
        )?;
        let cap = host.issue("research", &["discover"], 1)?;
        let finding = host
            .call(
                &run,
                "source-observer",
                &cap,
                "research",
                "discover",
                json!({"source":sources[0].id,"question":question}),
            )
            .await?;
        let observation_receipt = finding.receipt_id.clone();
        let finding = finding.require_output()?;
        let signals = signals::Signals::start(&directory, run.clone()).await?;
        let numeric = finding["passages"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter(|p| {
                        p["text"]
                            .as_str()
                            .is_some_and(|s| s.chars().any(|c| c.is_ascii_digit()))
                    })
                    .count()
            })
            .unwrap_or(0);
        let mut deposits = Vec::new();
        for (class, confidence, half_life) in [
            ("discover", 0.45, 600.0),
            ("contradiction", if numeric > 1 { 0.95 } else { 0.15 }, 60.0),
            ("reproduce", 0.8, 1800.0),
        ] {
            let age = input["observation_age_seconds"][class]
                .as_u64()
                .unwrap_or(0);
            anyhow::ensure!(age <= 3600, "Observation age must be at most 3600 seconds");
            let deposit=signals.deposit(class,json!({
    "responsibility":class,
    "source_receipt":observation_receipt,
    "evidence":finding,
    "suggestion":"Inspect these source claims; the observation itself grants no tool authority"
}),confidence,age,half_life)?;
            anyhow::ensure!(
                signals.deliver(deposit.clone()).await?["accepted"] == true,
                "Receiver refused a newly produced observation"
            );
            deposits.push(deposit);
        }
        // Query the actual runtime at the chosen time. No browser-side decay substitutes for this value.
        let concentrations = signals.concentrations(query_after, weight)?;
        let mut ranked = concentrations.clone();
        ranked.sort_by(|a, b| {
            b.total_strength
                .total_cmp(&a.total_strength)
                .then(a.subject_class.cmp(&b.subject_class))
        });
        let order = ranked
            .iter()
            .map(|v| v.subject_class.clone())
            .collect::<Vec<_>>();
        run.emit("scheduler.ranked","coordinator","Ranked real stored observations at the selected query time",json!({"concentrations":concentrations,"order":order,"query_after_seconds":query_after,"observer_weight":weight}))?;
        let mut jobs = Vec::new();
        for source in &sources {
            for task in signals::CLASSES {
                if task != "reproduce"
                    || source.text.lines().any(|line| line.starts_with("samples:"))
                {
                    jobs.push(Job {
                        id: format!("{}:{task}", source.id),
                        task: task.into(),
                        source: source.id.clone(),
                    });
                }
            }
        }
        let adaptive = work::schedule(
            &directory,
            &run,
            "observation-priority",
            question,
            sources.clone(),
            &jobs,
            &order,
            allowance,
            removed,
        )
        .await?;
        let fixed = work::schedule(
            &directory,
            &run,
            "fixed-assignment",
            question,
            sources.clone(),
            &jobs,
            &signals::CLASSES
                .iter()
                .map(|s| (*s).into())
                .collect::<Vec<_>>(),
            allowance,
            removed,
        )
        .await?;
        let denials = if input["exercise_denials"] == true {
            signals.denials(&deposits[0]).await?
        } else {
            Value::Null
        };
        Ok(json!({
            "question":question,
            "sources":sources,
            "observations":deposits,
            "concentrations":concentrations,
            "order":order,
            "adaptive":adaptive,
            "baseline":fixed,
            "denials":denials,
            "report":{
                "evidence":finding,
                "work":adaptive["assignments"],
                "unresolved":adaptive["remaining"],
                "interpretation":"The two schedules use the same input, allowance, tools, and durable claim rules. Priority changes which investigations finish first; the measured run does not assume a throughput advantage."
            },
            "transport":{
                "observations":"HTTP between separately configured observer and receiving host in this local application",
                "origin_signatures":"Verified against the receiver's selected observer passport",
                "workflow_proof_claimed":false
            }
        }))
    }
}
