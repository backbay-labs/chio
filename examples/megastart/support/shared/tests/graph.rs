use anyhow::Result;
use chio_agent_os_shared::{graph::GraphRuntime, host::Host, json, Run, Value};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_swarm_authority::{SwarmFanoutRequest, SwarmFanoutTask, SwarmTaskCompletion};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
struct Workers(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for Workers {
    fn server_id(&self) -> &str {
        "factory-workers"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["plan".into(), "test".into(), "review".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        input: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(input)
    }
}
#[tokio::test]
async fn graph_admits_real_work_binds_its_worker_and_closes_after_results() -> Result<()> {
    let root = std::env::temp_dir().join("chio-graph-application-tests");
    let run = Run::create(&root, "graph-test", &json!({}))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut host = Host::open(
        &run.directory()?.join("host"),
        "graph-test",
        vec![Box::new(Workers(calls.clone()))],
    )?;
    let planner = host.issue("factory-workers", &["plan"], 1)?;
    let planning = host
        .call(
            &run,
            "planner",
            &planner,
            "factory-workers",
            "plan",
            json!({"tasks":["test","review"]}),
        )
        .await?;
    assert!(planning.allowed);
    let root = host.root("factory-workers", &["test", "review"], 4)?;
    let test = host.delegate(&run, &root, "test", &["test"], 1, 5000)?;
    let review = host.delegate(&run, &root, "review", &["review"], 1, 5000)?;
    let bundle = host.mint_graph(SwarmFanoutRequest {
        graph_id: run.id()?,
        root_transaction_ref: planning.receipt_id.clone(),
        parent_receipt_id: planning.receipt_id,
        session_anchor: run.id()?,
        parent: root.token,
        tasks: vec![
            SwarmFanoutTask {
                task_id: "test".into(),
                capability: test.clone(),
                protocol_target: "local://factory-workers".into(),
                reserved_units: 1,
            },
            SwarmFanoutTask {
                task_id: "review".into(),
                capability: review.clone(),
                protocol_target: "local://factory-workers".into(),
                reserved_units: 1,
            },
        ],
        policy_digest: chio_core::sha256_hex(b"graph-test"),
        now_unix_ms: chio_agent_os_shared::events::now_ms(),
        lifetime_ms: 60_000,
    })?;
    let runtime = GraphRuntime::attach(
        &mut host,
        bundle,
        &run.directory()?.join("orchestration.db"),
    )?;
    let first = runtime
        .call(&host, &run, &test, "test", "test", json!({"candidate":"a"}))
        .await?;
    assert!(first.allowed, "{}", run.snapshot()?);
    let before = calls.load(Ordering::SeqCst);
    let replay = runtime
        .call(&host, &run, &test, "test", "test", json!({"candidate":"a"}))
        .await?;
    assert!(!replay.allowed);
    assert_eq!(calls.load(Ordering::SeqCst), before);
    let second = runtime
        .call(
            &host,
            &run,
            &review,
            "review",
            "review",
            json!({"candidate":"a"}),
        )
        .await?;
    assert!(second.allowed, "{}", run.snapshot()?);
    let closed = host.complete_graph(
        runtime.bundle,
        vec![
            SwarmTaskCompletion {
                task_id: "test".into(),
                receipt_id: first.receipt_id,
                consumed_units: 1,
            },
            SwarmTaskCompletion {
                task_id: "review".into(),
                receipt_id: second.receipt_id,
                consumed_units: 1,
            },
        ],
        json!({"candidate":"a"}),
    )?;
    assert_eq!(closed.terminal_receipts.len(), 1);
    assert!(chio_swarm_authority::verify_swarm_admission_bundle(
        &closed,
        &closed.continuation_tokens[0].token_id,
        &[host.signer]
    )
    .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    Ok(())
}
