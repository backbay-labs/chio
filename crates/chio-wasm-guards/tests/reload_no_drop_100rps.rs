use std::sync::Arc;
use std::time::Duration;

use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core::crypto::Keypair;
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use chio_wasm_guards::{
    Engine, GuardRequest, GuardVerdict, WasmGuard, WasmGuardAbi, WasmGuardError,
};
use tokio::task::JoinSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug)]
struct ByteVerdictBackend {
    verdict: GuardVerdict,
    loaded: bool,
}

impl ByteVerdictBackend {
    fn new() -> Self {
        Self {
            verdict: GuardVerdict::Deny {
                reason: Some("not loaded".to_string()),
            },
            loaded: false,
        }
    }
}

impl WasmGuardAbi for ByteVerdictBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        self.verdict = match wasm_bytes {
            b"allow" => GuardVerdict::Allow,
            b"deny" => GuardVerdict::Deny {
                reason: Some("reloaded deny".to_string()),
            },
            _ => {
                return Err(WasmGuardError::Compilation(
                    "unknown no-drop test module bytes".to_string(),
                ));
            }
        };
        self.loaded = true;
        Ok(())
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        if !self.loaded {
            return Err(WasmGuardError::BackendUnavailable);
        }
        Ok(self.verdict.clone())
    }

    fn backend_name(&self) -> &str {
        "byte-verdict"
    }
}

fn build_backend(bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    let mut backend = ByteVerdictBackend::new();
    backend.load_module(bytes, 1_000)?;
    Ok(Box::new(backend))
}

fn make_guard(bytes: &[u8]) -> Result<WasmGuard, WasmGuardError> {
    Ok(WasmGuard::new(
        "reload-no-drop".to_string(),
        build_backend(bytes)?,
        false,
        Some("initial".to_string()),
    ))
}

fn make_context_request(index: usize) -> TestResult<ToolCallRequest> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(ToolCallRequest {
        request_id: format!("req-{index}"),
        capability: CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-{index}"),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &issuer,
        )?,
        tool_name: "test_tool".to_string(),
        server_id: "test_server".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({ "index": index }),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

fn evaluate_guard(guard: &WasmGuard, index: usize) -> TestResult<(usize, Verdict)> {
    let request = make_context_request(index)?;
    let scope = ChioScope::default();
    let agent_id = "agent-1".to_string();
    let server_id = "test_server".to_string();
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    Ok((index, guard.evaluate(&ctx)?))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_reload_under_100rps_drops_no_requests() -> TestResult {
    let engine = Arc::new(Engine::new(build_backend).without_blocklist());
    let guard = engine.register_guard("guard-a", make_guard(b"allow")?)?;
    let reload_engine = Arc::clone(&engine);
    let reload = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(250)).await;
        reload_engine.reload("guard-a", b"deny")
    });

    let mut tasks = JoinSet::new();
    for index in 0..100 {
        let guard = Arc::clone(&guard);
        tasks.spawn(async move { evaluate_guard(&guard, index) });
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let reload_epoch = reload.await??;
    let mut allow = 0_usize;
    let mut deny = 0_usize;
    let mut outcomes = Vec::new();
    while let Some(outcome) = tasks.join_next().await {
        match outcome?? {
            (index, Verdict::Allow) => {
                allow += 1;
                outcomes.push((index, Verdict::Allow));
            }
            (index, Verdict::Deny) => {
                deny += 1;
                outcomes.push((index, Verdict::Deny));
            }
            (_, Verdict::PendingApproval) => {
                return Err(std::io::Error::other(
                    "unexpected pending approval verdict during reload",
                )
                .into());
            }
        }
    }

    assert_eq!(allow + deny, 100, "all scheduled requests must complete");
    assert!(allow > 0, "expected at least one pre-reload allow verdict");
    assert!(deny > 0, "expected at least one post-reload deny verdict");
    outcomes.sort_by_key(|(index, _)| *index);
    let first_deny = outcomes
        .iter()
        .position(|(_, verdict)| matches!(verdict, Verdict::Deny))
        .ok_or_else(|| std::io::Error::other("missing post-reload deny boundary"))?;
    assert!(
        outcomes[..first_deny]
            .iter()
            .all(|(_, verdict)| matches!(verdict, Verdict::Allow)),
        "pre-boundary requests must all use the initial allow epoch"
    );
    assert!(
        outcomes[first_deny..]
            .iter()
            .all(|(_, verdict)| matches!(verdict, Verdict::Deny)),
        "post-boundary requests must all use the reloaded deny epoch"
    );
    assert_eq!(guard.current_epoch_id(), reload_epoch);
    Ok(())
}
