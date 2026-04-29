use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core::crypto::Keypair;
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use chio_wasm_guards::{
    Engine, EpochId, GuardRequest, GuardVerdict, HotReloadError, WasmGuard, WasmGuardAbi,
    WasmGuardError,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
                reason: Some("byte verdict denied".to_string()),
            },
            _ => {
                return Err(WasmGuardError::Compilation(
                    "unknown test module bytes".to_string(),
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
        "reload-test".to_string(),
        build_backend(bytes)?,
        false,
        Some("initial".to_string()),
    ))
}

fn make_context_request() -> TestResult<ToolCallRequest> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(ToolCallRequest {
        request_id: "req-1".to_string(),
        capability: CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-1".to_string(),
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
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

fn evaluate_guard(guard: &WasmGuard) -> TestResult<Verdict> {
    let request = make_context_request()?;
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
    Ok(guard.evaluate(&ctx)?)
}

#[test]
fn engine_reload_publishes_replacement_module_epoch_atomically() -> TestResult {
    let engine = Engine::new(build_backend);
    let guard = engine.register_guard("guard-a", make_guard(b"deny")?)?;
    let in_flight_snapshot = guard.loaded_module();

    assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
    assert_eq!(evaluate_guard(&guard)?, Verdict::Deny);

    let published = engine.reload("guard-a", b"allow")?;

    assert_eq!(published, EpochId::new(1));
    assert_eq!(guard.current_epoch_id(), published);
    assert_eq!(evaluate_guard(&guard)?, Verdict::Allow);
    assert_eq!(in_flight_snapshot.epoch_id(), EpochId::INITIAL);
    Ok(())
}

#[test]
fn engine_reload_failure_leaves_current_epoch_unchanged() -> TestResult {
    let engine = Engine::new(build_backend);
    let guard = engine.register_guard("guard-a", make_guard(b"deny")?)?;

    let err = match engine.reload("guard-a", b"bad") {
        Ok(epoch) => {
            return Err(std::io::Error::other(format!(
                "reload unexpectedly succeeded with epoch {epoch}"
            ))
            .into());
        }
        Err(err) => err,
    };

    assert!(matches!(
        err,
        HotReloadError::ReplacementLoad {
            guard_id,
            source: WasmGuardError::Compilation(_)
        } if guard_id == "guard-a"
    ));
    assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
    assert_eq!(evaluate_guard(&guard)?, Verdict::Deny);
    Ok(())
}

#[test]
fn engine_reload_rejects_unknown_guard_id() -> TestResult {
    let engine = Engine::new(build_backend);

    let err = match engine.reload("missing", b"allow") {
        Ok(epoch) => {
            return Err(std::io::Error::other(format!(
                "reload unexpectedly succeeded with epoch {epoch}"
            ))
            .into());
        }
        Err(err) => err,
    };

    assert!(matches!(
        err,
        HotReloadError::GuardNotFound { guard_id } if guard_id == "missing"
    ));
    Ok(())
}
