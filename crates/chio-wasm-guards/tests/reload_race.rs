use std::sync::Arc;
use std::time::Duration;

use chio_wasm_guards::{
    DebouncedReload, Engine, EpochId, GuardRequest, GuardVerdict, WasmGuard, WasmGuardAbi,
    WasmGuardError,
};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct AcceptAnyBackend;

impl WasmGuardAbi for AcceptAnyBackend {
    fn load_module(&mut self, _wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        Ok(())
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        Ok(GuardVerdict::Allow)
    }

    fn backend_name(&self) -> &str {
        "accept-any"
    }
}

fn build_backend(_bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    Ok(Box::new(AcceptAnyBackend))
}

fn make_guard() -> WasmGuard {
    WasmGuard::new(
        "burst-test".to_string(),
        Box::new(AcceptAnyBackend),
        false,
        Some(digest_of(&module_bytes(0))),
    )
}

fn module_bytes(i: usize) -> Vec<u8> {
    format!("module-{i}").into_bytes()
}

fn digest_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[tokio::test]
async fn registry_poll_burst_does_not_double_swap() -> TestResult {
    let runtime = Arc::new(Engine::new(build_backend));
    let guard = runtime.register_guard("burst-test", make_guard())?;
    let debounce = Duration::from_millis(100);

    let first_runtime = Arc::clone(&runtime);
    let first = tokio::spawn(async move {
        first_runtime
            .reload_debounced("burst-test", module_bytes(0), debounce)
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    for i in 1..100 {
        let outcome = runtime
            .reload_debounced("burst-test", module_bytes(i), debounce)
            .await?;
        assert!(
            outcome.is_none(),
            "burst request {i} should collapse into the in-flight reload"
        );
    }

    let applied = first
        .await??
        .ok_or_else(|| std::io::Error::other("first reload did not publish"))?;

    assert_eq!(
        applied,
        DebouncedReload {
            reload_seq: 1,
            epoch_id: EpochId::new(1)
        }
    );
    assert_eq!(runtime.reload_seq("burst-test").await?, Some(1));
    assert_eq!(guard.current_epoch_id(), EpochId::new(1));
    assert_eq!(
        guard.manifest_sha256().as_deref(),
        Some(digest_of(&module_bytes(99)).as_str())
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_debounce_does_not_leave_reload_in_flight() -> TestResult {
    let runtime = Arc::new(Engine::new(build_backend));
    let guard = runtime.register_guard("burst-test", make_guard())?;
    let debounce = Duration::from_secs(60);

    let first_runtime = Arc::clone(&runtime);
    let first = tokio::spawn(async move {
        first_runtime
            .reload_debounced("burst-test", module_bytes(1), debounce)
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    first.abort();
    let _ = first.await;

    let applied = runtime
        .reload_debounced("burst-test", module_bytes(2), Duration::from_millis(1))
        .await?
        .ok_or_else(|| std::io::Error::other("second reload stayed in flight"))?;

    assert_eq!(
        applied,
        DebouncedReload {
            reload_seq: 2,
            epoch_id: EpochId::new(1)
        }
    );
    assert_eq!(guard.current_epoch_id(), EpochId::new(1));
    assert_eq!(
        guard.manifest_sha256().as_deref(),
        Some(digest_of(&module_bytes(2)).as_str())
    );
    Ok(())
}
