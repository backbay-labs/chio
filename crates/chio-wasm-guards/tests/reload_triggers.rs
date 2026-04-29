use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chio_wasm_guards::{
    Engine, GuardRequest, GuardVerdict, HotReloadError, ReloadTriggerSource, WasmGuardAbi,
    WasmGuardError,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct NoopBackend;

impl WasmGuardAbi for NoopBackend {
    fn load_module(&mut self, _wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        Ok(())
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        Ok(GuardVerdict::Allow)
    }

    fn backend_name(&self) -> &str {
        "noop"
    }
}

fn build_backend(_bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    Ok(Box::new(NoopBackend))
}

#[tokio::test]
async fn file_watcher_emits_reload_trigger_for_guard_path() -> TestResult {
    let engine = Engine::new(build_backend);
    let dir = tempfile::tempdir()?;
    let watched_file = dir.path().join("guard.wasm");
    std::fs::write(&watched_file, b"old")?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let _watcher = engine.watch_guard_path("guard-a", dir.path(), tx)?;

    std::fs::write(&watched_file, b"new")?;

    let trigger = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await?
        .ok_or_else(|| std::io::Error::other("watch trigger channel closed"))?;
    assert_eq!(trigger.guard_id, "guard-a");
    match trigger.source {
        ReloadTriggerSource::FileChanged { path } => {
            let reported_path = path.canonicalize().unwrap_or(path);
            let expected_file = watched_file.canonicalize()?;
            let expected_dir = dir.path().canonicalize()?;
            assert!(
                reported_path == expected_file || reported_path == expected_dir,
                "unexpected watched path: {}",
                reported_path.display()
            );
        }
        ReloadTriggerSource::RegistryDigestChanged { digest } => {
            return Err(std::io::Error::other(format!(
                "unexpected registry trigger digest {digest}"
            ))
            .into());
        }
        ReloadTriggerSource::WatcherError { message } => {
            return Err(
                std::io::Error::other(format!("unexpected watcher error {message}")).into(),
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn registry_poll_emits_reload_trigger_when_digest_changes() -> TestResult {
    let engine = Engine::new(build_backend);
    let digests = Arc::new(Mutex::new(VecDeque::from([
        Some("sha256:old".to_string()),
        Some("sha256:new".to_string()),
    ])));
    let poller_digests = Arc::clone(&digests);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);

    let handle = engine.spawn_registry_poll_task(
        "guard-a",
        Some("sha256:old".to_string()),
        Duration::from_millis(10),
        move |_guard_id: &str| {
            let mut guard = poller_digests
                .lock()
                .map_err(|_| HotReloadError::RegistryLockPoisoned)?;
            Ok(guard.pop_front().flatten())
        },
        tx,
    )?;

    let trigger = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await?
        .ok_or_else(|| std::io::Error::other("registry poll trigger channel closed"))?;
    handle.abort();

    assert_eq!(trigger.guard_id, "guard-a");
    assert_eq!(
        trigger.source,
        ReloadTriggerSource::RegistryDigestChanged {
            digest: "sha256:new".to_string()
        }
    );
    Ok(())
}

#[test]
fn registry_poll_fails_without_tokio_runtime() -> TestResult {
    let engine = Engine::new(build_backend);
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let error = match engine.spawn_registry_poll_task(
        "guard-a",
        None,
        Duration::from_secs(1),
        |_guard_id: &str| Ok(None),
        tx,
    ) {
        Ok(_handle) => panic!("expected registry polling to fail without a tokio runtime"),
        Err(error) => error,
    };

    assert!(matches!(error, HotReloadError::NoTokioRuntime));
    Ok(())
}
