use std::time::Duration;

use chio_wasm_guards::{
    Engine, EpochId, EvalTrace, GuardRequest, GuardVerdict, IncidentWriter, WasmGuard,
    WasmGuardAbi, WasmGuardError, WatchdogConfig,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct NoopBackend;

impl WasmGuardAbi for NoopBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        match wasm_bytes {
            b"good" | b"bad" => Ok(()),
            _ => Err(WasmGuardError::Compilation(
                "unknown watchdog test bytes".to_string(),
            )),
        }
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        Ok(GuardVerdict::Allow)
    }

    fn backend_name(&self) -> &str {
        "watchdog-noop"
    }
}

fn build_backend(bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    let mut backend = NoopBackend;
    backend.load_module(bytes, 1_000)?;
    Ok(Box::new(backend))
}

fn make_guard() -> Result<WasmGuard, WasmGuardError> {
    Ok(WasmGuard::new(
        "guard-a".to_string(),
        build_backend(b"good")?,
        false,
        Some("initial".to_string()),
    ))
}

#[test]
fn watchdog_rolls_back_after_five_errors_in_sixty_seconds() -> TestResult {
    let temp = tempfile::tempdir()?;
    let engine = Engine::new(build_backend).without_blocklist();
    let guard = engine.register_guard("guard-a", make_guard()?)?;
    let writer = IncidentWriter::from_state_home(temp.path());
    let config = WatchdogConfig {
        max_errors: 5,
        window: Duration::from_secs(60),
        incident_writer: writer,
    };

    let mut watchdog = engine.reload_with_watchdog("guard-a", b"bad", 42, config)?;
    assert_eq!(guard.current_epoch_id(), EpochId::new(1));

    for i in 0..4 {
        let outcome = watchdog.record_error(EvalTrace::new(
            format!("req-{i}"),
            "trap",
            "redacted backend trap",
        ))?;
        assert!(outcome.is_none());
        assert_eq!(guard.current_epoch_id(), EpochId::new(1));
    }

    let incident_dir = watchdog
        .record_error(EvalTrace::new("req-4", "trap", "redacted backend trap"))?
        .ok_or_else(|| std::io::Error::other("watchdog did not roll back"))?;

    assert!(watchdog.rolled_back());
    assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
    assert!(incident_dir.join("incident.json").is_file());
    let traces = std::fs::read_to_string(incident_dir.join("last_5_eval_traces.ndjson"))?;
    assert_eq!(traces.lines().count(), 5);
    assert!(!traces.contains("secret"));
    Ok(())
}
