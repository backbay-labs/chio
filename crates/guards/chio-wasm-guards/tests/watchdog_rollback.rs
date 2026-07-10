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

/// A watchdog rollback increments `chio_guard_reload_total{outcome="rolled_back"}`,
/// not merely emits a span, so a rolled-back reload is visible to the alerting
/// surface. A unique guard id isolates this process-global counter series from
/// the other tests in this binary.
#[test]
fn rollback_increments_reload_total_rolled_back() -> TestResult {
    use chio_metrics_spec::runtime::families;

    let guard_id = "reload-rolled-back-guard";
    let temp = tempfile::tempdir()?;
    let engine = Engine::new(build_backend).without_blocklist();
    engine.register_guard(
        guard_id,
        WasmGuard::new(
            guard_id.to_string(),
            build_backend(b"good")?,
            false,
            Some("initial".to_string()),
        ),
    )?;
    let writer = IncidentWriter::from_state_home(temp.path());
    let config = WatchdogConfig {
        max_errors: 5,
        window: Duration::from_secs(60),
        incident_writer: writer,
    };

    let mut watchdog = engine.reload_with_watchdog(guard_id, b"bad", 7, config)?;
    for i in 0..5 {
        watchdog.record_error(EvalTrace::new(
            format!("req-{i}"),
            "trap",
            "redacted backend trap",
        ))?;
    }
    assert!(
        watchdog.rolled_back(),
        "five errors must trigger a rollback"
    );

    let mut body = String::new();
    families::GUARD_RELOAD.render(&mut body);
    assert!(
        body.contains(&format!(
            "chio_guard_reload_total{{guard_id=\"{guard_id}\",outcome=\"rolled_back\"}} 1"
        )),
        "a rolled-back reload must increment the rolled_back outcome: {body}"
    );
    Ok(())
}

/// A rollback whose incident write fails is still a REAL rollback (the module was
/// restored and `rolled_back` set), so
/// `chio_guard_reload_total{outcome="rolled_back"}` must still increment. If the
/// counter incremented only AFTER a successful incident write, an incident-write
/// failure under I/O pressure would silently under-count a genuine rollback. A
/// unique guard id isolates this process-global counter series.
#[test]
fn rollback_counts_even_when_incident_write_fails() -> TestResult {
    use chio_metrics_spec::runtime::families;

    let guard_id = "reload-rolled-back-incident-write-fail";
    let temp = tempfile::tempdir()?;
    // Root the incident writer at a REGULAR FILE so `create_dir_all` inside
    // `write_reload_incident` fails and the incident write returns Err on the
    // rollback path.
    let blocker = temp.path().join("incident-root-is-a-file");
    std::fs::write(&blocker, b"not a directory")?;
    let writer = IncidentWriter::new(&blocker);

    let engine = Engine::new(build_backend).without_blocklist();
    engine.register_guard(
        guard_id,
        WasmGuard::new(
            guard_id.to_string(),
            build_backend(b"good")?,
            false,
            Some("initial".to_string()),
        ),
    )?;
    let config = WatchdogConfig {
        max_errors: 5,
        window: Duration::from_secs(60),
        incident_writer: writer,
    };

    let mut watchdog = engine.reload_with_watchdog(guard_id, b"bad", 11, config)?;
    for i in 0..4 {
        watchdog.record_error(EvalTrace::new(
            format!("req-{i}"),
            "trap",
            "redacted backend trap",
        ))?;
    }
    // The fifth error crosses the threshold: the module is restored and the
    // rollback becomes real, but the incident write fails, so this call returns
    // Err. The counter must already have been incremented.
    let write_result =
        watchdog.record_error(EvalTrace::new("req-4", "trap", "redacted backend trap"));
    assert!(
        write_result.is_err(),
        "the incident write must fail for this teeth-test"
    );
    assert!(
        watchdog.rolled_back(),
        "the rollback is real even though the incident write failed"
    );

    let mut body = String::new();
    families::GUARD_RELOAD.render(&mut body);
    assert!(
        body.contains(&format!(
            "chio_guard_reload_total{{guard_id=\"{guard_id}\",outcome=\"rolled_back\"}} 1"
        )),
        "a real rollback whose incident write fails must still increment rolled_back exactly once: {body}"
    );
    Ok(())
}
