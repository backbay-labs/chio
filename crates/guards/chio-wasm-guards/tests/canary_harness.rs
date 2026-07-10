use chio_wasm_guards::{
    CanaryCorpus, Engine, EpochId, GuardRequest, GuardVerdict, HotReloadError, WasmGuard,
    WasmGuardAbi, WasmGuardError,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendMode {
    Baseline,
    CanaryPass,
    CanaryDrift,
}

#[derive(Debug)]
struct FixtureBackend {
    mode: BackendMode,
}

impl WasmGuardAbi for FixtureBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        self.mode = match wasm_bytes {
            b"baseline" => BackendMode::Baseline,
            b"canary-pass" => BackendMode::CanaryPass,
            b"canary-drift" => BackendMode::CanaryDrift,
            _ => {
                return Err(WasmGuardError::Compilation(
                    "unknown canary test module bytes".to_string(),
                ));
            }
        };
        Ok(())
    }

    fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        if self.mode == BackendMode::Baseline {
            return Ok(GuardVerdict::Deny {
                reason: Some("baseline".to_string()),
            });
        }

        let case = request
            .arguments
            .get("case")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| WasmGuardError::Serialization("fixture missing case".to_string()))?;
        if self.mode == BackendMode::CanaryDrift && case == 16 {
            return Ok(GuardVerdict::Deny {
                reason: Some("drifted verdict".to_string()),
            });
        }

        match request
            .arguments
            .get("verdict")
            .and_then(serde_json::Value::as_str)
        {
            Some("allow") => Ok(GuardVerdict::Allow),
            Some("deny") => Ok(GuardVerdict::Deny {
                reason: request
                    .arguments
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
            }),
            _ => Err(WasmGuardError::Serialization(
                "fixture missing verdict".to_string(),
            )),
        }
    }

    fn backend_name(&self) -> &str {
        "fixture-canary"
    }
}

fn build_backend(bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    let mut backend = FixtureBackend {
        mode: BackendMode::Baseline,
    };
    backend.load_module(bytes, 1_000)?;
    Ok(Box::new(backend))
}

fn make_guard() -> Result<WasmGuard, WasmGuardError> {
    Ok(WasmGuard::new(
        "example-guard".to_string(),
        build_backend(b"baseline")?,
        false,
        Some("initial".to_string()),
    ))
}

fn canary_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/corpora/example-guard/canary")
}

#[test]
fn canary_harness_verifies_all_fixtures_before_swap() -> TestResult {
    let corpus = CanaryCorpus::from_dir("example-guard", canary_dir())?;
    let engine = Engine::new(build_backend);
    let guard = engine.register_guard("example-guard", make_guard()?)?;

    let epoch = engine.reload_with_canary("example-guard", b"canary-pass", &corpus)?;

    assert_eq!(epoch, EpochId::new(1));
    assert_eq!(guard.current_epoch_id(), EpochId::new(1));
    Ok(())
}

#[test]
fn canary_mismatch_aborts_swap() -> TestResult {
    let corpus = CanaryCorpus::from_dir("example-guard", canary_dir())?;
    let engine = Engine::new(build_backend);
    let guard = engine.register_guard("example-guard", make_guard()?)?;

    let err = match engine.reload_with_canary("example-guard", b"canary-drift", &corpus) {
        Ok(epoch) => {
            return Err(std::io::Error::other(format!(
                "canary reload unexpectedly succeeded at epoch {epoch}"
            ))
            .into());
        }
        Err(err) => err,
    };

    assert!(matches!(
        err,
        HotReloadError::CanaryFailed {
            guard_id,
            fixture,
            ..
        } if guard_id == "example-guard" && fixture == "16_deny_jailbreak.json"
    ));
    assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
    Ok(())
}

/// A canary-failed reload increments
/// `chio_guard_reload_total{outcome="canary_failed"}`, not merely emits a span,
/// so the alerting surface sees a failed reload. A unique guard id isolates this
/// process-global counter series from the other tests in this binary.
#[test]
fn canary_failure_increments_reload_total_canary_failed() -> TestResult {
    use chio_metrics_spec::runtime::families;

    let guard_id = "reload-canary-failed-guard";
    let corpus = CanaryCorpus::from_dir(guard_id, canary_dir())?;
    let engine = Engine::new(build_backend);
    engine.register_guard(
        guard_id,
        WasmGuard::new(
            guard_id.to_string(),
            build_backend(b"baseline")?,
            false,
            Some("initial".to_string()),
        ),
    )?;

    let outcome = engine.reload_with_canary(guard_id, b"canary-drift", &corpus);
    assert!(
        matches!(outcome, Err(HotReloadError::CanaryFailed { .. })),
        "canary drift must abort the swap: {outcome:?}"
    );

    let mut body = String::new();
    families::GUARD_RELOAD.render(&mut body);
    assert!(
        body.contains(&format!(
            "chio_guard_reload_total{{guard_id=\"{guard_id}\",outcome=\"canary_failed\"}} 1"
        )),
        "a canary-failed reload must increment the canary_failed outcome: {body}"
    );
    Ok(())
}

/// A canary-verified (successful) reload also increments
/// `chio_guard_reload_total{outcome="applied"}`. reload_with_canary replaces the
/// module directly rather than via record_reload_seq, so it must count the
/// applied outcome itself; otherwise the alerting surface stays blind to
/// successful canary reloads. A unique guard id isolates this process-global
/// counter series from the other tests here.
#[test]
fn canary_success_increments_reload_total_applied() -> TestResult {
    use chio_metrics_spec::runtime::families;

    let guard_id = "reload-canary-applied-guard";
    let corpus = CanaryCorpus::from_dir(guard_id, canary_dir())?;
    let engine = Engine::new(build_backend);
    engine.register_guard(
        guard_id,
        WasmGuard::new(
            guard_id.to_string(),
            build_backend(b"baseline")?,
            false,
            Some("initial".to_string()),
        ),
    )?;

    let epoch = engine.reload_with_canary(guard_id, b"canary-pass", &corpus)?;
    assert_eq!(epoch, EpochId::new(1));

    let mut body = String::new();
    families::GUARD_RELOAD.render(&mut body);
    assert!(
        body.contains(&format!(
            "chio_guard_reload_total{{guard_id=\"{guard_id}\",outcome=\"applied\"}} 1"
        )),
        "a canary-verified reload must increment the applied outcome: {body}"
    );
    Ok(())
}
