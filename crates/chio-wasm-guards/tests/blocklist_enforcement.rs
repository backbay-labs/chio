use chio_wasm_guards::{
    Engine, EpochId, GuardDigestBlocklist, GuardRequest, GuardVerdict, HotReloadError, WasmGuard,
    WasmGuardAbi, WasmGuardError, E_GUARD_DIGEST_BLOCKLISTED,
};
use sha2::{Digest, Sha256};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct NoopBackend;

impl WasmGuardAbi for NoopBackend {
    fn load_module(&mut self, wasm_bytes: &[u8], _fuel_limit: u64) -> Result<(), WasmGuardError> {
        match wasm_bytes {
            b"good" | b"blocked" => Ok(()),
            _ => Err(WasmGuardError::Compilation(
                "unknown blocklist test bytes".to_string(),
            )),
        }
    }

    fn evaluate(&mut self, _request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError> {
        Ok(GuardVerdict::Allow)
    }

    fn backend_name(&self) -> &str {
        "blocklist-noop"
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

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn engine_reload_denies_blocklisted_digest() -> TestResult {
    let temp = tempfile::tempdir()?;
    let blocklist = GuardDigestBlocklist::from_state_home(temp.path());
    let blocked = digest(b"blocked");
    assert!(blocklist.add_digest(&blocked)?);

    let engine = Engine::new(build_backend).with_blocklist(blocklist.clone());
    let guard = engine.register_guard("guard-a", make_guard()?)?;
    let err = match engine.reload("guard-a", b"blocked") {
        Ok(epoch) => {
            return Err(std::io::Error::other(format!(
                "blocklisted reload unexpectedly succeeded at epoch {epoch}"
            ))
            .into());
        }
        Err(err) => err,
    };

    assert!(matches!(
        err,
        HotReloadError::DigestBlocklisted { code, digest }
            if code == E_GUARD_DIGEST_BLOCKLISTED && digest == blocked
    ));
    assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);

    assert!(blocklist.remove_digest(&blocked)?);
    let epoch = engine.reload("guard-a", b"blocked")?;
    assert_eq!(epoch, EpochId::new(1));
    Ok(())
}
