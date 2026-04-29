use std::path::{Path, PathBuf};

use chio_wasm_guards::manifest::{
    load_manifest, MANIFEST_FILENAME, REQUIRED_WIT_WORLD, WIT_WORLD_MIGRATION_GUIDE,
};
use chio_wasm_guards::WasmGuardError;

fn write_manifest(
    wit_world_yaml: Option<&str>,
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut manifest = String::from(
        "name: test-guard\n\
         version: \"1.0.0\"\n\
         abi_version: \"1\"\n",
    );

    if let Some(wit_world) = wit_world_yaml {
        manifest.push_str("wit_world: ");
        manifest.push_str(wit_world);
        manifest.push('\n');
    }

    manifest.push_str(
        "wasm_path: guard.wasm\n\
         wasm_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n\
         allow_unsigned: true\n",
    );

    std::fs::write(dir.path().join(MANIFEST_FILENAME), manifest)?;
    let wasm_path = dir.path().join("guard.wasm");
    Ok((dir, wasm_path))
}

fn load_manifest_err(path: &Path) -> WasmGuardError {
    let path = path.to_string_lossy().into_owned();
    match load_manifest(&path) {
        Ok(_) => panic!("manifest load should have failed"),
        Err(err) => err,
    }
}

fn unsupported_wit_world_message(err: WasmGuardError) -> String {
    match err {
        WasmGuardError::UnsupportedWitWorld { .. } => err.to_string(),
        other => panic!("expected UnsupportedWitWorld, got {other:?}"),
    }
}

#[test]
fn accepts_required_wit_world() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, wasm_path) = write_manifest(Some("\"chio:guard/guard@0.2.0\""))?;
    let path = wasm_path.to_string_lossy().into_owned();

    let manifest = load_manifest(&path)?;

    assert_eq!(manifest.wit_world.as_deref(), Some(REQUIRED_WIT_WORLD));
    Ok(())
}

#[test]
fn rejects_old_0_1_wit_world() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, wasm_path) = write_manifest(Some("\"chio:guard/guard@0.1.0\""))?;

    let message = unsupported_wit_world_message(load_manifest_err(&wasm_path));

    assert!(message.contains("chio:guard/guard@0.1.0"), "{message}");
    assert!(message.contains(REQUIRED_WIT_WORLD), "{message}");
    Ok(())
}

#[test]
fn rejects_malformed_wit_world() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, wasm_path) = write_manifest(Some("\"not-a-wit-world\""))?;

    let message = unsupported_wit_world_message(load_manifest_err(&wasm_path));

    assert!(message.contains("not-a-wit-world"), "{message}");
    assert!(message.contains(REQUIRED_WIT_WORLD), "{message}");
    Ok(())
}

#[test]
fn rejects_missing_wit_world() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, wasm_path) = write_manifest(None)?;

    let message = unsupported_wit_world_message(load_manifest_err(&wasm_path));

    assert!(message.contains("<missing>"), "{message}");
    assert!(message.contains(REQUIRED_WIT_WORLD), "{message}");
    Ok(())
}

#[test]
fn mismatch_error_includes_migration_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, wasm_path) = write_manifest(Some("\"chio:guard/guard@0.1.9\""))?;

    let message = unsupported_wit_world_message(load_manifest_err(&wasm_path));

    assert!(message.contains(WIT_WORLD_MIGRATION_GUIDE), "{message}");
    Ok(())
}
