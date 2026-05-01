#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

//! Cross-SDK verdict-matrix driver registration test for the TypeScript
//! framework wrappers (`@chio/ai-sdk-middleware`, `@chio/next`).
//!
//! The wrappers do not embed kernel evaluation; they delegate to the
//! `typescript-node-http` transport-client driver. This test validates
//! the manifest registration shape: the main matrix manifest enumerates
//! both framework drivers, the typescript subdir manifest enumerates
//! them with the same ids, and the driver TypeScript files exist with
//! the expected exports.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod verdict_matrix;

use verdict_matrix::diff_oracle::load_manifest;

fn verdict_matrix_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("verdict_matrix")
}

fn typescript_driver_dir() -> PathBuf {
    verdict_matrix_root().join("drivers").join("typescript")
}

const FRAMEWORK_DRIVER_IDS: [&str; 2] = ["typescript-ai-sdk-middleware", "typescript-chio-next"];

const FRAMEWORK_DRIVER_FILES: [&str; 2] = ["ai_sdk_middleware.ts", "chio_next.ts"];

#[test]
fn main_manifest_registers_both_framework_drivers() {
    let manifest_path = verdict_matrix_root().join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };

    for id in FRAMEWORK_DRIVER_IDS {
        let Some(driver) = manifest.drivers.configured.get(id) else {
            panic!(
                "main verdict-matrix manifest does not register driver `{id}` \
                 (expected an entry under [drivers.{id}])"
            );
        };
        assert_eq!(
            driver.status, "prepared",
            "framework driver `{id}` must ship as `prepared`; got `{}`",
            driver.status,
        );
        assert!(
            driver.entrypoint.starts_with("drivers/typescript/"),
            "framework driver `{id}` must point at a file under \
             drivers/typescript/; got `{}`",
            driver.entrypoint,
        );
    }
}

#[test]
fn typescript_subdir_manifest_lists_both_framework_drivers() {
    let manifest_path = typescript_driver_dir().join("manifest.toml");
    let raw = match fs::read_to_string(&manifest_path) {
        Ok(raw) => raw,
        Err(error) => panic!("failed to read {}: {error}", manifest_path.display()),
    };
    let value = match raw.parse::<toml::Value>() {
        Ok(value) => value,
        Err(error) => panic!("failed to parse {}: {error}", manifest_path.display()),
    };

    let Some(drivers) = value.get("drivers").and_then(|drivers| drivers.as_array()) else {
        panic!("typescript subdir manifest must declare [[drivers]] entries");
    };
    let mut seen: Vec<String> = drivers
        .iter()
        .filter_map(|driver| {
            driver
                .as_table()
                .and_then(|table| table.get("id"))
                .and_then(|id| id.as_str())
                .map(String::from)
        })
        .collect();
    seen.sort();

    let mut expected: Vec<String> = FRAMEWORK_DRIVER_IDS
        .iter()
        .map(|id| String::from(*id))
        .collect();
    expected.sort();

    assert_eq!(
        seen, expected,
        "typescript subdir manifest must list exactly the two framework \
         driver ids; got {seen:?}",
    );
}

#[test]
fn driver_files_exist_and_export_a_driver_constant() {
    for file in FRAMEWORK_DRIVER_FILES {
        let path = typescript_driver_dir().join(file);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) => panic!("framework driver `{}` must exist: {error}", path.display()),
        };
        assert!(
            raw.contains("export const driver"),
            "{} must export a `driver` constant",
            path.display()
        );
        assert!(
            raw.contains("typescript-node-http"),
            "{} must reference the underlying typescript-node-http driver",
            path.display()
        );
        assert!(
            raw.contains("framework-wrapper"),
            "{} must declare its matrix role as a framework wrapper",
            path.display()
        );
    }
}

#[test]
fn run_scenarios_remains_the_underlying_transport_client() {
    let path = typescript_driver_dir().join("run_scenarios.ts");
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => panic!(
            "expected the transport-client driver at {}: {error}",
            path.display()
        ),
    };
    assert!(
        raw.contains("TYPESCRIPT_NODE_HTTP_DRIVER"),
        "{} must continue to export the typescript-node-http driver constant",
        path.display()
    );
}
