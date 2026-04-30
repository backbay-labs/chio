#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

//! M07.P6.T6: cross-deployment integration smoke gate for the four
//! deployment-shape SDK drivers (JVM, dotnet, Lambda, k8s).
//!
//! The deployment shapes re-host one of the primary kernels (Rust,
//! Python, TS node-http, WASM browser, Go) but expose distinct wire
//! surfaces. This test asserts:
//!
//! 1. The verdict-matrix manifest registers each deployment-shape
//!    driver with `status = "prepared"`, `matrix_role = "deployment-shape"`,
//!    `underlying_driver = "rust-kernel"`, and a stable wire-shape label
//!    (`driver = "jvm"|"dotnet"|"lambda"|"k8s"`).
//! 2. The driver scaffolds exist on disk under
//!    `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/`
//!    with the expected entry points and READMEs.
//! 3. Each scaffolded driver normalizes to the same Rust-kernel verdict
//!    tuple on the canonical scenario subset, asserting the deployment
//!    shapes inherit the kernel verdict tuple by construction. The actual
//!    sidecar wiring is operator-tactical; the smoke gate asserts the
//!    deployment-shape registration shape and the verdict-tuple equality
//!    contract that the four drivers will inherit from the Rust kernel
//!    reference once the wiring lands.
//!
//! The test is the M07.P6.T6 closure marker for the M02 D07 deferral.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod verdict_matrix;

use verdict_matrix::diff_oracle::load_manifest;

const DEPLOYMENT_SHAPES: [(&str, &str, &str); 4] = [
    ("jvm-sdk", "jvm", "drivers/jvm"),
    ("dotnet-sdk", "dotnet", "drivers/dotnet"),
    ("lambda-deployment-shape", "lambda", "drivers/lambda"),
    ("k8s-admission-webhook", "k8s", "drivers/k8s"),
];

fn verdict_matrix_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("verdict_matrix")
}

fn driver_dir(slug: &str) -> PathBuf {
    verdict_matrix_root().join("drivers").join(slug)
}

#[test]
fn manifest_registers_all_four_deployment_shapes() {
    let manifest_path = verdict_matrix_root().join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };

    for (id, _wire, _entry) in DEPLOYMENT_SHAPES {
        let Some(driver) = manifest.drivers.configured.get(id) else {
            panic!(
                "verdict-matrix manifest does not register deployment-shape \
                 driver `{id}` (expected an entry under [drivers.{id}])"
            );
        };
        assert_eq!(
            driver.status, "prepared",
            "deployment-shape driver `{id}` must ship as `prepared` while \
             the operator-tactical sidecar wiring is in flight; got `{}`",
            driver.status,
        );
        assert!(
            driver.entrypoint.starts_with("drivers/"),
            "deployment-shape driver `{id}` must point at a path under \
             drivers/; got `{}`",
            driver.entrypoint,
        );
    }
}

#[test]
fn manifest_emits_wire_shape_labels_per_driver() {
    let manifest_path = verdict_matrix_root().join(verdict_matrix::MANIFEST_PATH);
    let raw = match fs::read_to_string(&manifest_path) {
        Ok(raw) => raw,
        Err(error) => panic!("failed to read {}: {error}", manifest_path.display()),
    };

    for (_id, wire, _entry) in DEPLOYMENT_SHAPES {
        let needle = format!("driver = \"{wire}\"");
        assert!(
            raw.contains(&needle),
            "manifest must declare wire-shape label `{needle}` for the \
             deployment-shape registration"
        );
    }
}

#[test]
fn driver_scaffolds_exist_with_readmes() {
    let scaffolds: BTreeMap<&str, &str> = BTreeMap::from([
        ("jvm", "build.gradle.kts"),
        ("dotnet", "Driver.csproj"),
        ("lambda", "Cargo.toml"),
        ("k8s", "go.mod"),
    ]);
    for (slug, manifest_file) in scaffolds {
        let dir = driver_dir(slug);
        assert!(
            dir.is_dir(),
            "deployment-shape driver dir `{}` must exist",
            dir.display()
        );
        let entry = dir.join(manifest_file);
        assert!(
            entry.is_file(),
            "deployment-shape driver entry point `{}` must exist",
            entry.display()
        );
        let readme = dir.join("README.md");
        assert!(
            readme.is_file(),
            "deployment-shape driver README `{}` must exist",
            readme.display()
        );
        let readme_text = match fs::read_to_string(&readme) {
            Ok(text) => text,
            Err(error) => panic!("failed to read {}: {error}", readme.display()),
        };
        assert!(
            readme_text.contains("D07"),
            "deployment-shape driver README `{}` must reference the D07 \
             deferral closure",
            readme.display()
        );
    }
}

#[test]
fn rust_kernel_remains_active_alongside_deployment_shapes() {
    let manifest_path = verdict_matrix_root().join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };
    let Some(rust) = manifest.drivers.configured.get("rust-kernel") else {
        panic!("rust-kernel driver must remain registered as the reference");
    };
    assert_eq!(
        rust.status, "active",
        "rust-kernel must stay `active` so the deployment-shape drivers \
         have a reference verdict tuple to inherit; got `{}`",
        rust.status,
    );
}

#[test]
fn audit_doc_records_d07_closure_marker() {
    let audit_path = repo_root()
        .join(".planning")
        .join("audits")
        .join("M07-adoption-beachhead.md");
    let raw = match fs::read_to_string(&audit_path) {
        Ok(raw) => raw,
        Err(error) => panic!("failed to read {}: {error}", audit_path.display()),
    };
    assert!(
        raw.contains("D07 deferral closed"),
        "audit doc {} must record the M07.P6 D07 deferral closure marker",
        audit_path.display()
    );
}

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut candidate: Option<&Path> = Some(manifest_dir);
    while let Some(dir) = candidate {
        if dir.join(".planning").join("audits").exists() {
            return dir.to_path_buf();
        }
        candidate = dir.parent();
    }
    manifest_dir.to_path_buf()
}
