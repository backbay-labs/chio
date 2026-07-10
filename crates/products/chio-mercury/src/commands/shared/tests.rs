#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use std::fs;

#[test]
fn write_bundle_manifests_rejects_bundle_id_path_separator() {
    let dir = unique_temp_dir("mercury-bundle-manifest-stem");
    let mut safe = chio_mercury_core::sample_mercury_bundle_manifest();
    safe.bundle_id = "safe-bundle".to_string();
    let mut unsafe_manifest = chio_mercury_core::sample_mercury_bundle_manifest();
    unsafe_manifest.bundle_id = "unsafe/bundle".to_string();

    let error = write_bundle_manifests(&dir, &[safe, unsafe_manifest]).unwrap_err();

    assert!(error.to_string().contains("bundle_id"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn write_bundle_manifests_rejects_bundle_id_control_character() {
    let dir = unique_temp_dir("mercury-bundle-manifest-stem");
    let mut safe = chio_mercury_core::sample_mercury_bundle_manifest();
    safe.bundle_id = "safe-bundle".to_string();
    let mut unsafe_manifest = chio_mercury_core::sample_mercury_bundle_manifest();
    unsafe_manifest.bundle_id = "unsafe\tbundle".to_string();

    let error = write_bundle_manifests(&dir, &[safe, unsafe_manifest]).unwrap_err();

    assert!(error.to_string().contains("bundle_id"));
    let _ = fs::remove_dir_all(dir);
}
