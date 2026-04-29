use std::ffi::OsStr;
use std::fs;

use chio_guard_registry::{
    GuardCache, GuardCacheArtifact, GuardOciRef, GuardRegistryError, Sha256Digest,
    CACHE_CONFIG_JSON_FILE, CACHE_FILE_NAMES, CACHE_MANIFEST_JSON_FILE, CACHE_MODULE_WASM_FILE,
    CACHE_SIGSTORE_BUNDLE_JSON_FILE, CACHE_WIT_BIN_FILE,
};

const DIGEST: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn derives_content_addressed_cache_paths() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    let layout = cache.layout(&digest);

    assert_eq!(cache.root(), temp.path().join("chio").join("guards"));
    assert_eq!(
        layout.directory(),
        temp.path().join("chio").join("guards").join(DIGEST)
    );
    assert_eq!(
        layout.manifest_json_path(),
        layout.directory().join(CACHE_MANIFEST_JSON_FILE)
    );
    assert_eq!(
        layout.config_json_path(),
        layout.directory().join(CACHE_CONFIG_JSON_FILE)
    );
    assert_eq!(
        layout.wit_bin_path(),
        layout.directory().join(CACHE_WIT_BIN_FILE)
    );
    assert_eq!(
        layout.module_wasm_path(),
        layout.directory().join(CACHE_MODULE_WASM_FILE)
    );
    assert_eq!(
        layout.sigstore_bundle_json_path(),
        layout.directory().join(CACHE_SIGSTORE_BUNDLE_JSON_FILE)
    );
}

#[test]
fn exposes_normative_cache_file_names() {
    let temp = tempdir();
    let layout = GuardCache::from_cache_home(temp.path()).layout(&digest());
    let paths = layout.file_paths();

    assert_eq!(
        CACHE_FILE_NAMES,
        [
            "manifest.json",
            "config.json",
            "wit.bin",
            "module.wasm",
            "sigstore-bundle.json"
        ]
    );
    assert_eq!(
        paths[0].file_name(),
        Some(OsStr::new(CACHE_MANIFEST_JSON_FILE))
    );
    assert_eq!(
        paths[1].file_name(),
        Some(OsStr::new(CACHE_CONFIG_JSON_FILE))
    );
    assert_eq!(paths[2].file_name(), Some(OsStr::new(CACHE_WIT_BIN_FILE)));
    assert_eq!(
        paths[3].file_name(),
        Some(OsStr::new(CACHE_MODULE_WASM_FILE))
    );
    assert_eq!(
        paths[4].file_name(),
        Some(OsStr::new(CACHE_SIGSTORE_BUNDLE_JSON_FILE))
    );
}

#[test]
fn rejects_unpinned_or_non_sha256_pull_references() {
    assert!(matches!(
        "oci://ghcr.io/chio/tool-gate:latest".parse::<GuardOciRef>(),
        Err(GuardRegistryError::TaggedDigestReference)
    ));
    assert!(matches!(
        "oci://ghcr.io/chio/tool-gate".parse::<GuardOciRef>(),
        Err(GuardRegistryError::MissingDigest)
    ));
    assert!(matches!(
        "oci://ghcr.io/chio/tool-gate@sha512:2222222222222222222222222222222222222222222222222222222222222222"
            .parse::<GuardOciRef>(),
        Err(GuardRegistryError::InvalidSha256Digest)
    ));
    assert!(matches!(
        "oci://ghcr.io/chio/tool-gate@sha256:AAAA222222222222222222222222222222222222222222222222222222222222"
            .parse::<GuardOciRef>(),
        Err(GuardRegistryError::InvalidSha256Digest)
    ));
}

#[test]
fn writes_fixture_bytes_to_cache_files() {
    let temp = tempdir();
    let digest = digest();
    let cache = GuardCache::from_cache_home(temp.path());
    let cached = match cache.write_artifact(
        &digest,
        GuardCacheArtifact {
            manifest_json: br#"{"schemaVersion":2}"#,
            config_json: br#"{"wit_world":"chio:guard/guard@0.2.0"}"#,
            wit: b"package chio:guard@0.2.0;",
            module: b"\0asm\x01\0\0\0",
            sigstore_bundle_json: br#"{"bundle":"fixture"}"#,
        },
    ) {
        Ok(cached) => cached,
        Err(error) => panic!("cache write should succeed: {error}"),
    };

    assert_eq!(cached.digest, digest);
    assert_eq!(
        read(&cached.layout.manifest_json_path()),
        br#"{"schemaVersion":2}"#
    );
    assert_eq!(
        read(&cached.layout.config_json_path()),
        br#"{"wit_world":"chio:guard/guard@0.2.0"}"#
    );
    assert_eq!(
        read(&cached.layout.wit_bin_path()),
        b"package chio:guard@0.2.0;"
    );
    assert_eq!(read(&cached.layout.module_wasm_path()), b"\0asm\x01\0\0\0");
    assert_eq!(
        read(&cached.layout.sigstore_bundle_json_path()),
        br#"{"bundle":"fixture"}"#
    );
}

fn digest() -> Sha256Digest {
    match DIGEST.parse::<Sha256Digest>() {
        Ok(digest) => digest,
        Err(error) => panic!("fixture digest should parse: {error}"),
    }
}

fn tempdir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(temp) => temp,
        Err(error) => panic!("tempdir should be created: {error}"),
    }
}

fn read(path: &std::path::Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    }
}
