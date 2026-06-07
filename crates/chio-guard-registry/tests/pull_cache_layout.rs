use std::ffi::OsStr;
use std::fs;

use chio_guard_registry::{
    GuardCache, GuardCacheArtifact, GuardOciRef, GuardRegistryError, Sha256Digest,
    CACHE_CONFIG_JSON_FILE, CACHE_FILE_NAMES, CACHE_GUARD_MANIFEST_JSON_FILE,
    CACHE_MANIFEST_JSON_FILE, CACHE_MODULE_WASM_FILE, CACHE_SIGSTORE_BUNDLE_JSON_FILE,
    CACHE_WIT_BIN_FILE, GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE,
    GUARD_MANIFEST_LAYER_MEDIA_TYPE, GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_OCI_MANIFEST_MEDIA_TYPE,
    GUARD_WIT_LAYER_MEDIA_TYPE,
};
use oci_distribution::client::{Config, ImageLayer};
use oci_distribution::manifest::OciImageManifest;
use sha2::{Digest, Sha256};

const DIGEST: &str = "sha256:bafebd36189ad3688b7b3915ea55d461e0bfcfbdde11e54b0a123999fb6be50f";
const WRONG_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

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
        layout.guard_manifest_json_path(),
        layout.directory().join(CACHE_GUARD_MANIFEST_JSON_FILE)
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
            "guard-manifest.json",
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
        Some(OsStr::new(CACHE_GUARD_MANIFEST_JSON_FILE))
    );
    assert_eq!(
        paths[5].file_name(),
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
    let fixture = CacheFixture::new();
    let cache = GuardCache::from_cache_home(temp.path());
    let cached = match cache.write_artifact(
        &fixture.digest,
        fixture.artifact(Some(br#"{"bundle":"fixture"}"#)),
    ) {
        Ok(cached) => cached,
        Err(error) => panic!("cache write should succeed: {error}"),
    };

    assert_eq!(cached.digest, fixture.digest);
    assert_eq!(
        read(&cached.layout.manifest_json_path()),
        fixture.manifest_json
    );
    assert_eq!(read(&cached.layout.config_json_path()), fixture.config_json);
    assert_eq!(read(&cached.layout.wit_bin_path()), fixture.wit);
    assert_eq!(read(&cached.layout.module_wasm_path()), fixture.module);
    assert_eq!(
        read(&cached.layout.guard_manifest_json_path()),
        fixture.guard_manifest_json
    );
    assert_eq!(
        read(&cached.layout.sigstore_bundle_json_path()),
        br#"{"bundle":"fixture"}"#
    );
}

#[test]
fn rejects_manifest_json_that_does_not_match_pinned_digest() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let fixture = CacheFixture::new();
    let digest = match WRONG_DIGEST.parse::<Sha256Digest>() {
        Ok(digest) => digest,
        Err(error) => panic!("fixture digest should parse: {error}"),
    };

    let err = match cache.write_artifact(&digest, fixture.artifact(None)) {
        Ok(_) => panic!("expected digest mismatch"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        GuardRegistryError::ManifestDigestMismatch { .. }
    ));
}

#[test]
fn rejects_descriptor_mismatch_before_cache_write() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let mut fixture = CacheFixture::new();
    fixture.wit.push(b'!');

    let err = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(_) => panic!("expected descriptor digest mismatch"),
        Err(error) => error,
    };
    assert!(matches!(
        err,
        GuardRegistryError::DescriptorDigestMismatch {
            artifact: "wit.bin",
            ..
        }
    ));
    assert!(
        !cache.layout(&fixture.digest).manifest_json_path().exists(),
        "descriptor mismatch must not admit partial cache writes"
    );
}

#[test]
fn cache_admission_matches_layers_by_media_type_not_position() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let mut fixture = CacheFixture::new();
    fixture.reorder_manifest_layers([1, 2, 0]);

    let cached = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(cached) => cached,
        Err(error) => panic!("reordered manifest layers should admit by media type: {error}"),
    };

    assert_eq!(read(&cached.layout.wit_bin_path()), fixture.wit);
    assert_eq!(read(&cached.layout.module_wasm_path()), fixture.module);
    assert_eq!(
        read(&cached.layout.guard_manifest_json_path()),
        fixture.guard_manifest_json
    );
}

#[test]
fn rejects_manifest_with_wrong_top_level_artifact_type() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let mut fixture = CacheFixture::new();
    fixture.set_manifest_artifact_type(Some("application/example.invalid".to_owned()));

    let err = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(_) => panic!("expected wrong top-level artifact type to fail"),
        Err(error) => error,
    };

    assert!(matches!(
        err,
        GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: "manifest.json",
            expected: GUARD_ARTIFACT_MEDIA_TYPE,
            ..
        }
    ));
}

#[test]
fn rejects_manifest_with_missing_top_level_artifact_type() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let mut fixture = CacheFixture::new();
    fixture.set_manifest_artifact_type(None);

    let err = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(_) => panic!("expected missing top-level artifact type to fail"),
        Err(error) => error,
    };

    assert!(matches!(
        err,
        GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: "manifest.json",
            expected: GUARD_ARTIFACT_MEDIA_TYPE,
            ..
        }
    ));
}

#[test]
fn rejects_manifest_with_wrong_top_level_manifest_media_type() {
    let temp = tempdir();
    let cache = GuardCache::from_cache_home(temp.path());
    let mut fixture = CacheFixture::new();
    fixture.set_manifest_media_type(Some("application/example.invalid".to_owned()));

    let err = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(_) => panic!("expected wrong top-level media type to fail"),
        Err(error) => error,
    };

    assert!(matches!(
        err,
        GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: "manifest.json",
            expected: GUARD_OCI_MANIFEST_MEDIA_TYPE,
            ..
        }
    ));
}

#[test]
fn omits_sigstore_bundle_file_when_not_supplied() {
    let temp = tempdir();
    let fixture = CacheFixture::new();
    let cache = GuardCache::from_cache_home(temp.path());
    let cached = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(cached) => cached,
        Err(error) => panic!("cache write should succeed: {error}"),
    };

    assert!(cached.layout.manifest_json_path().is_file());
    assert!(cached.layout.config_json_path().is_file());
    assert!(cached.layout.wit_bin_path().is_file());
    assert!(cached.layout.module_wasm_path().is_file());
    assert!(cached.layout.guard_manifest_json_path().is_file());
    assert!(!cached.layout.sigstore_bundle_json_path().exists());
}

#[test]
fn clears_stale_sigstore_bundle_file_when_not_supplied() {
    let temp = tempdir();
    let fixture = CacheFixture::new();
    let cache = GuardCache::from_cache_home(temp.path());
    let cached = match cache.write_artifact(
        &fixture.digest,
        fixture.artifact(Some(br#"{"bundle":"old"}"#)),
    ) {
        Ok(cached) => cached,
        Err(error) => panic!("initial cache write should succeed: {error}"),
    };
    assert!(cached.layout.sigstore_bundle_json_path().exists());

    let cached = match cache.write_artifact(&fixture.digest, fixture.artifact(None)) {
        Ok(cached) => cached,
        Err(error) => panic!("cache refresh without bundle should succeed: {error}"),
    };
    assert!(
        !cached.layout.sigstore_bundle_json_path().exists(),
        "refresh without bundle must remove stale Sigstore material"
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

struct CacheFixture {
    manifest_json: Vec<u8>,
    config_json: Vec<u8>,
    wit: Vec<u8>,
    module: Vec<u8>,
    guard_manifest_json: Vec<u8>,
    digest: Sha256Digest,
}

impl CacheFixture {
    fn new() -> Self {
        let config_json = br#"{"wit_world":"chio:guard/guard@0.2.0"}"#.to_vec();
        let wit = b"package chio:guard@0.2.0;".to_vec();
        let module = b"\0asm\x01\0\0\0".to_vec();
        let guard_manifest_json = br#"{"name":"fixture"}"#.to_vec();
        let config = Config::new(
            config_json.clone(),
            GUARD_CONFIG_MEDIA_TYPE.to_owned(),
            None,
        );
        let layers = vec![
            ImageLayer::new(wit.clone(), GUARD_WIT_LAYER_MEDIA_TYPE.to_owned(), None),
            ImageLayer::new(
                module.clone(),
                GUARD_MODULE_LAYER_MEDIA_TYPE.to_owned(),
                None,
            ),
            ImageLayer::new(
                guard_manifest_json.clone(),
                GUARD_MANIFEST_LAYER_MEDIA_TYPE.to_owned(),
                None,
            ),
        ];
        let mut manifest = OciImageManifest::build(&layers, &config, None);
        manifest.media_type = Some(GUARD_OCI_MANIFEST_MEDIA_TYPE.to_owned());
        manifest.artifact_type = Some(GUARD_ARTIFACT_MEDIA_TYPE.to_owned());
        let manifest_json = match serde_json::to_vec(&manifest) {
            Ok(bytes) => bytes,
            Err(error) => panic!("fixture OCI manifest should serialize: {error}"),
        };
        let digest_text = format!("sha256:{:x}", Sha256::digest(&manifest_json));
        let digest = match digest_text.parse::<Sha256Digest>() {
            Ok(digest) => digest,
            Err(error) => panic!("fixture digest should parse: {error}"),
        };
        Self {
            manifest_json,
            config_json,
            wit,
            module,
            guard_manifest_json,
            digest,
        }
    }

    fn artifact<'a>(&'a self, sigstore_bundle_json: Option<&'a [u8]>) -> GuardCacheArtifact<'a> {
        GuardCacheArtifact {
            manifest_json: &self.manifest_json,
            config_json: &self.config_json,
            wit: &self.wit,
            module: &self.module,
            guard_manifest_json: &self.guard_manifest_json,
            sigstore_bundle_json,
        }
    }

    fn reorder_manifest_layers(&mut self, order: [usize; 3]) {
        let mut manifest = match serde_json::from_slice::<OciImageManifest>(&self.manifest_json) {
            Ok(manifest) => manifest,
            Err(error) => panic!("fixture OCI manifest should parse: {error}"),
        };
        manifest.layers = order
            .into_iter()
            .map(|index| manifest.layers[index].clone())
            .collect();
        self.manifest_json = match serde_json::to_vec(&manifest) {
            Ok(bytes) => bytes,
            Err(error) => panic!("reordered fixture OCI manifest should serialize: {error}"),
        };
        let digest_text = format!("sha256:{:x}", Sha256::digest(&self.manifest_json));
        self.digest = match digest_text.parse::<Sha256Digest>() {
            Ok(digest) => digest,
            Err(error) => panic!("reordered fixture digest should parse: {error}"),
        };
    }

    fn set_manifest_artifact_type(&mut self, artifact_type: Option<String>) {
        let mut manifest = self.parse_manifest();
        manifest.artifact_type = artifact_type;
        self.replace_manifest(manifest);
    }

    fn set_manifest_media_type(&mut self, media_type: Option<String>) {
        let mut manifest = self.parse_manifest();
        manifest.media_type = media_type;
        self.replace_manifest(manifest);
    }

    fn parse_manifest(&self) -> OciImageManifest {
        match serde_json::from_slice::<OciImageManifest>(&self.manifest_json) {
            Ok(manifest) => manifest,
            Err(error) => panic!("fixture OCI manifest should parse: {error}"),
        }
    }

    fn replace_manifest(&mut self, manifest: OciImageManifest) {
        self.manifest_json = match serde_json::to_vec(&manifest) {
            Ok(bytes) => bytes,
            Err(error) => panic!("fixture OCI manifest should serialize: {error}"),
        };
        let digest_text = format!("sha256:{:x}", Sha256::digest(&self.manifest_json));
        self.digest = match digest_text.parse::<Sha256Digest>() {
            Ok(digest) => digest,
            Err(error) => panic!("fixture digest should parse: {error}"),
        };
    }
}
