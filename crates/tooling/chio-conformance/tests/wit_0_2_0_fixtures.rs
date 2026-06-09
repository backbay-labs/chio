#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CURRENT_GUARD_WORLD: &str = "chio:guard/guard@0.2.0";
const FIXTURE_SCHEMA: &str = "chio.guard.wit.fixture.v1";
const MIN_FIXTURE_COUNT: usize = 5;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitFixture {
    schema: String,
    id: String,
    title: String,
    description: String,
    wit_world: String,
    imports: Vec<String>,
    blob_store: BlobStore,
    input: FixtureInput,
    expected: ExpectedOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobStore {
    handles: Vec<BlobHandle>,
    bundles: Vec<BundleBlob>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobHandle {
    handle: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleBlob {
    id: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "operation")]
enum FixtureInput {
    #[serde(rename = "host.fetch-blob")]
    HostFetchBlob { handle: u32, offset: u64, len: u32 },
    #[serde(rename = "policy-context.bundle-handle.read")]
    BundleHandleRead {
        #[serde(rename = "bundleId")]
        bundle_id: String,
        offset: u64,
        len: u32,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedOutcome {
    status: ExpectedStatus,
    #[serde(default)]
    bytes: Option<Vec<u8>>,
    #[serde(default)]
    error_kind: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ExpectedStatus {
    Ok,
    Deny,
}

fn repo_root() -> PathBuf {
    chio_conformance::default_repo_root()
}

fn corpus_root() -> PathBuf {
    repo_root().join("tests/corpora/wit-0.2.0")
}

fn current_wit_path() -> PathBuf {
    repo_root().join("wit/chio-guard/world.wit")
}

fn load_fixture(path: &Path) -> WitFixture {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    };
    match serde_json::from_slice::<WitFixture>(&bytes) {
        Ok(fixture) => fixture,
        Err(error) => panic!(
            "failed to parse {} as JSON fixture: {error}",
            path.display()
        ),
    }
}

fn fixture_paths() -> Vec<PathBuf> {
    let root = corpus_root();
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) => panic!("failed to read fixture corpus {}: {error}", root.display()),
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("failed to enumerate {}: {error}", root.display()),
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn load_fixtures() -> Vec<(PathBuf, WitFixture)> {
    fixture_paths()
        .into_iter()
        .map(|path| {
            let fixture = load_fixture(&path);
            (path, fixture)
        })
        .collect()
}

fn run_fixture(fixture: &WitFixture) -> Result<Vec<u8>, &'static str> {
    if fixture.wit_world != CURRENT_GUARD_WORLD {
        return Err("unsupported-wit-world");
    }

    match &fixture.input {
        FixtureInput::HostFetchBlob {
            handle,
            offset,
            len,
        } => {
            let Some(blob) = fixture
                .blob_store
                .handles
                .iter()
                .find(|candidate| candidate.handle == *handle)
            else {
                return Err("missing-blob");
            };
            read_slice(&blob.bytes, *offset, *len)
        }
        FixtureInput::BundleHandleRead {
            bundle_id,
            offset,
            len,
        } => {
            let Some(bundle) = fixture
                .blob_store
                .bundles
                .iter()
                .find(|candidate| candidate.id == *bundle_id)
            else {
                return Err("missing-bundle");
            };
            read_slice(&bundle.bytes, *offset, *len)
        }
    }
}

fn read_slice(bytes: &[u8], offset: u64, len: u32) -> Result<Vec<u8>, &'static str> {
    let Some(end) = offset.checked_add(u64::from(len)) else {
        return Err("offset-length-out-of-bounds");
    };
    let available = bytes.len() as u64;
    if offset > available || end > available {
        return Err("offset-length-out-of-bounds");
    }
    let start = offset as usize;
    let end = end as usize;
    Ok(bytes[start..end].to_vec())
}

#[test]
fn current_guard_wit_declares_fixture_operations() {
    let path = current_wit_path();
    let wit = match fs::read_to_string(&path) {
        Ok(wit) => wit,
        Err(error) => panic!("failed to read {}: {error}", path.display()),
    };

    for needle in [
        "package chio:guard@0.2.0;",
        "interface host",
        "fetch-blob: func(handle: u32, offset: u64, len: u32) -> result<list<u8>, string>;",
        "interface policy-context",
        "resource bundle-handle",
        "constructor(id: string);",
        "read: func(offset: u64, len: u32) -> result<list<u8>, string>;",
        "import host;",
        "import policy-context;",
    ] {
        assert!(
            wit.contains(needle),
            "{} is missing WIT declaration `{needle}`",
            path.display()
        );
    }
}

#[test]
fn all_guard_wit_0_2_0_fixtures_load_and_have_unique_ids() {
    let fixtures = load_fixtures();
    assert!(
        fixtures.len() >= MIN_FIXTURE_COUNT,
        "expected at least {MIN_FIXTURE_COUNT} WIT 0.2.0 fixtures in {}, found {}",
        corpus_root().display(),
        fixtures.len()
    );

    let mut seen_ids = BTreeSet::new();
    let mut failures = Vec::new();
    for (path, fixture) in fixtures {
        if fixture.schema != FIXTURE_SCHEMA {
            failures.push(format!(
                "{}: unexpected fixture schema `{}`",
                path.display(),
                fixture.schema
            ));
        }
        if fixture.id.trim().is_empty() {
            failures.push(format!("{}: fixture id must not be empty", path.display()));
        }
        if fixture.title.trim().is_empty() {
            failures.push(format!("{}: title must not be empty", path.display()));
        }
        if fixture.description.trim().is_empty() {
            failures.push(format!("{}: description must not be empty", path.display()));
        }
        if !seen_ids.insert(fixture.id.clone()) {
            failures.push(format!(
                "{}: duplicate fixture id `{}`",
                path.display(),
                fixture.id
            ));
        }
        if fixture.imports.is_empty() {
            failures.push(format!("{}: imports must not be empty", path.display()));
        }
        for import in &fixture.imports {
            if import != "host.fetch-blob" && import != "policy-context.bundle-handle" {
                failures.push(format!("{}: unsupported import `{import}`", path.display()));
            }
        }
        if fixture.wit_world != CURRENT_GUARD_WORLD
            && fixture.expected.error_kind.as_deref() != Some("unsupported-wit-world")
        {
            failures.push(format!(
                "{}: non-current WIT world `{}` must expect unsupported-wit-world",
                path.display(),
                fixture.wit_world
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "WIT 0.2.0 fixture shape failures ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn guard_wit_0_2_0_fixtures_match_fail_closed_semantics() {
    let fixtures = load_fixtures();
    let mut failures = Vec::new();

    for (path, fixture) in fixtures {
        match (fixture.expected.status, run_fixture(&fixture)) {
            (ExpectedStatus::Ok, Ok(actual)) => {
                let Some(expected) = fixture.expected.bytes.as_ref() else {
                    failures.push(format!(
                        "{}: ok fixture `{}` is missing expected bytes",
                        path.display(),
                        fixture.id
                    ));
                    continue;
                };
                if &actual != expected {
                    failures.push(format!(
                        "{}: fixture `{}` byte mismatch, expected {:?}, got {:?}",
                        path.display(),
                        fixture.id,
                        expected,
                        actual
                    ));
                }
            }
            (ExpectedStatus::Ok, Err(error_kind)) => failures.push(format!(
                "{}: fixture `{}` expected ok but failed closed with {error_kind}",
                path.display(),
                fixture.id
            )),
            (ExpectedStatus::Deny, Err(actual_kind)) => {
                let Some(expected_kind) = fixture.expected.error_kind.as_deref() else {
                    failures.push(format!(
                        "{}: deny fixture `{}` is missing errorKind",
                        path.display(),
                        fixture.id
                    ));
                    continue;
                };
                if actual_kind != expected_kind {
                    failures.push(format!(
                        "{}: fixture `{}` expected error kind `{expected_kind}`, got `{actual_kind}`",
                        path.display(),
                        fixture.id
                    ));
                }
            }
            (ExpectedStatus::Deny, Ok(actual)) => failures.push(format!(
                "{}: fixture `{}` expected deny but returned bytes {:?}",
                path.display(),
                fixture.id,
                actual
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "WIT 0.2.0 fixture semantic failures ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
