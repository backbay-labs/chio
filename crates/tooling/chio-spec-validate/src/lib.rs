//! Chio JSON Schema validator.
//!
//! Loads a JSON Schema from disk, compiles it via the `jsonschema` crate, and
//! validates a target document against it. Used by `cargo xtask
//! validate-scenarios` and by downstream conformance goldens to confirm that
//! wire artifacts conform to the published `spec/schemas/` definitions.
//!
//! All errors are surfaced via [`ValidateError`]; the crate never panics on
//! malformed input. The workspace clippy lints (`unwrap_used`, `expect_used`)
//! are enforced.
//!
//! # Trust boundary
//!
//! This crate is the gate between the **trusted** Chio schema set
//! (committed under `spec/schemas/`) and **untrusted** documents
//! (capability tokens, receipts, scenarios, wire artifacts). The
//! `schema` argument to every entry point MUST be a Chio-controlled
//! schema; user-supplied schemas are not in scope and may pull in
//! arbitrary `file://` resources via `$ref`. The `doc` argument is the
//! untrusted half: a document cannot trigger `$ref` resolution because
//! validation only walks the schema's reference graph, not the
//! instance's.
//!
//! The workspace pulls `jsonschema` with `default-features = false` and
//! only the `resolve-file` feature enabled. Absolute `http://` and
//! `https://` `$ref` URIs resolve only when they match Chio schema namespaces
//! registered from `spec/schemas/`; unregistered network refs fail with
//! `Unknown scheme`, "feature is required", or the local retriever rejection
//! rather than reaching the network. This is verified by the
//! `http_ref_in_schema_does_not_fetch_network` test.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::{Retrieve, Uri};
use serde_json::Value;

const CHIO_SCHEMA_URI_PREFIXES: &[&str] = &[
    "https://chio.world/schemas/",
    "https://chio-protocol.dev/schemas/",
];

/// Errors surfaced by [`validate`] and helpers.
#[derive(Debug)]
pub enum ValidateError {
    /// Failed to read a file from disk.
    Io(PathBuf, std::io::Error),
    /// The file did not parse as JSON.
    Json(PathBuf, serde_json::Error),
    /// The schema document could not be compiled.
    SchemaCompile(PathBuf, String),
    /// The document did not satisfy the schema.
    SchemaViolation(PathBuf, PathBuf, Vec<String>),
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "io error reading {}: {err}", path.display()),
            Self::Json(path, err) => write!(f, "json parse error in {}: {err}", path.display()),
            Self::SchemaCompile(path, err) => {
                write!(f, "failed to compile schema {}: {err}", path.display())
            }
            Self::SchemaViolation(schema, doc, errors) => write!(
                f,
                "document {} violates schema {}: {}",
                doc.display(),
                schema.display(),
                errors.join(" | ")
            ),
        }
    }
}

impl std::error::Error for ValidateError {}

/// Read and parse a JSON file from disk.
pub fn load_json(path: &Path) -> Result<Value, ValidateError> {
    let raw = fs::read_to_string(path).map_err(|err| ValidateError::Io(path.to_path_buf(), err))?;
    serde_json::from_str(&raw).map_err(|err| ValidateError::Json(path.to_path_buf(), err))
}

/// Validate a JSON document against a JSON Schema, both loaded from disk.
///
/// Returns `Ok(())` when the document passes; otherwise a
/// [`ValidateError::SchemaViolation`] enumerating every reported error.
pub fn validate(schema_path: &Path, doc_path: &Path) -> Result<(), ValidateError> {
    let schema = load_json(schema_path)?;
    let doc = load_json(doc_path)?;
    validate_value(schema_path, &schema, doc_path, &doc)
}

/// Validate an in-memory document against an in-memory schema.
///
/// `schema_path` and `doc_path` are used only for diagnostics and may be any
/// representative path (for example, a synthetic `<inline>`). When
/// `schema_path` has a parent directory, it is used as the base URI for
/// resolving sibling-file `$ref` references, matching the
/// `spec/schemas/<area>/v1/*.schema.json` convention used in the workspace.
pub fn validate_value(
    schema_path: &Path,
    schema: &Value,
    doc_path: &Path,
    doc: &Value,
) -> Result<(), ValidateError> {
    let mut options = jsonschema::options();
    if let Some(base_uri) = schema_base_uri(schema_path) {
        options = options.with_base_uri(base_uri);
    }
    if let Some(schema_root) = schema_registry_root(schema_path) {
        options = options.with_retriever(LocalSchemaRetriever { schema_root });
    }
    let validator = options
        .build(schema)
        .map_err(|err| ValidateError::SchemaCompile(schema_path.to_path_buf(), err.to_string()))?;
    if validator.is_valid(doc) {
        return Ok(());
    }
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|err| err.to_string())
        .collect();
    Err(ValidateError::SchemaViolation(
        schema_path.to_path_buf(),
        doc_path.to_path_buf(),
        errors,
    ))
}

/// Build a `file://` base URI from a schema's parent directory so that the
/// `jsonschema` `resolve-file` retriever can follow `$ref` strings such as
/// `caller-identity.schema.json` (sibling file) or `../shared/foo.json`.
///
/// Returns `None` when the schema path has no parent or cannot be canonicalized
/// to an absolute path; callers fall back to library defaults in that case.
fn schema_base_uri(schema_path: &Path) -> Option<String> {
    let parent = schema_path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    let canonical = match parent.canonicalize() {
        Ok(path) => path,
        Err(_) => parent.to_path_buf(),
    };
    // Normalize backslashes to forward slashes for Windows paths, then ensure
    // exactly one leading slash so the result is a well-formed `file:///...`
    // URI on every host platform.
    let mut path_str = canonical.to_string_lossy().replace('\\', "/");
    if !path_str.starts_with('/') {
        path_str.insert(0, '/');
    }
    if !path_str.ends_with('/') {
        path_str.push('/');
    }
    Some(format!("file://{path_str}"))
}

fn schema_registry_root(schema_path: &Path) -> Option<PathBuf> {
    let parent = schema_path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    let mut current = parent.to_path_buf();
    loop {
        let is_schema_root = current.file_name().is_some_and(|name| name == "schemas")
            && current
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "spec");
        if is_schema_root {
            return Some(current);
        }
        if !current.pop() {
            return Some(parent.to_path_buf());
        }
    }
}

#[derive(Debug, Clone)]
struct LocalSchemaRetriever {
    schema_root: PathBuf,
}

impl Retrieve for LocalSchemaRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        match uri.scheme().as_str() {
            "https" => {
                let Some(relative) = local_chio_schema_relative_path(uri) else {
                    return Err("unregistered network schema reference is not resolved".into());
                };
                let path = resolve_chio_schema_path(&self.schema_root, uri.as_str(), relative)?;
                read_local_schema_file(&self.schema_root, &path)
            }
            "file" => {
                let path = PathBuf::from(uri.path().as_str());
                read_local_schema_file(&self.schema_root, &path)
            }
            "http" => Err("unregistered network schema reference is not resolved".into()),
            scheme => Err(format!("Unknown scheme {scheme}").into()),
        }
    }
}

fn local_chio_schema_relative_path(uri: &Uri<String>) -> Option<&str> {
    if CHIO_SCHEMA_URI_PREFIXES
        .iter()
        .any(|prefix| uri.as_str().starts_with(prefix))
    {
        uri.path().as_str().strip_prefix("/schemas/")
    } else {
        None
    }
}

fn resolve_chio_schema_path(
    schema_root: &Path,
    uri: &str,
    relative: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let path = join_schema_path(schema_root, relative)?;
    if path.is_file() {
        return Ok(path);
    }
    if let Some(path) = find_schema_by_id(schema_root, uri)? {
        return Ok(path);
    }
    Err(format!("Chio schema URI is not registered locally: {uri}").into())
}

fn join_schema_path(
    schema_root: &Path,
    relative: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let mut path = schema_root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return Err("Chio schema URI must not contain parent traversal".into());
        }
        path.push(segment);
    }
    Ok(path)
}

fn find_schema_by_id(
    schema_root: &Path,
    uri: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    let target = uri.trim_end_matches('/');
    let mut pending = vec![schema_root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir)? {
            entries.push(entry?);
        }
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && is_json_file(&path)
                && schema_file_id_matches(&path, target)?
            {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn schema_file_id_matches(
    path: &Path,
    target: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let file = fs::File::open(path)?;
    let value: Value = serde_json::from_reader(file)?;
    let Some(id) = value.get("$id").and_then(Value::as_str) else {
        return Ok(false);
    };
    Ok(id.trim_end_matches('/') == target)
}

fn is_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "json")
}

fn read_local_schema_file(
    schema_root: &Path,
    path: &Path,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let canonical_path = fs::canonicalize(path)?;
    let canonical_root = fs::canonicalize(schema_root)?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err("schema reference resolves outside schema root".into());
    }
    let file = fs::File::open(canonical_path)?;
    Ok(serde_json::from_reader(file)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    /// Confirms the workspace `jsonschema` build does NOT pull in the
    /// `resolve-http` feature: a schema that references an `http://`
    /// URL must fail to compile rather than open a network connection.
    /// If this test ever starts passing the schema build, the feature
    /// flag has been re-enabled and the trust boundary documentation
    /// in `lib.rs` is no longer accurate.
    #[test]
    fn http_ref_in_schema_does_not_fetch_network() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "http://example.invalid/should-not-resolve.json"
        });
        let doc = json!({});
        let schema_path = std::path::PathBuf::from("<inline>");
        let doc_path = std::path::PathBuf::from("<inline>");
        let result = validate_value(&schema_path, &schema, &doc_path, &doc);
        match result {
            Err(ValidateError::SchemaCompile(_, msg)) => {
                let lower = msg.to_ascii_lowercase();
                // jsonschema 0.46 emits one of these messages when
                // resolve-http is OFF and the retriever rejects the
                // scheme.
                assert!(
                    lower.contains("resolve-http")
                        || lower.contains("unknown scheme")
                        || lower.contains("required to resolve"),
                    "expected resolve-http rejection, got: {msg}"
                );
            }
            Err(other) => panic!("expected SchemaCompile rejection, got {other}"),
            Ok(()) => panic!(
                "schema with http:// $ref unexpectedly compiled - resolve-http feature may be on"
            ),
        }
    }

    #[test]
    fn unknown_scheme_in_schema_ref_is_rejected() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "ftp://example.invalid/whatever.json"
        });
        let doc = json!({});
        let schema_path = std::path::PathBuf::from("<inline>");
        let doc_path = std::path::PathBuf::from("<inline>");
        let result = validate_value(&schema_path, &schema, &doc_path, &doc);
        assert!(
            matches!(result, Err(ValidateError::SchemaCompile(_, _))),
            "ftp:// $ref must be rejected at schema-compile time"
        );
    }

    #[test]
    fn absolute_id_sibling_schema_ref_resolves_from_local_files() {
        let root = unique_temp_dir("chio-spec-validate-sibling-ref");
        let _ = fs::remove_dir_all(&root);
        let schema_dir = root.join("spec/schemas/test/v1");
        fs::create_dir_all(&schema_dir)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", schema_dir.display()));
        let schema_path = schema_dir.join("root.schema.json");
        let sibling_path = schema_dir.join("sibling.schema.json");
        let doc_path = root.join("doc.json");
        fs::write(
            &schema_path,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://chio.world/schemas/test/v1/root.schema.json",
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {
                    "name": {
                        "$ref": "sibling.schema.json#/$defs/name"
                    }
                }
            }))
            .unwrap_or_else(|err| panic!("failed to encode root schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", schema_path.display()));
        fs::write(
            &sibling_path,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://chio.world/schemas/test/v1/sibling.schema.json",
                "$defs": {
                    "name": {
                        "type": "string",
                        "minLength": 1
                    }
                }
            }))
            .unwrap_or_else(|err| panic!("failed to encode sibling schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", sibling_path.display()));
        fs::write(&doc_path, br#"{"name":"kernel-a"}"#)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", doc_path.display()));

        let result = validate(&schema_path, &doc_path);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", root.display()));
        result.unwrap_or_else(|err| panic!("absolute $id sibling ref should resolve: {err}"));
    }

    #[test]
    fn protocol_dev_absolute_schema_id_resolves_from_local_registry() {
        let root = unique_temp_dir("chio-spec-validate-protocol-dev-ref");
        let _ = fs::remove_dir_all(&root);
        let schema_dir = root.join("spec/schemas/test/v1");
        fs::create_dir_all(&schema_dir)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", schema_dir.display()));
        let schema_path = schema_dir.join("root.schema.json");
        let sibling_path = schema_dir.join("sibling.schema.json");
        let doc_path = root.join("doc.json");
        fs::write(
            &schema_path,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://chio-protocol.dev/schemas/test/v1/root/v1",
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {
                    "name": {
                        "$ref": "https://chio-protocol.dev/schemas/test/v1/sibling/v1#/$defs/name"
                    }
                }
            }))
            .unwrap_or_else(|err| panic!("failed to encode root schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", schema_path.display()));
        fs::write(
            &sibling_path,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://chio-protocol.dev/schemas/test/v1/sibling/v1",
                "$defs": {
                    "name": {
                        "type": "string",
                        "minLength": 1
                    }
                }
            }))
            .unwrap_or_else(|err| panic!("failed to encode sibling schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", sibling_path.display()));
        fs::write(&doc_path, br#"{"name":"kernel-a"}"#)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", doc_path.display()));

        let result = validate(&schema_path, &doc_path);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", root.display()));
        result.unwrap_or_else(|err| {
            panic!("protocol.dev absolute $id ref should resolve locally: {err}")
        });
    }

    #[test]
    fn file_ref_outside_schema_root_is_rejected() {
        let root = unique_temp_dir("chio-spec-validate-file-ref-outside");
        let _ = fs::remove_dir_all(&root);
        let schema_dir = root.join("spec/schemas/test/v1");
        let outside_dir = root.join("outside");
        fs::create_dir_all(&schema_dir)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", schema_dir.display()));
        fs::create_dir_all(&outside_dir)
            .unwrap_or_else(|err| panic!("failed to create {}: {err}", outside_dir.display()));
        let schema_path = schema_dir.join("root.schema.json");
        let outside_schema = outside_dir.join("outside.schema.json");
        let doc_path = root.join("doc.json");

        fs::write(
            &outside_schema,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object"
            }))
            .unwrap_or_else(|err| panic!("failed to encode outside schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", outside_schema.display()));
        fs::write(
            &schema_path,
            serde_json::to_vec_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://chio.world/schemas/test/v1/root.schema.json",
                "$ref": file_uri(&outside_schema)
            }))
            .unwrap_or_else(|err| panic!("failed to encode root schema: {err}")),
        )
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", schema_path.display()));
        fs::write(&doc_path, br#"{}"#)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", doc_path.display()));

        let result = validate(&schema_path, &doc_path);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", root.display()));

        match result {
            Err(ValidateError::SchemaCompile(_, message)) => {
                assert!(
                    message.contains("outside schema root"),
                    "expected schema-root rejection, got: {message}"
                );
            }
            Err(error) => panic!("expected SchemaCompile rejection, got {error}"),
            Ok(()) => panic!("file:// ref outside schema root should fail closed"),
        }
    }

    #[test]
    fn web3_v2_anchor_schema_rejects_empty_nested_payloads() {
        let schema_path = workspace_schema_path("chio-web3/v2/anchor-inclusion-proof.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 anchor schema: {error}"));
        let document = json!({
            "schema": "chio.anchor-inclusion-proof.v2",
            "receipt": {},
            "receipt_inclusion": {},
            "checkpoint_statement": {},
            "key_binding_certificate": {}
        });

        assert!(
            matches!(
                validate_value(
                    &schema_path,
                    &schema,
                    Path::new("<empty-anchor-payload>"),
                    &document
                ),
                Err(ValidateError::SchemaViolation(_, _, _))
            ),
            "empty nested anchor payloads must compile the schema and fail validation"
        );
    }

    #[test]
    fn transparency_v2_schema_accepts_supported_checkpoint_algorithms() {
        let schema_path = workspace_schema_path("chio-transparency/v2/inclusion-proof.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 transparency schema: {error}"));
        let algorithm_values = [
            ("a".repeat(64), "b".repeat(128)),
            (
                format!("p256:04{}", "a".repeat(128)),
                format!("p256:{}", "b".repeat(142)),
            ),
            (
                format!("p384:04{}", "a".repeat(192)),
                format!("p384:{}", "b".repeat(208)),
            ),
            (
                format!(
                    "hybrid:{}:{}:ed25519+mldsa65",
                    "a".repeat(64),
                    "c".repeat(3904)
                ),
                format!(
                    "hybrid:{}:{}:ed25519+mldsa65",
                    "b".repeat(128),
                    "d".repeat(6618)
                ),
            ),
            (
                format!(
                    "hybrid:p256:04{}:{}:p256+mldsa65",
                    "a".repeat(128),
                    "c".repeat(3904)
                ),
                format!(
                    "hybrid:p256:{}:{}:p256+mldsa65",
                    "b".repeat(142),
                    "d".repeat(6618)
                ),
            ),
        ];

        for (kernel_key, signature) in algorithm_values {
            let document = json!({
                "schema": "chio.transparency.inclusion-proof.v2",
                "proof_id": "proof-1",
                "log_id": "log-1",
                "artifact_ref": "1".repeat(64),
                "root_hash": "2".repeat(64),
                "leaf_hash": "2".repeat(64),
                "tree_size": 1,
                "leaf_index": 0,
                "checkpoint": "log-1:1",
                "inclusion_path": [],
                "verified_at": 1,
                "checkpoint_statement": {
                    "body": {
                        "schema": "chio.checkpoint_statement.v2",
                        "checkpoint_seq": 1,
                        "batch_start_seq": 1,
                        "batch_end_seq": 1,
                        "tree_size": 1,
                        "merkle_root": format!("0x{}", "2".repeat(64)),
                        "issued_at": 1,
                        "kernel_key": kernel_key,
                        "chain_root": format!("0x{}", "3".repeat(64))
                    },
                    "signature": signature
                }
            });
            validate_value(
                &schema_path,
                &schema,
                Path::new("<supported-checkpoint-algorithm>"),
                &document,
            )
            .unwrap_or_else(|error| {
                panic!("supported checkpoint algorithm must validate: {error}")
            });
        }
    }

    #[test]
    fn transparency_v2_schema_rejects_mismatched_or_malformed_algorithm_envelopes() {
        let schema_path = workspace_schema_path("chio-transparency/v2/inclusion-proof.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 transparency schema: {error}"));
        let invalid_pairs = [
            (
                format!("p256:{}", "a".repeat(130)),
                format!("p256:{}", "b".repeat(141)),
            ),
            (
                format!(
                    "hybrid:{}:{}:p256+mldsa65",
                    "a".repeat(64),
                    "c".repeat(3904)
                ),
                format!(
                    "hybrid:{}:{}:p256+mldsa65",
                    "b".repeat(128),
                    "d".repeat(6618)
                ),
            ),
        ];

        for (kernel_key, signature) in invalid_pairs {
            let document = json!({
                "schema": "chio.transparency.inclusion-proof.v2",
                "proof_id": "proof-1",
                "log_id": "log-1",
                "artifact_ref": "1".repeat(64),
                "root_hash": "2".repeat(64),
                "leaf_hash": "2".repeat(64),
                "tree_size": 1,
                "leaf_index": 0,
                "checkpoint": "log-1:1",
                "inclusion_path": [],
                "verified_at": 1,
                "checkpoint_statement": {
                    "body": {
                        "schema": "chio.checkpoint_statement.v2",
                        "checkpoint_seq": 1,
                        "batch_start_seq": 1,
                        "batch_end_seq": 1,
                        "tree_size": 1,
                        "merkle_root": format!("0x{}", "2".repeat(64)),
                        "issued_at": 1,
                        "kernel_key": kernel_key,
                        "chain_root": format!("0x{}", "3".repeat(64))
                    },
                    "signature": signature
                }
            });
            assert!(matches!(
                validate_value(
                    &schema_path,
                    &schema,
                    Path::new("<invalid-checkpoint-algorithm>"),
                    &document
                ),
                Err(ValidateError::SchemaViolation(_, _, _))
            ));
        }
    }

    #[test]
    fn transparency_v2_schema_enforces_checkpoint_version_chain_root_rules() {
        let schema_path = workspace_schema_path("chio-transparency/v2/inclusion-proof.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 transparency schema: {error}"));
        let invalid_documents = [
            transparency_document(
                "chio.checkpoint_statement.v1",
                1,
                Some(json!(format!("0x{}", "3".repeat(64)))),
            ),
            transparency_document("chio.checkpoint_statement.v2", 1, None),
        ];
        for document in invalid_documents {
            assert!(matches!(
                validate_value(
                    &schema_path,
                    &schema,
                    Path::new("<invalid-checkpoint-version-root>"),
                    &document
                ),
                Err(ValidateError::SchemaViolation(_, _, _))
            ));
        }

        let detached_later = transparency_document("chio.checkpoint_statement.v2", 2, None);
        validate_value(
            &schema_path,
            &schema,
            Path::new("<detached-later-v2-checkpoint>"),
            &detached_later,
        )
        .unwrap_or_else(|error| panic!("later detached v2 checkpoint must validate: {error}"));
    }

    #[test]
    fn transparency_v2_schema_rejects_noncanonical_checkpoint_hashes() {
        let schema_path = workspace_schema_path("chio-transparency/v2/inclusion-proof.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 transparency schema: {error}"));
        let canonical_chain_root = json!(format!("0x{}", "3".repeat(64)));
        let canonical = transparency_document(
            "chio.checkpoint_statement.v2",
            1,
            Some(canonical_chain_root),
        );

        validate_value(
            &schema_path,
            &schema,
            Path::new("<canonical-checkpoint-hashes>"),
            &canonical,
        )
        .unwrap_or_else(|error| panic!("canonical checkpoint hashes must validate: {error}"));

        for field in ["merkle_root", "chain_root"] {
            let mut document = canonical.clone();
            document["checkpoint_statement"]["body"][field] = json!("2".repeat(64));
            assert!(
                matches!(
                    validate_value(
                        &schema_path,
                        &schema,
                        Path::new("<noncanonical-checkpoint-hash>"),
                        &document
                    ),
                    Err(ValidateError::SchemaViolation(_, _, _))
                ),
                "bare checkpoint {field} must fail schema validation"
            );
        }
    }

    #[test]
    fn web3_v2_anchor_bundle_excludes_the_primary_lane_from_secondary_lanes() {
        let schema_path = workspace_schema_path("chio-web3/v2/anchor-proof-bundle.schema.json");
        let schema = load_json(&schema_path)
            .unwrap_or_else(|error| panic!("load v2 anchor bundle schema: {error}"));
        assert_eq!(
            schema.pointer("/properties/secondary_lanes/items/enum"),
            Some(&json!(["bitcoin_ots", "solana_memo"]))
        );
    }

    fn workspace_schema_path(relative: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../..");
        path.push("spec/schemas");
        path.push(relative);
        fs::canonicalize(&path)
            .unwrap_or_else(|error| panic!("canonicalize {}: {error}", path.display()))
    }

    fn transparency_document(
        checkpoint_schema: &str,
        checkpoint_seq: u64,
        chain_root: Option<Value>,
    ) -> Value {
        let mut body = json!({
            "schema": checkpoint_schema,
            "checkpoint_seq": checkpoint_seq,
            "batch_start_seq": checkpoint_seq,
            "batch_end_seq": checkpoint_seq,
            "tree_size": 1,
            "merkle_root": format!("0x{}", "2".repeat(64)),
            "issued_at": 1,
            "kernel_key": "a".repeat(64)
        });
        if let Some(chain_root) = chain_root {
            body["chain_root"] = chain_root;
        }
        json!({
            "schema": "chio.transparency.inclusion-proof.v2",
            "proof_id": "proof-1",
            "log_id": "log-1",
            "artifact_ref": "1".repeat(64),
            "root_hash": "2".repeat(64),
            "leaf_hash": "2".repeat(64),
            "tree_size": 1,
            "leaf_index": 0,
            "checkpoint": format!("log-1:{checkpoint_seq}"),
            "inclusion_path": [],
            "verified_at": 1,
            "checkpoint_statement": {
                "body": body,
                "signature": "b".repeat(128)
            }
        })
    }

    fn file_uri(path: &Path) -> String {
        let mut value = path.to_string_lossy().replace('\\', "/");
        if !value.starts_with('/') {
            value.insert(0, '/');
        }
        format!("file://{value}")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{label}-{}", std::process::id()));
        path
    }
}
