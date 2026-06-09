//! HushSpec `extends` resolution.
//!
//! Ported from the HushSpec reference implementation. Resolves the `extends`
//! field by loading parent policies and merging them.

use crate::merge::merge;
use crate::models::HushSpec;
use std::fs;
use std::path::{Path, PathBuf};

/// A loaded HushSpec document plus its canonical source identifier.
#[derive(Clone, Debug)]
pub struct LoadedSpec {
    pub source: String,
    pub spec: HushSpec,
}

/// Errors raised while resolving `extends`.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse HushSpec document at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("circular extends detected: {chain}")]
    Cycle { chain: String },
    #[error("{message}")]
    Http { message: String },
    #[error("could not resolve reference '{reference}': {message}")]
    NotFound { reference: String, message: String },
}

/// Create a composite loader that chains: builtin -> file.
pub fn create_composite_loader() -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>
{
    move |reference: &str, from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
        if reference.starts_with("https://") || reference.starts_with("http://") {
            return Err(ResolveError::Http {
                message: "HTTP-based policy loading is not supported in chio-policy".to_string(),
            });
        }

        load_from_filesystem(reference, from)
    }
}

/// Resolve a parsed spec using a caller-provided loader.
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let mut stack = Vec::new();
    if let Some(source) = source {
        stack.push(source.to_string());
    }
    resolve_inner(spec, source, loader, &mut stack)
}

/// Resolve a HushSpec from a filesystem path, following `extends` chains.
pub fn resolve_from_path(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    resolve_with_loader(&spec, Some(&path.to_string_lossy()), &load_from_filesystem)
}

fn resolve_inner<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
    stack: &mut Vec<String>,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let Some(reference) = spec.extends.as_deref() else {
        return Ok(spec.clone());
    };

    let loaded = loader(reference, source)?;
    if let Some(index) = stack.iter().position(|entry| entry == &loaded.source) {
        let mut cycle = stack[index..].to_vec();
        cycle.push(loaded.source);
        return Err(ResolveError::Cycle {
            chain: cycle.join(" -> "),
        });
    }

    stack.push(loaded.source.clone());
    let resolved_parent = resolve_inner(&loaded.spec, Some(&loaded.source), loader, stack)?;
    stack.pop();
    Ok(merge(&resolved_parent, spec))
}

fn load_from_filesystem(reference: &str, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
    let path = resolve_reference_path(reference, from);
    let canonical = canonical_path(&path)?;
    let spec = load_spec_from_file(&canonical)?;
    Ok(LoadedSpec {
        source: canonical.to_string_lossy().into_owned(),
        spec,
    })
}

fn resolve_reference_path(reference: &str, from: Option<&str>) -> PathBuf {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute() {
        return candidate;
    }

    match from
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        Some(parent) => parent.join(candidate),
        None => candidate,
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf, ResolveError> {
    fs::canonicalize(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn load_spec_from_file(path: &Path) -> Result<HushSpec, ResolveError> {
    let content = fs::read_to_string(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    HushSpec::parse(&content).map_err(|error| ResolveError::Parse {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DefaultAction, EgressRule, ForbiddenPathsRule, Rules};
    use uuid::Uuid;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chio-policy-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_spec(path: &Path, spec: &HushSpec) {
        fs::write(path, spec.to_yaml().expect("serialize spec")).expect("write spec");
    }

    fn minimal_spec(extends: Option<&str>) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: None,
            description: None,
            extends: extends.map(str::to_string),
            merge_strategy: None,
            rules: None,
            extensions: None,
            metadata: None,
        }
    }

    #[test]
    fn resolve_reference_path_handles_relative_absolute_and_source_free_cases() {
        let absolute = std::env::temp_dir().join("chio-policy-absolute-base.yaml");
        assert_eq!(
            resolve_reference_path(
                absolute.to_str().expect("absolute path"),
                Some("/tmp/specs/child.yaml")
            ),
            absolute
        );
        assert_eq!(
            resolve_reference_path("base.yaml", Some("/tmp/specs/child.yaml")),
            PathBuf::from("/tmp/specs/base.yaml")
        );
        assert_eq!(
            resolve_reference_path("base.yaml", None),
            PathBuf::from("base.yaml")
        );
    }

    #[test]
    fn resolve_from_path_merges_parent_specs_from_filesystem() {
        let dir = temp_dir("resolve");
        let base_path = dir.join("base.yaml");
        let child_path = dir.join("child.yaml");

        let base_spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("base".to_string()),
            description: Some("base description".to_string()),
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                forbidden_paths: Some(ForbiddenPathsRule {
                    enabled: true,
                    patterns: vec!["/etc".to_string()],
                    exceptions: Vec::new(),
                }),
                ..Rules::default()
            }),
            extensions: None,
            metadata: None,
        };
        let child_spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: None,
            description: Some("child description".to_string()),
            extends: Some("base.yaml".to_string()),
            merge_strategy: None,
            rules: Some(Rules {
                egress: Some(EgressRule {
                    enabled: true,
                    allow: vec!["api.chio.test".to_string()],
                    block: Vec::new(),
                    default: DefaultAction::Block,
                }),
                ..Rules::default()
            }),
            extensions: None,
            metadata: None,
        };

        write_spec(&base_path, &base_spec);
        write_spec(&child_path, &child_spec);

        let merged = resolve_from_path(&child_path).expect("resolve child path");
        assert_eq!(merged.name.as_deref(), Some("base"));
        assert_eq!(merged.description.as_deref(), Some("child description"));

        let rules = merged.rules.expect("merged rules");
        assert!(rules.forbidden_paths.is_some());
        assert!(rules.egress.is_some());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_with_loader_detects_cycles_in_extends_chain() {
        let loader = |reference: &str, _from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
            match reference {
                "b" => Ok(LoadedSpec {
                    source: "b".to_string(),
                    spec: minimal_spec(Some("a")),
                }),
                "a" => Ok(LoadedSpec {
                    source: "a".to_string(),
                    spec: minimal_spec(Some("b")),
                }),
                other => Err(ResolveError::NotFound {
                    reference: other.to_string(),
                    message: "missing".to_string(),
                }),
            }
        };

        let error =
            resolve_with_loader(&minimal_spec(Some("b")), Some("a"), &loader).expect_err("cycle");
        match error {
            ResolveError::Cycle { chain } => assert_eq!(chain, "a -> b -> a"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn loader_errors_cover_http_parse_and_missing_paths() {
        let dir = temp_dir("resolve-errors");
        let invalid_path = dir.join("invalid.yaml");
        fs::write(&invalid_path, "hushspec: [").expect("write invalid yaml");

        match load_spec_from_file(&invalid_path).expect_err("parse error") {
            ResolveError::Parse { path, .. } => {
                assert!(path.ends_with("invalid.yaml"));
            }
            other => panic!("unexpected parse error: {other:?}"),
        }

        match canonical_path(&dir.join("missing.yaml")).expect_err("missing file") {
            ResolveError::Read { path, .. } => assert!(path.ends_with("missing.yaml")),
            other => panic!("unexpected read error: {other:?}"),
        }

        let composite = create_composite_loader();
        match composite("https://example.com/base.yaml", None).expect_err("http disabled") {
            ResolveError::Http { message } => {
                assert!(message.contains("not supported"));
            }
            other => panic!("unexpected http error: {other:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }
}
