//! `chio.yaml` schema validation probe.
//!
//! Loads the project `chio.yaml`, parses it with `serde_yml`, and
//! validates the document against the embedded set of required keys.
//! Errors carry line and column anchors derived from the parser
//! location so editors can jump to the offending span.
//!
//! The probe does not depend on `spec/schemas/chio-wire/v1/`
//! directly: those schemas live in JSON and target wire types, not the
//! `chio.yaml` config surface. This probe enforces the local config
//! contract (required top-level keys, scalar shape) and leaves
//! wire-type validation to the LSP, which loads the JSON schemas as a
//! unit.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde_yml::Value;

use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// Required top-level keys in `chio.yaml`. Missing any of these causes
/// the probe to fail with a `urn:chio:error:cli:doctor-chio-yaml-invalid`
/// report.
pub const REQUIRED_KEYS: &[&str] = &["version", "policy"];
const CHIO_YAML_SCAFFOLD: &str = "version: 1\npolicy: ./policy.yaml\n";

#[derive(Debug, Default, Clone)]
pub struct ChioYamlProbe {
    path_override: Option<PathBuf>,
}

impl ChioYamlProbe {
    #[must_use]
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path_override = Some(path);
        self
    }

    fn resolve_path(&self, config: &ProbeConfig) -> PathBuf {
        if let Some(p) = &self.path_override {
            return p.clone();
        }
        let root = config
            .workdir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        root.join("chio.yaml")
    }
}

impl Probe for ChioYamlProbe {
    fn name(&self) -> &'static str {
        "chio_yaml"
    }

    fn run(&self, config: &ProbeConfig) -> ProbeReport {
        let path = self.resolve_path(config);
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                if config.fix_enabled {
                    return self.scaffold_missing(&path);
                }
                return ProbeReport {
                    probe: self.name(),
                    severity: ProbeSeverity::Info,
                    code: "urn:chio:error:cli:other",
                    message: format!("No chio.yaml found at {}.", path.display()),
                    help: Some(
                        "Run `chio doctor --fix` to scaffold a minimal chio.yaml, or create one by hand."
                            .to_string(),
                    ),
                    context: Vec::new(),
                    repaired: false,
                };
            }
            Err(err) => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-chio-yaml-invalid",
                    format!("Could not read {}: {err}", path.display()),
                );
            }
        };

        self.validate_body(&path, &body)
    }
}

impl ChioYamlProbe {
    fn scaffold_missing(&self, path: &Path) -> ProbeReport {
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                return match std::fs::read_to_string(path) {
                    Ok(body) => self.validate_body(path, &body),
                    Err(read_err) => ProbeReport::fail(
                        self.name(),
                        ProbeSeverity::Error,
                        "urn:chio:error:cli:doctor-chio-yaml-invalid",
                        format!(
                            "Could not read {} after it appeared: {read_err}",
                            path.display()
                        ),
                    ),
                };
            }
            Err(err) => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-probe-failed",
                    format!("Could not create {}: {err}", path.display()),
                )
                .with_context("path", path.display().to_string());
            }
        };

        if let Err(err) = file.write_all(CHIO_YAML_SCAFFOLD.as_bytes()) {
            return ProbeReport::fail(
                self.name(),
                ProbeSeverity::Error,
                "urn:chio:error:cli:doctor-probe-failed",
                format!("Could not write {}: {err}", path.display()),
            )
            .with_context("path", path.display().to_string());
        }

        ProbeReport::ok(
            self.name(),
            format!("Created minimal chio.yaml at {}.", path.display()),
        )
        .with_context("path", path.display().to_string())
        .with_context("created", "true")
        .with_help("Review the scaffolded policy path before running production workloads.")
        .mark_repaired()
    }

    fn validate_body(&self, path: &Path, body: &str) -> ProbeReport {
        let doc: Value = match serde_yml::from_str(body) {
            Ok(v) => v,
            Err(err) => {
                let (line, column) = err
                    .location()
                    .map(|loc| (loc.line(), loc.column()))
                    .unwrap_or((0, 0));
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-chio-yaml-invalid",
                    format!(
                        "{} parse error at line {} column {}: {err}",
                        path.display(),
                        line,
                        column
                    ),
                )
                .with_context("path", path.display().to_string())
                .with_context("line", line.to_string())
                .with_context("column", column.to_string())
                .with_help("Repair the YAML at the reported anchor and rerun chio doctor.");
            }
        };

        let mapping = match doc.as_mapping() {
            Some(m) => m,
            None => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-chio-yaml-invalid",
                    format!("{} top-level value must be a mapping.", path.display()),
                )
                .with_context("path", path.display().to_string());
            }
        };

        let missing: Vec<&'static str> = REQUIRED_KEYS
            .iter()
            .filter(|key| {
                !mapping
                    .iter()
                    .any(|(k, _)| k.as_str().is_some_and(|s| s == **key))
            })
            .copied()
            .collect();

        if !missing.is_empty() {
            return ProbeReport::fail(
                self.name(),
                ProbeSeverity::Error,
                "urn:chio:error:cli:doctor-chio-yaml-invalid",
                format!(
                    "{} is missing required keys: {}",
                    path.display(),
                    missing.join(", ")
                ),
            )
            .with_context("path", path.display().to_string())
            .with_context("missing", missing.join(","))
            .with_context("line", "1")
            .with_context("column", "1")
            .with_help(
                "Add the missing top-level keys to chio.yaml; see `docs/README.md` for the schema.",
            );
        }

        ProbeReport::ok(
            self.name(),
            format!(
                "{} parses cleanly and carries all {} required key(s).",
                path.display(),
                REQUIRED_KEYS.len()
            ),
        )
        .with_context("path", path.display().to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_returns_info() {
        let dir = tempfile::tempdir().unwrap();
        let probe = ChioYamlProbe::default();
        let config = ProbeConfig {
            workdir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Info);
    }

    #[test]
    fn missing_keys_fail() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("chio.yaml");
        let mut f = std::fs::File::create(&yaml).unwrap();
        writeln!(f, "name: demo").unwrap();
        let probe = ChioYamlProbe::default().with_path(yaml);
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-chio-yaml-invalid");
    }

    #[test]
    fn complete_doc_passes() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("chio.yaml");
        let mut f = std::fs::File::create(&yaml).unwrap();
        writeln!(f, "version: 1\npolicy: ./policy.yaml").unwrap();
        let probe = ChioYamlProbe::default().with_path(yaml);
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Ok);
    }

    #[test]
    fn yaml_parse_error_carries_location() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("chio.yaml");
        let mut f = std::fs::File::create(&yaml).unwrap();
        writeln!(f, "version: 1\n  bad: indent").unwrap();
        let probe = ChioYamlProbe::default().with_path(yaml);
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-chio-yaml-invalid");
    }
}
