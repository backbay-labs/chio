//! Error type shared across the xtask handlers.

use std::fmt;

#[derive(Debug)]
pub(crate) enum XtaskError {
    Usage(String),
    Io(String, std::io::Error),
    Yaml(String, serde_yml::Error),
    Json(String, serde_json::Error),
    Drift(String),
    Validation(String),
    CratePaths(String),
    FormalMirrors(String),
    AdapterNoBypass(String),
    ProofCoverage(String),
    Codegen(chio_spec_codegen::CodegenError),
    Process(String),
    ToolMissing(String),
    ToolFailed(String),
    Manifest(String),
}

impl fmt::Display for XtaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "usage: {msg}"),
            Self::Io(path, err) => write!(f, "io error on {path}: {err}"),
            Self::Yaml(path, err) => write!(f, "yaml error in {path}: {err}"),
            Self::Json(path, err) => write!(f, "json error in {path}: {err}"),
            Self::Drift(detail) => write!(f, "manifest drift: {detail}"),
            Self::Validation(detail) => write!(f, "scenario validation failed: {detail}"),
            Self::CratePaths(detail) => write!(f, "crate-path check failed: {detail}"),
            Self::FormalMirrors(detail) => write!(f, "formal-mirrors: {detail}"),
            Self::AdapterNoBypass(detail) => write!(f, "adapter-no-bypass: {detail}"),
            Self::ProofCoverage(detail) => write!(f, "proof-coverage: {detail}"),
            Self::Codegen(err) => write!(f, "codegen failed: {err}"),
            Self::Process(msg) => write!(f, "subprocess error: {msg}"),
            Self::ToolMissing(detail) => write!(f, "codegen tool missing: {detail}"),
            Self::ToolFailed(detail) => write!(f, "codegen tool failed: {detail}"),
            Self::Manifest(detail) => write!(f, "pheromone manifest error: {detail}"),
        }
    }
}
