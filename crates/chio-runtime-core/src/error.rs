#[derive(Debug, thiserror::Error)]
pub enum ChioRuntimeError {
    #[error("runtime admission rejected: {code}: {detail}")]
    Rejected { code: &'static str, detail: String },
    #[error("duplicate runtime admission bundle")]
    DuplicateAdmissionBundle,
    #[error("runtime admission store failed: {0}")]
    Store(String),
    #[error("runtime admission IO failed: {0}")]
    Io(String),
    #[error("runtime admission JSON failed: {0}")]
    Json(String),
    #[error("runtime admission canonical JSON failed: {0}")]
    Canonical(String),
}

impl ChioRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ChioRuntimeError::Rejected { code, .. } => code,
            ChioRuntimeError::DuplicateAdmissionBundle => "duplicate_admission_bundle",
            ChioRuntimeError::Store(_) => "runtime_admission_store",
            ChioRuntimeError::Io(_) => "runtime_admission_io",
            ChioRuntimeError::Json(_) => "runtime_admission_json",
            ChioRuntimeError::Canonical(_) => "runtime_admission_canonical",
        }
    }
}
