#[derive(Debug, thiserror::Error)]
pub enum ChiodosRuntimeError {
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

impl ChiodosRuntimeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ChiodosRuntimeError::Rejected { code, .. } => code,
            ChiodosRuntimeError::DuplicateAdmissionBundle => "duplicate_admission_bundle",
            ChiodosRuntimeError::Store(_) => "runtime_admission_store",
            ChiodosRuntimeError::Io(_) => "runtime_admission_io",
            ChiodosRuntimeError::Json(_) => "runtime_admission_json",
            ChiodosRuntimeError::Canonical(_) => "runtime_admission_canonical",
        }
    }
}
