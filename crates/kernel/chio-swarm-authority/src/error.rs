#[derive(Debug, thiserror::Error)]
pub enum SwarmAuthorityError {
    #[error("{0}")]
    Rejected(String),
    #[error("swarm authority canonical JSON failed: {0}")]
    Canonical(String),
}

impl SwarmAuthorityError {
    #[must_use]
    pub fn runtime_detail(&self) -> String {
        match self {
            SwarmAuthorityError::Rejected(detail) => detail.clone(),
            SwarmAuthorityError::Canonical(detail) => {
                format!("swarm authority canonical JSON failed: {detail}")
            }
        }
    }
}
