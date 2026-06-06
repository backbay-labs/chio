use crate::discovery::DiscoveryProtocol;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("capability reference mismatch: expected {expected}, got {actual}")]
    CapabilityRefMismatch { expected: String, actual: String },

    #[error("invalid attenuation: {0}")]
    InvalidAttenuation(String),

    #[error("invalid request envelope: {0}")]
    InvalidRequest(String),

    #[error("canonical serialization failed: {0}")]
    Canonical(String),

    #[error("unsupported target protocol: {0}")]
    UnsupportedTargetProtocol(DiscoveryProtocol),

    #[error("kernel error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
}
