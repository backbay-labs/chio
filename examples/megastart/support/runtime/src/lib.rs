//! Host-side resource ownership for the downloadable Chio examples.
//!
//! This crate supplies no authority or policy. Chio owns admission; these
//! helpers own the host's tasks, blocking work, and retained files.
#![forbid(unsafe_code)]

pub mod files;
pub mod tasks;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Compare fixed-size credential digests using Subtle's reviewed primitive.
/// HTTP parsing and credential length are not claimed to be constant time.
pub fn credential_matches(supplied: &str, expected: &str) -> bool {
    if supplied.is_empty() || expected.is_empty() {
        return false;
    }
    let supplied: [u8; 32] = Sha256::digest(supplied.as_bytes()).into();
    let expected: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
    bool::from(supplied.ct_eq(&expected))
}

/// Subscribe before serving so startup failure cannot masquerade as a signal.
#[cfg(unix)]
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = interrupt.recv() => {},
        }
    })
}

#[cfg(not(unix))]
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    Ok(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("Signal listener failed: {error}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_reject_empty_prefix_and_mismatch() {
        assert!(credential_matches(
            "a correct credential",
            "a correct credential"
        ));
        for (supplied, expected) in [
            ("", ""),
            ("", "token"),
            ("token", ""),
            ("tok", "token"),
            ("Token", "token"),
        ] {
            assert!(!credential_matches(supplied, expected));
        }
    }
}
