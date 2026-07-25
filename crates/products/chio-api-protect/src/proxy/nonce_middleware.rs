use super::*;

use axum::http::HeaderMap;
use chio_kernel::execution_nonce::{
    verify_execution_nonce, ExecutionNonceStore, NonceBinding, SignedExecutionNonce,
};

/// Execution-nonce middleware for out-of-process tool-server implementations.
/// Tool servers reject executions that do not carry a valid
/// `X-Chio-Execution-Nonce`. In permissive (development) mode a missing nonce
/// logs and proceeds; in strict (production) mode it is rejected.
#[derive(Debug)]
// Kept for out-of-process tool-server implementations; exercised by unit tests.
#[allow(dead_code)]
pub(crate) enum ToolServerNonceError {
    MissingNonce,
    DecodeFailed(String),
    Rejected(String),
}

impl std::fmt::Display for ToolServerNonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNonce => write!(f, "missing X-Chio-Execution-Nonce header"),
            Self::DecodeFailed(msg) => write!(f, "execution nonce decode failed: {msg}"),
            Self::Rejected(msg) => write!(f, "execution nonce rejected: {msg}"),
        }
    }
}

impl std::error::Error for ToolServerNonceError {}

// Kept for out-of-process tool-server implementations; exercised by unit tests.
#[allow(dead_code)]
pub(crate) fn require_tool_server_execution_nonce(
    headers: &HeaderMap,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    store: &dyn ExecutionNonceStore,
    permissive: bool,
) -> Result<(), ToolServerNonceError> {
    let Some(raw) = headers.get("x-chio-execution-nonce") else {
        if permissive {
            warn!("missing execution nonce; permissive mode, allowing");
            return Ok(());
        }
        return Err(ToolServerNonceError::MissingNonce);
    };
    let raw = raw
        .to_str()
        .map_err(|error| ToolServerNonceError::DecodeFailed(error.to_string()))?;
    let signed: SignedExecutionNonce = serde_json::from_str(raw)
        .map_err(|error| ToolServerNonceError::DecodeFailed(error.to_string()))?;
    verify_execution_nonce(&signed, kernel_pubkey, expected, now, store)
        .map_err(|error| ToolServerNonceError::Rejected(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use chio_kernel::execution_nonce::{
        mint_execution_nonce, ExecutionNonceConfig, InMemoryExecutionNonceStore, NonceBinding,
    };

    fn binding() -> NonceBinding {
        NonceBinding {
            subject_id: "subject".to_string(),
            request_id: "req-1".to_string(),
            capability_id: "cap-1".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            parameter_hash: "0".repeat(64),
        }
    }

    #[test]
    fn strict_mode_rejects_missing_nonce() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let headers = HeaderMap::new();
        let result = require_tool_server_execution_nonce(
            &headers,
            &kp.public_key(),
            &binding(),
            1_000_000,
            &store,
            false,
        );
        assert!(matches!(result, Err(ToolServerNonceError::MissingNonce)));
    }

    #[test]
    fn valid_nonce_passes_then_replay_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let signed =
            mint_execution_nonce(&kp, binding(), &ExecutionNonceConfig::default(), 1_000_000)
                .unwrap();
        let encoded = serde_json::to_string(&signed).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-chio-execution-nonce", encoded.parse().unwrap());
        assert!(require_tool_server_execution_nonce(
            &headers,
            &kp.public_key(),
            &binding(),
            1_000_001,
            &store,
            false,
        )
        .is_ok());
        // single-use: a second presentation is rejected.
        assert!(matches!(
            require_tool_server_execution_nonce(
                &headers,
                &kp.public_key(),
                &binding(),
                1_000_002,
                &store,
                false
            ),
            Err(ToolServerNonceError::Rejected(_))
        ));
    }
}
