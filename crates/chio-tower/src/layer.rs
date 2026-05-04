//! Chio tower Layer implementation.

use chio_core_types::crypto::Keypair;
use tower_layer::Layer;

use crate::evaluator::ChioEvaluator;
use crate::service::{ChioService, DEFAULT_MAX_BODY_BYTES};

/// Tower `Layer` that wraps inner services with Chio evaluation.
///
/// # Example
///
/// ```rust,no_run
/// use chio_tower::ChioLayer;
/// use chio_core_types::crypto::Keypair;
///
/// let keypair = Keypair::generate();
/// let layer = ChioLayer::new(keypair, "policy-hash".to_string());
/// ```
#[derive(Clone)]
pub struct ChioLayer {
    evaluator: ChioEvaluator,
    max_body_bytes: usize,
}

impl ChioLayer {
    /// Create a new Chio layer with the given kernel keypair and policy hash.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ChioEvaluator::new(keypair, policy_hash),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Create a layer from an existing evaluator.
    pub fn from_evaluator(evaluator: ChioEvaluator) -> Self {
        Self {
            evaluator,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Override the maximum body size buffered for hashing in each request.
    ///
    /// See [`ChioService::with_max_body_bytes`] for details.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

impl<S> Layer<S> for ChioLayer {
    type Service = ChioService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ChioService::new(inner, self.evaluator.clone()).with_max_body_bytes(self.max_body_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;

    #[test]
    fn layer_creates_service() {
        let keypair = Keypair::generate();
        let layer = ChioLayer::new(keypair, "test-policy".to_string());

        // Verify that layer can wrap a simple closure.
        let _service = layer.layer(tower::service_fn(
            |_req: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
            },
        ));
    }
}
