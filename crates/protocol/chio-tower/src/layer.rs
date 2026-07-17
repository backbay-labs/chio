//! Chio tower Layer implementation.

use chio_core_types::crypto::Keypair;
use tower_layer::Layer;

use crate::error::ChioTowerError;
use crate::evaluator::{ChioEvaluator, ChioEvaluatorBuilder};
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
    /// Create a fail-closed Chio layer with the given kernel keypair and policy
    /// hash. No durable store is attached; use [`ChioLayer::builder`] to wire
    /// one, or [`ChioLayer::new_ephemeral`] for an in-memory scaffold.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ChioEvaluator::new(keypair, policy_hash),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Create an explicitly ephemeral Chio layer for local scaffolds and tests.
    pub fn new_ephemeral(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ChioEvaluator::new_ephemeral(keypair, policy_hash),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Start building a layer backed by durable receipt and revocation stores.
    #[must_use]
    pub fn builder(keypair: Keypair, policy_hash: String) -> ChioLayerBuilder {
        ChioLayerBuilder {
            inner: ChioEvaluator::builder(keypair, policy_hash),
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

/// Builder for a [`ChioLayer`] backed by durable stores. Mirrors
/// [`ChioEvaluatorBuilder`] and adds the layer's body-size cap.
pub struct ChioLayerBuilder {
    inner: ChioEvaluatorBuilder,
    max_body_bytes: usize,
}

impl ChioLayerBuilder {
    #[must_use]
    pub fn receipt_store(mut self, store: std::sync::Arc<dyn chio_kernel::ReceiptStore>) -> Self {
        self.inner = self.inner.receipt_store(store);
        self
    }

    #[must_use]
    pub fn revocation_store(
        mut self,
        store: std::sync::Arc<dyn chio_kernel::RevocationStore>,
    ) -> Self {
        self.inner = self.inner.revocation_store(store);
        self
    }

    #[must_use]
    pub fn allow_ephemeral(mut self, allow: bool) -> Self {
        self.inner = self.inner.allow_ephemeral(allow);
        self
    }

    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn build(self) -> Result<ChioLayer, ChioTowerError> {
        Ok(ChioLayer {
            evaluator: self.inner.build()?,
            max_body_bytes: self.max_body_bytes,
        })
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
        let layer = ChioLayer::new_ephemeral(keypair, "test-policy".to_string());

        // Verify that layer can wrap a simple closure.
        let _service = layer.layer(tower::service_fn(
            |_req: http::Request<Full<Bytes>>| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
            },
        ));
    }
}
