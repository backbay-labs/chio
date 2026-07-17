use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::Router;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::load_shed::LoadShedLayer;
use tower::{BoxError, ServiceBuilder};
use tower_http::timeout::TimeoutLayer;

/// Wall-clock ceiling on the drain: how long to wait for in-flight requests to
/// finish after the listener stops accepting. Operators must size the unit
/// `TimeoutStopSec` at least this high plus a flush margin.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(25);
/// Per-request processing ceiling before the request is denied with 408.
///
/// This stays strictly below [`DEFAULT_DRAIN_TIMEOUT`] so a request admitted just
/// before a stop signal reaches its own 408 and completes cleanly within the
/// drain window, rather than being severed mid-flight when the forced-drain timer
/// force-closes the connection. A serve site that lengthens the request timeout
/// must lengthen the drain to match.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum concurrent in-flight requests before surplus load sheds with 503.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1024;
/// Maximum simultaneously accepted TCP connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 2048;

/// Bounds and hygiene knobs for one serve site. The [`Default`] is a
/// conservative, fail-closed posture: a request that exceeds a bound is denied,
/// never queued.
#[derive(Debug, Clone)]
pub struct ServeHygieneConfig {
    /// How long the drain waits for in-flight requests after the listener stops
    /// accepting. See [`DEFAULT_DRAIN_TIMEOUT`].
    pub drain_timeout: Duration,
    /// Per-request processing timeout. `None` disables it.
    pub request_timeout: Option<Duration>,
    /// Maximum concurrent in-flight requests. Surplus load sheds with 503
    /// instead of queuing. `None` disables the limit.
    pub max_concurrent_requests: Option<usize>,
    /// Maximum simultaneously accepted TCP connections, enforced by
    /// [`MaxConnListener`](crate::MaxConnListener). `None` disables the cap.
    pub max_connections: Option<usize>,
    /// Global request body-size cap. `None` preserves each route's own limit,
    /// which matters for sites that set a large upload limit on one route that a
    /// global cap would clobber. A site with no route-local limit sets this
    /// explicitly.
    pub max_body_bytes: Option<usize>,
}

impl Default for ServeHygieneConfig {
    fn default() -> Self {
        Self {
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            max_concurrent_requests: Some(DEFAULT_MAX_CONCURRENT_REQUESTS),
            max_connections: Some(DEFAULT_MAX_CONNECTIONS),
            max_body_bytes: None,
        }
    }
}

/// Map the error surfaced by the load-shed / concurrency-limit stack to a
/// status. A shed request is a deliberate overload denial (503); anything else
/// reaching this handler is an internal fault (500).
async fn shed_to_status(error: BoxError) -> StatusCode {
    if error.is::<tower::load_shed::error::Overloaded>() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Wrap `router` with the configured request timeout, concurrency limit fronted
/// by load shedding, and optional body-size cap.
///
/// The stack returns a plain [`Router`], so a call site never touches tower
/// types beyond this call. Load shedding sits outside the concurrency limit so a
/// request over the limit fails fast with 503 rather than parking: in a
/// [`ServiceBuilder`] the first layer listed is outermost, giving
/// `HandleError(LoadShed(ConcurrencyLimit(router)))`. Both `LoadShed` and
/// `GlobalConcurrencyLimit` are fallible services, so the pair is wrapped in a
/// [`HandleErrorLayer`] that turns the shed error into a response, which is what
/// lets the result stay an infallible `Router` layer.
pub fn apply_server_hygiene(mut router: Router, config: &ServeHygieneConfig) -> Router {
    if let Some(limit) = config.max_body_bytes {
        router = router.layer(DefaultBodyLimit::max(limit));
    }
    if let Some(timeout) = config.request_timeout {
        router = router.layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ));
    }
    if let Some(max) = config.max_concurrent_requests {
        router = router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(shed_to_status))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(max)),
        );
    }
    router
}
