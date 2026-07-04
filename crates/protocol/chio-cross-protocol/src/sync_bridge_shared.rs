//! Compatibility-only synchronous bridge shim, shared by the outward protocol
//! edges (chio-a2a-edge, chio-acp-edge). The edges gate their use of it on
//! their own `compatibility-surface` feature; the helper itself is always
//! compiled here so both edges can depend on a single definition instead of
//! textually including this file.
//!
//! Mirrors the kernel's sync-bridge gate so the explicit passthrough surface
//! fails closed under a current-thread runtime instead of deadlocking.

/// Sentinel error returned by [`block_on_tool_server_invoke`] when the
/// passthrough is invoked from inside a current-thread Tokio runtime.
/// Mirrors `chio_kernel::KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime`:
/// polling an async tool-server future with `futures::executor::block_on`
/// on the only worker thread can deadlock indefinitely if the future
/// awaits Tokio I/O. The kernel bridge refuses this case fail-closed,
/// and the edge shims must match instead of reintroducing the
/// deadlock through the `compatibility-surface` feature.
#[derive(Debug, thiserror::Error)]
#[error(
    "sync bridge incompatible with current-thread Tokio runtime: \
     block_on under a current-thread reactor would deadlock the only worker thread; \
     move the host to a multi-thread runtime or call the async surface directly"
)]
pub struct SyncBridgeIncompatibleWithCurrentThreadRuntime;

/// Mirrors `chio_kernel::kernel::block_on_async_tool_dispatch`: on a
/// multi-thread runtime use `block_in_place` so we yield the runtime;
/// on a current-thread runtime fail-closed with
/// [`SyncBridgeIncompatibleWithCurrentThreadRuntime`] instead of
/// silently parking the only worker thread; with no runtime active,
/// drive the future with the non-tokio `futures::executor::block_on`.
pub fn block_on_tool_server_invoke<F, T>(
    future: F,
) -> Result<T, SyncBridgeIncompatibleWithCurrentThreadRuntime>
where
    F: std::future::Future<Output = T>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            Ok(tokio::task::block_in_place(|| handle.block_on(future)))
        }
        Ok(_handle) => {
            // Current-thread runtime active. Bridging here would deadlock
            // any tool-server future that awaits Tokio I/O. Surface a
            // typed error so callers see the architectural
            // incompatibility instead of a silent hang. The passthrough
            // call site converts this into a Failed passthrough response.
            Err(SyncBridgeIncompatibleWithCurrentThreadRuntime)
        }
        Err(_) => {
            // No Tokio runtime active. The future cannot collide with a
            // surrounding reactor; the non-tokio executor is the safe
            // bridge. This is the path the in-process, compute-only
            // tool servers used in unit tests rely on.
            Ok(futures::executor::block_on(future))
        }
    }
}
