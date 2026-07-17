use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Wrap any [`axum::serve::Listener`] with a hard cap on concurrent
/// connections.
///
/// `axum::serve` exposes no connection cap of its own, so the limit lives here
/// as a listener adapter. Each accepted connection holds one permit for its
/// whole lifetime; the permit releases when the connection IO is dropped. When
/// the permits are exhausted, `accept` waits before pulling the next connection
/// off the OS queue, which back-pressures the accept loop instead of
/// unbounded-buffering new sockets. The permit semaphore is never closed, so a
/// drain does not revoke the permits of connections that are still finishing.
///
/// This wrapper changes the listener's accepted IO type, which moves it out of
/// axum's built-in `Connected<_> for SocketAddr` impl (that impl is bound to the
/// concrete `TcpListener`, and coherence forbids re-adding one for the foreign
/// `SocketAddr`). A site that still needs the peer address serves
/// `into_make_service_with_connect_info::<CappedPeerAddr>()` and reads
/// `ConnectInfo<CappedPeerAddr>`, so it keeps both the accept cap and connect
/// info.
pub struct MaxConnListener<L> {
    inner: L,
    permits: Arc<Semaphore>,
}

impl<L> MaxConnListener<L> {
    /// Cap `inner` at `max_connections` simultaneously accepted connections.
    ///
    /// `usize::MAX` is a valid "effectively uncapped" sentinel: the count is
    /// clamped to [`Semaphore::MAX_PERMITS`] so a large value is a no-op cap
    /// rather than a startup panic.
    #[must_use]
    pub fn new(inner: L, max_connections: usize) -> Self {
        let permits = max_connections.min(Semaphore::MAX_PERMITS);
        Self {
            inner,
            permits: Arc::new(Semaphore::new(permits)),
        }
    }
}

impl<L> Listener for MaxConnListener<L>
where
    L: Listener,
    L::Io: Unpin,
{
    type Io = PermittedIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        // Acquire a permit BEFORE pulling the next connection off the OS queue,
        // so a saturated server stops draining the accept backlog rather than
        // accepting sockets it cannot serve. `acquire_owned` only errors when
        // the semaphore is closed, which this adapter never does; treat that
        // impossible case as "serve without a permit" so it can never wedge the
        // accept loop.
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok();
        let (io, addr) = self.inner.accept().await;
        (
            PermittedIo {
                io,
                _permit: permit,
            },
            addr,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Peer socket address for a connection accepted through a
/// [`MaxConnListener`] over a [`TcpListener`].
///
/// axum's built-in connect-info impl for [`SocketAddr`] is bound to the concrete
/// `TcpListener`, so a capped site cannot ask for `ConnectInfo<SocketAddr>`
/// directly (the cap wraps the listener). It asks for
/// `ConnectInfo<CappedPeerAddr>` instead; this type derefs and displays as the
/// wrapped `SocketAddr`, so per-IP logic reads unchanged.
#[derive(Clone, Copy, Debug)]
pub struct CappedPeerAddr(pub SocketAddr);

impl Deref for CappedPeerAddr {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for CappedPeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Connected<IncomingStream<'_, MaxConnListener<TcpListener>>> for CappedPeerAddr {
    fn connect_info(stream: IncomingStream<'_, MaxConnListener<TcpListener>>) -> Self {
        Self(*stream.remote_addr())
    }
}

/// Connection IO that carries the connection-cap permit alongside it, so the
/// permit is released exactly when the connection is dropped. The read and write
/// halves forward to the wrapped IO unchanged.
pub struct PermittedIo<Io> {
    io: Io,
    _permit: Option<OwnedSemaphorePermit>,
}

impl<Io: AsyncRead + Unpin> AsyncRead for PermittedIo<Io> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<Io: AsyncWrite + Unpin> AsyncWrite for PermittedIo<Io> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}
