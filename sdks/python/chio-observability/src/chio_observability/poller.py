"""Async poll loop that tails the Chio receipt store.

:class:`ReceiptPoller` periodically calls a receipt-source callable,
deduplicates on receipt ``id``, and forwards new receipts to every
configured bridge. It is intentionally source-agnostic: most operators
will pass a closure that calls the kernel's receipt API (or reads a
local SQLite / Merkle store) and returns a list of
:class:`chio_sdk.models.ChioReceipt`.

Typical wiring::

    poller = ReceiptPoller(
        source=fetch_new_receipts,
        bridges=[langsmith_bridge, langfuse_bridge],
        interval_seconds=2.0,
    )
    await poller.start()
    ...
    await poller.stop()

The poller never raises into the event loop; bridge errors are funneled
through an optional ``on_error`` callback so operators can decide the
retry / back-off policy for their environment.
"""

from __future__ import annotations

import asyncio
import inspect
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from chio_sdk.models import ChioReceipt

from chio_observability.errors import ChioObservabilityConfigError, ChioObservabilityError

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class _BridgeLike(Protocol):
    """Minimal publisher interface the poller calls into.

    Both :class:`LangSmithBridge` and :class:`LangFuseBridge` satisfy
    this; user code may pass any object exposing ``publish``.
    """

    BACKEND_NAME: str

    def publish(
        self,
        receipt: ChioReceipt,
        *,
        tool_result: Any | None = ...,
        error: str | None = ...,
    ) -> Any:
        ...


ReceiptSource = Callable[[], Awaitable[list[ChioReceipt]] | list[ChioReceipt]]
ErrorHandler = Callable[[BaseException, ChioReceipt | None, str | None], None]


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------


class ReceiptPoller:
    """Tail a Chio receipt source and forward new receipts to bridges.

    Parameters
    ----------
    source:
        Callable that returns the next batch of receipts. May be sync
        or async. The poller calls it each tick and diffs by receipt
        ``id`` against an internal LRU cache so already-published
        receipts are skipped.
    bridges:
        Iterable of bridge objects exposing ``publish``.
    interval_seconds:
        Seconds between polls. Must be positive.
    dedupe_cache_size:
        Number of receipt ids to retain for dedup. Defaults to 10k,
        which is more than enough for any single polling window.
    on_error:
        Optional callback invoked with ``(exc, receipt, backend)``
        whenever a bridge publish raises. Defaults to swallow so
        transient bridge outages do not stop the poll loop.
    max_backoff_seconds:
        Maximum backoff after an entire source fetch fails. The
        poller doubles the backoff on each consecutive failure and
        resets on the next success.
    """

    def __init__(
        self,
        *,
        source: ReceiptSource,
        bridges: list[_BridgeLike],
        interval_seconds: float = 2.0,
        dedupe_cache_size: int = 10_000,
        on_error: ErrorHandler | None = None,
        max_backoff_seconds: float = 60.0,
    ) -> None:
        if interval_seconds <= 0:
            raise ChioObservabilityConfigError(
                "ReceiptPoller.interval_seconds must be positive"
            )
        if dedupe_cache_size <= 0:
            raise ChioObservabilityConfigError(
                "ReceiptPoller.dedupe_cache_size must be positive"
            )
        if max_backoff_seconds < interval_seconds:
            raise ChioObservabilityConfigError(
                "ReceiptPoller.max_backoff_seconds must be >= interval_seconds"
            )

        self._source = source
        self._bridges: list[_BridgeLike] = list(bridges)
        self._interval = float(interval_seconds)
        self._on_error = on_error
        self._max_backoff = float(max_backoff_seconds)
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._cache_cap = dedupe_cache_size
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._running = False
        self._last_poll_at: float | None = None
        self._consecutive_failures = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background poll task.

        Idempotent: calling :meth:`start` while already running is a
        no-op. The coroutine returns as soon as the task is scheduled;
        use :meth:`stop` to join it.
        """
        if self._running:
            return
        self._stop_event = asyncio.Event()
        self._running = True
        self._task = asyncio.create_task(self._run(), name="chio-observability-poller")

    async def stop(self) -> None:
        """Signal the poll task to exit and await it.

        Idempotent.
        """
        if not self._running:
            return
        self._stop_event.set()
        task = self._task
        self._task = None
        self._running = False
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass

    @property
    def is_running(self) -> bool:
        """Return ``True`` while the poll task is active."""
        return self._running

    @property
    def last_poll_at(self) -> float | None:
        """Event-loop monotonic timestamp of the last completed poll."""
        return self._last_poll_at

    # ------------------------------------------------------------------
    # Single-shot poll (exposed for tests and manual operation)
    # ------------------------------------------------------------------

    async def poll_once(self) -> list[ChioReceipt]:
        """Fetch one batch, publish new receipts, and return what was new.

        Raises :class:`ChioObservabilityError` if the source itself
        raises; bridge errors are routed through ``on_error`` so a
        single failing backend never stops the remaining bridges.
        """
        receipts = await self._fetch_receipts()
        new_receipts: list[ChioReceipt] = []
        for receipt in receipts:
            if receipt.id in self._seen:
                continue
            self._remember(receipt.id)
            new_receipts.append(receipt)
            self._dispatch(receipt)
        self._last_poll_at = asyncio.get_event_loop().time()
        return new_receipts

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        backoff = self._interval
        while not self._stop_event.is_set():
            try:
                await self.poll_once()
                self._consecutive_failures = 0
                backoff = self._interval
            except ChioObservabilityError as exc:
                self._consecutive_failures += 1
                self._handle_error(exc, receipt=None, backend=None)
                backoff = min(self._max_backoff, backoff * 2)
            except Exception as exc:  # noqa: BLE001 -- poll loop resilience
                self._consecutive_failures += 1
                self._handle_error(exc, receipt=None, backend=None)
                backoff = min(self._max_backoff, backoff * 2)

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=backoff,
                )
            except TimeoutError:
                # Interval elapsed -- fall through to the next iteration.
                continue
            # Stop event fired: exit loop.
            break

    async def _fetch_receipts(self) -> list[ChioReceipt]:
        try:
            result = self._source()
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 -- wrap source failures
            raise ChioObservabilityError(
                "Chio receipt source raised during poll",
                cause=exc,
            ) from exc
        if not isinstance(result, list):
            raise ChioObservabilityError(
                "Chio receipt source must return list[ChioReceipt]"
            )
        for item in result:
            if not isinstance(item, ChioReceipt):
                raise ChioObservabilityError(
                    "Chio receipt source returned a non-ChioReceipt entry"
                )
        return result

    def _dispatch(self, receipt: ChioReceipt) -> None:
        for bridge in self._bridges:
            try:
                bridge.publish(receipt)
            except Exception as exc:  # noqa: BLE001 -- route to on_error
                backend = getattr(bridge, "BACKEND_NAME", None)
                self._handle_error(exc, receipt=receipt, backend=backend)

    def _handle_error(
        self,
        exc: BaseException,
        *,
        receipt: ChioReceipt | None,
        backend: str | None,
    ) -> None:
        if self._on_error is None:
            return
        try:
            self._on_error(exc, receipt, backend)
        except Exception:  # noqa: BLE001 -- error handler must not kill loop
            # Intentionally silent: the error handler itself failed.
            # We cannot log here without a structured logger and we do
            # not want a misbehaving handler to crash the poll task.
            return

    def _remember(self, receipt_id: str) -> None:
        self._seen[receipt_id] = None
        while len(self._seen) > self._cache_cap:
            self._seen.popitem(last=False)


__all__ = [
    "ReceiptPoller",
    "ReceiptSource",
    "ErrorHandler",
]
