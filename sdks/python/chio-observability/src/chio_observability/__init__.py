"""Chio observability bridges.

Push Chio receipts as enriched spans into agent observability platforms
(LangSmith, LangFuse) so every tool call trace includes the kernel's
guard evaluation result.

Public surface:

* :class:`LangSmithBridge` -- consume :class:`chio_sdk.models.ChioReceipt`
  objects and POST them as LangSmith runs.
* :class:`LangFuseBridge` -- same, but pushes to LangFuse as spans.
* :class:`ReceiptEnricher` -- build backend-neutral
  :class:`SpanPayload` objects; the bridges wrap this for their
  respective SDKs.
* :class:`ReceiptPoller` -- async tail loop over a Chio receipt source
  that forwards new receipts to the configured bridges.
* :class:`ChioObservabilityError` / :class:`ChioObservabilityConfigError` --
  error types.

Both backends are importable in isolation; the ``langsmith`` and
``langfuse`` SDKs are optional extras. Importing the top-level
package never requires either backend to be installed.
"""

from chio_observability.enricher import ReceiptEnricher, SpanPayload, TraceContext
from chio_observability.errors import ChioObservabilityConfigError, ChioObservabilityError
from chio_observability.langfuse_bridge import LangFuseBridge
from chio_observability.langsmith_bridge import LangSmithBridge
from chio_observability.poller import ErrorHandler, ReceiptPoller, ReceiptSource

__all__ = [
    "ChioObservabilityConfigError",
    "ChioObservabilityError",
    "ErrorHandler",
    "LangFuseBridge",
    "LangSmithBridge",
    "ReceiptEnricher",
    "ReceiptPoller",
    "ReceiptSource",
    "SpanPayload",
    "TraceContext",
]
