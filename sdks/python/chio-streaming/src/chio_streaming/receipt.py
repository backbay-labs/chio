"""Kafka receipt envelope serialization for Chio streaming.

This module converts an :class:`chio_sdk.models.ChioReceipt` (or the
HTTP-flavoured :class:`chio_sdk.models.HttpReceipt`) into the Kafka
wire representation the Chio receipt topic expects:

* ``key`` -- UTF-8 encoded ``request_id`` so Kafka's log compaction
  and partition assignment can key receipts to the originating
  event.
* ``value`` -- canonical JSON bytes (sorted keys, no whitespace,
  ensure_ascii) so Merkle chain hashing stays deterministic across
  producers.
* ``headers`` -- a small set of string headers so downstream
  consumers can filter / route without parsing the value.

The envelope schema version is ``chio-streaming/v1``. It is additive;
bumps only happen on breaking wire changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from chio_sdk.models import ChioReceipt

# Re-exported at module level; defined in core.py so every broker
# middleware can call it without importing through receipt.py.
from chio_streaming.core import new_request_id
from chio_streaming.errors import ChioStreamingConfigError

#: Envelope schema version. Bump on any breaking change to the wire
#: layout so receipt consumers can route old payloads.
ENVELOPE_VERSION = "chio-streaming/v1"

#: Kafka header carrying the receipt id on produced events. Downstream
#: consumers use this to correlate produced events with their Chio
#: authorization receipt.
RECEIPT_HEADER = "X-Chio-Receipt"

#: Kafka header carrying the Chio verdict ("allow" / "deny") so simple
#: routers can decide without deserialising the value.
VERDICT_HEADER = "X-Chio-Verdict"


def canonical_json(obj: Any) -> bytes:
    """Produce canonical JSON bytes (sorted keys, no whitespace).

    Matches the canonicalisation used by :mod:`chio_sdk.client` and the
    Rust kernel so content hashes remain byte-compatible across
    languages.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True)
class ReceiptEnvelope:
    """Kafka-friendly envelope around a Chio receipt.

    Attributes
    ----------
    key:
        Bytes for the Kafka record key (``request_id``).
    value:
        Canonical JSON bytes of the envelope payload.
    headers:
        Sequence of ``(name, bytes)`` tuples ready to pass to the
        confluent-kafka ``Producer.produce(headers=...)`` kwarg.
    request_id:
        Convenience accessor for tests / logging.
    receipt_id:
        Convenience accessor for tests / logging.
    """

    key: bytes
    value: bytes
    headers: list[tuple[str, bytes]]
    request_id: str
    receipt_id: str


def build_envelope(
    *,
    request_id: str,
    receipt: ChioReceipt,
    source_topic: str | None = None,
    source_partition: int | None = None,
    source_offset: int | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> ReceiptEnvelope:
    """Serialise ``receipt`` into a Kafka-friendly envelope.

    Parameters
    ----------
    request_id:
        The Chio ``request_id`` the receipt is associated with. Becomes
        the Kafka record key (bytes-encoded). Must be non-empty.
    receipt:
        The :class:`ChioReceipt` to envelope.
    source_topic:
        Optional originating topic. Included in the envelope for audit
        queries.
    source_partition:
        Optional originating partition.
    source_offset:
        Optional originating offset.
    extra_metadata:
        Optional caller-supplied metadata merged into the envelope's
        ``metadata`` field. Values must be JSON-serialisable.

    Raises
    ------
    ChioStreamingConfigError:
        If ``request_id`` is empty.
    """
    if not request_id:
        raise ChioStreamingConfigError("build_envelope requires a non-empty request_id")

    verdict = "allow" if receipt.is_allowed else ("deny" if receipt.is_denied else "none")
    metadata = dict(extra_metadata or {})

    payload: dict[str, Any] = {
        "version": ENVELOPE_VERSION,
        "request_id": request_id,
        "verdict": verdict,
        "receipt": receipt.model_dump(mode="json", exclude_none=True),
    }
    if source_topic is not None:
        payload["source_topic"] = source_topic
    if source_partition is not None:
        payload["source_partition"] = int(source_partition)
    if source_offset is not None:
        payload["source_offset"] = int(source_offset)
    if metadata:
        payload["metadata"] = metadata

    value = canonical_json(payload)
    headers: list[tuple[str, bytes]] = [
        (RECEIPT_HEADER, receipt.id.encode("utf-8")),
        (VERDICT_HEADER, verdict.encode("utf-8")),
    ]
    return ReceiptEnvelope(
        key=request_id.encode("utf-8"),
        value=value,
        headers=headers,
        request_id=request_id,
        receipt_id=receipt.id,
    )


__all__ = [
    "ENVELOPE_VERSION",
    "RECEIPT_HEADER",
    "VERDICT_HEADER",
    "ReceiptEnvelope",
    "build_envelope",
    "canonical_json",
    "new_request_id",
]
