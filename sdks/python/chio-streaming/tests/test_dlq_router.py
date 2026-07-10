"""Unit tests for :class:`chio_streaming.DLQRouter`."""

from __future__ import annotations

import hashlib
import json
import time
import uuid

import pytest
from chio_sdk._generated.receipt.record_schema import (
    BoundaryClass,
    ReceiptKind,
    RedactionMode,
    ToolOrigin,
    TrustLevel,
)
from chio_sdk.models import ChioReceipt, Decision, ToolCallAction

from chio_streaming import (
    RECEIPT_HEADER,
    VERDICT_HEADER,
    DLQRouter,
)
from chio_streaming.errors import ChioStreamingConfigError


def _deny_receipt(
    *,
    reason: str = "policy denied",
    guard: str = "test-guard",
    tool_name: str = "events:consume:orders",
) -> ChioReceipt:
    params = {"topic": "orders", "offset": 17}
    canonical = json.dumps(params, sort_keys=True).encode("utf-8")
    param_hash = hashlib.sha256(canonical).hexdigest()
    return ChioReceipt(
        id=hashlib.sha256(f"rec:{uuid.uuid4().hex}".encode()).hexdigest(),
        timestamp=int(time.time()),
        capability_id="cap-1",
        tool_server="kafka://local",
        tool_name=tool_name,
        action=ToolCallAction(
            parameters=params,
            parameter_hash=param_hash,
        ),
        decision=Decision.deny(reason=reason, guard=guard),
        receipt_kind=ReceiptKind.mediated_decision,
        boundary_class=BoundaryClass.prevent,
        tool_origin=ToolOrigin.caller_executed,
        redaction_mode=RedactionMode.none,
        content_hash=param_hash,
        policy_hash="a" * 64,
        evidence=[],
        trust_level=TrustLevel.mediated,
        kernel_key="b" * 64,
        signature="c" * 128,
    )


def _allow_receipt() -> ChioReceipt:
    params = {"topic": "orders"}
    canonical = json.dumps(params, sort_keys=True).encode("utf-8")
    param_hash = hashlib.sha256(canonical).hexdigest()
    return ChioReceipt(
        id=hashlib.sha256(b"rec:allow").hexdigest(),
        timestamp=int(time.time()),
        capability_id="cap-1",
        tool_server="kafka://local",
        tool_name="events:consume:orders",
        action=ToolCallAction(
            parameters=params,
            parameter_hash=param_hash,
        ),
        decision=Decision.allow(),
        receipt_kind=ReceiptKind.mediated_decision,
        boundary_class=BoundaryClass.prevent,
        tool_origin=ToolOrigin.caller_executed,
        redaction_mode=RedactionMode.none,
        content_hash=param_hash,
        policy_hash="a" * 64,
        evidence=[],
        trust_level=TrustLevel.mediated,
        kernel_key="b" * 64,
        signature="c" * 128,
    )


# ---------------------------------------------------------------------------
# route()
# ---------------------------------------------------------------------------


def test_route_uses_topic_map_first() -> None:
    router = DLQRouter(
        default_topic="dlq-catchall",
        topic_map={"orders": "dlq-orders", "payments": "dlq-payments"},
    )
    assert router.route("orders") == "dlq-orders"
    assert router.route("payments") == "dlq-payments"


def test_route_falls_back_to_default() -> None:
    router = DLQRouter(default_topic="dlq-catchall")
    assert router.route("unknown-topic") == "dlq-catchall"


def test_route_raises_without_mapping_or_default() -> None:
    router = DLQRouter()
    with pytest.raises(ChioStreamingConfigError):
        router.route("unknown")


def test_route_rejects_empty_topic() -> None:
    router = DLQRouter(default_topic="dlq")
    with pytest.raises(ChioStreamingConfigError):
        router.route("")


def test_router_rejects_empty_default_topic() -> None:
    with pytest.raises(ChioStreamingConfigError):
        DLQRouter(default_topic="")


# ---------------------------------------------------------------------------
# build_record()
# ---------------------------------------------------------------------------


def test_build_record_envelope_contains_denial_metadata() -> None:
    router = DLQRouter(default_topic="dlq-denied")
    receipt = _deny_receipt(reason="missing scope", guard="scope-guard")

    record = router.build_record(
        source_topic="orders",
        source_partition=3,
        source_offset=42,
        original_key=b"order-key",
        original_value=b'{"ok":true}',
        request_id="chio-evt-abc",
        receipt=receipt,
    )

    assert record.topic == "dlq-denied"
    assert record.key == b"order-key"
    payload = json.loads(record.value.decode("utf-8"))
    assert payload["version"] == "chio-streaming/dlq/v1"
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["guard"] == "scope-guard"
    assert payload["request_id"] == "chio-evt-abc"
    assert payload["receipt_id"] == receipt.id
    assert payload["source"] == {"topic": "orders", "partition": 3, "offset": 42}
    assert payload["original_value"] == {"utf8": '{"ok":true}'}


def test_build_record_headers_have_expected_pairs() -> None:
    router = DLQRouter(default_topic="dlq")
    receipt = _deny_receipt(reason="nope", guard="g")

    record = router.build_record(
        source_topic="orders",
        source_partition=0,
        source_offset=0,
        original_key=None,
        original_value=None,
        request_id="chio-evt-1",
        receipt=receipt,
    )
    header_dict = {name: value for name, value in record.headers}
    assert header_dict[RECEIPT_HEADER] == receipt.id.encode("utf-8")
    assert header_dict[VERDICT_HEADER] == b"deny"
    assert header_dict["X-Chio-Deny-Guard"] == b"g"
    assert header_dict["X-Chio-Deny-Reason"] == b"nope"


def test_build_record_falls_back_to_request_id_key() -> None:
    router = DLQRouter(default_topic="dlq")
    receipt = _deny_receipt()
    record = router.build_record(
        source_topic="orders",
        source_partition=None,
        source_offset=None,
        original_key=None,
        original_value=None,
        request_id="chio-evt-xyz",
        receipt=receipt,
    )
    assert record.key == b"chio-evt-xyz"


def test_build_record_hex_encodes_non_utf8_bytes() -> None:
    router = DLQRouter(default_topic="dlq")
    receipt = _deny_receipt()
    record = router.build_record(
        source_topic="orders",
        source_partition=1,
        source_offset=1,
        original_key=None,
        original_value=b"\xff\xfe\xfd",
        request_id="req-1",
        receipt=receipt,
    )
    payload = json.loads(record.value.decode("utf-8"))
    assert payload["original_value"] == {"hex": "fffefd"}


def test_build_record_rejects_allow_receipt() -> None:
    router = DLQRouter(default_topic="dlq")
    with pytest.raises(ChioStreamingConfigError):
        router.build_record(
            source_topic="orders",
            source_partition=0,
            source_offset=0,
            original_key=None,
            original_value=None,
            request_id="rid",
            receipt=_allow_receipt(),
        )


def test_build_record_omits_original_value_when_disabled() -> None:
    router = DLQRouter(default_topic="dlq", include_original_value=False)
    record = router.build_record(
        source_topic="orders",
        source_partition=1,
        source_offset=1,
        original_key=None,
        original_value=b"hello",
        request_id="rid",
        receipt=_deny_receipt(),
    )
    payload = json.loads(record.value.decode("utf-8"))
    assert "original_value" not in payload


def test_topic_for_returns_explicit_mapping() -> None:
    router = DLQRouter(
        default_topic="dlq-default",
        topic_map={"orders": "dlq-orders"},
    )
    assert router.topic_for("orders") == "dlq-orders"
    assert router.topic_for("unmapped") is None
    assert router.default_topic == "dlq-default"
