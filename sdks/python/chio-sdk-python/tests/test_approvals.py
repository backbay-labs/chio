"""Tests for HITL approval methods on ChioClient."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from chio_sdk.client import ChioClient, _canonical_json, _sha256_hex
from chio_sdk.errors import ChioValidationError
from chio_sdk.models_approvals import (
    ApprovalVerdict,
    PendingApproval,
)

BASE = "http://127.0.0.1:9090"


def _pending_dict(approval_id: str = "ap-1") -> dict:
    return {
        "approval_id": approval_id,
        "policy_id": "policy-hermes-hitl",
        "subject_id": "00" * 32,
        "capability_id": "cap-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "action": "invoke",
        "parameter_hash": "a" * 64,
        "expires_at": 4_000_000_000,
        "created_at": 100,
        "summary": "rm -rf old_build",
        "triggered_by": ["shell.requires_approval"],
    }


@pytest.mark.asyncio
@respx.mock
async def test_list_pending_approvals_parses_array_payload():
    respx.get(f"{BASE}/approvals/pending").mock(
        return_value=httpx.Response(
            200,
            json={"approvals": [_pending_dict("ap-1"), _pending_dict("ap-2")], "count": 2},
        )
    )
    client = ChioClient(BASE)
    rows = await client.list_pending_approvals()
    await client.close()
    assert len(rows) == 2
    assert all(isinstance(row, PendingApproval) for row in rows)
    assert rows[0].approval_id == "ap-1"
    assert rows[1].tool_server == "shell"


@pytest.mark.asyncio
@respx.mock
async def test_list_pending_approvals_tolerates_bare_list():
    respx.get(f"{BASE}/approvals/pending").mock(
        return_value=httpx.Response(200, json=[_pending_dict("ap-9")])
    )
    client = ChioClient(BASE)
    rows = await client.list_pending_approvals()
    await client.close()
    assert len(rows) == 1
    assert rows[0].approval_id == "ap-9"


@pytest.mark.asyncio
@respx.mock
async def test_get_approval_returns_either_pending_or_resolution():
    respx.get(f"{BASE}/approvals/ap-1").mock(
        return_value=httpx.Response(
            200,
            json={
                "pending": _pending_dict("ap-1"),
                "resolution": None,
            },
        )
    )
    client = ChioClient(BASE)
    approval = await client.get_approval("ap-1")
    await client.close()
    assert approval.pending is not None
    assert approval.pending.approval_id == "ap-1"
    assert approval.resolution is None


@pytest.mark.asyncio
async def test_get_approval_rejects_empty_id():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.get_approval("")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_respond_approval_posts_operator_endpoint_with_string_verdict():
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "approval_id": "ap-1",
                "outcome": "approved",
                "resolved_at": 4242,
            },
        )

    respx.post(f"{BASE}/approvals/ap-1/operator-respond").mock(side_effect=_handler)
    client = ChioClient(BASE)
    response = await client.respond_approval("ap-1", "approve", reason="ok")
    await client.close()

    assert captured["url"].endswith("/approvals/ap-1/operator-respond")
    assert captured["body"] == {"outcome": "approved", "reason": "ok"}
    assert response.outcome is ApprovalVerdict.APPROVED
    assert response.resolved_at == 4242


@pytest.mark.asyncio
@respx.mock
async def test_respond_approval_accepts_enum_verdict():
    respx.post(f"{BASE}/approvals/ap-1/operator-respond").mock(
        return_value=httpx.Response(
            200,
            json={
                "approval_id": "ap-1",
                "outcome": "denied",
                "resolved_at": 1,
            },
        )
    )
    client = ChioClient(BASE)
    response = await client.respond_approval("ap-1", ApprovalVerdict.DENIED)
    await client.close()
    assert response.outcome is ApprovalVerdict.DENIED


@pytest.mark.asyncio
async def test_respond_approval_rejects_unknown_verdict_string():
    client = ChioClient(BASE)
    with pytest.raises(ValueError):
        await client.respond_approval("ap-1", "maybe")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_submit_for_approval_hashes_args_and_returns_id():
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "approval_id": "ap-new-1",
                "expires_at": 4_000_000_000,
                "created_at": 100,
                "trusted_approvers": ["aa" * 32],
            },
        )

    respx.post(f"{BASE}/approvals/submit").mock(side_effect=_handler)
    client = ChioClient(BASE)
    args = {"command": "rm -rf old_build"}
    expected_hash = _sha256_hex(_canonical_json(args))
    approval_id = await client.submit_for_approval(
        capability_id="cap-1",
        tool_name="run_command",
        tool_args=args,
        requested_by="bb" * 32,
        ttl_seconds=600,
        triggered_by=["shell.requires_approval"],
    )
    await client.close()

    assert approval_id == "ap-new-1"
    body = captured["body"]
    assert body["capability_id"] == "cap-1"
    assert body["tool_server"] == "shell"
    assert body["tool_name"] == "run_command"
    assert body["parameter_hash"] == expected_hash
    assert body["requested_by"] == "bb" * 32
    assert body["ttl_seconds"] == 600
    assert body["triggered_by"] == ["shell.requires_approval"]


@pytest.mark.asyncio
async def test_submit_for_approval_rejects_missing_capability():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.submit_for_approval(
            capability_id="",
            tool_name="run_command",
            tool_args={"command": "ls"},
        )
    await client.close()


@pytest.mark.asyncio
async def test_submit_for_approval_rejects_missing_tool_name():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.submit_for_approval(
            capability_id="cap-1",
            tool_name="",
            tool_args={"command": "ls"},
        )
    await client.close()


def test_approval_verdict_from_action_normalisation():
    assert ApprovalVerdict.from_action("approve") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("Approved") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("allow") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("deny") is ApprovalVerdict.DENIED
    assert ApprovalVerdict.from_action("REJECT") is ApprovalVerdict.DENIED
    with pytest.raises(ValueError):
        ApprovalVerdict.from_action("something-else")
