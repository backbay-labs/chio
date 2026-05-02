from __future__ import annotations

import pytest

from chio_bedrock import BedrockChioClient, issue_receipt, metering_callback, verify_receipt


class FakeBedrockRuntime:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": "hello"}]}},
            "usage": {"inputTokens": 3, "outputTokens": 1},
        }


def test_bedrock_chio_client_issues_receipt_and_metering_payload() -> None:
    runtime = FakeBedrockRuntime()
    client = BedrockChioClient(
        bedrock_runtime=runtime,
        principal_arn="arn:aws:sts::111122223333:assumed-role/chio-bedrock/session",
        account_id="111122223333",
        customer_identifier="customer-123",
        product_code="prod-abc",
    )

    invocation = client.converse(
        tenant_id="tenant-a",
        capability_id="cap-bedrock-a",
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        messages=[{"role": "user", "content": [{"text": "hello"}]}],
    )

    assert len(runtime.calls) == 1
    assert runtime.calls[0]["modelId"] == "anthropic.claude-3-haiku-20240307-v1:0"
    assert invocation.receipt["tool_server"] == "aws-bedrock"
    assert invocation.receipt["tenant_id"] == "tenant-a"
    assert invocation.receipt["metadata"]["region"] == "us-east-1"
    assert verify_receipt(invocation.receipt)
    assert invocation.metering["api"] == "MeterUsage"
    assert invocation.metering["customer_identifier"] == "customer-123"
    assert invocation.metering["receipt_id"] == invocation.receipt["id"]


def test_receipt_verifier_fails_closed_on_tamper() -> None:
    receipt = issue_receipt(
        capability_id="cap-bedrock-a",
        tenant_id="tenant-a",
        model_id="model-a",
        parameters={"modelId": "model-a", "messages": []},
        response={"ok": True},
        principal_arn="arn:aws:iam::111122223333:role/chio",
        account_id="111122223333",
        timestamp=1710000200,
        receipt_id="rcpt-test",
    )

    assert verify_receipt(receipt)
    receipt["metadata"]["region"] = "us-west-2"
    assert not verify_receipt(receipt)


def test_region_and_metering_fail_closed() -> None:
    runtime = FakeBedrockRuntime()
    with pytest.raises(ValueError, match="us-east-1"):
        BedrockChioClient(
            bedrock_runtime=runtime,
            principal_arn="arn:aws:iam::111122223333:role/chio",
            account_id="111122223333",
            region="us-west-2",
        )

    with pytest.raises(ValueError, match="quantity"):
        metering_callback(
            receipt={"id": "rcpt-a", "timestamp": 1710000200, "tenant_id": "tenant-a"},
            customer_identifier="customer-123",
            product_code="prod-abc",
            quantity=0,
        )
