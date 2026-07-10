from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from chio_bedrock import (
    BedrockChioClient,
    MeteringTrustError,
    TrustedVerification,
    issue_receipt,
    metering_callback,
    sign_trusted_receipt_body,
    verify_receipt,
    verify_trusted_receipt,
)
from chio_bedrock.receipt import (
    DEFAULT_SIGNING_KEY,
    _content_addressed_receipt_id,
    _hash_value,
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _receipt_id_input(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "timestamp": receipt["timestamp"],
        "capability_id": receipt["capability_id"],
        "tool_server": receipt["tool_server"],
        "tool_name": receipt["tool_name"],
        "action": receipt["action"],
        "receipt_kind": receipt["receipt_kind"],
        "boundary_class": receipt["boundary_class"],
        "tool_origin": receipt["tool_origin"],
        "redaction_mode": receipt["redaction_mode"],
        "content_hash": receipt["content_hash"],
        "policy_hash": receipt["policy_hash"],
        "metadata": receipt["metadata"],
        "trust_level": receipt["trust_level"],
        "tenant_id": receipt["tenant_id"],
        "kernel_key": receipt["kernel_key"],
    }
    if receipt.get("decision") is not None:
        value["decision"] = receipt["decision"]
    if receipt.get("observation_outcome") is not None:
        value["observation_outcome"] = receipt["observation_outcome"]
    if receipt.get("actor_chain"):
        value["actor_chain"] = receipt["actor_chain"]
    if receipt.get("evidence"):
        value["evidence"] = receipt["evidence"]
    return value


def _content_addressed_receipt_id(receipt: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_receipt_id_input(receipt)).encode("utf-8")).hexdigest()


def _v1_signature(receipt: Mapping[str, Any], signing_key: str = DEFAULT_SIGNING_KEY) -> str:
    signing_body = {"id": receipt["id"], "body": _receipt_id_input(receipt)}
    return hmac.new(
        signing_key.encode("utf-8"),
        _canonical_json(signing_body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _resign_v1(receipt: dict[str, Any]) -> None:
    receipt["id"] = _content_addressed_receipt_id(receipt)
    receipt["signature"] = _v1_signature(receipt)


def _legacy_signature(receipt: Mapping[str, Any]) -> str:
    body = dict(receipt)
    body.pop("signature", None)
    return hashlib.sha256(
        (_canonical_json(body) + DEFAULT_SIGNING_KEY).encode("utf-8")
    ).hexdigest()


def _sample_receipt(**overrides: Any) -> dict[str, Any]:
    args = {
        "capability_id": "cap-bedrock-a",
        "tenant_id": "tenant-a",
        "model_id": "model-a",
        "parameters": {"modelId": "model-a", "messages": []},
        "response": {"ok": True},
        "principal_arn": "arn:aws:iam::111122223333:role/chio",
        "account_id": "111122223333",
        "timestamp": 1710000200,
    }
    args.update(overrides)
    return issue_receipt(**args)


_TRUSTED_SEED = bytes(range(32))
_TRUSTED_PRIVATE = ed25519.Ed25519PrivateKey.from_private_bytes(_TRUSTED_SEED)
_TRUSTED_PUB_HEX = (
    _TRUSTED_PRIVATE.public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    .hex()
)


def _authoritative_receipt(
    *,
    parameters: Mapping[str, Any] | None = None,
    tenant_id: str = "tenant-a",
    capability_id: str = "cap-bedrock-a",
    model_id: str = "model-a",
    timestamp: int = 1710000200,
    kernel_pub_hex: str = _TRUSTED_PUB_HEX,
    signing_seed: bytes | str = _TRUSTED_SEED,
    principal_arn: str = "arn:aws:iam::111122223333:role/chio",
    account_id: str = "111122223333",
) -> dict[str, Any]:
    """Build a properly signed authoritative mediated metering receipt."""

    params = dict(parameters or {"modelId": model_id, "messages": []})
    body: dict[str, Any] = {
        "timestamp": timestamp,
        "capability_id": capability_id,
        "tool_server": "aws-bedrock",
        "tool_name": "bedrock.converse",
        "action": {"parameters": params, "parameter_hash": _hash_value(params)},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "redacted",
        "actor_chain": [],
        "trust_level": "mediated",
        "content_hash": _hash_value({"ok": True}),
        "policy_hash": "chio-bedrock-marketplace-policy-v1",
        "evidence": [],
        "metadata": {
            "surface": "aws-bedrock",
            "version": 1,
            "region": "us-east-1",
            "model_id": model_id,
            "principal_arn": principal_arn,
            "account_id": account_id,
        },
        "tenant_id": tenant_id,
        "kernel_key": kernel_pub_hex,
        "decision": {"verdict": "allow"},
    }
    receipt_id = _content_addressed_receipt_id(body)
    body = {"id": receipt_id, **body}
    body["signature"] = sign_trusted_receipt_body(body, signing_seed)
    return body


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
    assert invocation.metering is None


def test_receipt_id_and_signature_use_v1_content_addressing() -> None:
    receipt = _sample_receipt()
    repeat = _sample_receipt()

    assert receipt == repeat
    assert receipt["id"] == _content_addressed_receipt_id(receipt)
    assert receipt["signature"] == _v1_signature(receipt)
    assert len(receipt["id"]) == 64
    assert int(receipt["id"], 16) >= 0
    assert receipt["receipt_kind"] == "trace_observation"
    assert receipt["boundary_class"] == "detect_only"
    assert receipt["trust_level"] == "verified"
    assert "decision" not in receipt


def test_receipt_verifier_rejects_uppercase_content_addressed_id() -> None:
    receipt = _sample_receipt()
    receipt["id"] = receipt["id"].upper()
    receipt["signature"] = _v1_signature(receipt)

    assert not verify_receipt(receipt)


def test_redacted_trace_receipt_does_not_embed_invocation_parameters() -> None:
    secret = "customer secret prompt"
    receipt = _sample_receipt(
        parameters={
            "modelId": "model-a",
            "messages": [{"role": "user", "content": [{"text": secret}]}],
        }
    )

    assert receipt["redaction_mode"] == "redacted"
    assert "parameters" not in receipt["action"]
    assert receipt["action"]["parameter_hash"] == _hash_value(
        {
            "modelId": "model-a",
            "messages": [{"role": "user", "content": [{"text": secret}]}],
        }
    )
    assert secret not in json.dumps(receipt)
    assert verify_receipt(receipt)


def test_receipt_verifier_rejects_symbolic_ids_even_when_legacy_signed() -> None:
    receipt = {
        "id": "rcpt-bedrock-symbolic",
        "timestamp": 1710000200,
        "capability_id": "cap-bedrock-a",
        "tool_server": "aws-bedrock",
        "tool_name": "bedrock.converse",
        "action": {
            "parameters": {"modelId": "model-a", "messages": []},
            "parameter_hash": hashlib.sha256(
                _canonical_json({"modelId": "model-a", "messages": []}).encode("utf-8")
            ).hexdigest(),
        },
        "receipt_kind": "trace_observation",
        "boundary_class": "detect_only",
        "observation_outcome": "observed",
        "tool_origin": "host_executed_provider_reported",
        "redaction_mode": "redacted",
        "actor_chain": [],
        "trust_level": "verified",
        "content_hash": hashlib.sha256(_canonical_json({"ok": True}).encode("utf-8")).hexdigest(),
        "policy_hash": "chio-bedrock-marketplace-policy-v1",
        "evidence": [],
        "metadata": {
            "surface": "aws-bedrock",
            "version": 1,
            "region": "us-east-1",
            "model_id": "model-a",
            "principal_arn": "arn:aws:iam::111122223333:role/chio",
            "account_id": "111122223333",
        },
        "tenant_id": "tenant-a",
        "kernel_key": "chio-bedrock-sdk-local-kernel",
    }
    receipt["signature"] = _legacy_signature(receipt)

    assert not verify_receipt(receipt)


def test_receipt_verifier_rejects_invalid_v1_trace_receipts() -> None:
    assert verify_receipt(_sample_receipt())

    mismatched_id = _sample_receipt()
    mismatched_id["id"] = "0" * 64
    mismatched_id["signature"] = _v1_signature(mismatched_id)
    assert not verify_receipt(mismatched_id)

    uppercase_id = _sample_receipt()
    uppercase_id["id"] = uppercase_id["id"].upper()
    uppercase_id["signature"] = _v1_signature(uppercase_id)
    assert not verify_receipt(uppercase_id)

    missing_trust_level = _sample_receipt()
    missing_trust_level.pop("trust_level")
    assert not verify_receipt(missing_trust_level)

    trace_with_decision = _sample_receipt()
    trace_with_decision["decision"] = {"verdict": "allow"}
    _resign_v1(trace_with_decision)
    assert not verify_receipt(trace_with_decision)

    advisory_with_decision = _sample_receipt()
    advisory_with_decision["receipt_kind"] = "advisory_evaluation"
    advisory_with_decision["boundary_class"] = "advisory_only"
    advisory_with_decision["observation_outcome"] = "evaluated"
    advisory_with_decision["trust_level"] = "advisory"
    advisory_with_decision["decision"] = {"verdict": "allow"}
    _resign_v1(advisory_with_decision)
    assert not verify_receipt(advisory_with_decision)

    bad_signature = _sample_receipt()
    bad_signature["signature"] = "bad"
    assert not verify_receipt(bad_signature)


def test_receipt_verifier_fails_closed_on_tamper() -> None:
    receipt = _sample_receipt()

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

    params = {"modelId": "model-a", "messages": []}
    with pytest.raises(ValueError, match="authoritative mediated authorization receipt"):
        metering_callback(
            receipt=_sample_receipt(),
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        )

    authoritative_receipt = _authoritative_receipt(parameters=params)
    payload = metering_callback(
        receipt=authoritative_receipt,
        customer_identifier="customer-123",
        product_code="prod-abc",
        invocation_parameters=params,
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
    )
    assert payload["receipt_id"] == authoritative_receipt["id"]
    assert payload["tenant_id"] == authoritative_receipt["tenant_id"]
    assert payload["api"] == "MeterUsage"

    with pytest.raises(ValueError, match="quantity"):
        metering_callback(
            receipt=authoritative_receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[_TRUSTED_PUB_HEX],
            quantity=0,
        )


def test_metering_requires_verified_receipt() -> None:
    params = {"modelId": "model-a", "messages": [{"role": "user", "content": [{"text": "hi"}]}]}
    receipt = _authoritative_receipt(parameters=params)
    payload = metering_callback(
        receipt=receipt,
        customer_identifier="customer-123",
        product_code="prod-abc",
        invocation_parameters=params,
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
    )
    assert payload["receipt_id"] == receipt["id"]
    assert payload["usage_dimension"] == "bedrock_receipt_overage"
    assert payload["usage_quantity"] == 1
    assert payload["customer_identifier"] == "customer-123"
    assert payload["product_code"] == "prod-abc"


def test_metering_fails_closed_without_trusted_keys() -> None:
    params = {"modelId": "model-a", "messages": []}
    receipt = _authoritative_receipt(parameters=params)
    with pytest.raises(MeteringTrustError) as exc_info:
        metering_callback(
            receipt=receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[],
        )
    verification = exc_info.value.verification
    assert isinstance(verification, TrustedVerification)
    assert verification.signer_trusted is False
    assert verification.ok is False
    assert any("trusted_kernel_keys" in reason for reason in verification.reasons)


def test_metering_fails_closed_on_signature_mismatch() -> None:
    params = {"modelId": "model-a", "messages": []}
    receipt = _authoritative_receipt(parameters=params)
    receipt = dict(receipt)
    # Tamper with the signature by flipping the last hex nibble.
    last = receipt["signature"][-1]
    flipped = "0" if last != "0" else "1"
    receipt["signature"] = receipt["signature"][:-1] + flipped
    with pytest.raises(MeteringTrustError) as exc_info:
        metering_callback(
            receipt=receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        )
    verification = exc_info.value.verification
    assert verification.signature_ok is False
    assert any("ed25519 signature" in reason for reason in verification.reasons)


def test_metering_fails_closed_on_parameter_hash_mismatch() -> None:
    receipt_params = {"modelId": "model-a", "messages": []}
    other_params = {"modelId": "model-a", "messages": [{"role": "user", "content": [{"text": "x"}]}]}
    receipt = _authoritative_receipt(parameters=receipt_params)
    with pytest.raises(MeteringTrustError) as exc_info:
        metering_callback(
            receipt=receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=other_params,
            trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        )
    verification = exc_info.value.verification
    assert verification.parameter_hash_ok is False
    assert any(
        "parameter_hash" in reason for reason in verification.reasons
    )


def test_metering_fails_closed_on_untrusted_signer() -> None:
    params = {"modelId": "model-a", "messages": []}
    # Receipt is signed by the trusted kernel, but we configure a different
    # trusted set so membership fails.
    other_seed = bytes([1] * 32)
    other_priv = ed25519.Ed25519PrivateKey.from_private_bytes(other_seed)
    other_pub_hex = (
        other_priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    receipt = _authoritative_receipt(parameters=params)
    with pytest.raises(MeteringTrustError) as exc_info:
        metering_callback(
            receipt=receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[other_pub_hex],
        )
    verification = exc_info.value.verification
    assert verification.signer_trusted is False
    assert any("trusted_kernel_keys" in reason for reason in verification.reasons)


def test_metering_rejects_shape_only_fake_receipt() -> None:
    # Pre-existing PR682 fixture: correct kind/boundary/trust shape but only
    # hex-shaped id and signature with no cryptographic backing.
    params = {"modelId": "model-a", "messages": []}
    fake_receipt = _sample_receipt(parameters=params)
    fake_receipt["receipt_kind"] = "mediated_decision"
    fake_receipt["boundary_class"] = "prevent"
    fake_receipt["trust_level"] = "mediated"
    fake_receipt["tool_origin"] = "caller_executed"
    fake_receipt["decision"] = {"verdict": "allow"}
    fake_receipt.pop("observation_outcome", None)
    fake_receipt["id"] = "a" * 64
    fake_receipt["signature"] = "b" * 128
    fake_receipt["kernel_key"] = _TRUSTED_PUB_HEX
    with pytest.raises(MeteringTrustError) as exc_info:
        metering_callback(
            receipt=fake_receipt,
            customer_identifier="customer-123",
            product_code="prod-abc",
            invocation_parameters=params,
            trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        )
    verification = exc_info.value.verification
    # Both signature and content-addressed id must fail for the shape-only
    # fake; the request never reaches a payload.
    assert verification.signature_ok is False
    assert verification.receipt_id_ok is False


def test_verify_trusted_receipt_returns_structured_outcome() -> None:
    params = {"modelId": "model-a", "messages": []}
    receipt = _authoritative_receipt(parameters=params)

    happy = verify_trusted_receipt(
        receipt,
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        invocation_parameters=params,
    )
    assert isinstance(happy, TrustedVerification)
    assert happy.signature_ok
    assert happy.receipt_id_ok
    assert happy.parameter_hash_ok
    assert happy.signer_trusted
    assert happy.reasons == ()
    assert happy.ok is True

    uppercase_id = dict(receipt)
    uppercase_id["id"] = receipt["id"].upper()
    uppercase_id["signature"] = sign_trusted_receipt_body(uppercase_id, _TRUSTED_SEED)
    uppercase = verify_trusted_receipt(
        uppercase_id,
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        invocation_parameters=params,
    )
    assert uppercase.ok is False
    assert uppercase.receipt_id_ok is False
    assert uppercase.signature_ok is True

    untrusted = verify_trusted_receipt(
        receipt,
        trusted_kernel_keys=[],
        invocation_parameters=params,
    )
    assert untrusted.signature_ok is True
    assert untrusted.signer_trusted is False
    assert untrusted.ok is False

    wrong_params = verify_trusted_receipt(
        receipt,
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
        invocation_parameters={"different": "shape"},
    )
    assert wrong_params.parameter_hash_ok is False
    assert wrong_params.signature_ok is True
    assert wrong_params.ok is False


def test_metering_verifier_does_not_require_signing_key() -> None:
    """A verifier with only trusted_kernel_keys (and no signing secret)
    can verify and emit metering payloads end to end.
    """

    params = {"modelId": "model-a", "messages": []}
    # The mint side (test harness / local kernel) holds the signing seed
    # and produces the signed receipt.
    receipt = _authoritative_receipt(parameters=params, signing_seed=_TRUSTED_SEED)

    # The verify side only knows the trusted public keys. It must NOT need
    # the kernel signing seed to verify or emit metering.
    verifier_trusted_keys = (_TRUSTED_PUB_HEX,)

    verification = verify_trusted_receipt(
        receipt,
        trusted_kernel_keys=verifier_trusted_keys,
        invocation_parameters=params,
    )
    assert verification.ok is True
    assert verification.signature_ok is True
    assert verification.signer_trusted is True

    payload = metering_callback(
        receipt=receipt,
        customer_identifier="customer-123",
        product_code="prod-abc",
        invocation_parameters=params,
        trusted_kernel_keys=verifier_trusted_keys,
    )
    assert payload["receipt_id"] == receipt["id"]

    runtime = FakeBedrockRuntime()
    client = BedrockChioClient(
        bedrock_runtime=runtime,
        principal_arn="arn:aws:iam::111122223333:role/chio",
        account_id="111122223333",
        customer_identifier="customer-123",
        product_code="prod-abc",
        trusted_kernel_keys=verifier_trusted_keys,
    )
    client_payload = client.emit_metering(
        receipt=receipt,
        invocation_parameters=params,
    )
    assert client_payload["receipt_id"] == receipt["id"]


def test_bedrock_chio_client_emit_metering_round_trip() -> None:
    runtime = FakeBedrockRuntime()
    client = BedrockChioClient(
        bedrock_runtime=runtime,
        principal_arn="arn:aws:iam::111122223333:role/chio",
        account_id="111122223333",
        customer_identifier="customer-123",
        product_code="prod-abc",
        trusted_kernel_keys=[_TRUSTED_PUB_HEX],
    )
    assert client.trusted_kernel_keys == (_TRUSTED_PUB_HEX,)
    params = {"modelId": "model-a", "messages": []}
    receipt = _authoritative_receipt(parameters=params)
    payload = client.emit_metering(
        receipt=receipt,
        invocation_parameters=params,
    )
    assert payload["receipt_id"] == receipt["id"]
    assert payload["customer_identifier"] == "customer-123"


def test_bedrock_chio_client_emit_metering_requires_trusted_keys() -> None:
    runtime = FakeBedrockRuntime()
    client = BedrockChioClient(
        bedrock_runtime=runtime,
        principal_arn="arn:aws:iam::111122223333:role/chio",
        account_id="111122223333",
    )
    params = {"modelId": "model-a", "messages": []}
    receipt = _authoritative_receipt(parameters=params)
    with pytest.raises(ValueError, match="trusted_kernel_keys"):
        client.emit_metering(
            receipt=receipt,
            invocation_parameters=params,
        )
