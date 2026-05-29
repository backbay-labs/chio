"""Client surface for Chio-governed Amazon Bedrock calls."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from chio_bedrock.metering import DEFAULT_DIMENSION, metering_callback
from chio_bedrock.receipt import BEDROCK_REGION, Receipt, issue_receipt, verify_receipt


class BedrockRuntimeClient(Protocol):
    def converse(self, **kwargs: Any) -> Mapping[str, Any]:
        """Invoke Amazon Bedrock Runtime Converse."""


@dataclass(frozen=True)
class BedrockInvocation:
    response: Mapping[str, Any]
    receipt: Receipt
    metering: Mapping[str, Any] | None


class BedrockChioClient:
    """Small Python wrapper around a Bedrock runtime client.

    Production use injects a boto3 Bedrock Runtime client or a thin wrapper
    around the Rust adapter. Tests inject an object with a `converse` method.

    `trusted_kernel_keys` is the set of ed25519 public keys (hex) whose
    signatures the SDK will accept on authoritative mediated metering
    receipts. It is keyword-only and optional at construction time so that
    callers that never emit metering payloads need not configure it.
    `emit_metering()` requires the set to be non-empty.
    """

    def __init__(
        self,
        *,
        bedrock_runtime: BedrockRuntimeClient,
        principal_arn: str,
        account_id: str,
        customer_identifier: str = "local-customer",
        product_code: str = "chio-bedrock",
        region: str = BEDROCK_REGION,
        receipt_issuer: Callable[..., Receipt] = issue_receipt,
        receipt_verifier: Callable[[Mapping[str, Any]], bool] = verify_receipt,
        trusted_kernel_keys: Iterable[str] | None = None,
    ) -> None:
        if region != BEDROCK_REGION:
            raise ValueError(
                f"chio-bedrock currently supports only the {BEDROCK_REGION} region"
            )
        if not principal_arn or not account_id:
            raise ValueError("principal_arn and account_id are required")
        self._bedrock_runtime = bedrock_runtime
        self._principal_arn = principal_arn
        self._account_id = account_id
        self._customer_identifier = customer_identifier
        self._product_code = product_code
        self._receipt_issuer = receipt_issuer
        self._receipt_verifier = receipt_verifier
        self._trusted_kernel_keys: tuple[str, ...] = (
            tuple(trusted_kernel_keys) if trusted_kernel_keys is not None else ()
        )

    @property
    def trusted_kernel_keys(self) -> tuple[str, ...]:
        """Hex ed25519 public keys this client trusts for metering receipts."""

        return self._trusted_kernel_keys

    @property
    def customer_identifier(self) -> str:
        return self._customer_identifier

    @property
    def product_code(self) -> str:
        return self._product_code

    def converse(
        self,
        *,
        tenant_id: str,
        capability_id: str,
        model_id: str,
        messages: Sequence[Mapping[str, Any]],
        inference_config: Mapping[str, Any] | None = None,
        tool_config: Mapping[str, Any] | None = None,
        additional_model_request_fields: Mapping[str, Any] | None = None,
    ) -> BedrockInvocation:
        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": [dict(message) for message in messages],
        }
        if inference_config is not None:
            request["inferenceConfig"] = dict(inference_config)
        if tool_config is not None:
            request["toolConfig"] = dict(tool_config)
        if additional_model_request_fields is not None:
            request["additionalModelRequestFields"] = dict(additional_model_request_fields)

        response = dict(self._bedrock_runtime.converse(**request))
        receipt = self._receipt_issuer(
            capability_id=capability_id,
            tenant_id=tenant_id,
            model_id=model_id,
            parameters=request,
            response=response,
            principal_arn=self._principal_arn,
            account_id=self._account_id,
        )
        if not self._receipt_verifier(receipt):
            raise ValueError("issued Bedrock receipt failed local verification")
        return BedrockInvocation(response=response, receipt=receipt, metering=None)

    def emit_metering(
        self,
        *,
        receipt: Mapping[str, Any],
        invocation_parameters: Mapping[str, Any],
        dimension: str = DEFAULT_DIMENSION,
        quantity: int = 1,
    ) -> dict[str, Any]:
        """Build a metering payload, gated by trusted-receipt verification.

        The receipt must be an authoritative mediated authorization receipt
        signed by a kernel whose public key is in this client's
        `trusted_kernel_keys`. Fails closed via `MeteringTrustError` (a
        `ValueError` subclass) when verification fails.

        The verifier only needs trusted public keys; production callers do
        not need to hold the kernel's private signing secret.
        """

        if not self._trusted_kernel_keys:
            raise ValueError(
                "BedrockChioClient.emit_metering requires trusted_kernel_keys "
                "to be configured on the client"
            )
        return metering_callback(
            receipt=receipt,
            customer_identifier=self._customer_identifier,
            product_code=self._product_code,
            invocation_parameters=invocation_parameters,
            trusted_kernel_keys=self._trusted_kernel_keys,
            dimension=dimension,
            quantity=quantity,
        )
