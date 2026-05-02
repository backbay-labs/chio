"""Client surface for Chio-governed Amazon Bedrock calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
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
    metering: Mapping[str, Any]


class BedrockChioClient:
    """Small Python wrapper around a Bedrock runtime client.

    Production use injects a boto3 Bedrock Runtime client or a thin wrapper
    around the Rust adapter. Tests inject an object with a `converse` method.
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
        metering_dimension: str = DEFAULT_DIMENSION,
    ) -> None:
        if region != BEDROCK_REGION:
            raise ValueError("chio-bedrock is pinned to us-east-1 for trajectory-3")
        if not principal_arn or not account_id:
            raise ValueError("principal_arn and account_id are required")
        self._bedrock_runtime = bedrock_runtime
        self._principal_arn = principal_arn
        self._account_id = account_id
        self._customer_identifier = customer_identifier
        self._product_code = product_code
        self._receipt_issuer = receipt_issuer
        self._receipt_verifier = receipt_verifier
        self._metering_dimension = metering_dimension

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
        metering = metering_callback(
            receipt=receipt,
            customer_identifier=self._customer_identifier,
            product_code=self._product_code,
            dimension=self._metering_dimension,
        )
        return BedrockInvocation(response=response, receipt=receipt, metering=metering)
