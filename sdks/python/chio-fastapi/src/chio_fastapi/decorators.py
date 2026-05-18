"""FastAPI route decorators for Chio capability enforcement.

These decorators wrap FastAPI route handlers to evaluate Chio capabilities,
approval requirements, and budget limits via the sidecar before the handler
executes.

Usage::

    from chio_fastapi import chio_requires, chio_approval, chio_budget

    @app.post("/tools/deploy")
    @chio_requires("deploy-server", "deploy", ["Invoke"])
    async def deploy(request: Request):
        ...

    @app.post("/tools/transfer")
    @chio_approval(threshold_cents=10000)
    @chio_requires("payments", "transfer", ["Invoke"])
    async def transfer(request: Request):
        ...

    @app.post("/tools/query")
    @chio_budget(max_cost_cents=500, currency="USD")
    @chio_requires("ai", "query", ["Invoke"])
    async def query(request: Request):
        ...
"""

from __future__ import annotations

import functools
import hashlib
import uuid
from typing import Any, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioConnectionError, ChioDeniedError, ChioError, ChioTimeoutError
from chio_sdk.models import CallerIdentity

from chio_fastapi.dependencies import get_chio_client, get_caller_identity
from chio_fastapi.errors import ChioErrorCode, chio_error_response


def chio_requires(
    server_id: str,
    tool_name: str,
    operations: list[str] | None = None,
) -> Callable[..., Any]:
    """Decorator that enforces Chio capability requirements on a FastAPI route.

    The request must carry a valid Chio capability token (via X-Chio-Capability
    header or chio_capability query parameter) that grants the specified
    server_id/tool_name/operations.

    Parameters
    ----------
    server_id:
        The Chio tool server ID required.
    tool_name:
        The tool name required.
    operations:
        List of required operations (default ``["Invoke"]``).
    """
    ops = operations or ["Invoke"]

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return chio_error_response(
                    500,
                    ChioErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Extract capability ID
            cap_id = (
                request.headers.get("x-chio-capability")
                or request.query_params.get("chio_capability")
            )
            if not cap_id:
                return chio_error_response(
                    401,
                    ChioErrorCode.CAPABILITY_REQUIRED,
                    f"Chio capability required for {server_id}/{tool_name}",
                )

            # Evaluate via sidecar
            try:
                client = await get_chio_client()
                caller = await get_caller_identity(request)

                body_bytes = await request.body()
                body_hash = (
                    hashlib.sha256(body_bytes).hexdigest() if body_bytes else None
                )

                evaluation = await client.evaluate_http_request(
                    request_id=str(uuid.uuid4()),
                    method=request.method,
                    route_pattern=str(request.url.path),
                    path=str(request.url.path),
                    caller=caller,
                    query={
                        key: value
                        for key, value in request.query_params.items()
                    },
                    headers={
                        key.lower(): value
                        for key, value in (
                            ("content-type", request.headers.get("content-type")),
                            ("content-length", request.headers.get("content-length")),
                        )
                        if value is not None
                    },
                    body_hash=body_hash,
                    body_length=len(body_bytes),
                    capability_token=cap_id,
                )
            except ChioDeniedError as exc:
                return chio_error_response(
                    403,
                    ChioErrorCode.GUARD_DENIED,
                    exc.reason or str(exc),
                    guard=exc.guard,
                )
            except (ChioConnectionError, ChioTimeoutError):
                return chio_error_response(
                    503,
                    ChioErrorCode.SIDECAR_UNAVAILABLE,
                    "Chio sidecar is unavailable",
                )
            except ChioError as exc:
                return chio_error_response(
                    502,
                    ChioErrorCode.INTERNAL_ERROR,
                    str(exc),
                )

            receipt = evaluation.receipt

            if not evaluation.verdict.is_allowed or not receipt.is_allowed:
                return chio_error_response(
                    receipt.verdict.http_status or 403,
                    ChioErrorCode.GUARD_DENIED,
                    receipt.verdict.reason or "denied",
                    guard=receipt.verdict.guard,
                )
            try:
                verification = await client.verify_http_receipt(receipt)
            except (ChioConnectionError, ChioTimeoutError, ChioError):
                verification = None
            if verification is None or not verification.authorizes(receipt):
                return chio_error_response(
                    502,
                    ChioErrorCode.INTERNAL_ERROR,
                    "Chio sidecar returned an unverified receipt",
                )

            # Attach receipt to request state
            request.state.chio_receipt = receipt
            return await func(*args, **kwargs)

        # Store metadata for introspection
        wrapper._chio_requires = {  # type: ignore[attr-defined]
            "server_id": server_id,
            "tool_name": tool_name,
            "operations": ops,
        }
        return wrapper

    return decorator


def chio_approval(
    threshold_cents: int = 0,
    currency: str = "USD",
) -> Callable[..., Any]:
    """Decorator that requires human approval above a monetary threshold.

    Must be combined with ``@chio_requires``. If the request's cost exceeds
    ``threshold_cents``, the sidecar will require an approval token.

    Parameters
    ----------
    threshold_cents:
        Cost threshold in minor currency units above which approval is
        required. Default 0 means always require approval.
    currency:
        ISO 4217 currency code.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return chio_error_response(
                    500,
                    ChioErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Check for approval token
            approval_token = request.headers.get("x-chio-approval")
            if not approval_token:
                return chio_error_response(
                    403,
                    ChioErrorCode.APPROVAL_REQUIRED,
                    f"Approval required for operations above {threshold_cents} {currency}",
                    details={
                        "threshold_cents": threshold_cents,
                        "currency": currency,
                    },
                )

            # Store approval metadata for downstream handlers
            request.state.chio_approval = {
                "token": approval_token,
                "threshold_cents": threshold_cents,
                "currency": currency,
            }
            return await func(*args, **kwargs)

        wrapper._chio_approval = {  # type: ignore[attr-defined]
            "threshold_cents": threshold_cents,
            "currency": currency,
        }
        return wrapper

    return decorator


def chio_budget(
    max_cost_cents: int,
    currency: str = "USD",
) -> Callable[..., Any]:
    """Decorator that enforces a per-request budget limit.

    If the tool invocation's cost would exceed ``max_cost_cents``, the
    sidecar denies the request.

    Parameters
    ----------
    max_cost_cents:
        Maximum cost in minor currency units for this endpoint.
    currency:
        ISO 4217 currency code.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return chio_error_response(
                    500,
                    ChioErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Store budget metadata for the sidecar evaluation
            request.state.chio_budget = {
                "max_cost_cents": max_cost_cents,
                "currency": currency,
            }
            return await func(*args, **kwargs)

        wrapper._chio_budget = {  # type: ignore[attr-defined]
            "max_cost_cents": max_cost_cents,
            "currency": currency,
        }
        return wrapper

    return decorator
