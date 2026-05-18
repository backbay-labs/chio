"""Synchronous HTTP client for the Chio Lambda Extension.

The extension exposes a localhost evaluator at ``http://127.0.0.1:9090/v1/evaluate``
that accepts a JSON tool-call description and returns a non-authoritative
evaluation observation. Handlers must require an authoritative
``mediated_decision`` / ``prevent`` allow before executing.
Because Lambda handlers are typically synchronous, this client is synchronous by
default and uses :class:`httpx.Client` under the hood.

The client is **fail-closed**:

* If the extension is unreachable (connect error, timeout), ``evaluate`` raises
  :class:`ChioLambdaError` and callers must treat the request as denied.
* If the extension returns a non-JSON body or an HTTP error, the same exception
  is raised.
* If the extension returns a deny, advisory, trace-only, or otherwise
  non-authoritative observation, the returned :class:`EvaluateVerdict` has
  ``denied=True`` and carries the ``reason`` so the handler can surface a
  structured error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:9090"
DEFAULT_TIMEOUT_SECONDS = 3.0


class ChioLambdaError(RuntimeError):
    """Raised when the Chio Lambda Extension is unreachable or misbehaving."""

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.__cause__ = cause


@dataclass(frozen=True, slots=True)
class EvaluateVerdict:
    """Outcome of a single ``POST /v1/evaluate`` call."""

    decision: str
    receipt_id: str
    authorized: bool
    authoritative: bool
    receipt_kind: str
    boundary_class: str
    reason: str | None
    capability_id: str
    tool_server: str
    tool_name: str
    timestamp: int

    @property
    def allowed(self) -> bool:
        """True only for authoritative Chio authorization."""
        return (
            self.decision == "allow"
            and self.authorized
            and self.authoritative
            and self.receipt_kind == "mediated_decision"
            and self.boundary_class == "prevent"
        )

    @property
    def denied(self) -> bool:
        """True if the extension denied the call.

        Any decision string other than ``"allow"`` is treated as a deny. This
        preserves the fail-closed contract if the extension ever returns a
        novel decision value that the client does not understand.
        """
        return not self.allowed


class ChioLambdaClient:
    """Thin synchronous client for the Chio Lambda Extension evaluator.

    Parameters
    ----------
    base_url:
        Base URL of the extension. Defaults to ``http://127.0.0.1:9090`` which
        is what the extension binds to inside a Lambda execution environment.
    timeout:
        Per-request timeout in seconds. The extension runs in-process on
        loopback, so single-digit seconds is plenty.
    transport:
        Optional custom :class:`httpx.BaseTransport`. Primarily used in tests
        with :class:`httpx.MockTransport`.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
            transport=transport,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> ChioLambdaClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Return the extension's health payload. Raises on error."""
        try:
            response = self._client.get("/health")
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ChioLambdaError(
                f"Chio Lambda Extension unreachable at {self._base_url}: {exc}",
                cause=exc,
            ) from exc
        return self._handle_json(response)

    def evaluate(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        scope: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> EvaluateVerdict:
        """Ask the extension to evaluate a single tool call.

        Parameters
        ----------
        capability_id:
            Identifier of the capability token the call is bound to. Must be
            non-empty; the extension will deny otherwise.
        tool_server:
            Tool server identifier.
        tool_name:
            Name of the invoked tool. Must be non-empty.
        scope:
            Optional scope name (e.g. ``"db:read"``) surfaced in the receipt.
        arguments:
            Optional tool arguments, forwarded verbatim in the receipt.

        Returns
        -------
        EvaluateVerdict
            The structured decision.

        Raises
        ------
        ChioLambdaError
            If the extension is unreachable or returns a malformed response.
            Callers MUST treat this as a denial.
        """
        body: dict[str, Any] = {
            "capability_id": capability_id,
            "tool_server": tool_server,
            "tool_name": tool_name,
        }
        if scope is not None:
            body["scope"] = scope
        if arguments is not None:
            body["arguments"] = arguments

        try:
            response = self._client.post("/v1/evaluate", json=body)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ChioLambdaError(
                f"Chio Lambda Extension unreachable at {self._base_url}: {exc}",
                cause=exc,
            ) from exc

        data = self._handle_json(response)
        try:
            return EvaluateVerdict(
                decision=str(data["decision"]),
                receipt_id=str(data["receipt_id"]),
                authorized=bool(data.get("authorized", False)),
                authoritative=bool(data.get("authoritative", False)),
                receipt_kind=str(data.get("receipt_kind", "")),
                boundary_class=str(data.get("boundary_class", "")),
                reason=data.get("reason"),
                capability_id=str(data.get("capability_id", capability_id)),
                tool_server=str(data.get("tool_server", tool_server)),
                tool_name=str(data.get("tool_name", tool_name)),
                timestamp=int(data.get("timestamp", 0)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChioLambdaError(
                f"Chio Lambda Extension returned malformed response: {data!r}",
                cause=exc,
            ) from exc

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_json(response: httpx.Response) -> dict[str, Any]:
        if response.status_code >= 500:
            raise ChioLambdaError(
                f"Chio Lambda Extension returned {response.status_code}: {response.text!r}",
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ChioLambdaError(
                f"Chio Lambda Extension returned non-JSON body: {response.text!r}",
                cause=exc,
            ) from exc
        if not isinstance(data, dict):
            raise ChioLambdaError(
                f"Chio Lambda Extension returned non-object JSON: {data!r}",
            )
        if response.status_code >= 400:
            message = str(data.get("message") or data.get("error") or response.text)
            raise ChioLambdaError(
                f"Chio Lambda Extension returned {response.status_code}: {message}",
            )
        return data
