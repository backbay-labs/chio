"""Async HTTP client for the Chio sidecar kernel.

The Chio sidecar runs as a local process exposing a localhost HTTP API. This
client provides a typed Python interface over that API, handling serialization,
error mapping, and receipt verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel

from chio_sdk.errors import (
    ChioConnectionError,
    ChioDeniedError,
    ChioError,
    ChioTimeoutError,
    ChioValidationError,
)
from chio_sdk.models import (
    CallerIdentity,
    CapabilityToken,
    ChioHttpRequest,
    ChioReceipt,
    ChioScope,
    EvaluateResponse,
    GuardEvidence,
    HttpReceipt,
    VerifyReceiptResponse,
)
from chio_sdk.models_approvals import (
    Approval,
    ApprovalResponse,
    ApprovalVerdict,
    PendingApproval,
    PendingApprovalList,
    SubmitApprovalResult,
)


def _jsonable(obj: Any) -> Any:
    """Convert Pydantic and enum values into HTTP JSON payload values."""
    if isinstance(obj, BaseModel):
        return _jsonable(
            obj.model_dump(
                mode="json",
                exclude_none=True,
                by_alias=True,
            )
        )
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {key: _jsonable(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(value) for value in obj]
    if isinstance(obj, tuple):
        return [_jsonable(value) for value in obj]
    return obj


def _canonical_json(obj: Any) -> bytes:
    """Produce canonical JSON (sorted keys, no extra whitespace, ensure_ascii).

    This matches the Rust kernel's canonical JSON (RFC 8785 subset) for
    deterministic hashing. Full RFC 8785 compliance (e.g. number serialization)
    is handled by the sidecar; this is a best-effort local approximation
    sufficient for content hashing.
    """
    return json.dumps(
        _jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _default_tool_server(tool_name: str) -> str:
    """Best-effort tool-server guess from a chio_* tool name.

    Mirrors the routing chio-hermes uses so adapters that omit
    ``tool_server`` still produce sensible approval entries.
    """
    if tool_name.startswith("chio_file_") or tool_name.startswith("file_"):
        return "fs"
    if tool_name.startswith("chio_shell_") or tool_name.startswith("shell_"):
        return "shell"
    if tool_name.startswith("chio_git_") or tool_name.startswith("git_"):
        return "git"
    if tool_name in {"run_command", "run"}:
        return "shell"
    return "unknown"


def _capability_id_from_token(raw_token: str | None) -> str | None:
    """Best-effort extraction of a capability token ID from its JSON payload."""
    if raw_token is None:
        return None
    try:
        return CapabilityToken.model_validate_json(raw_token).id
    except Exception:
        return None


def _is_advisory_evaluation_wrapper(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and data.get("schema") == "chio.sidecar.advisory-evaluation.v1"
    )


def _wrapped_advisory_receipt_payload(data: dict[str, Any]) -> Any:
    if data.get("authorization") is not False:
        raise ChioError(
            "Chio sidecar advisory evaluation did not explicitly mark "
            "authorization as false",
            code="INVALID_RECEIPT",
        )
    if data.get("authorizationBasis") != "advisory_only":
        raise ChioError(
            "Chio sidecar advisory evaluation did not identify its "
            "authorization basis",
            code="INVALID_RECEIPT",
        )
    return data.get("receipt")


def _receipt_field_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _receipt_is_advisory_evaluation(receipt: ChioReceipt) -> bool:
    return (
        _receipt_field_value(receipt.receipt_kind) == "advisory_evaluation"
        and _receipt_field_value(receipt.boundary_class) == "advisory_only"
        and _receipt_field_value(receipt.trust_level) == "advisory"
    )


def _operations_subset(child: list[Any], parent: list[Any]) -> bool:
    return set(_jsonable(child)) <= set(_jsonable(parent))


def _money_within_child_limit(child: Any | None, parent: Any | None) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    child_json = _jsonable(child)
    parent_json = _jsonable(parent)
    return (
        child_json.get("currency") == parent_json.get("currency")
        and child_json.get("units", 0) <= parent_json.get("units", 0)
    )


def _constraints_preserve_parent(child: Any | None, parent: Any | None) -> bool:
    parent_constraints = parent or []
    if not parent_constraints:
        return True
    child_constraints = child or []
    child_set = {
        _canonical_json(constraint).decode("utf-8")
        for constraint in child_constraints
    }
    return all(
        _canonical_json(constraint).decode("utf-8") in child_set
        for constraint in parent_constraints
    )


def _tool_grant_subset(child: Any, parent: Any) -> bool:
    child_json = _jsonable(child)
    parent_json = _jsonable(parent)
    if child_json.get("server_id") != parent_json.get("server_id"):
        return False
    if child_json.get("tool_name") != parent_json.get("tool_name"):
        return False
    if not _operations_subset(
        child_json.get("operations", []), parent_json.get("operations", [])
    ):
        return False
    if not _constraints_preserve_parent(
        child_json.get("constraints"), parent_json.get("constraints")
    ):
        return False
    for field in ("max_invocations",):
        parent_value = parent_json.get(field)
        child_value = child_json.get(field)
        if parent_value is not None and (
            child_value is None or child_value > parent_value
        ):
            return False
    for field in ("max_cost_per_invocation", "max_total_cost"):
        if not _money_within_child_limit(
            child_json.get(field), parent_json.get(field)
        ):
            return False
    if (
        parent_json.get("dpop_required") is True
        and child_json.get("dpop_required") is not True
    ):
        return False
    return True


def _resource_grant_subset(child: Any, parent: Any) -> bool:
    child_json = _jsonable(child)
    parent_json = _jsonable(parent)
    return (
        child_json.get("uri_pattern") == parent_json.get("uri_pattern")
        and _operations_subset(
            child_json.get("operations", []), parent_json.get("operations", [])
        )
    )


def _prompt_grant_subset(child: Any, parent: Any) -> bool:
    child_json = _jsonable(child)
    parent_json = _jsonable(parent)
    return (
        child_json.get("prompt_name") == parent_json.get("prompt_name")
        and _operations_subset(
            child_json.get("operations", []), parent_json.get("operations", [])
        )
    )


def _all_grants_subset(
    child_grants: list[Any] | None,
    parent_grants: list[Any] | None,
    predicate: Any,
) -> bool:
    parents = parent_grants or []
    return all(
        any(predicate(child, parent) for parent in parents)
        for child in child_grants or []
    )


def _scope_subset(child: ChioScope, parent: ChioScope) -> bool:
    return (
        _all_grants_subset(child.grants, parent.grants, _tool_grant_subset)
        and _all_grants_subset(
            child.resource_grants,
            parent.resource_grants,
            _resource_grant_subset,
        )
        and _all_grants_subset(
            child.prompt_grants,
            parent.prompt_grants,
            _prompt_grant_subset,
        )
    )


class ChioClient:
    """Async HTTP client for the Chio sidecar.

    Parameters
    ----------
    base_url:
        Base URL of the Chio sidecar (default ``http://127.0.0.1:9090``).
    timeout:
        Request timeout in seconds (default 5).
    """

    DEFAULT_BASE_URL = "http://127.0.0.1:9090"

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        self._base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> ChioClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Check sidecar health."""
        return await self._get("/chio/health")

    # ------------------------------------------------------------------
    # Capability tokens
    # ------------------------------------------------------------------

    async def create_capability(
        self,
        *,
        subject: str,
        scope: ChioScope,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Request a new capability token from the sidecar.

        Parameters
        ----------
        subject:
            Hex-encoded Ed25519 public key of the agent the token is bound to.
        scope:
            The scope (tool/resource/prompt grants) to authorize.
        ttl_seconds:
            Token lifetime in seconds.
        """
        body = {
            "subject": subject,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
        }
        data = await self._post("/v1/capabilities", body)
        return CapabilityToken.model_validate(data)

    async def validate_capability(
        self,
        token: CapabilityToken,
    ) -> bool:
        """Ask the sidecar to validate a capability token.

        Returns True if the token is valid, False otherwise.
        """
        data = await self._post(
            "/v1/capabilities/validate",
            token,
        )
        return bool(data.get("valid", False))

    async def attenuate_capability(
        self,
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        """Request capability attenuation from the sidecar fail-closed.

        The sidecar route is a control boundary, not a signer. It rejects
        attenuation because minting a child token requires the parent subject
        signer, which the sidecar must not hold.
        """
        if not _scope_subset(new_scope, token.scope):
            raise ChioValidationError(
                "new_scope must be a subset of the parent token scope"
            )
        body = {
            "parent_token": token,
            "new_scope": new_scope,
        }
        await self._post("/v1/capabilities/attenuate", body)
        raise ChioDeniedError(
            "capability attenuation requires the parent subject signer; sidecar returned unsupported success",
            reason="sidecar attenuation must fail closed until subject-signer delegation is implemented",
            reason_code="chio_attenuation_requires_subject_signer",
        )

    # ------------------------------------------------------------------
    # Receipt verification
    # ------------------------------------------------------------------

    async def _verify_receipt_integrity(self, receipt: ChioReceipt) -> bool:
        """Verify signature and structural fields without requiring mediation."""
        data = await self._post("/v1/receipts/verify", receipt)
        try:
            report = VerifyReceiptResponse.model_validate(data)
        except ValueError:
            return False
        return (
            report.signature_valid
            and report.signer_trusted
            and report.receipt_id_valid
            and report.parameter_hash_valid
        )

    async def verify_receipt(self, receipt: ChioReceipt) -> bool:
        """Ask the sidecar to verify a receipt's authority.

        Returns True only when the structured verification report authorizes
        the presented receipt. Bare ``{"valid": true}`` responses are not
        authoritative.
        """
        data = await self._post(
            "/v1/receipts/verify",
            receipt,
        )
        try:
            report = VerifyReceiptResponse.model_validate(data)
        except ValueError:
            return False
        return report.authorizes(receipt)

    async def verify_http_receipt(self, receipt: HttpReceipt) -> VerifyReceiptResponse:
        """Ask the sidecar to verify an HTTP receipt's authority."""
        data = await self._post(
            "/chio/verify",
            receipt,
        )
        return VerifyReceiptResponse.model_validate(data)

    async def verify_receipt_chain(
        self, receipts: list[ChioReceipt]
    ) -> bool:
        """Verify that a chain of receipts has contiguous content hashes.

        Each receipt's content_hash should match the SHA-256 of the canonical
        JSON of the previous receipt, forming an append-only chain.
        """
        if len(receipts) < 2:
            return True
        for i in range(1, len(receipts)):
            prev_canonical = _canonical_json(
                receipts[i - 1]
            )
            expected_hash = _sha256_hex(prev_canonical)
            if receipts[i].content_hash != expected_hash:
                return False
        return True

    # ------------------------------------------------------------------
    # Tool evaluation (sidecar proxy)
    # ------------------------------------------------------------------

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        """Require mediated tool-call authorization.

        The current sidecar tool-call route emits an audit receipt. This method
        verifies the advisory receipt's integrity, then fails closed because
        advisory evaluation is not execution authorization.
        """
        receipt = await self.evaluate_tool_call_advisory(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
        outcome = getattr(receipt.observation_outcome, "value", receipt.observation_outcome)
        if outcome == "dropped":
            raise ChioDeniedError(
                "Chio sidecar advisory evaluation refused the tool call"
            )
        raise ChioDeniedError(
            "Chio sidecar returned an advisory evaluation, not an "
            "authoritative authorization decision"
        )

    async def evaluate_tool_call_advisory(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        """Run advisory tool-call evaluation for observability only."""
        param_canonical = _canonical_json(parameters)
        param_hash = _sha256_hex(param_canonical)

        body = {
            "capability_id": capability_id,
            "tool_server": tool_server,
            "tool_name": tool_name,
            "parameters": parameters,
            "parameter_hash": param_hash,
        }
        data = await self._post("/v1/evaluate/advisory", body)
        if not _is_advisory_evaluation_wrapper(data):
            raise ChioError(
                "Chio sidecar advisory evaluation response did not use the "
                "advisory non-authorization wrapper",
                code="INVALID_RECEIPT",
            )
        receipt_payload = _wrapped_advisory_receipt_payload(data)
        receipt = ChioReceipt.model_validate(receipt_payload)
        if not _receipt_is_advisory_evaluation(receipt):
            raise ChioError(
                "Chio sidecar advisory evaluation response did not include "
                "an advisory receipt",
                code="INVALID_RECEIPT",
            )
        if not await self._verify_receipt_integrity(receipt):
            raise ChioError(
                "Chio sidecar returned an advisory evaluation receipt "
                "that failed integrity checks",
                code="INVALID_RECEIPT",
            )
        return receipt

    async def evaluate_http_request(
        self,
        *,
        request_id: str,
        method: str,
        route_pattern: str,
        path: str,
        caller: CallerIdentity,
        query: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body_hash: str | None = None,
        body_length: int = 0,
        session_id: str | None = None,
        capability_id: str | None = None,
        capability_token: str | None = None,
        model_metadata: dict[str, Any] | None = None,
        timestamp: int | None = None,
    ) -> EvaluateResponse:
        """Evaluate an HTTP request through the sidecar kernel."""
        resolved_capability_id = capability_id or _capability_id_from_token(
            capability_token
        )
        request_model = ChioHttpRequest(
            request_id=request_id,
            method=method,
            route_pattern=route_pattern,
            path=path,
            query=query or {},
            headers=headers or {},
            caller=caller,
            body_hash=body_hash,
            body_length=body_length,
            session_id=session_id,
            capability_id=resolved_capability_id,
            model_metadata=model_metadata,
            timestamp=timestamp or int(time.time()),
        )
        request_headers: dict[str, str] | None = None
        if capability_token is not None:
            request_headers = {"X-Chio-Capability": capability_token}
        data = await self._post(
            "/chio/evaluate",
            request_model,
            headers=request_headers,
        )
        result = EvaluateResponse.model_validate(data)
        if result.verdict.is_allowed:
            if not result.receipt.is_allowed:
                raise ChioError(
                    "Chio sidecar returned an allow verdict without an authorizing receipt",
                    code="INVALID_RECEIPT",
                )
            verification = await self.verify_http_receipt(result.receipt)
            if not verification.authorizes(result.receipt):
                raise ChioError(
                    "Chio sidecar returned an unverified receipt",
                    code="INVALID_RECEIPT",
                )
        return result

    # ------------------------------------------------------------------
    # HITL approval channel
    # ------------------------------------------------------------------

    async def list_pending_approvals(self) -> list[PendingApproval]:
        """List pending HITL approvals (``GET /approvals/pending``).

        Returns the ``approvals`` array from the sidecar response,
        already coerced into :class:`PendingApproval`. The companion
        ``count`` field is dropped to match the documented signature
        from the chio-hermes integration plan.
        """
        data = await self._get("/approvals/pending", allow_array=True)
        # The sidecar response is `{"approvals": [...], "count": N}`.
        # Tolerate a bare list response for forward compatibility.
        payload = (
            {"approvals": data, "count": len(data)}
            if isinstance(data, list)
            else data
        )
        listing = PendingApprovalList.model_validate(payload)
        return list(listing.approvals)

    async def get_approval(self, approval_id: str) -> Approval:
        """Fetch a single approval by id (``GET /approvals/{id}``).

        Either ``Approval.pending`` or ``Approval.resolution`` is
        populated. Raises :class:`ChioError` (HTTP_404) when the id is
        unknown.
        """
        if not approval_id:
            raise ChioValidationError("approval_id must be a non-empty string")
        data = await self._get(f"/approvals/{approval_id}")
        return Approval.model_validate(data)

    async def respond_approval(
        self,
        approval_id: str,
        verdict: ApprovalVerdict | str,
        reason: str | None = None,
    ) -> ApprovalResponse:
        """Resolve an approval via the operator-respond shortcut.

        v0.2 manual flow: posts to ``POST /approvals/{id}/operator-respond``
        which has the sidecar sign a `GovernedApprovalToken` with its
        own keypair. Use the signed `/respond` route directly when an
        external approver keypair is required.

        Parameters
        ----------
        approval_id:
            Identifier returned by :meth:`submit_for_approval` or
            surfaced via :meth:`list_pending_approvals`.
        verdict:
            ``"approve"``/``"deny"`` shorthand or a
            :class:`ApprovalVerdict` enum value.
        reason:
            Optional free-form note recorded with the resolution.
        """
        if not approval_id:
            raise ChioValidationError("approval_id must be a non-empty string")
        normalised = (
            ApprovalVerdict.from_action(verdict)
            if isinstance(verdict, str)
            else verdict
        )
        body: dict[str, Any] = {"outcome": normalised.value}
        if reason is not None:
            body["reason"] = reason
        data = await self._post(
            f"/approvals/{approval_id}/operator-respond", body
        )
        return ApprovalResponse.model_validate(data)

    async def submit_for_approval(
        self,
        *,
        capability_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_server: str | None = None,
        requested_by: str | None = None,
        ttl_seconds: int = 3600,
        summary: str | None = None,
        triggered_by: list[str] | None = None,
    ) -> str:
        """Hold a tool call in the sidecar pending human approval.

        Posts to ``POST /approvals/submit`` and returns the new
        ``approval_id``. The parameter hash is derived from the
        canonical JSON of ``tool_args`` so a later operator-respond
        binds the signature to the exact arguments the LLM proposed.

        Parameters
        ----------
        capability_id:
            Capability the agent presented for the held call.
        tool_name:
            Name of the tool being invoked (e.g. ``run_command``).
        tool_args:
            Arguments the LLM passed; used for the parameter hash and
            optional summary text. Must be JSON-serializable.
        tool_server:
            Server id (e.g. ``shell``, ``git``); defaults to a best
            guess from the tool name.
        requested_by:
            Hex Ed25519 public key of the agent that initiated the
            call. When omitted the sidecar records an anonymous
            subject marker; operator-respond will then fail because there
            is no parseable subject binding, so set this whenever the
            call originates from a real agent.
        ttl_seconds:
            Approval lifetime; clamped to 3600 by the sidecar.
        summary:
            Optional human-friendly summary surfaced in dashboards.
        triggered_by:
            Optional list of guard ids that forced the approval.
        """
        if not capability_id:
            raise ChioValidationError(
                "capability_id is required to submit an approval"
            )
        if not tool_name:
            raise ChioValidationError(
                "tool_name is required to submit an approval"
            )
        param_hash = _sha256_hex(_canonical_json(tool_args))
        body: dict[str, Any] = {
            "capability_id": capability_id,
            "tool_server": tool_server or _default_tool_server(tool_name),
            "tool_name": tool_name,
            "parameter_hash": param_hash,
            "requested_by": requested_by or "",
            "ttl_seconds": ttl_seconds,
        }
        if summary is not None:
            body["summary"] = summary
        if triggered_by:
            body["triggered_by"] = list(triggered_by)
        data = await self._post("/approvals/submit", body)
        result = SubmitApprovalResult.model_validate(data)
        return result.approval_id

    # ------------------------------------------------------------------
    # Guard evidence helpers
    # ------------------------------------------------------------------

    @staticmethod
    def collect_evidence(
        receipts: list[ChioReceipt],
    ) -> list[GuardEvidence]:
        """Collect all guard evidence from a list of receipts."""
        evidence: list[GuardEvidence] = []
        for receipt in receipts:
            evidence.extend(receipt.evidence or [])
        return evidence

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    async def _get(
        self, path: str, *, allow_array: bool = False
    ) -> dict[str, Any] | list[Any]:
        try:
            resp = await self._http.get(path)
        except httpx.ConnectError as exc:
            raise ChioConnectionError(
                f"Failed to connect to Chio sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ChioTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp, allow_array=allow_array)

    async def _post(
        self,
        path: str,
        body: Any,
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            resp = await self._http.post(path, json=_jsonable(body), headers=headers)
        except httpx.ConnectError as exc:
            raise ChioConnectionError(
                f"Failed to connect to Chio sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ChioTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(
        resp: httpx.Response, *, allow_array: bool = False
    ) -> dict[str, Any] | list[Any]:
        if resp.status_code == 403:
            try:
                data = resp.json()
            except Exception:
                body = resp.text.strip()
                data = {
                    "message": "denied",
                    "reason": body[:200] if body else "Chio sidecar returned 403",
                    "reason_code": "HTTP_403",
                }
            if not isinstance(data, dict):
                data = {"message": "denied", "reason": str(data), "reason_code": "HTTP_403"}
            raise ChioDeniedError(
                data.get("message", "denied"),
                guard=data.get("guard"),
                reason=data.get("reason") or data.get("error"),
                reason_code=data.get("reason_code") or data.get("error"),
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise ChioError(
                f"Chio sidecar returned {resp.status_code}: {detail}",
                code=f"HTTP_{resp.status_code}",
            )
        try:
            data = resp.json()
        except Exception as exc:
            raise ChioError(
                "Chio sidecar returned malformed JSON response",
                code="INVALID_RESPONSE",
            ) from exc
        if allow_array and isinstance(data, list):
            return data
        if not isinstance(data, dict):
            raise ChioError(
                f"Chio sidecar returned invalid JSON response: {data!r}",
                code="INVALID_RESPONSE",
            )
        return data
