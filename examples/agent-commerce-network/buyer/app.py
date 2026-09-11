from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from threading import RLock, local
from typing import Any, Literal, Protocol

import httpx
from chio.invariants import canonicalize_json, sha256_hex_utf8, verify_receipt_with_trusted_signers
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

try:
    from .store import ProcurementStore
except ImportError:
    from store import ProcurementStore


CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"
PROTOCOL_VERSION = "2025-11-25"
DEFAULT_APPROVAL_THRESHOLD_MINOR = 100_000
DEFAULT_BUDGET_MINOR = 150_000
DEFAULT_BUYER_ID = "lattice-platform-security"
DEFAULT_PROVIDER_ID = "vanguard-security"


def contract_template(name: str) -> dict[str, Any]:
    return json.loads((CONTRACTS_DIR / name).read_text())


def random_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class QuoteRequestPayload(BaseModel):
    service_family: str = Field(pattern="^security-review$")
    target: str = Field(min_length=1, max_length=500)
    requested_scope: Literal[
        "hotfix-review", "release-review", "release-plus-cloud-review", "full-estate-review"
    ]
    release_window: str | None = Field(default=None, max_length=200)


class CreateJobPayload(BaseModel):
    quote_id: str = Field(min_length=1, max_length=200)
    provider_id: str = Field(min_length=1, max_length=200)
    service_family: Literal["security-review"]
    budget_minor: int | None = Field(default=None, ge=0)


class ApprovalPayload(BaseModel):
    approver: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


class DisputePayload(BaseModel):
    reason_code: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=2000)


class ProviderGateway(Protocol):
    def request_quote(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def execute_review(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    def open_dispute(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class ProviderReviewClient:
    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
        trusted_kernel_key: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.trusted_kernel_key = trusted_kernel_key
        self.auth_token = auth_token
        self.client = client or httpx.Client(timeout=timeout)
        self._trace = local()
        self._lock = RLock()
        self._session_id: str | None = None
        self._sequence = 1

    @property
    def last_trace(self) -> dict[str, Any] | None:
        return getattr(self._trace, "value", None)

    def request_quote(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("request_quote", payload)

    def execute_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("execute_review", payload)

    def open_dispute(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("open_dispute", payload)

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._trace.value = None
            if self._session_id is None:
                self._session_id = self._initialize_session()
                self._post_mcp(
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    session_id=self._session_id,
                    expect_response=False,
                )
            self._sequence += 1
            payload = self._post_mcp(
                {
                    "jsonrpc": "2.0",
                    "id": self._sequence,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                session_id=self._session_id,
                expect_response=True,
            )
            if payload.get("id") != self._sequence or "error" in payload:
                raise RuntimeError("Provider response did not complete the requested MCP operation")
            result = payload.get("result", {})
            metadata = result.get("_meta", {}).get("chioReceipt", {})
            receipt_id, request_id = metadata.get("receiptId"), metadata.get("requestId")
            if not receipt_id or not request_id:
                raise RuntimeError(
                    "Provider response is missing its authoritative receipt association"
                )
            capability_ids = self._session_capability_ids(self._session_id)
            mapped_result = {
                key: result[key]
                for key in ("content", "structuredContent", "isError")
                if key in result
            }
            mapped_result.setdefault("content", [])
            mapped_result.setdefault("isError", False)
            self._trace.value = {
                "tool_name": name,
                "session_id": self._session_id,
                "capability_ids": sorted(capability_ids),
                "result": mapped_result,
                "receipt_id": receipt_id,
                "request_id": request_id,
                "arguments": arguments,
                "is_error": bool(result.get("isError")),
                "edge_base_url": self.base_url,
            }
            receipt = self._verified_receipt(
                receipt_id, request_id, capability_ids, name, arguments, mapped_result
            )
            self._trace.value["receipt"] = receipt
            self._trace.value["capability_id"] = receipt["capability_id"]
            if result.get("isError"):
                raise RuntimeError(
                    f"Provider refused or failed the operation; receipt {receipt_id}"
                )
            structured = result.get("structuredContent")
            if not isinstance(structured, dict):
                raise RuntimeError("Provider result is missing its structured work product")
            return deepcopy(structured)

    def _verified_receipt(self, identity, request_id, capability_ids, name, arguments, result):
        if not self.trusted_kernel_key or not capability_ids:
            raise RuntimeError("Configure the provider kernel key before accepting its work")
        response = self.client.get(
            self.base_url + "/admin/receipts/tools",
            headers={"Authorization": "Bearer " + self.auth_token},
            params={"receiptId": identity},
        )
        response.raise_for_status()
        receipts = response.json().get("receipts", [])
        matches = [receipt for receipt in receipts if receipt.get("id") == identity]
        if len(matches) != 1:
            raise RuntimeError(
                "The exact provider receipt is not available; do not settle this job"
            )
        receipt = matches[0]
        checks = verify_receipt_with_trusted_signers(receipt, [self.trusted_kernel_key])
        if not checks["ok"] or receipt["metadata"]["receipt_context"]["request_id"] != request_id:
            raise RuntimeError(
                "Provider receipt is invalid, untrusted or belongs to another request"
            )
        if (
            receipt["action"]["parameters"] != arguments
            or receipt["tool_name"] != name
            or receipt["capability_id"] not in capability_ids
        ):
            raise RuntimeError("Provider receipt does not match the requested operation")
        if receipt["decision"]["verdict"] == "allow":
            if sha256_hex_utf8(canonicalize_json(result)) != receipt["content_hash"]:
                raise RuntimeError("Provider result does not match its signed output hash")
        elif not result.get("isError"):
            raise RuntimeError("Provider reported success for a refused operation")
        return receipt

    def _initialize_session(self) -> str:
        response = self._post_raw(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agent-commerce-network-buyer",
                        "version": "0.1.0",
                    },
                },
            }
        )
        _ = self._decode_response(response)
        session_id = response.headers.get("MCP-Session-Id")
        if not session_id:
            raise RuntimeError("provider edge did not return MCP-Session-Id")
        return session_id

    def _post_mcp(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        expect_response: bool,
    ) -> dict[str, Any]:
        response = self._post_raw(payload, session_id=session_id)
        if not expect_response or not response.text.strip():
            return {}
        return self._decode_response(response)

    def _post_raw(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if session_id:
            headers["MCP-Session-Id"] = session_id
        response = self.client.post(f"{self.base_url}/mcp", headers=headers, json=payload)
        if response.is_error:
            raise RuntimeError(
                f"Provider MCP transport failed (HTTP {response.status_code}): {response.text[:2000]}"
            )
        return response

    def _session_capability_ids(self, session_id: str) -> set[str]:
        response = self.client.get(
            f"{self.base_url}/admin/sessions/{session_id}/trust",
            headers={"Authorization": f"Bearer {self.auth_token}"},
        )
        response.raise_for_status()
        return {item["capabilityId"] for item in response.json().get("capabilities", [])}

    @staticmethod
    def _decode_response(response: httpx.Response) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        data_lines: list[str] = []
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line:
                if data_lines:
                    break
                continue
            if line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
        if not data_lines:
            raise RuntimeError("no JSON-RPC payload received from provider edge")
        return json.loads("\n".join(data_lines))


class ProcurementService:
    def __init__(
        self,
        provider: ProviderGateway,
        *,
        buyer_id: str = DEFAULT_BUYER_ID,
        default_budget_minor: int = DEFAULT_BUDGET_MINOR,
        database: str = ":memory:",
    ) -> None:
        self.provider = provider
        self.buyer_id = buyer_id
        self.default_budget_minor = default_budget_minor
        self.store = ProcurementStore(database, default_budget_minor)

    def submit_quote_request(self, payload: QuoteRequestPayload) -> dict[str, Any]:
        request_id = random_id("quote_req")
        quote = self.provider.request_quote(
            {"request_id": request_id, "buyer_id": self.buyer_id, **payload.model_dump()}
        )
        if (
            quote.get("request_id") != request_id
            or quote.get("service_family") != payload.service_family
            or type(quote.get("price_minor")) is not int
            or quote["price_minor"] <= 0
            or quote.get("currency") != "USD"
            or not quote.get("quote_id")
            or quote.get("provider_id") != DEFAULT_PROVIDER_ID
            or quote.get("offer_id") != payload.requested_scope
            or quote.get("target") != payload.target
        ):
            raise ValueError(
                "Provider quote does not match the request or supported monetary terms"
            )
        # The buyer owns its approval threshold; the provider cannot waive it.
        quote["approval_required"] = quote["price_minor"] > DEFAULT_APPROVAL_THRESHOLD_MINOR
        record = {
            "request_id": request_id,
            "request": payload.model_dump(),
            "quote": quote,
            "provider_trace": self._provider_trace(),
        }
        with self.store.transaction() as db:
            db.execute("INSERT INTO quotes VALUES(?,?)", (quote["quote_id"], json.dumps(record)))
        return {
            "request_id": request_id,
            "status": "quoted",
            "quote": quote,
            "provider_trace": record["provider_trace"],
        }

    def create_job(self, payload: CreateJobPayload) -> dict[str, Any]:
        with self.store.transaction() as db:
            record = self.store.load(db, "quotes", payload.quote_id)
            quote = record["quote"]
            if (
                payload.provider_id != quote.get("provider_id", DEFAULT_PROVIDER_ID)
                or payload.service_family != quote["service_family"]
            ):
                raise ValueError("Provider and service must match the accepted quote")
            if db.execute("SELECT 1 FROM jobs WHERE quote_id=?", (payload.quote_id,)).fetchone():
                raise ValueError("This quote has already been consumed; inspect the existing job")
            budget = (
                self.store.capacity(db) if payload.budget_minor is None else payload.budget_minor
            )
            if budget > self.store.capacity(db):
                raise ValueError("A caller cannot increase the operator budget")
            job = {
                "job_id": random_id("job"),
                "buyer_id": self.buyer_id,
                "provider_id": payload.provider_id,
                "service_family": payload.service_family,
                "budget_minor": budget,
                "quote": quote,
                "requested_scope": record["request"]["requested_scope"],
                "target": record["request"]["target"],
                "release_window": record["request"]["release_window"],
                "status": "ready",
                "approval_required": quote["approval_required"],
                "approval": None,
                "fulfillment": None,
                "fulfillment_trace": None,
                "settlement": None,
                "disputes": [],
                "quote_provider_trace": record["provider_trace"],
            }
            if quote["price_minor"] > min(budget, self.store.available(db)):
                job.update(
                    status="denied_budget",
                    denial_reason="Quoted work exceeds the requested or remaining operator budget",
                )
            else:
                db.execute(
                    "INSERT INTO positions VALUES(?,?,?)",
                    (job["job_id"], quote["price_minor"], "reserved"),
                )
                if quote["approval_required"]:
                    job["status"] = "pending_approval"
            db.execute(
                "INSERT INTO jobs VALUES(?,?,?)", (job["job_id"], payload.quote_id, json.dumps(job))
            )
        if job["status"] == "ready":
            self._execute_job(job["job_id"])
        return self.get_job(job["job_id"])

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self.store.transaction() as db:
            return self.store.load(db, "jobs", job_id)

    def approve_job(self, job_id: str, payload: ApprovalPayload) -> dict[str, Any]:
        with self.store.transaction() as db:
            job = self.store.load(db, "jobs", job_id)
            if job["status"] != "pending_approval":
                raise ValueError("Job is not waiting for approval")
            job["approval"] = {
                "approver": payload.approver,
                "reason": payload.reason,
                "status": "approved",
            }
            job["status"] = "ready"
            self.store.save_job(db, job)
        self._execute_job(job_id)
        return self.get_job(job_id)

    def dispute_job(self, job_id: str, payload: DisputePayload) -> dict[str, Any]:
        with self.store.transaction() as db:
            job = self.store.load(db, "jobs", job_id)
            if job["status"] != "fulfilled":
                raise ValueError("Only fulfilled jobs can open a dispute")
            job["status"] = "dispute_submitting"
            self.store.save_job(db, job)
        # A failed or ambiguous provider response leaves the durable submission
        # state for investigation. It never pretends the debit was reversed.
        dispute = self.provider.open_dispute({"job_id": job_id, **payload.model_dump()})
        with self.store.transaction() as db:
            job = self.store.load(db, "jobs", job_id)
            job["disputes"].append({"record": dispute, "provider_trace": self._provider_trace()})
            job["status"] = "disputed"
            job["settlement"].update(
                status="reversal_pending",
                buyer_position="contested",
                provider_position="review_requested",
            )
            self.store.save_job(db, job)
        return job

    def _execute_job(self, job_id: str) -> None:
        with self.store.transaction() as db:
            job = self.store.load(db, "jobs", job_id)
            if job["status"] != "ready":
                raise ValueError("Job is already dispatched or is not authorized")
            job["status"] = "executing"
            self.store.save_job(db, job)
        try:
            fulfillment = self.provider.execute_review(
                {
                    "job_id": job_id,
                    "quote_id": job["quote"]["quote_id"],
                    "service_family": job["service_family"],
                    "requested_scope": job["requested_scope"],
                    "target": job["target"],
                    "release_window": job["release_window"],
                }
            )
            if fulfillment.get("job_id") != job_id or fulfillment.get("status") not in {
                "completed",
                "completed_with_findings",
            }:
                raise ValueError("Provider did not return completed work for this job")
            expected_terms = {
                "quote_id": job["quote"]["quote_id"],
                "service_family": job["service_family"],
                "requested_scope": job["requested_scope"],
                "target": job["target"],
            }
            if any(fulfillment.get(key) != value for key, value in expected_terms.items()):
                raise ValueError("Delivered work does not match the accepted quote and target")
            artifacts = fulfillment.get("artifacts", [])
            if not artifacts or {item["name"] for item in artifacts} != set(
                fulfillment.get("deliverables", [])
            ):
                raise ValueError("Provider fulfillment is missing its actual deliverables")
            for artifact in artifacts:
                if hashlib.sha256(artifact["content"].encode()).hexdigest() != artifact["sha256"]:
                    raise ValueError("Provider artifact digest mismatch")
        except Exception as error:
            with self.store.transaction() as db:
                job = self.store.load(db, "jobs", job_id)
                job.update(
                    status="outcome_unknown",
                    error=str(error),
                    fulfillment_trace=self._provider_trace(),
                )
                self.store.save_job(db, job)
            return
        with self.store.transaction() as db:
            job = self.store.load(db, "jobs", job_id)
            amount = job["quote"]["price_minor"]
            entries = [
                {"account": self.buyer_id, "amount_minor": -amount},
                {"account": job["provider_id"], "amount_minor": amount},
            ]
            for entry in entries:
                db.execute(
                    "INSERT INTO ledger VALUES(?,?,?)",
                    (job_id, entry["account"], entry["amount_minor"]),
                )
            db.execute(
                "UPDATE positions SET status='settled' WHERE job_id=? AND status='reserved'",
                (job_id,),
            )
            job["settlement"] = {
                "settlement_id": f"settlement_{job_id}",
                "job_id": job_id,
                "quoted_amount_minor": amount,
                "approved_amount_minor": amount,
                "settled_amount_minor": amount,
                "currency": job["quote"]["currency"],
                "status": "reconciled",
                "settlement_kind": "internal_book_entry",
                "entries": entries,
                "buyer_position": "accepted",
                "provider_position": "accepted",
                "remaining_budget_minor": self.store.available(db),
            }
            job.update(
                fulfillment=fulfillment,
                fulfillment_trace=self._provider_trace(),
                status="fulfilled",
            )
            self.store.save_job(db, job)

    def _provider_trace(self) -> dict[str, Any] | None:
        trace = getattr(self.provider, "last_trace", None)
        return deepcopy(trace) if trace is not None else None


class UnconfiguredProvider:
    def request_quote(self, payload):
        raise RuntimeError(
            "Set BUYER_PROVIDER_BASE_URL and BUYER_PROVIDER_AUTH_TOKEN to the governed provider edge"
        )


def provider_from_env() -> ProviderGateway:
    provider_base_url = os.environ.get("BUYER_PROVIDER_BASE_URL")
    provider_auth_token = os.environ.get("BUYER_PROVIDER_AUTH_TOKEN")
    if provider_base_url:
        if not provider_auth_token or not os.environ.get("BUYER_PROVIDER_KERNEL_KEY"):
            raise ValueError(
                "Configure the provider credential and its independently selected kernel key"
            )
        return ProviderReviewClient(
            base_url=provider_base_url,
            auth_token=provider_auth_token,
            trusted_kernel_key=os.environ.get("BUYER_PROVIDER_KERNEL_KEY"),
        )
    return UnconfiguredProvider()


def build_service(provider: ProviderGateway | None = None) -> ProcurementService:
    buyer_id = os.environ.get("BUYER_ID", DEFAULT_BUYER_ID)
    default_budget_minor = int(
        os.environ.get("BUYER_DEFAULT_BUDGET_MINOR", str(DEFAULT_BUDGET_MINOR))
    )
    return ProcurementService(
        provider or provider_from_env(),
        buyer_id=buyer_id,
        default_budget_minor=default_budget_minor,
        database=":memory:"
        if provider is not None
        else os.environ.get("BUYER_STATE_DB", str(CONTRACTS_DIR.parent / ".state" / "buyer.db")),
    )


def create_app(provider: ProviderGateway | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        service = build_service(provider)
        app.state.procurement_service = service
        try:
            yield
        finally:
            service.store.db.close()
            if isinstance(service.provider, ProviderReviewClient):
                service.provider.client.close()

    app = FastAPI(
        lifespan=lifespan,
        title="Lattice Procurement API",
        version="0.1.0",
        description="Buyer-side procurement service for the agent-commerce-network example.",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        mode = (
            "wrapped-mcp-provider"
            if isinstance(app.state.procurement_service.provider, ProviderReviewClient)
            else "unconfigured"
        )
        if isinstance(app.state.procurement_service.provider, UnconfiguredProvider):
            raise HTTPException(
                status_code=503, detail="Configure the governed provider before accepting jobs"
            )
        return {"status": "ok", "provider_mode": mode}

    @app.post("/procurement/quote-requests", status_code=202)
    def request_quote(payload: QuoteRequestPayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        return service.submit_quote_request(payload)

    @app.post("/procurement/jobs", status_code=202)
    def create_job(payload: CreateJobPayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.create_job(payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/procurement/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.get_job(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc

    @app.post("/procurement/jobs/{job_id}/approve")
    def approve_job(job_id: str, payload: ApprovalPayload, request: Request) -> dict[str, Any]:
        expected = os.environ.get("BUYER_APPROVAL_TOKEN", "")
        actual = request.headers.get("X-Buyer-Approval", "")
        if not expected or not secrets.compare_digest(expected, actual):
            raise HTTPException(
                status_code=403, detail="An independent operator approval credential is required"
            )
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.approve_job(job_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/procurement/jobs/{job_id}/disputes", status_code=202)
    def dispute_job(job_id: str, payload: DisputePayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.dispute_job(job_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc

    @app.exception_handler(ValueError)
    async def invalid_operation(request: Request, error: ValueError):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=409, content={"detail": str(error)})

    @app.exception_handler(RuntimeError)
    @app.exception_handler(httpx.HTTPError)
    async def provider_failure(request: Request, error: Exception):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=502,
            content={
                "detail": str(error),
                "recovery": "Inspect the retained job and provider receipt before retrying an operation",
            },
        )

    return app


app = create_app()
