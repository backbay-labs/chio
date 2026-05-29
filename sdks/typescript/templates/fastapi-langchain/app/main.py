"""FastAPI app wrapping a LangChain agent with Chio verdict gating.

The agent itself is LangChain-native; the ``/chat`` route consults a
local evaluator before forwarding the user message and records a
receipt either way. The static viewer at ``/receipts`` reads the local
sink. The first-run happy path runs without any outbound network call
beyond an explicitly configured upstream provider.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .receipt_sink import Receipt, get_local_receipt_sink

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="Chio fastapi-langchain template")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ChatRequest(BaseModel):
    message: str


class ChioEvaluation(BaseModel):
    verdict: str = "allow"
    reason_code: str | None = None
    receipt_id: str | None = None


def _default_evaluator(_: ChatRequest) -> ChioEvaluation:
    """Static allow evaluator; replace with the kernel shim to enforce."""

    return ChioEvaluation(verdict="allow")


_evaluator: Callable[[ChatRequest], ChioEvaluation] = _default_evaluator


def set_evaluator(evaluator: Callable[[ChatRequest], ChioEvaluation]) -> None:
    """Test hook for swapping the evaluator without monkey-patching globals."""

    global _evaluator
    _evaluator = evaluator


def _next_receipt_id() -> str:
    sink = get_local_receipt_sink()
    return f"local-receipt-{len(tuple(sink.list())):04d}"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/receipts")
def receipts() -> JSONResponse:
    sink = get_local_receipt_sink()
    payload: list[dict[str, Any]] = [
        {
            "id": receipt.id,
            "verdict": receipt.verdict,
            "source": receipt.source,
            "captured_at_iso": receipt.captured_at_iso,
        }
        for receipt in sink.list()
    ]
    return JSONResponse({"receipts": payload})


@app.post("/chat")
def chat(req: ChatRequest) -> JSONResponse:
    evaluation = _evaluator(req)
    sink = get_local_receipt_sink()
    receipt = Receipt(
        id=evaluation.receipt_id or _next_receipt_id(),
        verdict=evaluation.verdict,
        source="/chat",
        captured_at_iso=_now_iso(),
    )
    sink.record(receipt)
    if evaluation.verdict != "allow":
        body = {
            "error": "chio_denied",
            "reason_code": evaluation.reason_code,
            "receipt_id": receipt.id,
        }
        return JSONResponse(body, status_code=403)
    return JSONResponse(
        {
            "reply": f"echo: {req.message}",
            "receipt_id": receipt.id,
        }
    )
