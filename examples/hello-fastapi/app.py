from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from chio_asgi import ChioASGIMiddleware
from chio_asgi.config import ChioASGIConfig


class EchoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: StrictStr = Field(min_length=1)
    count: StrictInt = Field(default=1, ge=1)


def build_chio_config(sidecar_url: str | None = None) -> ChioASGIConfig:
    return ChioASGIConfig(
        sidecar_url=sidecar_url
        or os.environ.get("CHIO_SIDECAR_URL", "http://127.0.0.1:9090"),
        exclude_paths=frozenset({"/healthz"}),
    )


def create_app(
    *,
    enable_chio: bool = True,
    chio_config: ChioASGIConfig | None = None,
) -> FastAPI:
    app = FastAPI(
        title="hello-fastapi",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    if enable_chio:
        app.add_middleware(
            ChioASGIMiddleware,
            config=chio_config or build_chio_config(),
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/hello")
    async def hello() -> dict[str, str]:
        return {"message": "hello from fastapi"}

    @app.post("/echo")
    async def echo(payload: EchoRequest) -> dict[str, object]:
        return {
            "message": payload.message,
            "count": payload.count,
        }

    return app


app = create_app()
