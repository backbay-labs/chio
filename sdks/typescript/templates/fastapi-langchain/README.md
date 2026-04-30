# fastapi-langchain

```bash
npx create-chio-app fastapi-langchain
```

Python FastAPI + LangChain agent + static receipts viewer template. The
`/chat` route runs a Chio evaluator before forwarding the user message
to the agent and records a receipt either way. The receipts viewer is
served from `/static/index.html` and reads the in-memory sink. No
outbound network calls run during the first-run TTFRH bench.

## Layout

| Path                          | Role                                              |
|-------------------------------|---------------------------------------------------|
| `app/main.py`                 | FastAPI app: `/chat`, `/receipts`, `/health`      |
| `app/receipt_sink.py`         | Telemetry-free in-memory receipt sink             |
| `static/index.html`           | Static receipts viewer (no network egress)        |
| `chio.yaml`                   | Template manifest consumed by `create-chio-app`   |
| `pyproject.toml`              | UV-managed dependency manifest (FastAPI + opt LangChain) |

## Telemetry-free first run

The local sink lives in process memory. The TTFRH bench
(`bench/ttfrh/runners/fastapi_langchain.rs`) wraps the run in the
network sentinel and asserts zero unsanctioned hostnames during
bootstrap and the first `/chat` call.

## Single-command bootstrap

```bash
npx create-chio-app fastapi-langchain
cd fastapi-langchain
uv sync
uv run uvicorn app.main:app --reload
```

`POST http://127.0.0.1:8000/chat` with `{"message":"hi"}` and then open
`http://127.0.0.1:8000/static/index.html` to see the receipt list.
