# hello-fastapi Architecture

## Owning Boundary

`hello-fastapi` owns the framework-native Python HTTP path for Chio. It wraps a
FastAPI application with `chio-asgi`, delegates authorization decisions to a
local `chio api protect` sidecar, and keeps the application itself free of
trust-control logic.

This package owns:

- `app.py`: the FastAPI routes, request schema, and Chio middleware wiring.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher.
- `smoke.sh`: the end-to-end trust authority, sidecar, app, capability, and
  receipt-persistence flow.
- `pyproject.toml` and `uv.lock`: the package-local Python dependency closure.

## Runtime Shape

The app has three routes:

- `GET /healthz` bypasses Chio and exists only for readiness checks.
- `GET /hello` is evaluated by the sidecar and allowed without a capability.
- `POST /echo` is evaluated by the sidecar and requires a capability token.

FastAPI serves the upstream app. `ChioASGIMiddleware` intercepts inbound
requests, calls the sidecar over `/chio/evaluate`, denies failed evaluations,
and attaches the configured receipt header to accepted responses. The FastAPI
code does not issue, parse, or validate Chio capabilities directly.

## Architectural Constraints

- Health checks must remain excluded from Chio evaluation.
- The middleware is unconditionally fail-closed: if the sidecar is unreachable, requests are denied.
- The app may depend on the sidecar URL only through `CHIO_SIDECAR_URL` or an
  injected `ChioASGIConfig`.
- The `/echo` request schema in `app.py` and `openapi.yaml` must remain aligned.
- Smoke evidence must prove all three HTTP decisions and persisted sidecar
  receipts.
