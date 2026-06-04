# hello-django Architecture

## Owning Boundary

`hello-django` owns the Django middleware-style HTTP example for Chio. It uses
`chio-django` as the in-process request interceptor while keeping the Django
views themselves focused on application payload handling and receipt display.

This package owns:

- `hello_project/settings.py`: Django settings and Chio middleware wiring.
- `hello_project/urls.py`: the public route table.
- `hello_app/views.py`: the teaching routes and payload validation.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher.
- `smoke.sh`: the end-to-end trust authority, sidecar, Django app,
  capability, and receipt-persistence flow.
- `pyproject.toml` and `uv.lock`: the package-local Python dependency closure.

## Runtime Shape

The app has three routes:

- `GET /healthz` bypasses Chio and exists only for readiness checks.
- `GET /hello` is evaluated by the sidecar and returns the receipt id attached
  to the Django request by `ChioDjangoMiddleware`.
- `POST /echo` is evaluated by the sidecar, requires a capability token, and
  proves the Django request body remains readable after middleware hashing.

`ChioDjangoMiddleware` reads its sidecar URL and receipt header from Django
settings, calls `/chio/evaluate`, verifies the returned receipt through
`/chio/verify`, stores receipt data on the request, and attaches
`X-Chio-Receipt` to accepted responses.

## Architectural Constraints

- Health checks must remain excluded from Chio evaluation.
- `CHIO_FAIL_OPEN` must stay `False`.
- Views must not issue or validate Chio capability tokens directly.
- The `/echo` request schema in `views.py` and `openapi.yaml` must stay
  aligned.
- Smoke evidence must prove all three HTTP decisions and persisted sidecar
  receipts.
- Route tests must be able to run with Chio middleware disabled so Django
  payload behavior is tested without a live sidecar.

## Current Improvement Target

The example currently mixes untyped JSON extraction into the view, accepts
coerced or partial `/echo` payloads that the sidecar contract does not describe,
and uses an outdated smoke capability grant. The package needs a stricter
Django route boundary plus an end-to-end smoke flow that matches the current
HTTP authority contract and sidecar receipt store.
