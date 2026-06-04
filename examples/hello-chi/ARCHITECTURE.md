# hello-chi Architecture

## Owning Boundary

`hello-chi` owns the Go `chi` HTTP framework example for Chio. It uses
`chio-go-http` as a `net/http` middleware around a small Chi router while
keeping the route handlers focused on payload handling and response shape.

This package owns:

- `main.go`: Chi route construction, payload validation, Chio middleware
  wrapping, and production startup.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher.
- `smoke.sh`: the end-to-end trust authority, sidecar, Chi app, capability,
  and receipt-persistence flow.
- `go.mod` and `go.sum`: the package-local Go dependency closure.

## Runtime Shape

The app has three routes:

- `GET /healthz` exists for readiness checks.
- `GET /hello` is evaluated by `chio-go-http` and returns the app greeting.
- `POST /echo` is evaluated by `chio-go-http`, requires a capability token,
  and echoes a validated JSON payload.

The runtime handler wraps the Chi router with `chio.Protect`, which calls the
sidecar over `/chio/evaluate`, verifies accepted receipts through
`/chio/verify`, denies failed evaluations, and attaches `X-Chio-Receipt-Id` to
accepted responses.

## Architectural Constraints

- Route tests must be able to exercise the Chi router without the Chio
  middleware or a live sidecar.
- Production startup must keep the fail-closed `chio-go-http` middleware on
  governed routes.
- Handlers must not issue or validate Chio capability tokens directly.
- The `/echo` request schema in `main.go` and `openapi.yaml` must stay aligned.
- Smoke evidence must prove all three HTTP decisions and persisted sidecar
  receipts.

## Current Improvement Target

The example currently builds the router only inside `main`, so route behavior
cannot be tested without booting the Chio sidecar. It also accepts missing or
zero-valued `/echo` fields that the OpenAPI contract does not describe, and
its smoke flow uses an outdated capability grant plus a receipt-list path that
does not match the sidecar HTTP receipt store.
