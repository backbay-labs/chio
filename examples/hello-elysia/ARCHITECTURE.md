# hello-elysia Architecture

## Owning Boundary

`hello-elysia` owns the Elysia lifecycle-hook HTTP example for Chio. It uses
`@chio-protocol/elysia` as the in-process request interceptor while keeping the
application routes focused on payload handling and the plugin's header-first
receipt contract.

This package owns:

- `server.mjs`: Elysia app construction, route registration, payload
  validation, Node HTTP bridge, and production startup.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher plus local SDK build bootstrap.
- `smoke.sh`: the end-to-end trust authority, sidecar, Elysia app,
  capability, and receipt-persistence flow.
- `package.json`: the package-local runtime and test commands.

## Runtime Shape

The app has three routes:

- `GET /healthz` bypasses Chio and exists only for readiness checks.
- `GET /hello` is evaluated by the Elysia plugin and returns the greeting body.
- `POST /echo` is evaluated by the plugin, requires a capability token, and
  returns the validated JSON echo payload.

The Elysia plugin calls the sidecar over `/chio/evaluate`, verifies accepted
receipts, and attaches `X-Chio-Receipt-Id` to accepted responses. Unlike the
Express and Fastify examples, this route surface does not expose the receipt id
inside handler return bodies.

## Architectural Constraints

- Health checks must remain skipped by Chio evaluation.
- The app must keep fail-closed plugin behavior for governed routes.
- Routes must not issue or validate Chio capability tokens directly.
- The `/echo` request schema in `server.mjs` and `openapi.yaml` must stay
  aligned.
- Smoke evidence must prove all three HTTP decisions and persisted sidecar
  receipts.
- Route tests must be able to run with Chio disabled so app payload behavior is
  verified without a live sidecar.
- The Node HTTP bridge must preserve request headers and raw body bytes so the
  Elysia plugin can hash bodies and read `X-Chio-Capability`.

## Current Improvement Target

The example currently starts from a top-level script, so route behavior cannot
be tested without booting a sidecar. It also echoes arbitrary request body
fields despite declaring only `message` and `count` in OpenAPI, and its smoke
flow uses an outdated capability grant plus a receipt-list path that does not
match the sidecar HTTP receipt store.
