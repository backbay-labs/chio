# hello-fastify Architecture

## Owning Boundary

`hello-fastify` owns the Fastify plugin-style HTTP example for Chio. It uses
`@chio-protocol/fastify` as the in-process request interceptor while keeping
the app routes focused on payload handling and receipt display.

This package owns:

- `server.mjs`: Fastify app construction, route registration, payload
  validation, and production startup.
- `openapi.yaml`: the sidecar contract for the same HTTP surface.
- `run.sh`: the app-only launcher.
- `smoke.sh`: the end-to-end trust authority, sidecar, Fastify app,
  capability, and receipt-persistence flow.
- `package.json`: the package-local runtime and test commands.

## Runtime Shape

The app has three routes:

- `GET /healthz` bypasses Chio and exists only for readiness checks.
- `GET /hello` is evaluated by the Fastify plugin and returns the receipt id
  attached to the request.
- `POST /echo` is evaluated by the plugin, requires a capability token, and
  proves the parsed Fastify body remains available after Chio interception.

The Fastify plugin calls the sidecar over `/chio/evaluate`, verifies accepted
receipts, stores the result on `request.chioResult`, and attaches
`X-Chio-Receipt-Id` to accepted responses.

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

## Current Improvement Target

The example currently starts from a top-level script, so route behavior cannot
be tested without booting a sidecar. It also echoes arbitrary request body
fields despite declaring only `message` and `count` in OpenAPI, and its smoke
flow uses an outdated capability grant plus a receipt-list path that does not
match the sidecar HTTP receipt store.
