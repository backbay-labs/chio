# hello-openapi-sidecar Architecture

## Owning Boundary

`examples/hello-openapi-sidecar` owns the first supported web-backend adoption
path. It keeps the upstream application plain and places all Chio governance in
`chio api protect`, driven by `openapi.yaml` and a trust-issued capability.

The package owns:

- `app.py`: the plain upstream Python HTTP server.
- `openapi.yaml`: the API description consumed by the sidecar.
- `run.sh`: the app-only launch path.
- `smoke.sh`: the full trust service plus sidecar verification flow.

There is no package manager manifest in this example. It intentionally uses
only the Python standard library so the first web-backend smoke path has no app
SDK, middleware, or dependency installation step.

## Security And API Constraints

- Preserve the plain-upstream contract: `app.py` must not import Chio modules,
  parse Chio capability tokens, inspect receipt headers, or enforce Chio policy.
- Preserve the documented routes: `GET /healthz`, `GET /hello`, and `POST
  /echo`.
- Preserve the sidecar smoke behavior: safe route allows, governed route denies
  without a capability, governed route allows with a capability, and all three
  paths emit persisted receipts.
- Preserve JSON response shapes used by `smoke.sh`: `message`, `count`,
  `handled_by`, and `chio_sdk` on allowed echo responses; `chio_sdk: false` on
  the upstream hello response.
- Fail closed on malformed upstream request bodies without changing Chio
  authorization semantics.

## Affected Dependents

The direct dependents are:

- `examples/run-hello-smokes.sh`, which runs `hello-openapi-sidecar` first.
- `docs/guides/WEB_BACKEND_QUICKSTART.md`, which points to this example as the
  sidecar-first path.
- `examples/README.md` and `examples/EXAMPLE_SURFACE_MATRIX.md`, which describe
  the example surface.

No Chio crate should require code changes. Any transitive edits should be
limited to package-local docs or smoke expectations if a validated response
shape changes.
