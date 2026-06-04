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

## Current Pain Points

- `app.py` mixes HTTP method dispatch, JSON serialization, content-length
  parsing, request-body reading, JSON decoding, and echo payload validation in
  one handler class.
- The smoke script proves sidecar allow, deny, and receipt persistence, but the
  upstream app has no local tests for malformed direct requests.
- The current `content-length` path coerces invalid values to zero and does not
  reject negative or oversized bodies before reading from the request stream.
  That is a poor teaching boundary for an upstream app sitting behind a
  fail-closed sidecar.
- `openapi.yaml` describes `message` and `count`, but the app-level validation
  contract is not independently testable.

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

## Planned Improvement

Move request-body and echo-payload validation into explicit app-level
boundaries, reject negative and oversized `Content-Length` values before body
reads, and add standard-library unit tests for valid echo payloads, malformed
JSON, invalid content lengths, oversized bodies, and plain-app responses. This
is architectural because it separates upstream HTTP parsing from sidecar
governance and makes the no-Chio plain-app contract independently testable.
