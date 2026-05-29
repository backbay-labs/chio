# hello-openapi-sidecar

Minimal spec-driven HTTP example using `chio api protect` directly in front of a plain upstream app.

The upstream app has no Chio framework SDK or middleware. All governance, deny behavior, and receipt capture happen in the OpenAPI sidecar.

This is the recommended first web-backend example. Start here before moving to
framework-specific integrations.

## What It Demonstrates

- `GET /hello` is allowed through the sidecar and returns a Chio receipt header
- `POST /echo` is denied by the sidecar without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- the app itself is a plain Python HTTP server with no Chio coupling
- the smoke flow lists persisted sidecar receipts from SQLite

## Files

```text
README.md
app.py
openapi.yaml
run.sh
smoke.sh
```

## Run

Start the upstream app only:

```bash
./run.sh
```

Run the full trust + sidecar smoke flow:

```bash
./smoke.sh
```

Use the shared verification flow from
[`docs/guides/WEB_BACKEND_QUICKSTART.md`](../../docs/guides/WEB_BACKEND_QUICKSTART.md):
safe route allows, governed route denies without a capability, governed route
allows with a capability, and receipts are persisted.

This example is intentionally not an MCP session example. There is no
`initialize` or `GET /mcp` replay stream here. It is the plain HTTP sidecar
path for request evaluation and receipt persistence.
