# Web Backend Quickstart

This is the supported order for web backends in Chio:

1. start with [`examples/hello-openapi-sidecar/`](../../examples/hello-openapi-sidecar/)
2. move to [`examples/hello-fastapi/`](../../examples/hello-fastapi/) only if you specifically want app-level Python integration
3. use [`examples/hello-drogon/`](../../examples/hello-drogon/) when you want the C++ Drogon middleware path

That ordering is intentional.

- `hello-openapi-sidecar` is first because the upstream app stays plain. Chio
  lives entirely in the OpenAPI sidecar, so you can prove deny, allow, and
  receipt behavior before adopting a framework SDK.
- `hello-fastapi` is second because it adds `chio-asgi` and `chio-fastapi` on top
  of the same local sidecar model.
- `hello-drogon` is a C++ follow-on that uses
  `sdks/cpp/chio-drogon` and `chio::drogon::ChioMiddleware`. Its local
  scripts skip clearly when CMake or Drogon is not available.

## Shared Verification Flow

Use the same proof loop for these examples:

1. start the app-only path with `./run.sh`
2. run `./smoke.sh` for the full trust + sidecar flow
3. confirm the safe route succeeds
4. confirm the governed route denies without a capability token
5. confirm the governed route allows with a trust-issued capability token
6. confirm the smoke flow prints or lists persisted receipts

These examples are plain HTTP request/response governance examples. They do not
exercise the hosted MCP session lifecycle. If you need the `initialize` ->
`notifications/initialized` -> `GET /mcp` replay contract, use
[`docs/guides/MIGRATING-FROM-MCP.md`](MIGRATING-FROM-MCP.md)
or [`examples/hello-mcp/`](../../examples/hello-mcp/).

## Commands

### Sidecar-first path

```bash
cd examples/hello-openapi-sidecar
./run.sh
./smoke.sh
```

### FastAPI follow-on

```bash
cd examples/hello-fastapi
./run.sh
./smoke.sh
```

### Drogon follow-on

```bash
cd examples/hello-drogon
./run.sh
./smoke.sh
```

## Related Guides

- [`MIGRATING-FROM-MCP.md`](MIGRATING-FROM-MCP.md) for coding-agent stacks
- [`NATIVE_ADOPTION_GUIDE.md`](../start-here/NATIVE_ADOPTION_GUIDE.md) for the native service-builder path
