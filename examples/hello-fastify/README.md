# hello-fastify

Minimal Fastify example using [`@chio-protocol/fastify`](../../sdks/typescript/packages/fastify/).

## What It Demonstrates

- `GET /hello` is allowed and returns the attached Chio receipt id
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- Fastify request bodies remain available after Chio interception
- the smoke flow lists persisted sidecar receipts

## Files

```text
README.md
ARCHITECTURE.md
package.json
server.mjs
server.test.mjs
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```

Run the package-local Fastify route tests:

```bash
npm test
```

The route tests build the app with Chio disabled so payload validation is
checked without a live sidecar. The smoke flow remains the authority for live
sidecar evaluation, capability gating, receipt verification, and persisted
receipt evidence.
