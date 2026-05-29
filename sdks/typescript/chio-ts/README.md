# `@chio-protocol/sdk`

Stable TypeScript SDK for Chio hosted MCP sessions, receipt queries, and
invariant verification.

## Installation

```bash
npm install @chio-protocol/sdk
```

Requirements: Node.js `>=22`. The package ships as ESM and includes `.d.ts`
types in the published artifact.

## Quickstart

```ts
import { ChioClient, ReceiptQueryClient } from "@chio-protocol/sdk";

const client = ChioClient.withStaticBearer("http://127.0.0.1:8931", "demo-token");
const session = await client.initialize();

try {
  const tools = await session.listTools();
  console.log(tools);

  const receipts = await new ReceiptQueryClient(
    "http://127.0.0.1:8940",
    "demo-token",
  ).query({ toolServer: "wrapped-http-mock", limit: 5 });
  console.log(receipts.totalCount);
} finally {
  await session.close();
}
```

## API Reference

- `ChioClient` and `ChioSession` cover Chio hosted MCP HTTP sessions.
- `ReceiptQueryClient` wraps `GET /v1/receipts/query`.
- `signDpopProof` signs DPoP proofs for governed invocations.
- `@chio-protocol/sdk/invariants` exposes canonical JSON, hashing, signing,
  receipt, capability, and manifest helpers.

The full public reference lives in [docs/reference/SDK_TYPESCRIPT_REFERENCE.md](../../../docs/reference/SDK_TYPESCRIPT_REFERENCE.md).

## Official Example

The package-local governed example expects a running Chio hosted edge and trust
service:

```bash
CHIO_BASE_URL=http://127.0.0.1:8931 \
CHIO_CONTROL_URL=http://127.0.0.1:8940 \
CHIO_AUTH_TOKEN=demo-token \
node --experimental-strip-types sdks/typescript/chio-ts/examples/governed_hello.ts
```

For a repo-local end-to-end verification run that boots those services
automatically, use:

```bash
./scripts/check-sdk-publication-examples.sh
```

## Canonical Example Links

- `../../../docs/guides/WEB_BACKEND_QUICKSTART.md`
- `../../../examples/hello-openapi-sidecar/README.md`
- `../../../examples/hello-fastapi/README.md`

## Release Checks

```bash
npm --prefix sdks/typescript/chio-ts test
./scripts/check-chio-ts-release.sh
```
