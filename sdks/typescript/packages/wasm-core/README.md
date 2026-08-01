# @chio-protocol/wasm-core

Shared, dependency-free helpers used by the Chio runtime SDKs
(`@chio-protocol/workers`, `@chio-protocol/edge`, `@chio-protocol/deno`, and
`@chio-protocol/browser`).

The package ships ESM JavaScript and TypeScript declarations so it can be consumed
directly by Node.js and bundled for Cloudflare Workers, Vercel Edge, Deno, and the
browser.

## API

### `receiptHexToBytes(hex: string): Uint8Array`

Normalizes and validates a receipt envelope hex string, returning the decoded
bytes. Accepts an optional `0x` prefix, and rejects odd-length input and any non
hexadecimal characters so malformed receipts fail fast before they reach the wasm
`verify_receipt` boundary.
