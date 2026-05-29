# Chio TypeScript SDK Reference

This document covers all five Chio TypeScript packages. Each package communicates with the Chio Rust kernel via a localhost HTTP sidecar. All packages are ESM-first and work with Node.js 18+ and Bun.

## Quick Start

```bash
# Core HTTP substrate (required by framework packages)
npm install @chio-protocol/node-http

# Pick your framework integration
npm install @chio-protocol/express    # Express.js
npm install @chio-protocol/fastify    # Fastify
npm install @chio-protocol/elysia     # Elysia (Bun)

# Testing and conformance utilities
npm install @chio-protocol/conformance --save-dev
```

Minimal Express example:

```ts
import express from "express";
import { chio } from "@chio-protocol/express";

const app = express();
app.use(chio({ config: "chio.yaml" }));
app.use(express.json());

app.get("/pets", (_req, res) => {
  res.json([{ name: "Fido" }]);
});

app.listen(3000);
```

## Sidecar Communication Model

All Chio TypeScript SDKs communicate with the Chio Rust kernel through localhost HTTP. The kernel runs as a sidecar process alongside your application.

- **Default URL**: `http://127.0.0.1:9090`
- **Configurable via**: `CHIO_SIDECAR_URL` environment variable or the `sidecarUrl` config option
- **No native compilation or FFI**: pure TypeScript/JavaScript over HTTP (uses `fetch`)
- **Fail-closed by default**: when the sidecar is unreachable, requests receive a 502 response. Set `onSidecarError: "allow"` to forward the request without synthesizing a Chio receipt.

---

## 1. @chio-protocol/node-http

The core HTTP substrate. Provides types, identity extraction, the sidecar client, and request interceptors. All framework packages depend on this.

### Installation

```bash
npm install @chio-protocol/node-http
```

### Types

All types mirror the Rust `chio-http-core` crate.

**HttpMethod**

```ts
type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

isMethodSafe(method: HttpMethod): boolean  // true for GET, HEAD, OPTIONS
```

**AuthMethod** (tagged union)

```ts
type AuthMethod =
  | { method: "bearer"; token_hash: string }
  | { method: "api_key"; key_name: string; key_hash: string }
  | { method: "cookie"; cookie_name: string; cookie_hash: string }
  | { method: "mtls_certificate"; subject_dn: string; fingerprint: string }
  | { method: "anonymous" };
```

**CallerIdentity**

```ts
interface CallerIdentity {
  subject: string;
  auth_method: AuthMethod;
  verified: boolean;
  tenant?: string;
  agent_id?: string;
}
```

**Verdict** (tagged union)

```ts
type Verdict =
  | { verdict: "allow" }
  | { verdict: "deny"; reason: string; guard: string; http_status: number }
  | { verdict: "cancel"; reason: string }
  | { verdict: "incomplete"; reason: string };

isAllowed(verdict: Verdict): boolean
isDenied(verdict: Verdict): boolean
```

**HttpReceipt**

```ts
interface HttpReceipt {
  id: string;
  request_id: string;
  route_pattern: string;
  method: HttpMethod;
  caller_identity_hash: string;
  session_id?: string;
  verdict: Verdict;
  evidence: GuardEvidence[];
  response_status: number; // Chio evaluation-time HTTP status, not guaranteed downstream response evidence for allow-path receipts
  timestamp: number;
  content_hash: string;
  policy_hash: string;
  capability_id?: string;
  metadata?: unknown;
  kernel_key: string;
  signature: string;
}
```

**GuardEvidence**

```ts
interface GuardEvidence {
  guard_name: string;
  verdict: boolean;
  details?: string;
}
```

**ChioHttpRequest** (sent to sidecar for evaluation)

```ts
interface ChioHttpRequest {
  request_id: string;
  method: HttpMethod;
  route_pattern: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  body_hash?: string;
  body_length: number;
  session_id?: string;
  capability_id?: string;
  timestamp: number;
}
```

**EvaluateResponse**

```ts
interface EvaluateResponse {
  verdict: Verdict;
  receipt: HttpReceipt;
  evidence: GuardEvidence[];
}
```

**ChioConfig**

```ts
interface ChioConfig {
  sidecarUrl?: string;             // Default: CHIO_SIDECAR_URL env or "http://127.0.0.1:9090"
  config?: string;                 // Path to chio.yaml config file
  identityExtractor?: IdentityExtractor;
  routePatternResolver?: RoutePatternResolver;
  onSidecarError?: "deny" | "allow";  // Default: "deny" (fail-closed)
  timeoutMs?: number;              // Default: 5000
  forwardHeaders?: string[];       // Default: ["content-type", "content-length"]
}
```

**Error codes**

```ts
const CHIO_ERROR_CODES = {
  ACCESS_DENIED: "chio_access_denied",
  SIDECAR_UNREACHABLE: "chio_sidecar_unreachable",
  EVALUATION_FAILED: "chio_evaluation_failed",
  INVALID_RECEIPT: "chio_invalid_receipt",
  TIMEOUT: "chio_timeout",
} as const;
```

### ChioSidecarClient

HTTP client for the Chio sidecar. Uses the Fetch API internally.

```ts
import { ChioSidecarClient } from "@chio-protocol/node-http";

const client = new ChioSidecarClient({
  sidecarUrl: "http://127.0.0.1:9090",
  timeoutMs: 5000,
});

// Evaluate an HTTP request
const result: EvaluateResponse = await client.evaluate(arcHttpRequest);

// Verify a receipt signature
const valid: boolean = await client.verifyReceipt(receipt);

// Health check
const healthy: boolean = await client.healthCheck();
```

**SidecarError**

Thrown when the sidecar is unreachable or returns an error:

```ts
class SidecarError extends Error {
  readonly code: string;        // e.g., "chio_sidecar_unreachable", "chio_timeout"
  readonly statusCode: number | undefined;
}
```

### Identity Extraction

The default identity extractor checks headers in this order:

1. `Authorization: Bearer <token>` -- hashes the token with SHA-256
2. `X-API-Key` header -- hashes the key value
3. `Cookie` header -- hashes the first cookie value
4. Falls back to anonymous

```ts
import { defaultIdentityExtractor, sha256Hex } from "@chio-protocol/node-http";

// Use directly
const identity = defaultIdentityExtractor(request.headers);

// Provide a custom extractor via config
const config: ChioConfig = {
  identityExtractor: (headers) => ({
    subject: "custom-subject",
    auth_method: { method: "bearer", token_hash: sha256Hex("my-token") },
    verified: true,
  }),
};
```

### Interceptors

Two interceptor patterns are provided for direct use (the framework packages use these internally):

**Node.js `(req, res)` pattern:**

```ts
import { interceptNodeRequest, resolveConfig } from "@chio-protocol/node-http";

const resolved = resolveConfig({ config: "chio.yaml" });

const outcome = await interceptNodeRequest(req, res, resolved);
if (!outcome.responseSent) {
  if (outcome.result) {
    // Request allowed with a real Chio receipt.
  }
  if (outcome.passthrough) {
    // Fail-open passthrough. No Chio receipt exists for this request.
  }
}
```

**Web API `Request -> Response` pattern:**

```ts
import { interceptWebRequest, resolveConfig } from "@chio-protocol/node-http";

const resolved = resolveConfig({ config: "chio.yaml" });

const { response, result, passthrough } = await interceptWebRequest(request, resolved);
if (result != null) {
  // Allowed with a real Chio receipt. The original Request body remains readable.
} else if (passthrough != null) {
  // Fail-open passthrough. No Chio receipt exists for this request.
} else {
  // Denied -- return the error response
  return response;
}
```

### Helper Functions

```ts
import { buildChioHttpRequest, resolveConfig } from "@chio-protocol/node-http";

// Build a ChioHttpRequest from parts
const chioReq = buildChioHttpRequest({
  method: "POST",
  path: "/api/deploy",
  query: {},
  headers: { "content-type": "application/json" },
  caller: { subject: "user-1", auth_method: { method: "anonymous" }, verified: false },
  bodyHash: "sha256...",
  bodyLength: 42,
  routePattern: "/api/deploy",
  capabilityId: "cap-123",
});
```

---

## 2. @chio-protocol/express

Express.js middleware for Chio protocol evaluation.

### Installation

```bash
npm install @chio-protocol/express
```

### Basic Usage

```ts
import express from "express";
import { chio, chioErrorHandler } from "@chio-protocol/express";

const app = express();

// Evaluate every request against Chio
app.use(chio({ config: "chio.yaml" }));

// Routes
app.get("/pets", (req, res) => {
  res.json([{ name: "Fido" }]);
});

// Optional: structured error handler for Chio errors
app.use(chioErrorHandler);

app.listen(3000);
```

### Configuration

`ChioExpressConfig` extends `ChioConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass Chio evaluation |

```ts
app.use(chio({
  config: "chio.yaml",
  sidecarUrl: "http://127.0.0.1:9090",
  onSidecarError: "deny",
  timeoutMs: 5000,
  skip: ["/health", "/ready", /^\/public\//],
}));
```

### Accessing Results

The evaluation result is attached to the request when Chio evaluation succeeds:

```ts
import type { ChioRequest } from "@chio-protocol/express";

app.get("/pets", (req, res) => {
  const chioReq = req as ChioRequest;
  if (chioReq.chioResult) {
    console.log("Receipt ID:", chioReq.chioResult.receipt.id);
  }
  if (chioReq.chioPassthrough) {
    console.log("Chio passthrough mode:", chioReq.chioPassthrough.mode);
  }
  res.json([]);
});
```

### Error Handler

`chioErrorHandler` is an Express error middleware that formats Chio-related errors as structured JSON:

```ts
app.use(chioErrorHandler);
// Errors with a `chio_*` code are returned as { error: "chio_...", message: "..." }
// Other errors pass through to the next error handler
```

---

## 3. @chio-protocol/fastify

Fastify plugin for Chio protocol evaluation.

### Installation

```bash
npm install @chio-protocol/fastify
```

### Basic Usage

```ts
import Fastify from "fastify";
import { chio } from "@chio-protocol/fastify";

const fastify = Fastify();

// Register the Chio plugin
await fastify.register(chio, { config: "chio.yaml" });

fastify.get("/pets", async (request, reply) => {
  return [{ name: "Fido" }];
});

await fastify.listen({ port: 3000 });
```

### Configuration

`ChioFastifyConfig` extends `ChioConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass Chio evaluation |

```ts
await fastify.register(chio, {
  config: "chio.yaml",
  sidecarUrl: "http://127.0.0.1:9090",
  onSidecarError: "deny",
  timeoutMs: 5000,
  skip: ["/health", /^\/public\//],
});
```

### Accessing Results

The Chio evaluation result is available on the Fastify request object when Chio evaluation succeeds:

```ts
fastify.get("/pets", async (request, reply) => {
  if (request.chioResult) {
    console.log("Receipt ID:", request.chioResult.receipt.id);
  }
  return [{ name: "Fido" }];
});
```

### Route Pattern Resolution

The plugin automatically uses Fastify's `routeOptions.url` for route pattern resolution. For example, a request to `/pets/42` matched by route `/pets/:petId` will evaluate against the pattern `/pets/:petId`.

### Plugin Details

The plugin is wrapped with `fastify-plugin` to skip Fastify encapsulation, so hooks apply to all routes in the instance. Requires Fastify 4.0.0 or later.

---

## 4. @chio-protocol/elysia

Elysia lifecycle hook for Chio protocol evaluation. Designed for Bun.

### Installation

```bash
npm install @chio-protocol/elysia
# or
bun add @chio-protocol/elysia
```

### Basic Usage

```ts
import { Elysia } from "elysia";
import { chio } from "@chio-protocol/elysia";

const app = new Elysia()
  .use(chio({ config: "chio.yaml" }))
  .get("/pets", () => [{ name: "Fido" }])
  .listen(3000);
```

### Configuration

`ChioElysiaConfig` extends `ChioConfig` with:

| Option | Type | Description |
|--------|------|-------------|
| `skip` | `Array<string \| RegExp>` | Paths to bypass Chio evaluation |

```ts
const app = new Elysia()
  .use(chio({
    config: "chio.yaml",
    sidecarUrl: "http://127.0.0.1:9090",
    onSidecarError: "deny",
    skip: ["/health"],
  }))
  .get("/pets", () => [{ name: "Fido" }]);
```

### How It Works

The plugin hooks into Elysia's `onBeforeHandle` lifecycle. For each request it:

1. Checks skip patterns
2. Extracts caller identity from headers
3. Computes a SHA-256 body hash
4. Sends an evaluation request to the Chio sidecar
5. Returns a structured error response on deny, or allows the request to proceed
6. Attaches `X-Chio-Receipt-Id` to the response

---

## 5. @chio-protocol/conformance

Test utilities for verifying that TypeScript SDK behavior matches the Rust kernel. Intended for use in integration and conformance test suites.

### Installation

```bash
npm install @chio-protocol/conformance --save-dev
```

### Canonical JSON (RFC 8785)

Chio requires canonical JSON for all signed payloads. These functions produce byte-identical output to the Rust kernel.

```ts
import { canonicalJsonString, canonicalJsonBytes } from "@chio-protocol/conformance";

// Returns a string with sorted keys, no extra whitespace
const json = canonicalJsonString({ b: 2, a: 1 });
// '{"a":1,"b":2}'

// Returns UTF-8 bytes
const bytes = canonicalJsonBytes({ b: 2, a: 1 });
```

RFC 8785 rules enforced:
- Object keys sorted lexicographically
- No whitespace between tokens
- Numbers as shortest representation
- `undefined` values are skipped (matching Rust `skip_serializing_if`)
- Non-finite numbers throw an error

### Receipt Structure Validation

```ts
import { validateReceiptStructure } from "@chio-protocol/conformance";

const errors: string[] = validateReceiptStructure(receipt);
if (errors.length > 0) {
  console.error("Invalid receipt:", errors);
}
```

Validates:
- All required fields are present and correctly typed
- `id` and `request_id` are non-empty strings
- `method` is a valid HTTP method
- `caller_identity_hash` is a 64-character hex string
- `verdict` has valid structure
- `evidence` entries have `guard_name` (string) and `verdict` (boolean)
- `response_status` is a valid HTTP status code (100-599)
- `timestamp` is a positive number
- `content_hash` is a 64-character hex string
- `kernel_key` and `signature` are non-empty strings

### Content Hash Verification

Verify that a receipt's content hash matches the expected request content binding:

```ts
import { verifyContentHash } from "@chio-protocol/conformance";

const matches = verifyContentHash(
  receipt,
  "POST",          // method
  "/pets/{petId}", // route pattern
  "/pets/42",      // actual path
  { limit: "10" }, // query parameters
  "sha256hex...",  // body hash (or null)
);
```

### Verdict Assertion

```ts
import { assertVerdictMatch } from "@chio-protocol/conformance";

const errors = assertVerdictMatch(receipt.verdict, {
  verdict: "deny",
  reason: "rate limit exceeded",
  guard: "velocity-guard",
  http_status: 429,
});
// Returns string[] of mismatches, empty on success
```

### E2E Test Helpers

The conformance package includes end-to-end test examples for Express and Fastify in `test/e2e/`. These demonstrate how to spin up a test server with Chio middleware and validate receipt production.
