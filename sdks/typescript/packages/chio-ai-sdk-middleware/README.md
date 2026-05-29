# @chio-protocol/ai-sdk-middleware

Structural Vercel AI SDK language-model middleware for Chio verdict gating.

```ts
import { wrapWithChio } from "@chio-protocol/ai-sdk-middleware";

const model = wrapWithChio(baseModel, {
  provider: "openai",
  modelId: "gpt-4.1",
});
```

The wrapper evaluates at the tool-use boundary before `doGenerate` or
`doStream` delegates to the underlying model. Allowed streams are returned
untouched. Denials throw `ChioMiddlewareDeniedError` with the denial reason
and optional receipt id.

The default Edge path consumes `@chio-protocol/edge` dynamically. Node uses
`fetch` against `/chio/evaluate`. Tests can inject `evaluate` directly.

## Runtime selection

`wrapWithChio` runs the verdict at the tool-use boundary, not per stream
delta. The runtime path is selected as follows:

- `runtime: "edge"` (or detected `EdgeRuntime` global) - dynamic `import`
  of `@chio-protocol/edge` evaluates the wasm artifact in-process.
- `runtime: "node"` (default outside Edge) - HTTP POST to a Chio sidecar at
  `sidecarUrl` (default `http://127.0.0.1:9090/chio/evaluate`).
- `runtime: "auto"` (the default) - picks Edge when `EdgeRuntime` is set,
  Node otherwise.

A custom `evaluate` callback short-circuits both paths and is the
recommended seam for unit tests.

## Allow / deny shape

On `allow`, the wrapped model's `doGenerate` or `doStream` is invoked with
the original arguments and the underlying response is returned untouched
(streams are passed by reference). On `deny`, `ChioMiddlewareDeniedError`
is thrown with the receipt id and reason; the underlying model is never
invoked.
