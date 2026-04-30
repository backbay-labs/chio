# @chio/ai-sdk-middleware

Structural Vercel AI SDK language-model middleware for Chio verdict gating.

```ts
import { wrapWithChio } from "@chio/ai-sdk-middleware";

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
