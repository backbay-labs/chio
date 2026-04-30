# @chio/next

Next.js App Router wrappers for Chio verdict gating.

```ts
import { withChio } from "@chio/next";

export const POST = withChio(async request => {
  return new Response("ok");
}, {
  evaluate: request => evaluateRequestWithChio(request),
});
```

Allowed route-handler responses are returned untouched, including streaming
responses. Denials return JSON with `error: "chio_denied"` and Chio verdict
headers. Pages Router support is intentionally out of scope for v1.
