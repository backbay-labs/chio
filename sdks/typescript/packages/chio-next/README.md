# @chio-protocol/next

Next.js App Router wrappers for Chio verdict gating.

Requires Next.js 15.5.24 or newer within the 15.x line. Earlier versions are
outside this package's supported security baseline. Upgrading the application
does not replace Chio capability or receipt verification.

## Route Handler

```ts
import { withChio } from "@chio-protocol/next";

export const POST = withChio(async request => {
  return new Response("ok");
}, {
  evaluate: request => evaluateRequestWithChio(request),
});
```

Allowed route-handler responses are returned untouched, including streaming
responses. Denials return JSON with `error: "chio_denied"` and Chio verdict
headers (`x-chio-verdict`, `x-chio-receipt-id`).

## Server Action

```ts
"use server";
import { withChioAction } from "@chio-protocol/next";

export const archiveDocument = withChioAction(async (id: string) => {
  return database.archive(id);
}, {
  evaluate: (id: string) => evaluateActionWithChio({ tool: "archive", id }),
});
```

Denials throw `ChioActionDeniedError` with the receipt id; the wrapped
action is never invoked.

## Runtime support

The package picks Edge or Node automatically based on Next.js's `runtime`
export in the calling Route Handler. Pages Router is intentionally out of
scope for v1; emit a build-time error if the wrappers are imported from a
`pages/` route.
