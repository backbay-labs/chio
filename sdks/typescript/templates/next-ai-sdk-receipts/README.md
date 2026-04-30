# next-ai-sdk-receipts

```bash
npx create-chio-app next-ai-sdk-receipts
```

This P1 skeleton reserves the Next.js + Vercel AI SDK + receipts viewer
template path. P5 owns the complete app, local receipt sink, lockfile, and
TTFRH stopwatch gate. The scaffold is telemetry-free and does not call a
hosted control plane.

## Layout

| Path                    | Role                                              |
|-------------------------|---------------------------------------------------|
| `app/layout.tsx`        | App Router root layout                            |
| `app/page.tsx`          | Home with a link into the receipts viewer         |
| `app/api/chat/route.ts` | Edge Route Handler wrapped with `@chio/next`      |
| `app/receipts/page.tsx` | Local-only receipts viewer skeleton               |
| `next.config.mjs`       | App Router enabled, strict React mode             |
| `tsconfig.json`         | App Router TypeScript baseline                    |

The chat Route Handler is wrapped with `withChio` from `@chio/next` and
allows by default; P5 will replace the static evaluator with a sidecar
call. The receipts viewer reads from a local sink only; no network
egress.
