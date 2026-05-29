# next-ai-sdk-receipts

```bash
npx create-chio-app next-ai-sdk-receipts
```

Next.js (App Router) + Vercel AI SDK + Chio receipts viewer template. The
chat Route Handler is wrapped with `withChio` from `@chio-protocol/next`. The
receipts viewer reads from a local in-memory sink only; no outbound
network calls run during the first-run TTFRH bench.

## Layout

| Path                       | Role                                              |
|----------------------------|---------------------------------------------------|
| `app/layout.tsx`           | App Router root layout                            |
| `app/page.tsx`             | Home with a link into the receipts viewer         |
| `app/api/chat/route.ts`    | Edge Route Handler wrapped with `@chio-protocol/next` |
| `app/receipts/page.tsx`    | Local-only receipts viewer reading the in-memory sink |
| `lib/local-sink.ts`        | Telemetry-free in-memory ChioReceiptSink          |
| `lib/evaluator.ts`         | Static allow evaluator that records receipts      |
| `chio.yaml`                | Template manifest consumed by `create-chio-app`   |
| `next.config.mjs`          | App Router enabled, strict React mode             |
| `tsconfig.json`            | App Router TypeScript baseline                    |

## Telemetry-free first run

The local sink is in-memory and has no outbound transport. The TTFRH
bench (`bench/ttfrh/runners/next_ai_sdk_receipts.rs`) asserts a clean
machine run produces a signed receipt under 60 s with the network
sentinel logging zero unsanctioned outbound hostnames.

## Single-command bootstrap

```bash
npx create-chio-app next-ai-sdk-receipts
cd next-ai-sdk-receipts
bun install
bun run build
bun run dev
```

Browse to `http://localhost:3000/receipts` after `POST /api/chat` to
see the local receipt entries.
