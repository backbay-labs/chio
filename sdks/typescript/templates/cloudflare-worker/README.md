# cloudflare-worker

```bash
npx create-chio-app cloudflare-worker
```

Cloudflare Worker template consuming `@chio-protocol/workers` and
`@chio-protocol/ai-sdk-middleware`. Receipts persist to a local Workers KV
namespace by default; the first-run TTFRH bench provisions the binding
through `wrangler dev` and asserts no outbound calls beyond the
explicitly configured upstream provider.

## Layout

| Path              | Role                                              |
|-------------------|---------------------------------------------------|
| `src/index.ts`    | Worker entry point with `/chat`, `/receipts`, `/health` routes |
| `src/sink.ts`     | KV-backed receipt sink and `KvLike` shim          |
| `wrangler.toml`   | Worker config: KV binding, compatibility flags     |
| `chio.yaml`       | Template manifest consumed by `create-chio-app`   |
| `package.json`    | npm manifest with workspace dependencies          |
| `tsconfig.json`   | TypeScript baseline targeting Workers runtime     |

## Telemetry-free first run

The Worker reads and writes its own KV namespace and never opens an
outbound socket during the first-run bench. The TTFRH bench runner
(`bench/ttfrh/runners/cloudflare_worker.rs`) wraps the run in the
network sentinel.

## Single-command bootstrap

```bash
npx create-chio-app cloudflare-worker
cd cloudflare-worker
bun install
bun run dev
```

Replace the placeholder KV ids in `wrangler.toml` before deploying to a
non-local environment.
