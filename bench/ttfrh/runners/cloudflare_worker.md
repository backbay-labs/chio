Top-level runner index file. The executable runner lives in
`src/runners/cloudflare_worker.rs`; this file documents the
container-lane invocation for `.github/workflows/ttfrh.yml`.

Container-lane command:

```sh
npx create-chio-app cloudflare-worker \
  && cd cloudflare-worker \
  && bun install --frozen-lockfile \
  && bun run build
```
