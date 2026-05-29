Top-level runner index file. The executable runner lives in
`src/runners/next_ai_sdk_receipts.rs`; this file documents the
container-lane invocation for `.github/workflows/ttfrh.yml`.

Container-lane command:

```sh
npx create-chio-app next-ai-sdk-receipts \
  && cd next-ai-sdk-receipts \
  && bun install --frozen-lockfile \
  && bun run build
```
