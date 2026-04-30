# create-chio-app

```bash
npx create-chio-app <template> [destination]
```

CLI scaffold for first-run Chio applications. Templates are vendored
in-repo at `sdks/typescript/templates/<slug>/`; `create-chio-app`
clones one into the user's working directory and prints the next
command. Network egress is opt-in: the scaffold step does not make
any outbound calls during the TTFRH first-run bench.

## Templates

| Slug                     | Description                                              |
|--------------------------|----------------------------------------------------------|
| `next-ai-sdk-receipts`   | Next.js + Vercel AI SDK middleware + receipts viewer    |
| `fastapi-langchain`      | Python FastAPI + LangChain + static receipts viewer     |
| `cloudflare-worker`      | Cloudflare Worker + KV-backed receipts                  |

List them at runtime with `create-chio-app --list`.

## Behavior

`create-chio-app <template>` copies the corresponding `templates/<slug>`
directory into `./<slug>` (or the explicit destination if provided),
refuses to overwrite an existing path, and prints both the next command
and the bench runner that gates the < 60 s TTFRH budget for that
template.

## Tests

```bash
bun install --frozen-lockfile
bun run test
```

Tests cover argument parsing, template registry shape, error paths
(unknown template, missing source, existing destination), and the
happy-path scaffold flow against a fake filesystem.
