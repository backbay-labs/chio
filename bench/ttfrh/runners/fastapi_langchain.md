Top-level runner index file. The executable runner lives in
`src/runners/fastapi_langchain.rs`; this file documents the
container-lane invocation for `.github/workflows/ttfrh.yml`.

Container-lane command:

```sh
npx create-chio-app fastapi-langchain \
  && cd fastapi-langchain \
  && uv sync --frozen \
  && uv run python -c 'import app.main'
```
