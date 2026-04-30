// Template registry consumed by the create-chio-app CLI. The list is
// hard-coded against the in-repo templates so the scaffold step works
// offline; each entry pins the relative path inside the monorepo and
// the bench runner that enforces the < 60 s TTFRH budget.

export interface TemplateEntry {
  readonly slug: string;
  readonly description: string;
  readonly directory: string;
  readonly bench: string;
  readonly nextCommand: string;
}

export const TEMPLATES: readonly TemplateEntry[] = [
  {
    slug: "next-ai-sdk-receipts",
    description:
      "Next.js (App Router) + Vercel AI SDK middleware + receipts viewer.",
    directory: "sdks/typescript/templates/next-ai-sdk-receipts",
    bench: "bench/ttfrh/runners/next_ai_sdk_receipts.rs",
    nextCommand: "bun install && bun run dev",
  },
  {
    slug: "fastapi-langchain",
    description:
      "Python FastAPI + LangChain agent with a static receipts viewer.",
    directory: "sdks/typescript/templates/fastapi-langchain",
    bench: "bench/ttfrh/runners/fastapi_langchain.rs",
    nextCommand: "uv sync && uv run uvicorn app.main:app --reload",
  },
  {
    slug: "cloudflare-worker",
    description:
      "Cloudflare Worker consuming @chio-protocol/workers and KV-backed receipts.",
    directory: "sdks/typescript/templates/cloudflare-worker",
    bench: "bench/ttfrh/runners/cloudflare_worker.rs",
    nextCommand: "bun install && bun run dev",
  },
];

export function findTemplate(slug: string): TemplateEntry | undefined {
  return TEMPLATES.find(template => template.slug === slug);
}

export function listTemplateSlugs(): readonly string[] {
  return TEMPLATES.map(template => template.slug);
}
