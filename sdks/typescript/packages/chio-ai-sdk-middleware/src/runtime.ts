import type {
  ChioEvaluation,
  ChioMiddlewareOptions,
  LanguageModelInvocation,
  ToolUseCandidate,
} from "./middleware.js";

export type ChioRuntime = "edge" | "node";

export interface RuntimeEvaluationOptions {
  runtime?: ChioRuntime | "auto" | undefined;
  request?: LanguageModelInvocation | undefined;
  toolUse?: ToolUseCandidate | undefined;
  sidecarUrl?: string | undefined;
  fetch?: typeof fetch | undefined;
}

type EdgeModule = {
  evaluate?: (requestJson: string) => Promise<unknown> | unknown;
};

export async function evaluateWithChio(
  options: ChioMiddlewareOptions,
  runtimeOptions: RuntimeEvaluationOptions = {},
): Promise<ChioEvaluation> {
  if (options.evaluate != null) {
    return options.evaluate({
      runtime: normalizeRuntime(runtimeOptions.runtime),
      request: runtimeOptions.request,
      toolUse: runtimeOptions.toolUse,
    });
  }

  const payload = {
    schema: "chio.ai-sdk-middleware.invocation.v1",
    provider: options.provider,
    model_id: options.modelId,
    tool_use: runtimeOptions.toolUse ?? null,
    request: runtimeOptions.request ?? null,
  };

  const runtime = normalizeRuntime(runtimeOptions.runtime);
  if (runtime === "edge") {
    const edge = await importOptionalEdge();
    if (typeof edge.evaluate !== "function") {
      throw new Error("@chio-protocol/edge did not expose evaluate()");
    }
    return normalizeEvaluation(await edge.evaluate(JSON.stringify(payload)));
  }

  const fetchImpl = runtimeOptions.fetch ?? options.fetch ?? globalThis.fetch;
  if (fetchImpl == null) {
    throw new Error("no fetch implementation available for Chio node runtime evaluation");
  }
  const sidecarUrl = (runtimeOptions.sidecarUrl ?? options.sidecarUrl ?? "http://127.0.0.1:9090")
    .replace(/\/+$/, "");
  const response = await fetchImpl(`${sidecarUrl}/chio/evaluate`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Chio sidecar returned ${response.status}`);
  }
  return normalizeEvaluation(await response.json());
}

function normalizeRuntime(runtime: ChioRuntime | "auto" | undefined): ChioRuntime {
  if (runtime === "edge" || runtime === "node") {
    return runtime;
  }
  return typeof EdgeRuntime === "string" ? "edge" : "node";
}

declare const EdgeRuntime: string | undefined;

async function importOptionalEdge(): Promise<EdgeModule> {
  const dynamicImport = new Function("specifier", "return import(specifier)") as
    (specifier: string) => Promise<EdgeModule>;
  return dynamicImport("@chio-protocol/edge");
}

function normalizeEvaluation(value: unknown): ChioEvaluation {
  if (value != null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const verdict = record["verdict"];
    if (verdict === "allow" || verdict === "deny") {
      return {
        verdict,
        reason: typeof record["reason"] === "string" ? record["reason"] : undefined,
        receiptId: typeof record["receipt_id"] === "string" ? record["receipt_id"] : undefined,
      };
    }
    if (verdict != null && typeof verdict === "object") {
      const nested = verdict as Record<string, unknown>;
      if (nested["verdict"] === "allow" || nested["verdict"] === "deny") {
        return {
          verdict: nested["verdict"],
          reason: typeof nested["reason"] === "string" ? nested["reason"] : undefined,
          receiptId: typeof record["receipt_id"] === "string" ? record["receipt_id"] : undefined,
        };
      }
    }
    const decision = record["decision"];
    if (decision != null && typeof decision === "object") {
      const nested = decision as Record<string, unknown>;
      if (nested["verdict"] === "allow" || nested["verdict"] === "deny") {
        return {
          verdict: nested["verdict"],
          reason: typeof nested["reason"] === "string" ? nested["reason"] : undefined,
          receiptId: typeof record["receipt_id"] === "string" ? record["receipt_id"] : undefined,
        };
      }
    }
  }
  throw new Error("Chio evaluation response did not include an allow or deny verdict");
}
