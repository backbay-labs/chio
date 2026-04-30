import { evaluateWithChio, type ChioRuntime } from "./runtime.js";

export interface LanguageModelInvocation {
  tools?: unknown;
  toolCalls?: unknown;
  experimental_toolCalls?: unknown;
  prompt?: unknown;
  messages?: unknown;
  [key: string]: unknown;
}

export interface LanguageModelLike {
  doGenerate?: (options: LanguageModelInvocation) => Promise<unknown>;
  doStream?: (options: LanguageModelInvocation) => Promise<unknown>;
  [key: string]: unknown;
}

export interface ToolUseCandidate {
  name: string;
  arguments?: unknown;
}

export interface ChioEvaluation {
  verdict: "allow" | "deny";
  reason?: string | undefined;
  receiptId?: string | undefined;
}

export type ChioEvaluator = (input: {
  runtime: ChioRuntime;
  request?: LanguageModelInvocation | undefined;
  toolUse?: ToolUseCandidate | undefined;
}) => Promise<ChioEvaluation> | ChioEvaluation;

export interface ChioMiddlewareOptions {
  provider?: string | undefined;
  modelId?: string | undefined;
  runtime?: ChioRuntime | "auto" | undefined;
  sidecarUrl?: string | undefined;
  fetch?: typeof fetch | undefined;
  evaluate?: ChioEvaluator | undefined;
}

export class ChioMiddlewareDeniedError extends Error {
  readonly receiptId: string | undefined;
  readonly reason: string | undefined;

  constructor(evaluation: ChioEvaluation) {
    super(evaluation.reason ?? "Chio denied the language-model tool invocation");
    this.name = "ChioMiddlewareDeniedError";
    this.receiptId = evaluation.receiptId;
    this.reason = evaluation.reason;
  }
}

export function createChioMiddleware(options: ChioMiddlewareOptions = {}) {
  return {
    wrapLanguageModel<Model extends LanguageModelLike>(model: Model): Model {
      return wrapWithChio(model, options);
    },
  };
}

export function wrapWithChio<Model extends LanguageModelLike>(
  model: Model,
  options: ChioMiddlewareOptions = {},
): Model {
  const wrapped: LanguageModelLike = { ...model };
  if (typeof model.doGenerate === "function") {
    wrapped.doGenerate = async (request: LanguageModelInvocation) => {
      await evaluateToolBoundary(request, options);
      return model.doGenerate!(request);
    };
  }
  if (typeof model.doStream === "function") {
    wrapped.doStream = async (request: LanguageModelInvocation) => {
      await evaluateToolBoundary(request, options);
      return model.doStream!(request);
    };
  }
  return wrapped as Model;
}

async function evaluateToolBoundary(
  request: LanguageModelInvocation,
  options: ChioMiddlewareOptions,
): Promise<void> {
  const toolUses = collectToolUses(request);
  if (toolUses.length === 0) {
    return;
  }
  for (const toolUse of toolUses) {
    const evaluation = await evaluateWithChio(options, {
      runtime: options.runtime,
      request,
      toolUse,
    });
    if (evaluation.verdict !== "allow") {
      throw new ChioMiddlewareDeniedError(evaluation);
    }
  }
}

function collectToolUses(request: LanguageModelInvocation): ToolUseCandidate[] {
  const explicitCalls = request.toolCalls ?? request.experimental_toolCalls;
  if (Array.isArray(explicitCalls)) {
    return explicitCalls
      .map(candidateFromCall)
      .filter((candidate): candidate is ToolUseCandidate => candidate != null);
  }

  if (request.tools != null && typeof request.tools === "object") {
    return Object.keys(request.tools as Record<string, unknown>)
      .sort()
      .map(name => ({ name }));
  }

  return [];
}

function candidateFromCall(call: unknown): ToolUseCandidate | undefined {
  if (call == null || typeof call !== "object") {
    return undefined;
  }
  const record = call as Record<string, unknown>;
  const name = record["toolName"] ?? record["tool_name"] ?? record["name"];
  if (typeof name !== "string" || name.length === 0) {
    return undefined;
  }
  return {
    name,
    arguments: record["args"] ?? record["arguments"] ?? record["input"],
  };
}
