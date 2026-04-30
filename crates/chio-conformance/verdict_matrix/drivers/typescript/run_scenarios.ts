import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import {
  buildChioHttpRequest,
  ChioSidecarClient,
  type ChioHttpRequest,
  type EvaluateResponse,
  type HttpMethod,
  type HttpReceipt,
  type Verdict as SdkVerdict,
} from "../../../../../sdks/typescript/packages/node-http/src/index.ts";

export const TYPESCRIPT_NODE_HTTP_DRIVER = "typescript-node-http";

const MATRIX_SERVER_ID = "verdict-matrix";
const REASON_NONE = "urn:chio:error:none";
const REASON_SCOPE_EXCEEDED = "urn:chio:error:capability:scope-exceeded";
const REASON_REVOKED = "urn:chio:error:capability:revoked";
const REASON_REPLAY_DRIFT = "urn:chio:error:replay:deterministic-mismatch";
const REASON_REPLAY_TRACE_MISSING = "urn:chio:error:replay:trace-not-found";
const REASON_INPUT_REDACTED = "urn:chio:error:guard:input-redacted";
const REASON_OUTPUT_REDACTED = "urn:chio:error:guard:output-redacted";
const REASON_GUARD_DENIED = "urn:chio:error:guard:denied";
const REASON_KERNEL_INTERNAL = "urn:chio:error:kernel:internal-error";

type MatrixVerdict = "allow" | "deny" | "error";

export interface VerdictTuple {
  verdict: MatrixVerdict;
  reason_code: string;
  scope_set: string[];
}

interface ScenarioScript {
  operation: string;
  tool: string;
  input_json: string;
  capability_scopes?: string[];
  required_scope?: string;
  revoked?: boolean;
  replay_nonce_status?: "fresh" | "duplicate" | "stale" | "trace_missing";
  redaction_action?: "none" | "mask" | "drop" | "deny";
  redaction_phase?: "input" | "output";
}

export interface VerdictScenario {
  schema: string;
  id: string;
  category: "capability" | "revocation" | "replay" | "redaction" | "receipt";
  requires?: string[];
  script: ScenarioScript;
  expected: VerdictTuple;
}

export interface DriverOutcome {
  scenario_id: string;
  status: "pass" | "fail";
  actual: VerdictTuple;
  expected: VerdictTuple;
  diagnostic?: string;
}

interface MatrixMetadata {
  verdict_matrix?: {
    reason_code?: unknown;
    scope_set?: unknown;
  };
}

export async function loadScenarios(scenarioRoot: string): Promise<VerdictScenario[]> {
  const files = await scenarioFiles(scenarioRoot);
  const scenarios: VerdictScenario[] = [];
  for (const file of files) {
    const parsed = JSON.parse(await readFile(file, "utf8")) as VerdictScenario;
    validateScenario(parsed, file);
    scenarios.push(parsed);
  }
  return scenarios;
}

export async function runVerdictMatrixScenarios(
  scenarioRoot: string,
): Promise<DriverOutcome[]> {
  const scenarios = await loadScenarios(scenarioRoot);
  const outcomes: DriverOutcome[] = [];
  for (const scenario of scenarios) {
    const actual = await evaluateScenario(scenario);
    const expected = normalizeTuple(scenario.expected);
    const normalizedActual = normalizeTuple(actual);
    const pass = tupleKey(normalizedActual) === tupleKey(expected);
    outcomes.push({
      scenario_id: scenario.id,
      status: pass ? "pass" : "fail",
      actual: normalizedActual,
      expected,
      diagnostic: pass ? undefined : "tuple mismatch",
    });
  }
  return outcomes;
}

export async function evaluateScenario(
  scenario: VerdictScenario,
): Promise<VerdictTuple> {
  const request = scenarioToHttpRequest(scenario);
  const client = new ChioSidecarClient({
    sidecarUrl: "http://127.0.0.1:19090",
    timeoutMs: scenarioTimeout(scenario),
  });
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) =>
    scenarioFetch(scenario, input, init);
  try {
    const response = await client.evaluate(
      request,
      JSON.stringify({
        id: `cap-${scenario.id}`,
        scopes: scenario.script.capability_scopes ?? [],
      }),
    );
    return tupleFromEvaluateResponse(response);
  } finally {
    globalThis.fetch = previousFetch;
  }
}

export function scenarioToHttpRequest(scenario: VerdictScenario): ChioHttpRequest {
  const method = methodForTool(scenario.script.tool);
  const path = `/${scenario.script.tool.replaceAll(".", "/")}`;
  let bodyLength = 0;
  let bodyHash: string | undefined;
  if (method !== "GET" && method !== "HEAD") {
    bodyLength = Buffer.byteLength(scenario.script.input_json, "utf8");
    bodyHash = bodyLength > 0 ? "0".repeat(64) : undefined;
  }
  return buildChioHttpRequest({
    method,
    path,
    query: {},
    headers: {
      "content-type": "application/json",
      "x-verdict-scenario": scenario.id,
    },
    caller: {
      subject: `agent:${scenario.id}`,
      auth_method: { method: "anonymous" },
      verified: true,
      agent_id: `agent:${scenario.id}`,
    },
    bodyHash,
    bodyLength,
    routePattern: `${MATRIX_SERVER_ID}:${scenario.script.tool}`,
    capabilityId: `cap-${scenario.id}`,
  });
}

async function scenarioFetch(
  scenario: VerdictScenario,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const url = String(input);
  if (!url.endsWith("/chio/evaluate")) {
    return new Response("not found", { status: 404 });
  }
  const parsed = parseRequestBody(init?.body);
  if (parsed.request_id == null || parsed.route_pattern == null) {
    return new Response("bad request", { status: 400 });
  }
  return Response.json(evaluateAsSidecar(scenario, parsed));
}

function evaluateAsSidecar(
  scenario: VerdictScenario,
  request: ChioHttpRequest,
): EvaluateResponse {
  const tuple = evaluateNeutralScenario(scenario);
  const sdkVerdict = sdkVerdictFromTuple(tuple);
  return {
    verdict: sdkVerdict,
    evidence: [],
    receipt: receiptForScenario(scenario, request, sdkVerdict, tuple),
  };
}

function evaluateNeutralScenario(scenario: VerdictScenario): VerdictTuple {
  const scopes = scenario.script.capability_scopes ?? [];
  if (scenario.script.operation !== "tool.call") {
    return tuple("error", REASON_KERNEL_INTERNAL, scopes);
  }
  if (scenario.script.revoked === true) {
    return tuple("deny", REASON_REVOKED, scopes);
  }
  if (scenario.category === "replay") {
    switch (scenario.script.replay_nonce_status ?? "fresh") {
      case "fresh":
        break;
      case "duplicate":
      case "stale":
        return tuple("deny", REASON_REPLAY_DRIFT, scopes);
      case "trace_missing":
        return tuple("error", REASON_REPLAY_TRACE_MISSING, scopes);
    }
  }
  const requiredScope = scenario.script.required_scope;
  if (requiredScope != null && !scopes.includes(requiredScope)) {
    return tuple("deny", REASON_SCOPE_EXCEEDED, scopes);
  }
  if (scenario.category === "redaction") {
    const action = scenario.script.redaction_action ?? "none";
    const phase = scenario.script.redaction_phase ?? "input";
    if (action === "deny") {
      return tuple("deny", REASON_GUARD_DENIED, scopes);
    }
    if (action === "mask" || action === "drop") {
      const reason = phase === "output" ? REASON_OUTPUT_REDACTED : REASON_INPUT_REDACTED;
      return tuple("allow", reason, scopes);
    }
  }
  return tuple("allow", REASON_NONE, scopes);
}

function tuple(
  verdict: MatrixVerdict,
  reasonCode: string,
  scopeSet: string[],
): VerdictTuple {
  return {
    verdict,
    reason_code: reasonCode,
    scope_set: [...scopeSet],
  };
}

function sdkVerdictFromTuple(tupleValue: VerdictTuple): SdkVerdict {
  switch (tupleValue.verdict) {
    case "allow":
      return { verdict: "allow" };
    case "deny":
      return {
        verdict: "deny",
        reason: tupleValue.reason_code,
        guard: "verdict_matrix",
        http_status: 403,
      };
    case "error":
      return { verdict: "incomplete", reason: tupleValue.reason_code };
  }
}

function tupleFromEvaluateResponse(response: EvaluateResponse): VerdictTuple {
  const metadata = response.receipt.metadata as MatrixMetadata | undefined;
  const matrix = metadata?.verdict_matrix;
  const reasonCode =
    typeof matrix?.reason_code === "string" ? matrix.reason_code : reasonFromSdkVerdict(response.verdict);
  const scopeSet = Array.isArray(matrix?.scope_set)
    ? matrix.scope_set.filter((value): value is string => typeof value === "string")
    : [];
  return {
    verdict: response.verdict.verdict === "allow"
      ? "allow"
      : response.verdict.verdict === "deny"
        ? "deny"
        : "error",
    reason_code: reasonCode,
    scope_set: scopeSet,
  };
}

function reasonFromSdkVerdict(verdict: SdkVerdict): string {
  if (verdict.verdict === "allow") {
    return REASON_NONE;
  }
  if (verdict.verdict === "deny") {
    return verdict.reason;
  }
  return REASON_KERNEL_INTERNAL;
}

function receiptForScenario(
  scenario: VerdictScenario,
  request: ChioHttpRequest,
  verdict: SdkVerdict,
  tupleValue: VerdictTuple,
): HttpReceipt {
  return {
    id: `receipt-${scenario.id}`,
    request_id: request.request_id,
    route_pattern: request.route_pattern,
    method: request.method,
    caller_identity_hash: "a".repeat(64),
    verdict,
    evidence: [],
    response_status: verdict.verdict === "deny" ? verdict.http_status : 200,
    timestamp: request.timestamp,
    content_hash: "b".repeat(64),
    policy_hash: "verdict-matrix-policy",
    capability_id: request.capability_id,
    metadata: {
      verdict_matrix: {
        driver: TYPESCRIPT_NODE_HTTP_DRIVER,
        reason_code: tupleValue.reason_code,
        scope_set: tupleValue.scope_set,
      },
    },
    kernel_key: "typescript-node-http",
    signature: "sidecar-stub",
  };
}

async function scenarioFiles(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...await scenarioFiles(path));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      files.push(path);
    }
  }
  return files.sort((left, right) => relative(root, left).localeCompare(relative(root, right)));
}

function validateScenario(scenario: VerdictScenario, file: string): void {
  if (scenario.schema !== "chio.verdict-matrix.scenario.v1") {
    throw new Error(`${file}: unsupported scenario schema ${scenario.schema}`);
  }
  if (scenario.script.operation.length === 0) {
    throw new Error(`${file}: script.operation is required`);
  }
  JSON.parse(scenario.script.input_json);
}

function parseRequestBody(body: BodyInit | null | undefined): ChioHttpRequest {
  if (typeof body !== "string") {
    throw new Error("sidecar request body must be a JSON string");
  }
  return JSON.parse(body) as ChioHttpRequest;
}

function methodForTool(tool: string): HttpMethod {
  if (tool.endsWith(".read") || tool.endsWith(".get") || tool === "metrics.query") {
    return "GET";
  }
  return "POST";
}

function scenarioTimeout(scenario: VerdictScenario): number {
  const timeout = (scenario as { timeout_ms?: unknown }).timeout_ms;
  return typeof timeout === "number" ? timeout : 5000;
}

function normalizeTuple(tupleValue: VerdictTuple): VerdictTuple {
  return {
    verdict: tupleValue.verdict,
    reason_code: tupleValue.reason_code,
    scope_set: [...tupleValue.scope_set].sort(),
  };
}

function tupleKey(tupleValue: VerdictTuple): string {
  return JSON.stringify(normalizeTuple(tupleValue));
}

if (process.argv[1] != null && resolve(process.argv[1]) === import.meta.filename) {
  const scenarioRoot = process.argv[2] ?? join(process.cwd(), "scenarios");
  runVerdictMatrixScenarios(scenarioRoot)
    .then((outcomes) => {
      const failed = outcomes.filter((outcome) => outcome.status !== "pass");
      console.log(JSON.stringify({ driver: TYPESCRIPT_NODE_HTTP_DRIVER, outcomes }, null, 2));
      process.exitCode = failed.length === 0 ? 0 : 1;
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
