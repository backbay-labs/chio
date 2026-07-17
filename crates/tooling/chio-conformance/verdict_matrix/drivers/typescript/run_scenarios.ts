import { readFile, readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import {
  buildChioHttpRequest,
  ChioSidecarClient,
  type ChioHttpRequest,
  type EvaluateResponse,
  type HttpMethod,
  type Verdict as SdkVerdict,
} from "../../../../../../sdks/typescript/packages/node-http/src/index.ts";

export const TYPESCRIPT_NODE_HTTP_DRIVER = "typescript-node-http";

const MATRIX_SERVER_ID = "verdict-matrix";
const REASON_NONE = "urn:chio:error:none";
const REASON_KERNEL_INTERNAL = "urn:chio:error:kernel:internal-error";
const SIDECAR_ENV = "CHIO_VERDICT_MATRIX_SIDECAR_URL";

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
  status: "pass" | "fail" | "unsupported";
  actual?: VerdictTuple;
  expected: VerdictTuple;
  diagnostic?: string;
}

interface MatrixMetadata {
  verdict_matrix?: {
    reason_code?: unknown;
    scope_set?: unknown;
  };
}

export interface RunOptions {
  sidecarUrl?: string;
  timeoutMs?: number;
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
  options: RunOptions = {},
): Promise<DriverOutcome[]> {
  const scenarios = await loadScenarios(scenarioRoot);
  const sidecarUrl = resolveDriverSidecarUrl(options);
  const outcomes: DriverOutcome[] = [];
  for (const scenario of scenarios) {
    const expected = normalizeTuple(scenario.expected);
    if (sidecarUrl == null) {
      outcomes.push({
        scenario_id: scenario.id,
        status: "unsupported",
        expected,
        diagnostic:
          `set ${SIDECAR_ENV} or CHIO_SIDECAR_URL to a live Chio sidecar; ` +
          "the TypeScript SDK does not embed kernel evaluation",
      });
      continue;
    }
    const unsupported = unsupportedRequirement(scenario.requires ?? []);
    if (unsupported != null) {
      outcomes.push({
        scenario_id: scenario.id,
        status: "unsupported",
        expected,
        diagnostic: `unsupported requirement \`${unsupported}\``,
      });
      continue;
    }
    const unsignedCapabilityReason = unsupportedSignedCapability(scenario);
    if (unsignedCapabilityReason != null) {
      outcomes.push({
        scenario_id: scenario.id,
        status: "unsupported",
        expected,
        diagnostic: unsignedCapabilityReason,
      });
      continue;
    }

    let actual: VerdictTuple;
    try {
      actual = await evaluateScenario(scenario, {
        ...options,
        sidecarUrl,
      });
    } catch (error) {
      outcomes.push({
        scenario_id: scenario.id,
        status: "fail",
        expected,
        diagnostic: error instanceof Error ? error.message : String(error),
      });
      continue;
    }

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
  options: RunOptions = {},
): Promise<VerdictTuple> {
  const sidecarUrl = resolveDriverSidecarUrl(options);
  if (sidecarUrl == null) {
    throw new Error(`missing ${SIDECAR_ENV} or CHIO_SIDECAR_URL`);
  }
  const request = scenarioToHttpRequest(scenario);
  const client = new ChioSidecarClient({
    sidecarUrl,
    timeoutMs: options.timeoutMs ?? scenarioTimeout(scenario),
  });
  const response = await client.evaluate(request, capabilityTokenForScenario(scenario));
  return tupleFromEvaluateResponse(response);
}

export function scenarioToHttpRequest(scenario: VerdictScenario): ChioHttpRequest {
  const method = methodForTool(scenario.script.tool);
  const path = `/chio/tools/${encodeURIComponent(MATRIX_SERVER_ID)}/${encodeURIComponent(scenario.script.tool)}`;
  let bodyLength = 0;
  let bodyHash: string | undefined;
  if (method !== "GET" && method !== "HEAD") {
    bodyLength = Buffer.byteLength(scenario.script.input_json, "utf8");
    bodyHash = bodyLength > 0 ? "0".repeat(64) : undefined;
  }
  // Populate tool-call fields so the sidecar's capability-scope check sees
  // requested_tool_server / requested_tool_name / arguments. Without these
  // the sidecar evaluator (chio-api-protect/evaluator.rs) treats the request
  // as a generic HTTP call and can not apply scope-subset rules.
  let toolArguments: unknown = undefined;
  try {
    toolArguments = JSON.parse(scenario.script.input_json);
  } catch {
    toolArguments = undefined;
  }
  return buildChioHttpRequest({
    method,
    path,
    query: {},
    headers: {
      "content-type": "application/json",
    },
    caller: {
      subject: `agent:${scenario.id}`,
      auth_method: { method: "anonymous" },
      verified: true,
      agent_id: `agent:${scenario.id}`,
    },
    bodyHash,
    bodyLength,
    routePattern: path,
    capabilityId: `cap-${scenario.id}`,
    toolServer: MATRIX_SERVER_ID,
    toolName: scenario.script.tool,
    toolArguments,
  });
}

export function tupleFromEvaluateResponse(response: EvaluateResponse): VerdictTuple {
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

function resolveDriverSidecarUrl(options: RunOptions): string | undefined {
  const explicit = options.sidecarUrl ?? process.env[SIDECAR_ENV] ?? process.env["CHIO_SIDECAR_URL"];
  if (explicit == null || explicit.trim().length === 0) {
    return undefined;
  }
  return explicit;
}

function unsupportedRequirement(requirements: string[]): string | undefined {
  for (const requirement of requirements) {
    switch (requirement) {
      case "rust-kernel":
      case "kernel-semantics":
      case "typescript-node-http":
      case "typescript-sdk":
        break;
      default:
        return requirement;
    }
  }
  return undefined;
}

function capabilityTokenForScenario(scenario: VerdictScenario): string {
  // The Chio sidecar validates a full signed CapabilityToken (issuer,
  // signature, time-validity) via crates/platform/chio-http-core/src/authority.rs:
  // `validate_capability_token`. The TypeScript node-http SDK does not yet
  // expose capability signing primitives, so we surface the structural
  // shape (id + scopes) for diagnostic correlation only. The driver
  // pre-empts evaluation for scenarios whose tuples depend on signed-token
  // validity via `unsupportedSignedCapability`, so this token never reaches
  // the live sidecar evaluator for capability/revocation cases. Replay,
  // redaction, and receipt scenarios are already gated by `requires` and
  // do not exercise the signed-capability path through this driver.
  return JSON.stringify({
    id: `cap-${scenario.id}`,
    scopes: scenario.script.capability_scopes ?? [],
  });
}

function unsupportedSignedCapability(
  scenario: VerdictScenario,
): string | undefined {
  // Capability and revocation tuples are gated by the kernel's signed
  // capability-token validation. Until the TypeScript node-http SDK
  // provides a signed-token builder, sidecar evaluation of these classes
  // would systematically deny on token validation rather than surface the
  // intended verdict. Report unsupported with an actionable diagnostic
  // instead of producing misleading conformance outcomes.
  if (scenario.category === "capability" || scenario.category === "revocation") {
    return (
      "typescript node-http SDK does not yet expose a signed CapabilityToken " +
      "builder; sidecar evaluation of `" +
      scenario.category +
      "` scenarios requires issuer + signature + time-valid fields per " +
      "chio-http-core::authority::validate_capability_token"
    );
  }
  return undefined;
}

if (process.argv[1] != null && resolve(process.argv[1]) === import.meta.filename) {
  const scenarioRoot = process.argv[2] ?? join(process.cwd(), "scenarios");
  runVerdictMatrixScenarios(scenarioRoot)
    .then((outcomes) => {
      const failed = outcomes.filter((outcome) => outcome.status !== "pass");
      const unsupported = outcomes.filter((outcome) => outcome.status === "unsupported");
      console.log(JSON.stringify({
        driver: TYPESCRIPT_NODE_HTTP_DRIVER,
        unsupported_count: unsupported.length,
        outcomes,
      }, null, 2));
      process.exitCode = failed.some((outcome) => outcome.status === "fail") ? 1 : 0;
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
