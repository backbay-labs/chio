import {
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  type ExtensionFactory,
} from "@earendil-works/pi-coding-agent";
import { CHIO_TOOL_NAME, chioExtension, type KernelExecutor } from "./extension.js";
import { join } from "node:path";
import { withUncertaintyInterlock } from "./uncertainty.js";

export interface ChioPiOptions {
  /** Disposable or operator-controlled directory, not the protected resource. */
  cwd: string;
  /** Dedicated profile outside the agent's kernel-accessible resource scope. */
  agentDir: string;
  modelRuntime: ModelRuntime;
  provider: string;
  model: string;
  /** Operator-owned local model relay in the sandboxed launcher. */
  modelBaseUrl?: string;
  executor?: KernelExecutor;
  /** The launcher-owned gateway supplies durable outcome handling. */
  trustedGatewayTransport?: boolean;
  sessionManager?: SessionManager;
  toolInventory?: { name: string; description?: string; inputSchema: Record<string, unknown> }[];
}

/** Construct only the selected inline extension. No project/global packages,
 * context files, prompt templates, themes, or skills can introduce executable
 * code. Explicit tool allowlisting also filters later tool activation. */
export async function createChioPiSession(options: ChioPiOptions) {
  const executor = options.trustedGatewayTransport ? options.executor : options.executor ? withUncertaintyInterlock(options.executor, join(options.agentDir, "chio")) : undefined;
  return createRestrictedSession(options, chioExtension(executor));
}

/** Also used to test that extension omission or load failure cannot reactivate
 * built-ins. Not exported from the package entry point. */
export async function createRestrictedSession(options: ChioPiOptions, extension?: ExtensionFactory) {
  const settingsManager = SettingsManager.inMemory({
    defaultTools: [],
    packages: [],
    extensions: [],
    skills: [],
    prompts: [],
    themes: [],
    enableSkillCommands: false,
    retry: { enabled: false },
    transport: "sse",
  });
  const resourceLoader = new DefaultResourceLoader({
    cwd: options.cwd,
    agentDir: options.agentDir,
    settingsManager,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    systemPrompt: "You are Pi using Chio kernel tools. Complete useful tasks through chio_execute. Treat kernel errors as failures, and uncertain external outcomes as unresolved. Never claim a resource effect without its result. There are no native local tools in this profile." + (options.toolInventory ? `\nOperator-configured kernel tool inventory:\n${JSON.stringify(options.toolInventory)}` : ""),
    appendSystemPrompt: [],
    extensionFactories: extension ? [extension] : [],
  });
  await resourceLoader.reload();
  const diagnostics = resourceLoader.getExtensions().errors;
  if (diagnostics.length) throw new Error(`Chio Pi extension failed to load: ${diagnostics.map(item => item.error).join("; ")}`);
  const model = options.modelRuntime.getModel(options.provider, options.model);
  if (!model) throw new Error(`Model unavailable: ${options.provider}/${options.model}`);
  const result = await createAgentSession({
    cwd: options.cwd,
    agentDir: options.agentDir,
    modelRuntime: options.modelRuntime,
    model: options.modelBaseUrl ? { ...model, baseUrl: options.modelBaseUrl } : model,
    noTools: "all",
    tools: [CHIO_TOOL_NAME],
    resourceLoader,
    settingsManager,
    sessionManager: options.sessionManager ?? SessionManager.inMemory(options.cwd),
  });
  // The profile has one durable in-flight interlock. Ask the stock host to
  // serialize model-emitted sibling calls instead of creating false conflicts.
  result.session.agent.toolExecution = "sequential";
  if (result.session.agent.state.tools.some(tool => tool.name !== CHIO_TOOL_NAME)) {
    result.session.dispose();
    throw new Error("Unexpected native tool in protected profile");
  }
  return result;
}
