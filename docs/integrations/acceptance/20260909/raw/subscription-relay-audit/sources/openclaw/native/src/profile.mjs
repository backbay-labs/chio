export const TOOL_NAME = "chio_call";
export const PLUGIN_ID = "chio-kernel";

// This policy is independent of plugin loading. Removing this plugin cannot
// reveal native tools. The resource owner must also deny direct host access.
export function restrictedTools() {
  return {
    profile: "minimal",
    alsoAllow: [TOOL_NAME],
    deny: ["group:openclaw"],
    elevated: { enabled: false },
    exec: { security: "deny", applyPatch: { enabled: false } },
  };
}

export function assertRestrictedProfile(config) {
  const tools = config?.tools;
  // The pinned host auto-enables its bundled provider plugin for this canonical
  // subscription provider. It registers provider capabilities, not agent tools.
  const providers = config?.models?.providers ?? {};
  const nativeSubscription = JSON.stringify(Object.keys(providers)) === JSON.stringify(["openai-codex"]) &&
    providers["openai-codex"].api === "openai-codex-responses";
  const allowedPlugins = nativeSubscription ? [PLUGIN_ID, "openai"] : [PLUGIN_ID];
  if (tools?.profile !== "minimal" ||
      JSON.stringify(tools.alsoAllow) !== JSON.stringify([TOOL_NAME]) ||
      !tools.deny?.includes("group:openclaw") ||
      tools.allow !== undefined || tools.byProvider !== undefined ||
      tools.elevated?.enabled !== false || tools.exec?.security !== "deny") {
    throw new Error("Chio requires the restricted native OpenClaw tools profile");
  }
  if (Object.values(config?.mcp?.servers ?? {}).length ||
      Object.values(config?.channels ?? {}).some((channel) => channel?.enabled !== false) ||
      config?.acp?.enabled === true || config?.cron?.enabled !== false ||
      config?.browser?.enabled !== false || config?.hooks?.enabled === true ||
      ["native", "nativeSkills", "text", "bash", "config", "restart", "mcp", "plugins", "debug"].some((key) => config?.commands?.[key] !== false)) {
    throw new Error("Chio restricted mode requires channels, MCP, automation, browser, and administrative chat commands disabled");
  }
  if (JSON.stringify(config?.plugins?.allow) !== JSON.stringify(allowedPlugins) ||
      config?.agents?.defaults?.skipBootstrap !== true ||
      JSON.stringify(config?.agents?.defaults?.skills) !== "[]" ||
      config?.agents?.defaults?.heartbeat?.every !== "0m" ||
      Object.values(config?.models?.providers ?? {}).some((provider) => provider.agentRuntime?.id !== "pi")) {
    throw new Error("Chio restricted mode requires isolated bootstrap, no skills or heartbeat, only required Chio/provider plugins, and explicit PI model runtime");
  }
  const defaults = config?.agents?.defaults;
  if (defaults?.agentRuntime !== undefined || defaults?.embeddedHarness !== undefined ||
      Object.values(defaults?.models ?? {}).some((model) => model?.agentRuntime !== undefined) ||
      Object.values(config?.models?.providers ?? {}).some((provider) =>
        (provider.models ?? []).some((model) => model?.agentRuntime !== undefined))) {
    throw new Error("Model and default runtime overrides can supersede the required PI provider runtime");
  }
  for (const agent of config?.agents?.list ?? []) {
    if (Object.keys(agent).some((key) => !["id", "default", "name", "description"].includes(key))) {
      throw new Error("Per-agent operational overrides are not supported by the Chio restricted profile");
    }
  }
}
