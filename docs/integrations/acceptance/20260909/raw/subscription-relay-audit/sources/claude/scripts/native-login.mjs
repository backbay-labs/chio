import { createServer } from "node:http";
import { spawn } from "node:child_process";

/** Let native Claude own Keychain access and OAuth refresh. The trusted parent
 * observes one local gateway request; no model or tool execution is requested
 * upstream and no credential is written into the sandbox or evidence. */
export async function nativeLogin(host, workspace) {
  let child, timer, forceStop, credential, completed = false;
  let settle;
  const result = new Promise((resolve, reject) => { settle = {resolve, reject}; });
  const server = createServer(async (request, response) => {
    request.resume();
    if (request.method === "POST" && request.url === "/v1/messages?beta=true"
      && typeof request.headers.authorization === "string" && request.headers.authorization.startsWith("Bearer ")
      && typeof request.headers["anthropic-beta"] === "string") {
      credential = { authorization: request.headers.authorization, beta: request.headers["anthropic-beta"] };
      response.writeHead(403); response.end("Native authentication observed; no inference dispatched");
      stop();
    } else { response.writeHead(403); response.end("Authentication observation only"); }
  });
  function stop() {
    child?.kill("SIGTERM");
    if (child && !forceStop) forceStop = setTimeout(() => child.kill("SIGKILL"), 2000);
  }
  function finish(error) {
    if (completed) return;
    completed = true; clearTimeout(timer); clearTimeout(forceStop);
    if (error || !credential) settle.reject(new Error("Native Claude subscription authentication unavailable; run claude auth login in the operator profile"));
    else settle.resolve(credential);
  }
  try {
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const env = {};
    for (const key of ["PATH", "HOME", "USER", "LOGNAME", "LANG", "CLAUDE_CONFIG_DIR"]) if (process.env[key]) env[key] = process.env[key];
    Object.assign(env, {ANTHROPIC_BASE_URL:`http://127.0.0.1:${server.address().port}`,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1",DISABLE_AUTOUPDATER:"1"});
    child = spawn(host, ["--safe-mode", "--tools", "", "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence", "--model", "sonnet", "--print", "Credential acquisition only."],
      {cwd: workspace, env, stdio:"ignore"});
    child.once("error", finish); child.once("close", () => finish());
    timer = setTimeout(() => { stop(); }, 30_000);
    return await result;
  } finally {
    clearTimeout(timer); clearTimeout(forceStop); child?.kill("SIGKILL");
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  }
}
