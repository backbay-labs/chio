import {
  readRpcMessagesUntilTerminal,
  terminalMessage,
  type JsonRpcMessage,
  type RpcMessageHandler,
} from "./messages.ts";

export interface SessionState {
  sessionId: string;
  protocolVersion: string;
}

export interface RpcExchange {
  request: Record<string, unknown>;
  status: number;
  headers: Record<string, string>;
  messages: JsonRpcMessage[];
}

export interface InitializeSessionResult extends SessionState {
  initializeResponse: RpcExchange;
  initializedResponse: RpcExchange;
}

export type InitializeSessionMessageHandler = (
  message: JsonRpcMessage,
  session: SessionState,
) => void | Promise<void>;

type FetchImpl = typeof fetch;

function responseHeaders(response: Response): Record<string, string> {
  return Object.fromEntries(response.headers.entries());
}

export function buildRpcHeaders(
  authToken: string,
  sessionId?: string | null,
  protocolVersion?: string | null,
): Record<string, string> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${authToken}`,
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
  };
  if (sessionId) {
    headers["MCP-Session-Id"] = sessionId;
  }
  if (protocolVersion) {
    headers["MCP-Protocol-Version"] = protocolVersion;
  }
  return headers;
}

export function buildSessionDeleteHeaders(authToken: string, sessionId: string): Record<string, string> {
  return {
    Authorization: `Bearer ${authToken}`,
    "MCP-Session-Id": sessionId,
  };
}

export async function postRpc(
  baseUrl: string,
  authToken: string,
  sessionId: string | null,
  protocolVersion: string | null,
  body: Record<string, unknown>,
  onMessage: RpcMessageHandler = async () => {},
  fetchImpl: FetchImpl = fetch,
): Promise<RpcExchange> {
  const response = await fetchImpl(`${baseUrl}/mcp`, {
    method: "POST",
    headers: buildRpcHeaders(authToken, sessionId, protocolVersion),
    body: JSON.stringify(body),
  });
  return {
    request: body,
    status: response.status,
    headers: responseHeaders(response),
    messages: await readRpcMessagesUntilTerminal(
      response,
      body.id as string | number | null | undefined,
      onMessage,
    ),
  };
}

export async function postNotification(
  baseUrl: string,
  authToken: string,
  sessionId: string,
  protocolVersion: string | null,
  body: Record<string, unknown>,
  onMessage: RpcMessageHandler = async () => {},
  fetchImpl: FetchImpl = fetch,
): Promise<RpcExchange> {
  const response = await fetchImpl(`${baseUrl}/mcp`, {
    method: "POST",
    headers: buildRpcHeaders(authToken, sessionId, protocolVersion),
    body: JSON.stringify(body),
  });
  return {
    request: body,
    status: response.status,
    headers: responseHeaders(response),
    messages: await readRpcMessagesUntilTerminal(response, undefined, onMessage),
  };
}

export async function deleteSession(
  baseUrl: string,
  authToken: string,
  sessionId: string,
  fetchImpl: FetchImpl = fetch,
): Promise<{ status: number; headers: Record<string, string> }> {
  const response = await fetchImpl(`${baseUrl}/mcp`, {
    method: "DELETE",
    headers: buildSessionDeleteHeaders(authToken, sessionId),
  });
  return {
    status: response.status,
    headers: responseHeaders(response),
  };
}

export async function initializeSession(
  baseUrl: string,
  authToken: string,
  initializeBody: Record<string, unknown>,
  onInitializedMessage: InitializeSessionMessageHandler = async () => {},
  fetchImpl: FetchImpl = fetch,
): Promise<InitializeSessionResult> {
  const initializeResponse = await postRpc(
    baseUrl,
    authToken,
    null,
    null,
    initializeBody,
    async () => {},
    fetchImpl,
  );
  const initializeId = initializeBody.id as string | number | null | undefined;
  const message = terminalMessage(initializeResponse.messages, initializeId ?? null);
  if (initializeResponse.status !== 200) {
    throw new Error(`initialize returned HTTP ${initializeResponse.status}`);
  }
  const sessionId = initializeResponse.headers["mcp-session-id"];
  if (!sessionId) {
    throw new Error("initialize response did not include MCP-Session-Id");
  }
  const result = message.result;
  const protocolVersion =
    result && typeof result === "object" && "protocolVersion" in result
      ? result.protocolVersion
      : undefined;
  if (typeof protocolVersion !== "string" || protocolVersion.length === 0) {
    throw new Error("initialize response did not include protocolVersion");
  }

  const initializedResponse = await postNotification(
    baseUrl,
    authToken,
    sessionId,
    protocolVersion,
    {
      jsonrpc: "2.0",
      method: "notifications/initialized",
    },
    async (message) => {
      await onInitializedMessage(message, { sessionId, protocolVersion });
    },
    fetchImpl,
  );
  if (![200, 202].includes(initializedResponse.status)) {
    throw new Error(`notifications/initialized returned HTTP ${initializedResponse.status}`);
  }

  return {
    sessionId,
    protocolVersion,
    initializeResponse,
    initializedResponse,
  };
}
