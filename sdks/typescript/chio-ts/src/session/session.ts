import {
  deleteSession,
  postNotification,
  postRpc,
  terminalMessage,
  type JsonRpcMessage,
  type RpcExchange,
  type RpcMessageHandler,
  type SessionState,
} from "../transport/index.ts";
import { isJsonRpcFailure, type JsonRpcNotification, type JsonRpcRequest, type JsonRpcResponse } from "../types.ts";

export interface ChioSessionHandshake {
  initializeResponse: RpcExchange;
  initializedResponse: RpcExchange;
}

export interface ChioSessionOptions extends SessionState {
  authToken: string;
  baseUrl: string;
  fetchImpl?: typeof fetch;
  onMessage?: RpcMessageHandler;
  handshake?: ChioSessionHandshake | null;
}

export class ChioSession {
  readonly authToken: string;
  readonly baseUrl: string;
  handshake: ChioSessionHandshake | null;
  readonly protocolVersion: string;
  readonly sessionId: string;

  #fetchImpl: typeof fetch;
  #nextRequestId: number;
  #onMessage: RpcMessageHandler;

  constructor(options: ChioSessionOptions) {
    this.authToken = options.authToken;
    this.baseUrl = options.baseUrl;
    this.handshake = options.handshake ?? null;
    this.protocolVersion = options.protocolVersion;
    this.sessionId = options.sessionId;
    this.#fetchImpl = options.fetchImpl ?? fetch;
    this.#nextRequestId = 2;
    this.#onMessage = options.onMessage ?? (async () => {});
  }

  setMessageHandler(onMessage: RpcMessageHandler): void {
    this.#onMessage = onMessage;
  }

  async request<TParams = unknown>(
    method: string,
    params?: TParams,
    onMessage: RpcMessageHandler = this.#onMessage,
  ): Promise<RpcExchange> {
    const request: JsonRpcRequest<TParams> = {
      jsonrpc: "2.0",
      id: this.#nextId(),
      method,
    };
    if (params !== undefined) {
      request.params = params;
    }

    return postRpc(
      this.baseUrl,
      this.authToken,
      this.sessionId,
      this.protocolVersion,
      request,
      onMessage,
      this.#fetchImpl,
    );
  }

  async sendEnvelope(
    body: Record<string, unknown>,
    onMessage: RpcMessageHandler = this.#onMessage,
  ): Promise<RpcExchange> {
    return postRpc(
      this.baseUrl,
      this.authToken,
      this.sessionId,
      this.protocolVersion,
      body,
      onMessage,
      this.#fetchImpl,
    );
  }

  async requestResult<TResult = unknown, TParams = unknown>(
    method: string,
    params?: TParams,
    onMessage: RpcMessageHandler = this.#onMessage,
  ): Promise<JsonRpcResponse<TResult>> {
    const exchange = await this.request(method, params, onMessage);
    return terminalMessage(
      exchange.messages,
      exchange.request.id as string | number | null,
    ) as unknown as JsonRpcResponse<TResult>;
  }

  async notification<TParams = unknown>(
    method: string,
    params?: TParams,
    onMessage: RpcMessageHandler = this.#onMessage,
  ): Promise<RpcExchange> {
    const notification: JsonRpcNotification<TParams> = {
      jsonrpc: "2.0",
      method,
    };
    if (params !== undefined) {
      notification.params = params;
    }

    return postNotification(
      this.baseUrl,
      this.authToken,
      this.sessionId,
      this.protocolVersion,
      notification,
      onMessage,
      this.#fetchImpl,
    );
  }

  async listTools(params: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("tools/list", params);
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("tools/call", {
      name,
      arguments: args,
    });
  }

  async listResources(params: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("resources/list", params);
  }

  async readResource(uri: string): Promise<unknown> {
    return this.#result("resources/read", { uri });
  }

  async subscribeResource(uri: string): Promise<unknown> {
    return this.#result("resources/subscribe", { uri });
  }

  async unsubscribeResource(uri: string): Promise<unknown> {
    return this.#result("resources/unsubscribe", { uri });
  }

  async listResourceTemplates(params: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("resources/templates/list", params);
  }

  async listPrompts(params: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("prompts/list", params);
  }

  async getPrompt(name: string, args?: Record<string, unknown>): Promise<unknown> {
    const params: Record<string, unknown> = { name };
    if (args) {
      params.arguments = args;
    }
    return this.#result("prompts/get", params);
  }

  async complete(params: Record<string, unknown>): Promise<unknown> {
    return this.#result("completion/complete", params);
  }

  async setLogLevel(level: string): Promise<RpcExchange> {
    return this.notification("logging/setLevel", { level });
  }

  async listTasks(params: Record<string, unknown> = {}): Promise<unknown> {
    return this.#result("tasks/list", params);
  }

  async getTask(taskId: string): Promise<unknown> {
    return this.#result("tasks/get", { taskId });
  }

  async getTaskResult(taskId: string): Promise<unknown> {
    return this.#result("tasks/result", { taskId });
  }

  async cancelTask(taskId: string): Promise<unknown> {
    return this.#result("tasks/cancel", { taskId });
  }

  async close(): Promise<{ status: number; headers: Record<string, string> }> {
    return deleteSession(this.baseUrl, this.authToken, this.sessionId, this.#fetchImpl);
  }

  #nextId(): number {
    const id = this.#nextRequestId;
    this.#nextRequestId += 1;
    return id;
  }

  async #result<TResult = unknown>(
    method: string,
    params?: Record<string, unknown>,
  ): Promise<TResult> {
    const response = await this.requestResult<TResult>(method, params);
    if (isJsonRpcFailure(response)) {
      throw new Error(response.error.message);
    }
    return response.result;
  }
}
