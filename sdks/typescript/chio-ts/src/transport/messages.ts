export type JsonRpcId = string | number | null;

export type JsonRpcMessage = Record<string, unknown> & {
  id?: JsonRpcId;
  method?: string;
};

export type RpcMessageHandler = (message: JsonRpcMessage) => void | Promise<void>;

function parseJsonRpcMessage(input: string): JsonRpcMessage {
  return JSON.parse(input) as JsonRpcMessage;
}

export function parseRpcMessages(rawBody: string): JsonRpcMessage[] {
  const trimmed = rawBody.trim();
  if (!trimmed) {
    return [];
  }
  if (trimmed.startsWith("{")) {
    return [parseJsonRpcMessage(trimmed)];
  }

  const messages: JsonRpcMessage[] = [];
  let buffer: string[] = [];
  for (const line of rawBody.split(/\r?\n/)) {
    if (!line.trim()) {
      if (buffer.length > 0) {
        messages.push(parseJsonRpcMessage(buffer.join("\n")));
        buffer = [];
      }
      continue;
    }
    if (line.startsWith("data:")) {
      buffer.push(line.slice(5).trimStart());
    }
  }
  if (buffer.length > 0) {
    messages.push(parseJsonRpcMessage(buffer.join("\n")));
  }
  return messages;
}

export async function readRpcMessagesUntilTerminal(
  response: Response,
  expectedId?: JsonRpcId,
  onMessage: RpcMessageHandler = async () => {},
): Promise<JsonRpcMessage[]> {
  if (!response.body) {
    const messages = parseRpcMessages(await response.text());
    for (const message of messages) {
      await onMessage(message);
    }
    return messages;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const messages: JsonRpcMessage[] = [];
  const eventData: string[] = [];
  let rawBody = "";
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      rawBody += decoder.decode();
      break;
    }

    const chunk = decoder.decode(value, { stream: true });
    rawBody += chunk;
    buffer += chunk;
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line.trim()) {
        if (eventData.length > 0) {
          const message = parseJsonRpcMessage(eventData.join("\n"));
          messages.push(message);
          if (expectedId !== undefined && message.id === expectedId && !message.method) {
            await reader.cancel();
            return messages;
          }
          await onMessage(message);
          eventData.length = 0;
        }
        continue;
      }
      if (line.startsWith("data:")) {
        eventData.push(line.slice(5).trimStart());
      }
    }
  }

  if (eventData.length > 0) {
    const message = parseJsonRpcMessage(eventData.join("\n"));
    messages.push(message);
    await onMessage(message);
  }
  if (messages.length === 0) {
    messages.push(...parseRpcMessages(rawBody));
  }
  return messages;
}

export function terminalMessage(messages: JsonRpcMessage[], expectedId: JsonRpcId): JsonRpcMessage {
  const match = messages.find((message) => message.id === expectedId && !message.method);
  if (!match) {
    throw new Error(`no terminal response for JSON-RPC id ${expectedId}`);
  }
  const error = match.error;
  if (error && typeof error === "object") {
    const message =
      "message" in error && typeof error.message === "string"
        ? error.message
        : `JSON-RPC error for id ${expectedId}`;
    throw new Error(message);
  }
  return match;
}
