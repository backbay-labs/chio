import { ChioClient, ReceiptQueryClient } from "../src/index.ts";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable: ${name}`);
  }
  return value;
}

async function sessionCapabilityId(
  baseUrl: string,
  authToken: string,
  sessionId: string,
): Promise<string> {
  const response = await fetch(`${baseUrl}/admin/sessions/${sessionId}/trust`, {
    headers: { Authorization: `Bearer ${authToken}` },
  });
  if (!response.ok) {
    throw new Error(`session trust query failed with HTTP ${response.status}`);
  }
  const payload = (await response.json()) as {
    capabilities?: Array<{ capabilityId?: string }>;
  };
  const capabilityId = payload.capabilities?.[0]?.capabilityId;
  if (!capabilityId) {
    throw new Error("session trust endpoint did not return an active capability id");
  }
  return capabilityId;
}

const baseUrl = requireEnv("CHIO_BASE_URL");
const controlUrl = process.env.CHIO_CONTROL_URL ?? baseUrl;
const authToken = requireEnv("CHIO_AUTH_TOKEN");
const message = process.argv[2] ?? "hello from the TypeScript SDK";

const client = ChioClient.withStaticBearer(baseUrl, authToken);
const session = await client.initialize({
  clientInfo: {
    name: "@chio-protocol/sdk/examples/typescript",
    version: "0.1.0",
  },
});

try {
  const tools = (await session.listTools()) as { tools?: Array<{ name: string }> };
  const capabilityId = await sessionCapabilityId(baseUrl, authToken, session.sessionId);
  const toolResult = (await session.callTool("echo_text", { message })) as {
    content?: Array<{ text?: string }>;
    structuredContent?: { echo?: string };
  };
  const receipts = await new ReceiptQueryClient(controlUrl, authToken).query({
    capabilityId,
    limit: 10,
  });
  const receipt = receipts.receipts.at(-1);
  if (!receipt) {
    throw new Error("receipt query did not return the governed tool receipt");
  }

  console.log(
    JSON.stringify(
      {
        sessionId: session.sessionId,
        capabilityId,
        toolNames: tools.tools?.map((tool) => tool.name) ?? [],
        echo:
          toolResult.structuredContent?.echo ??
          toolResult.content?.[0]?.text ??
          null,
        receiptId: receipt.id,
        receiptDecision: receipt.decision,
      },
      null,
      2,
    ),
  );
} finally {
  await session.close();
}
