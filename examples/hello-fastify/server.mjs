import Fastify from "fastify";
import { chio } from "@chio-protocol/fastify";
import { pathToFileURL } from "node:url";

export class EchoPayloadError extends Error {}

export function parseEchoPayload(payload) {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new EchoPayloadError("body must be a JSON object");
  }

  const allowedKeys = new Set(["message", "count"]);
  const extraKeys = Object.keys(payload)
    .filter((key) => !allowedKeys.has(key))
    .sort();
  if (extraKeys.length > 0) {
    throw new EchoPayloadError(`unexpected fields: ${extraKeys.join(", ")}`);
  }

  if (typeof payload.message !== "string" || payload.message.length === 0) {
    throw new EchoPayloadError("message must be a non-empty string");
  }

  const count = payload.count ?? 1;
  if (!Number.isInteger(count) || count < 1) {
    throw new EchoPayloadError("count must be an integer greater than or equal to 1");
  }

  return {
    message: payload.message,
    count,
  };
}

export async function createServer({
  enableChio = true,
  sidecarUrl = process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
} = {}) {
  const fastify = Fastify({ logger: false });

  if (enableChio) {
    await fastify.register(chio, {
      sidecarUrl,
      skip: ["/healthz"],
    });
  }

  fastify.get("/healthz", async () => ({ status: "ok" }));

  fastify.get("/hello", async (request) => ({
    message: "hello from fastify",
    receipt_id: request.chioResult?.receipt.id ?? null,
  }));

  fastify.post("/echo", async (request, reply) => {
    let payload;
    try {
      payload = parseEchoPayload(request.body ?? {});
    } catch (error) {
      if (error instanceof EchoPayloadError) {
        reply.code(400);
        return { error: error.message };
      }
      throw error;
    }

    return {
      ...payload,
      receipt_id: request.chioResult?.receipt.id ?? null,
      body_cached: request.body !== undefined,
    };
  });

  return fastify;
}

const isMain = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;

if (isMain) {
  const fastify = await createServer();
  const port = Number(process.env["HELLO_FASTIFY_PORT"] ?? "8012");
  await fastify.listen({ host: "127.0.0.1", port });
}
