import http from "node:http";
import { pathToFileURL } from "node:url";
import { Elysia } from "elysia";
import { chio } from "@chio-protocol/elysia";

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

export function createApp({
  enableChio = true,
  sidecarUrl = process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
} = {}) {
  const app = new Elysia();

  if (enableChio) {
    app.use(
      chio({
        sidecarUrl,
        skip: ["/healthz"],
      }),
    );
  }

  return app
    .get("/healthz", () => ({ status: "ok" }))
    .get("/hello", () => ({ message: "hello from elysia" }))
    .post("/echo", ({ body, set }) => {
      try {
        return parseEchoPayload(body ?? {});
      } catch (error) {
        if (error instanceof EchoPayloadError) {
          set.status = 400;
          return { error: error.message };
        }
        throw error;
      }
    });
}

export function createNodeServer(app, port) {
  return http.createServer(async (req, res) => {
    const url = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? `127.0.0.1:${port}`}`,
    );
    const bodyChunks = [];
    for await (const chunk of req) {
      bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    const request = new Request(url, {
      method: req.method ?? "GET",
      headers: req.headers,
      body:
        bodyChunks.length > 0
          ? Buffer.concat(bodyChunks)
          : undefined,
    });

    const response = await app.handle(request);
    res.statusCode = response.status;
    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    const responseBody = Buffer.from(await response.arrayBuffer());
    res.end(responseBody);
  });
}

const isMain = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;

if (isMain) {
  const port = Number(process.env["HELLO_ELYSIA_PORT"] ?? "8014");
  const server = createNodeServer(createApp(), port);
  server.listen(port, "127.0.0.1", () => {
    process.stdout.write(`hello-elysia listening on http://127.0.0.1:${port}\n`);
  });
}
