import express from "express";
import { chio, chioErrorHandler } from "@chio-protocol/express";
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

export function createApp({
  enableChio = true,
  sidecarUrl = process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
} = {}) {
  const app = express();

  if (enableChio) {
    app.use(
      chio({
        sidecarUrl,
        skip: ["/healthz"],
      }),
    );
  }
  app.use(express.json());

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/hello", (req, res) => {
    res.json({
      message: "hello from express",
      receipt_id: req.chioResult?.receipt.id ?? null,
    });
  });

  app.post("/echo", (req, res) => {
    let payload;
    try {
      payload = parseEchoPayload(req.body ?? {});
    } catch (error) {
      if (error instanceof EchoPayloadError) {
        res.status(400).json({ error: error.message });
        return;
      }
      throw error;
    }

    res.json({
      ...payload,
      receipt_id: req.chioResult?.receipt.id ?? null,
      has_raw_body: Buffer.isBuffer(req.rawBody),
    });
  });

  app.use(chioErrorHandler);

  return app;
}

const isMain = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;

if (isMain) {
  const port = Number(process.env["HELLO_EXPRESS_PORT"] ?? "8011");
  createApp().listen(port, "127.0.0.1", () => {
    process.stdout.write(`hello-express listening on http://127.0.0.1:${port}\n`);
  });
}
