// Test-only network fault in the trusted launcher. The installed host and
// gateway files remain unchanged. Do not use this preload for normal operation.
import { ServerResponse } from "node:http";
import { appendFileSync, closeSync, openSync } from "node:fs";
import { createHash } from "node:crypto";
const path = process.env.CHIO_HOST_RESPONSE_FAULT_LOG;
if (!path?.startsWith("/")) throw new Error("An absolute, fresh fault evidence path is required");
closeSync(openSync(path, "wx", 0o600));
const original = ServerResponse.prototype.end;
ServerResponse.prototype.end = function (chunk, ...args) {
  let message, outcome;
  try {
    message = JSON.parse(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
    const content = message?.result?.content;
    if (message?.jsonrpc === "2.0" && Array.isArray(content) && content.length === 1 && content[0].type === "text") outcome = JSON.parse(content[0].text);
  } catch { /* Forward all other responses without changing them. */ }
  if (outcome?.state === "completed" && outcome.evidence === "verified" && outcome.delivery) {
    appendFileSync(path, JSON.stringify({schema: "chio.test.host-response-loss.v1", rpcId: message.id,
      requestId: outcome.requestId, receiptId: outcome.receipt.id,
      frameSha256: createHash("sha256").update(chunk).digest("hex"), bytes: Buffer.byteLength(chunk),
      action: "destroy-before-host-response-body", pid: process.pid}) + "\n");
    this.destroy();
    return this;
  }
  return original.call(this, chunk, ...args);
};
