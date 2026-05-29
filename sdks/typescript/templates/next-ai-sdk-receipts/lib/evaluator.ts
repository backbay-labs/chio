// Default chat-route evaluator. Returns an allow verdict and writes a
// stub receipt into the local sink. The evaluator is static by default;
// swap it for a sidecar call without changing the route handler shape.

import type { ChioRouteEvaluation } from "@chio-protocol/next";
import { getLocalReceiptSink } from "./local-sink.js";

let sequence = 0;

export function localChatEvaluator(): ChioRouteEvaluation {
  sequence += 1;
  const id = `local-receipt-${sequence.toString().padStart(4, "0")}`;
  const sink = getLocalReceiptSink();
  sink.record({
    id,
    verdict: "allow",
    source: "/api/chat",
    capturedAtIso: new Date(0).toISOString(),
  });
  return {
    verdict: "allow",
    receiptId: id,
  };
}
