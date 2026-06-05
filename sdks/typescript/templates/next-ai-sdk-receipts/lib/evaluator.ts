// TEMPLATE STUB: replace this module before production use.
// Wire a real Chio sidecar or policy evaluator here; do not ship the default.
// The scaffold denies by default (fail-closed) and only records a local stub receipt.

import type { ChioRouteEvaluation } from "@chio-protocol/next";
import { getLocalReceiptSink } from "./local-sink.js";

let sequence = 0;

export function localChatEvaluator(): ChioRouteEvaluation {
  sequence += 1;
  const id = `local-receipt-${sequence.toString().padStart(4, "0")}`;
  const sink = getLocalReceiptSink();
  sink.record({
    id,
    verdict: "deny",
    source: "/api/chat",
    capturedAtIso: new Date(0).toISOString(),
  });
  return {
    verdict: "deny",
    receiptId: id,
  };
}
