import { withChio } from "@chio-protocol/next";
import { localChatEvaluator } from "../../../lib/evaluator.js";

export const runtime = "edge";

export const POST = withChio(async () => {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(
        encoder.encode("data: {\"message\":\"hello from Chio\"}\n\n"),
      );
      controller.close();
    },
  });
  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
    },
  });
}, {
  evaluate: localChatEvaluator,
});
