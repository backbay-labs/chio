import { withChio } from "@chio/next";

export const runtime = "edge";

export const POST = withChio(async () => {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode("data: {\"message\":\"hello from Chio\"}\n\n"));
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
  evaluate: () => ({
    verdict: "allow",
    receiptId: "local-template-receipt",
  }),
});
