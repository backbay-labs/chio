// Telemetry-free local receipt sink. The TTFRH bench asserts no
// outbound network calls beyond the explicitly configured upstream
// provider, so this sink writes to an in-memory ring buffer for the
// first-run happy path. Production deployments swap the implementation
// behind ChioReceiptSink with a durable transport.

export interface ChioReceipt {
  id: string;
  verdict: "allow" | "deny";
  reasonCode?: string;
  source: string;
  capturedAtIso: string;
}

export interface ChioReceiptSink {
  list(): readonly ChioReceipt[];
  record(receipt: ChioReceipt): void;
}

class InMemorySink implements ChioReceiptSink {
  private readonly buffer: ChioReceipt[] = [];
  private readonly capacity: number;

  constructor(capacity: number) {
    this.capacity = capacity;
  }

  list(): readonly ChioReceipt[] {
    return [...this.buffer];
  }

  record(receipt: ChioReceipt): void {
    this.buffer.push(receipt);
    if (this.buffer.length > this.capacity) {
      this.buffer.shift();
    }
  }
}

let sharedSink: ChioReceiptSink | undefined;

export function getLocalReceiptSink(): ChioReceiptSink {
  if (sharedSink === undefined) {
    sharedSink = new InMemorySink(64);
    sharedSink.record({
      id: "local-template-receipt",
      verdict: "allow",
      source: "local receipt sink",
      capturedAtIso: "1970-01-01T00:00:00Z",
    });
  }
  return sharedSink;
}

export function resetLocalReceiptSinkForTesting(): void {
  sharedSink = undefined;
}
