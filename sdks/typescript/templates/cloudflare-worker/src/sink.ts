// Telemetry-free receipt sink backed by a Workers KV namespace.
// The TTFRH first-run bench asserts the worker stays offline beyond
// the explicitly configured upstream provider.

export interface ChioReceipt {
  id: string;
  verdict: "allow" | "deny";
  source: string;
  capturedAtIso: string;
}

export interface KvLike {
  get(key: string, options?: { type?: "json" | "text" }): Promise<unknown>;
  put(key: string, value: string): Promise<void>;
  list(options?: { prefix?: string }): Promise<{ keys: { name: string }[] }>;
}

const KEY_PREFIX = "receipt:";

export async function recordReceipt(
  kv: KvLike,
  receipt: ChioReceipt,
): Promise<void> {
  await kv.put(`${KEY_PREFIX}${receipt.id}`, JSON.stringify(receipt));
}

export async function listReceipts(kv: KvLike): Promise<ChioReceipt[]> {
  const list = await kv.list({ prefix: KEY_PREFIX });
  const items: ChioReceipt[] = [];
  for (const entry of list.keys) {
    const raw = await kv.get(entry.name, { type: "json" });
    if (raw && typeof raw === "object") {
      items.push(raw as ChioReceipt);
    }
  }
  return items;
}
