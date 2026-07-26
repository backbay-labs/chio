import test from "node:test";
import assert from "node:assert/strict";

import { ReceiptQueryClient } from "../src/receipt_query_client.ts";
import { QueryError, TransportError } from "../src/errors.ts";
import type { ReceiptQueryResponse } from "../src/receipt_query_client.ts";

// Minimal ChioReceipt fixture for response mocking
const FAKE_RECEIPT = {
  id: "receipt-001",
  timestamp: 1700000000,
  capability_id: "cap-001",
  tool_server: "tool.example.com",
  tool_name: "read_file",
  action: { parameters: {}, parameter_hash: "abc123" },
  decision: { verdict: "allow" },
  content_hash: "deadbeef",
  policy_hash: "cafebabe",
  kernel_key: "aa".repeat(32),
  signature: "bb".repeat(64),
};

function makeMockFetch(
  status: number,
  body: unknown,
  capturedRequests?: Array<{ url: string; options: RequestInit }>,
): typeof fetch {
  return async (url: string | URL | Request, options?: RequestInit): Promise<Response> => {
    if (capturedRequests !== undefined) {
      capturedRequests.push({ url: String(url), options: options ?? {} });
    }
    const json = JSON.stringify(body);
    return new Response(json, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

function makeThrowingFetch(error: Error): typeof fetch {
  return async (_url: string | URL | Request, _options?: RequestInit): Promise<Response> => {
    throw error;
  };
}

// --- Constructor and basic query() tests ---

test("query() with no params calls GET baseUrl/v1/receipts/query", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(
    200,
    { totalCount: 0, receipts: [] } satisfies ReceiptQueryResponse,
    requests,
  );

  const client = new ReceiptQueryClient("http://localhost:8080", "tok-123", mockFetch as typeof fetch);
  await client.query();

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "http://localhost:8080/v1/receipts/query");
  assert.equal(requests[0].options.method, "GET");
});

test("query() passes Authorization Bearer header", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080", "my-token", mockFetch as typeof fetch);
  await client.query();

  const headers = requests[0].options.headers as Record<string, string>;
  assert.equal(headers["Authorization"], "Bearer my-token");
});

test("query() strips trailing slash from baseUrl", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080/", "tok", mockFetch as typeof fetch);
  await client.query();

  assert.equal(requests[0].url, "http://localhost:8080/v1/receipts/query");
});

test("query() with params encodes them as URL query parameters", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  await client.query({
    capabilityId: "cap-001",
    toolServer: "tool.example.com",
    toolName: "read_file",
    limit: 10,
    cursor: 5,
  });

  const requestUrl = new URL(requests[0].url);
  assert.equal(requestUrl.searchParams.get("capabilityId"), "cap-001");
  assert.equal(requestUrl.searchParams.get("toolServer"), "tool.example.com");
  assert.equal(requestUrl.searchParams.get("toolName"), "read_file");
  assert.equal(requestUrl.searchParams.get("limit"), "10");
  assert.equal(requestUrl.searchParams.get("cursor"), "5");
});

test("query() preserves exact u64 cost bounds and currency", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);

  await client.query({
    minCost: 18446744073709551615n,
    maxCost: 18446744073709551615n,
    costCurrency: "USD",
  });

  const requestUrl = new URL(requests[0].url);
  assert.equal(requestUrl.searchParams.get("minCost"), "18446744073709551615");
  assert.equal(requestUrl.searchParams.get("maxCost"), "18446744073709551615");
  assert.equal(requestUrl.searchParams.get("costCurrency"), "USD");
});

test("query() returns typed ReceiptQueryResponse with totalCount, nextCursor, receipts", async () => {
  const responseBody: ReceiptQueryResponse = {
    totalCount: 1,
    nextCursor: 42,
    receipts: [FAKE_RECEIPT as never],
  };
  const mockFetch = makeMockFetch(200, responseBody);

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const result = await client.query();

  assert.equal(result.totalCount, 1);
  assert.equal(result.nextCursor, 42);
  assert.equal(result.receipts.length, 1);
  assert.equal(result.receipts[0].id, "receipt-001");
});

test("query() throws QueryError with status on non-200 HTTP response", async () => {
  const mockFetch = makeMockFetch(404, { error: "not found" });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError, `expected QueryError, got ${String(err)}`);
      assert.equal(err.status, 404);
      return true;
    },
  );
});

test("query() throws QueryError on 500 response", async () => {
  const mockFetch = makeMockFetch(500, { error: "internal server error" });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.equal(err.status, 500);
      return true;
    },
  );
});

test("query() throws TransportError on network failure", async () => {
  const networkError = new Error("ECONNREFUSED");
  const mockFetch = makeThrowingFetch(networkError);
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof TransportError, `expected TransportError, got ${String(err)}`);
      assert.equal(err.cause, networkError);
      return true;
    },
  );
});

// --- paginate() tests ---

test("paginate() yields successive pages following nextCursor", async () => {
  let callCount = 0;
  const pages = [
    { totalCount: 4, nextCursor: 2, receipts: [{ ...FAKE_RECEIPT, id: "r1" }, { ...FAKE_RECEIPT, id: "r2" }] },
    { totalCount: 4, nextCursor: 4, receipts: [{ ...FAKE_RECEIPT, id: "r3" }, { ...FAKE_RECEIPT, id: "r4" }] },
    { totalCount: 4, nextCursor: undefined, receipts: [] },
  ];

  const mockFetch: typeof fetch = async () => {
    const page = pages[callCount++];
    return new Response(JSON.stringify(page), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const collectedPages: string[][] = [];

  for await (const page of client.paginate()) {
    collectedPages.push(page.map((r) => r.id));
  }

  assert.equal(collectedPages.length, 2, "should yield 2 non-empty pages");
  assert.deepEqual(collectedPages[0], ["r1", "r2"]);
  assert.deepEqual(collectedPages[1], ["r3", "r4"]);
});

test("paginate() stops when nextCursor is undefined", async () => {
  const mockFetch = makeMockFetch(200, {
    totalCount: 1,
    nextCursor: undefined,
    receipts: [FAKE_RECEIPT],
  });

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const pages: unknown[][] = [];

  for await (const page of client.paginate()) {
    pages.push(page);
  }

  assert.equal(pages.length, 1);
});

test("paginate() with empty first page yields nothing", async () => {
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const pages: unknown[][] = [];

  for await (const page of client.paginate()) {
    pages.push(page);
  }

  assert.equal(pages.length, 0, "empty first page should yield no pages");
});

test("paginate() fails when the server repeats a cursor", async () => {
  let callCount = 0;
  const responses = [
    { totalCount: 1, nextCursor: 5, receipts: [FAKE_RECEIPT] },
    { totalCount: 1, nextCursor: 5, receipts: [{ ...FAKE_RECEIPT, id: "dup" }] },
  ];
  const mockFetch: typeof fetch = async () => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount += 1;
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const iterator = client.paginate();

  const first = await iterator.next();
  assert.equal(first.done, false);
  await assert.rejects(
    () => iterator.next(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.match(err.message, /cursor did not advance/);
      return true;
    },
  );
});

test("paginate() fails when the server regresses a cursor", async () => {
  let callCount = 0;
  const responses = [
    { totalCount: 1, nextCursor: 10, receipts: [FAKE_RECEIPT] },
    { totalCount: 1, nextCursor: 5, receipts: [{ ...FAKE_RECEIPT, id: "dup" }] },
  ];
  const mockFetch: typeof fetch = async () => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount += 1;
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const iterator = client.paginate();

  const first = await iterator.next();
  assert.equal(first.done, false);
  await assert.rejects(
    () => iterator.next(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.match(err.message, /cursor did not advance/);
      return true;
    },
  );
});

// --- Package smoke tests ---

async function readPackageJson(): Promise<{ name: string; version: string; private?: boolean }> {
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const testDir = dirname(fileURLToPath(import.meta.url));
  const pkgPath = resolve(testDir, "../package.json");
  const raw = await readFile(pkgPath, "utf8");
  return JSON.parse(raw) as { name: string; version: string; private?: boolean };
}

test("package.json name is @chio-protocol/sdk", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.name, "@chio-protocol/sdk");
});

test("package.json version is 0.1.0", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.version, "0.1.0");
});

test("package.json private field is absent", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.private, undefined);
});
