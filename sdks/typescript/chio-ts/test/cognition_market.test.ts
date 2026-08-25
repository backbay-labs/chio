import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  CognitionMarketBuyer,
  CognitionMarketSeller,
  type VerifiedFindingProof,
} from "../src/cognition_market.ts";

function profileFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-"));
  const path = join(directory, "buyer.json");
  writeFileSync(
    path,
    "{\"bearerToken\":\"buyer-secret\",\"endpoint\":\"http://operator.local\",\"market\":{\"statusFeedOperator\":{\"feedId\":\"finding-status/local\"}},\"payoutDestination\":\"0x1111111111111111111111111111111111111111\",\"principalId\":\"buyer-1\",\"schema\":\"chio.finding.buyer-client.v1\",\"signingSeed\":\"2222222222222222222222222222222222222222222222222222222222222222\"}",
  );
  return path;
}

function sellerProfileFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-seller-"));
  const path = join(directory, "seller.json");
  writeFileSync(
    path,
    "{\"bearerToken\":\"seller-secret\",\"endpoint\":\"http://operator.local\",\"market\":{\"statusFeedOperator\":{\"feedId\":\"finding-status/local\"}},\"payoutDestination\":\"0x3333333333333333333333333333333333333333\",\"principalId\":\"seller-1\",\"schema\":\"chio.finding.seller-client.v1\"}",
  );
  return path;
}

test("buyer executes search, proof, status, and purchase with scoped auth", async () => {
  const findingId = "a".repeat(64);
  const requests: Request[] = [];
  const mockedFetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    requests.push(request);
    assert.equal(request.headers.get("authorization"), "Bearer buyer-secret");
    if (request.url.endsWith("/proof")) {
      return new Response('{"schema":"proof"}', { status: 200 });
    }
    if (request.url.endsWith("/purchase")) {
      const body = JSON.parse(await request.text()) as Record<string, unknown>;
      assert.equal(body.schema, "chio.finding.purchase-request.v1");
      assert.equal(typeof body.requestId, "string");
      assert.equal((body.requestId as string).length, 64);
      assert.equal("payer" in body, false);
      return Response.json({ verdict: "allow" });
    }
    if (request.url.includes("/status/")) return Response.json({ status: "live" });
    return Response.json({ count: 1, results: [] });
  };
  const buyer = new CognitionMarketBuyer(profileFile(), { fetch: mockedFetch });
  assert.equal((await buyer.search({ topicPrefix: "rust" })).count, 1);
  assert.equal(new TextDecoder().decode(await buyer.proof(findingId)), '{"schema":"proof"}');
  assert.equal((await buyer.status(findingId)).status, "live");
  const verified: VerifiedFindingProof = {
    findingId,
    proof: new Uint8Array([1]),
    verification: { findingId },
  };
  assert.equal((await buyer.purchase(verified, { maxPriceUnits: 300 })).verdict, "allow");
  assert.equal(requests.length, 4);
});

test("buyer rejects noncanonical credential files", () => {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-invalid-"));
  const path = join(directory, "buyer.json");
  writeFileSync(path, '{ "schema": "chio.finding.buyer-client.v1" }');
  assert.throws(() => new CognitionMarketBuyer(path), /client profile is invalid/);
});

test("seller packages and admits with only its scoped credential", async () => {
  let submitted: Record<string, unknown> | undefined;
  const seller = new CognitionMarketSeller(sellerProfileFile(), {
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.headers.get("authorization"), "Bearer seller-secret");
      submitted = JSON.parse(await request.text()) as Record<string, unknown>;
      assert.equal(typeof submitted.requestId, "string");
      return Response.json({
        activation: { outcome: "activated" },
        findingId: "c".repeat(64),
        proofBundle: "/operator/proof.json",
        requestId: submitted.requestId,
        schema: "chio.finding.verified-fix-submission-result.v1",
        sellerPrincipal: "seller-1",
      });
    },
  });
  const packageRequest = await seller.packageVerifiedFix({
    repository: ".",
    base: "base",
    candidate: "candidate",
    tests: ["./check.sh"],
    topic: "rust/fix",
  });
  const result = await seller.admit(packageRequest);
  assert.equal(result.findingId, "c".repeat(64));
  assert.deepEqual(packageRequest, submitted);
});

test("seller retracts with the same scoped credential", async () => {
  const findingId = "d".repeat(64);
  const seller = new CognitionMarketSeller(sellerProfileFile(), {
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.url, "http://operator.local/v1/findings/operator/retractions");
      assert.equal(request.headers.get("authorization"), "Bearer seller-secret");
      const body = JSON.parse(await request.text()) as Record<string, unknown>;
      assert.equal(body.findingId, findingId);
      assert.equal((body.requestId as string).length, 64);
      return Response.json({ findingId, status: "retracted" });
    },
  });
  assert.equal((await seller.retract(findingId)).status, "retracted");
});

test("buyer rejects a credential without the pinned status feed", () => {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-invalid-pin-"));
  const path = join(directory, "buyer.json");
  writeFileSync(
    path,
    "{\"bearerToken\":\"buyer-secret\",\"endpoint\":\"http://operator.local\",\"market\":{},\"payoutDestination\":\"0x1111111111111111111111111111111111111111\",\"principalId\":\"buyer-1\",\"schema\":\"chio.finding.buyer-client.v1\",\"signingSeed\":\"2222222222222222222222222222222222222222222222222222222222222222\"}",
  );
  assert.throws(() => new CognitionMarketBuyer(path), /client profile is invalid/);
});

test("buyer returns a patch without applying it", async () => {
  const findingId = "7".repeat(64);
  const payload = Buffer.from(JSON.stringify({
    baseRevision: "base",
    baseline: [{ exitCode: 1 }],
    candidate: [{ exitCode: 0 }],
    candidateRevision: "candidate",
    patch: "diff --git a/example.ts b/example.ts\n",
    repository: "/srv/example",
    schema: "chio.finding.verified-fix-payload.v1",
  })).toString("base64");
  const commitment = createHash("sha256").update(Buffer.from(JSON.stringify({
    media_type: "application/vnd.chio.verified-fix+json",
    payload_b64: payload,
  }))).digest("hex");
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-verifier-"));
  const verifier = join(directory, "chio");
  writeFileSync(verifier, "#!/bin/sh\nprintf '%s' '{\"purchaseTerminalVerified\":true}'\n");
  chmodSync(verifier, 0o700);
  const buyer = new CognitionMarketBuyer(profileFile(), {
    chioBinary: verifier,
    fetch: async () => Response.json({
      findingId,
      output: {
        mediaType: "application/vnd.chio.verified-fix+json",
        payloadB64: payload,
      },
      settlement: "captured",
      verdict: "allow",
    }),
  });
  const verified: VerifiedFindingProof = {
    findingId,
    proof: Buffer.from(JSON.stringify({
      bundle: { finding: { payload_sha256: commitment } },
    })),
    verification: { findingId },
  };
  const purchased = await buyer.purchaseVerifiedFix(verified, { maxPriceUnits: 300 });
  assert.equal(purchased.baseRevision, "base");
  assert.equal(purchased.patch, "diff --git a/example.ts b/example.ts\n");
});

test("buyer request deadline aborts a stalled transport", async () => {
  const buyer = new CognitionMarketBuyer(profileFile(), {
    timeoutMs: 5,
    fetch: async (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    }),
  });
  await assert.rejects(
    buyer.search({ topicPrefix: "rust" }),
    /operator request timed out/,
  );
});
