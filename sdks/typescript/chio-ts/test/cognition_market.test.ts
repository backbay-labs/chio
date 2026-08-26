import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  CognitionMarketBuyer,
  CognitionMarketError,
  CognitionMarketSeller,
  type PurchasedVerifiedFix,
  type VerifiedFindingProof,
} from "../src/cognition_market.ts";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(object[key])}`
  )).join(",")}}`;
}

function profileFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-"));
  const path = join(directory, "buyer.json");
  writeFileSync(
    path,
    canonical({
      bearerToken: "buyer-secret",
      endpoint: "https://operator.local",
      market: {
        statusFeedOperator: {
          authority: {
            authorityId: "status-operator",
            keyEpoch: 1,
            keyHex: "a".repeat(64),
            revocationStatusRef: "local/revocations/status",
            validFrom: 1,
            validUntil: 2_000_000_000,
          },
          feedId: "finding-status/local",
          revokedFrom: null,
          role: "finding_status_operator",
          rotationPolicyRef: "local/rotation/status",
        },
        statusFeedServiceBond: {
          bond_id: "status-bond",
          currency: "USD",
          equivocation_slash_units: 100,
          evidence_sha256: "b".repeat(64),
          feed_id: "finding-status/local",
          inclusion_sla_secs: 300,
          locked_units: 100,
          missed_inclusion_slash_units: 10,
          operator_id: "status-operator",
          valid_from: 1,
          valid_until: 2_000_000_000,
        },
        statusMaxEpochAgeSecs: 300,
      },
      payer: "9".repeat(64),
      payoutDestination: `0x${"1".repeat(40)}`,
      principalId: "buyer-1",
      schema: "chio.finding.buyer-client.v1",
      signingSeed: "2".repeat(64),
    }),
  );
  return path;
}

function sellerProfileFile(): string {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-seller-"));
  const path = join(directory, "seller.json");
  writeFileSync(
    path,
    "{\"bearerToken\":\"seller-secret\",\"endpoint\":\"https://operator.local\",\"market\":{\"statusFeedOperator\":{\"feedId\":\"finding-status/local\"}},\"payoutDestination\":\"0x3333333333333333333333333333333333333333\",\"principalId\":\"seller-1\",\"schema\":\"chio.finding.seller-client.v1\"}",
  );
  return path;
}

test("buyer executes search, proof, status, and purchase with scoped auth", async () => {
  const findingId = "a".repeat(64);
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-status-"));
  const verifier = join(directory, "chio");
  writeFileSync(
    verifier,
    `#!/bin/sh\ncase "$*" in\n  *--purchase-result*) printf '%s' '{"purchaseTerminalVerified":true}' ;;\n  *) printf '%s' '{"finding_id":"${findingId}","proof_kind":"non_inclusion"}' ;;\nesac\n`,
  );
  chmodSync(verifier, 0o700);
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
      assert.equal(body.payer, "9".repeat(64));
      return Response.json({
        verdict: "allow",
        payer: "9".repeat(64),
        payerKey: "9".repeat(64),
      });
    }
    return Response.json({ count: 1, results: [] });
  };
  const buyer = new CognitionMarketBuyer(profileFile(), {
    chioBinary: verifier,
    fetch: mockedFetch,
  });
  assert.equal((await buyer.search({ topicPrefix: "rust" })).count, 1);
  assert.equal(new TextDecoder().decode(await buyer.proof(findingId)), '{"schema":"proof"}');
  assert.equal((await buyer.status(findingId)).status, "live");
  const verified: VerifiedFindingProof = {
    findingId,
    proof: new Uint8Array([1]),
    verification: { findingId },
  };
  assert.equal((await buyer.purchase(verified, { maxPriceUnits: 300 })).verdict, "allow");
  assert.equal(requests.length, 3);
});

test("buyer rejects an unverified generic purchase terminal", async () => {
  const findingId = "a".repeat(64);
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-purchase-reject-"));
  const verifier = join(directory, "chio");
  writeFileSync(
    verifier,
    "#!/bin/sh\nprintf '%s' '{\"purchaseTerminalVerified\":false}'\n",
  );
  chmodSync(verifier, 0o700);
  const buyer = new CognitionMarketBuyer(profileFile(), {
    chioBinary: verifier,
    fetch: async () => Response.json({
      verdict: "allow",
      payer: "9".repeat(64),
      payerKey: "9".repeat(64),
    }),
  });
  const verified: VerifiedFindingProof = {
    findingId,
    proof: new Uint8Array([1]),
    verification: { findingId },
  };
  await assert.rejects(
    buyer.purchase(verified, { maxPriceUnits: 300 }),
    /did not authorize the terminal/,
  );
});

test("buyer rejects a substituted signed payer key", async () => {
  const findingId = "a".repeat(64);
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-payer-substitution-"));
  const verifier = join(directory, "chio");
  writeFileSync(
    verifier,
    "#!/bin/sh\nprintf '%s' '{\"purchaseTerminalVerified\":true}'\n",
  );
  chmodSync(verifier, 0o700);
  const buyer = new CognitionMarketBuyer(profileFile(), {
    chioBinary: verifier,
    fetch: async () => Response.json({
      verdict: "allow",
      payer: "9".repeat(64),
      payerKey: "8".repeat(64),
    }),
  });
  const verified: VerifiedFindingProof = {
    findingId,
    proof: new Uint8Array([1]),
    verification: { findingId },
  };
  await assert.rejects(
    buyer.purchase(verified, { maxPriceUnits: 300 }),
    /signed payer key/,
  );
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
    repository: "/srv/operator-repositories/example",
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
      assert.equal(request.url, "https://operator.local/v1/findings/operator/retractions");
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
    "{\"bearerToken\":\"buyer-secret\",\"endpoint\":\"https://operator.local\",\"market\":{},\"payer\":\"9999999999999999999999999999999999999999999999999999999999999999\",\"payoutDestination\":\"0x1111111111111111111111111111111111111111\",\"principalId\":\"buyer-1\",\"schema\":\"chio.finding.buyer-client.v1\",\"signingSeed\":\"2222222222222222222222222222222222222222222222222222222222222222\"}",
  );
  assert.throws(() => new CognitionMarketBuyer(path), /client profile is invalid/);
});

test("buyer converts an early verifier stdin close into an SDK rejection", async () => {
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-stdin-close-"));
  const verifier = join(directory, "chio");
  writeFileSync(verifier, "#!/bin/sh\nexit 7\n");
  chmodSync(verifier, 0o700);
  const buyer = new CognitionMarketBuyer(profileFile(), { chioBinary: verifier });

  await assert.rejects(
    buyer.verifyProof(new Uint8Array(2 * 1024 * 1024)),
    (error: unknown) => {
      assert.ok(error instanceof CognitionMarketError);
      assert.match(error.message, /failed to write chio input|chio command failed/);
      return true;
    },
  );
});

test("buyer rejects an ephemeral operator port", () => {
  const path = profileFile();
  const profile = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  profile.endpoint = "http://127.0.0.1:0";
  writeFileSync(path, canonical(profile));
  assert.throws(() => new CognitionMarketBuyer(path), /client profile is invalid/);
});

test("buyer requires https away from literal loopback", () => {
  const path = profileFile();
  const profile = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  profile.endpoint = "http://operator.example";
  writeFileSync(path, canonical(profile));
  assert.throws(() => new CognitionMarketBuyer(path), /client profile is invalid/);
});

test("buyer allows literal loopback http", () => {
  const path = profileFile();
  const profile = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  profile.endpoint = "http://127.0.0.1:8787";
  writeFileSync(path, canonical(profile));
  assert.doesNotThrow(() => new CognitionMarketBuyer(path));
});

test("buyer authenticates a purchase terminal again before challenge filing", async () => {
  const findingId = "e".repeat(64);
  const payerKey = "9".repeat(64);
  const proof = {
    bundle: {
      admission: {
        body: {
          backing_envelope_sha256: "1".repeat(64),
          challenge_administration_pool: {
            principal_id: "challenge-pool",
            rail_destination: `0x${"2".repeat(40)}`,
          },
          fee_schedule_envelope_sha256: "3".repeat(64),
          listing_id: "listing-1",
          profile_envelope_sha256: "4".repeat(64),
          terms_envelope_sha256: "5".repeat(64),
        },
        signature: "admission-signature",
      },
      feeSchedule: { body: { disputeFee: { currency: "USD", units: 10 } } },
      finding: { evidence_checkpoint_ref: "committed-checkpoint-7" },
      marketTerms: { body: { challenge_bond_limits: [{
        guarantee_class: "deterministic_replay",
        min_bond: { currency: "USD", units: 10 },
      }] } },
    },
    evidenceCheckpoint: { body: { checkpoint_seq: 7 } },
    evidenceReceipts: [{ receipt: { id: "evidence-1" } }],
  };
  const purchase = {
    deliveryReceipt: { id: "delivery-1" },
    payer: payerKey,
    payerKey,
    purchaseRecord: { body: { purchase_key: "purchase-1" }, signature: "purchase" },
  };
  const directory = mkdtempSync(join(tmpdir(), "chio-market-ts-challenge-"));
  const verifier = join(directory, "chio");
  writeFileSync(
    verifier,
    "#!/bin/sh\nif [ \"$2\" = \"verify-bundle\" ]; then\n"
      + "  printf '%s' '{\"purchaseTerminalVerified\":true}'\n"
      + "else\n"
      + `  printf '%s' '{"challengeId":"${"6".repeat(64)}"}'\n`
      + "fi\n",
  );
  chmodSync(verifier, 0o700);
  const buyer = new CognitionMarketBuyer(profileFile(), { chioBinary: verifier });
  const verified: VerifiedFindingProof = {
    findingId,
    proof: Buffer.from(canonical(proof)),
    verification: { findingId },
  };
  const purchased: PurchasedVerifiedFix = {
    findingId,
    repository: "https://example.com/repo.git",
    baseRevision: "base",
    candidateRevision: "candidate",
    patch: "diff --git a/file b/file\n",
    request: { findingId, payer: payerKey, requestId: "7".repeat(64) },
    purchase,
  };
  const result = await buyer.challengeEvidenceInvalid(
    verified,
    purchased,
    { filedAt: 1_800_000_000 },
  );
  assert.equal(result.challengeId, "6".repeat(64));
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
      payer: "9".repeat(64),
      payerKey: "9".repeat(64),
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
  assert.equal(purchased.request.payer, "9".repeat(64));
});

test("seller rejects prices above operator exposure", async () => {
  const seller = new CognitionMarketSeller(sellerProfileFile());
  await assert.rejects(
    seller.packageVerifiedFix({
      repository: ".",
      base: "base",
      candidate: "candidate",
      tests: ["./check.sh"],
      topic: "rust/fix",
      price: 451,
    }),
    /sale exposure/,
  );
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

test("buyer cancels an oversized streaming response", async () => {
  const findingId = "8".repeat(64);
  const chunk = new Uint8Array(1024 * 1024);
  let emitted = 0;
  let cancelled = false;
  const buyer = new CognitionMarketBuyer(profileFile(), {
    fetch: async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) {
        if (emitted === 100) {
          controller.close();
          return;
        }
        emitted += 1;
        controller.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    })),
  });
  await assert.rejects(
    buyer.proof(findingId),
    /exceeds the SDK size bound/,
  );
  assert.ok(emitted < 100);
  assert.equal(cancelled, true);
});

test("buyer rejects purchase responses above the retained terminal bound", async () => {
  const findingId = "9".repeat(64);
  const verified: VerifiedFindingProof = {
    findingId,
    proof: new Uint8Array(),
    verification: { findingId },
  };
  const buyer = new CognitionMarketBuyer(profileFile(), {
    fetch: async () => new Response("{}", {
      headers: { "content-length": String(16 * 1024 * 1024 + 1) },
    }),
  });

  await assert.rejects(
    buyer.purchase(verified, { maxPriceUnits: 300 }),
    /exceeds the SDK size bound/,
  );
});
