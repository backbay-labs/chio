import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  findingBidCeiling,
  FindingBidCeilingError,
  type FindingBidCeilingInput,
} from "../src/index.ts";

interface VectorCase {
  id: string;
  input: FindingBidCeilingInput;
  expectedCeiling: string;
}

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

async function vectors(): Promise<VectorCase[]> {
  const raw = await readFile(
    resolve(
      repoRoot,
      "tests/bindings/fixtures/cognition-market-finding-bid-ceiling-v1.json",
    ),
    "utf8",
  );
  return (JSON.parse(raw) as { valid_cases: VectorCase[] }).valid_cases;
}

function clone(input: FindingBidCeilingInput): FindingBidCeilingInput {
  return structuredClone(input);
}

function rejectsWith(input: FindingBidCeilingInput, code: string): void {
  assert.throws(
    () => findingBidCeiling(input),
    (error) => error instanceof FindingBidCeilingError && error.code === code,
  );
}

test("finding_bid_ceiling TypeScript parity matches shared Rust and Python goldens", async () => {
  for (const vector of await vectors()) {
    assert.equal(findingBidCeiling(vector.input), vector.expectedCeiling, vector.id);
  }
});

test("finding_bid_ceiling accepts decimal strings above 2^53 but rejects unsafe Numbers", async () => {
  const vector = (await vectors()).find((candidate) => candidate.id === "above_javascript_safe_integer");
  assert.ok(vector);
  assert.equal(findingBidCeiling(vector.input), "9007199254740993");

  const unsafe = clone(vector.input);
  unsafe.estimate.units = 9_007_199_254_740_992;
  rejectsWith(unsafe, "invalid_decimal");
});

test("finding_bid_ceiling rejects encodings, bounds, currency, provenance, and rounding hazards", async () => {
  const [first] = await vectors();
  assert.ok(first);
  for (const encoding of ["", "01", "+1", "-1", "1.0", "NaN"]) {
    const input = clone(first.input);
    input.estimate.units = encoding;
    rejectsWith(input, "invalid_decimal");
  }

  const overflow = clone(first.input);
  overflow.estimate.units = "18446744073709551616";
  rejectsWith(overflow, "u64_overflow");

  const oversizedDecimal = clone(first.input);
  oversizedDecimal.estimate.units = "9".repeat(100_000);
  rejectsWith(oversizedDecimal, "u64_overflow");

  const bps = clone(first.input);
  bps.policy.guaranteeClassBps = "10001";
  rejectsWith(bps, "basis_points_out_of_range");

  const currency = clone(first.input);
  currency.policy.currency = "EUR";
  rejectsWith(currency, "currency_mismatch");

  const numericCurrency = clone(first.input);
  (numericCurrency.policy as unknown as { currency: unknown }).currency = 123;
  (numericCurrency.estimate as unknown as { currency: unknown }).currency = 123;
  rejectsWith(numericCurrency, "currency_mismatch");

  const coercibleAmount = clone(first.input);
  (coercibleAmount.estimate as unknown as { units: unknown }).units = {
    toString: () => "100",
  };
  rejectsWith(coercibleAmount, "invalid_decimal");

  const coercibleDigest = clone(first.input);
  const digestObject = { toString: () => "a".repeat(64) };
  (coercibleDigest.estimate as unknown as { sourceSha256: unknown }).sourceSha256 = digestObject;
  (coercibleDigest as unknown as { expectedSourceSha256: unknown }).expectedSourceSha256 =
    digestObject;
  rejectsWith(coercibleDigest, "digest_malformed");

  const provenance = clone(first.input);
  provenance.estimate.provenance = "operator_assertion_v1";
  rejectsWith(provenance, "provenance_unsupported");

  const stale = clone(first.input);
  stale.nowUnixMs = stale.estimate.validUntilUnixMs;
  rejectsWith(stale, "stale_estimate");

  const source = clone(first.input);
  source.expectedSourceSha256 = "0".repeat(64);
  rejectsWith(source, "source_substituted");

  const context = clone(first.input);
  context.expectedContextSha256 = "0".repeat(64);
  rejectsWith(context, "context_substituted");

  const replay = clone(first.input);
  replay.expectedReplayRecipeSha256 = "0".repeat(64);
  rejectsWith(replay, "replay_recipe_substituted");
});
