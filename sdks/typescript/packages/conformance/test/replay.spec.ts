import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  anchoredRootTuplesForReplayOutputs,
  computeRootFromInclusionProof,
  runReplayAnchoredRootTuples,
  runReplayScenarios,
  verifyInclusionProof,
  type HexHash,
  type ReplayAnchoredRootTuple,
} from "../src/replay.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..", "..");
const FIXTURES_ROOT = resolve(REPO_ROOT, "tests", "replay", "fixtures");
const EXPECTED_FIXTURE_COUNT = 50;
const CANARY_RECEIPT_ID = "allow_simple/01_basic_capability";
const CANARY_LEAF_HASH =
  "0xe4b0ab524d5ed0a97dec2d92d0dceba4d1b8abb551acacfafff9df69a16436bb";

function leafHash(bytes: Uint8Array): HexHash {
  const hash = createHash("sha256");
  hash.update(Buffer.from([0x00]));
  hash.update(Buffer.from(bytes));
  return `0x${hash.digest("hex")}`;
}

function tupleKey(tuple: ReplayAnchoredRootTuple): string {
  return tuple.receipt_id;
}

describe("replay anchored-root tuples", () => {
  it("emits deterministic tuple output for every replay fixture", async () => {
    const outputs = await runReplayScenarios({
      fixturesRoot: FIXTURES_ROOT,
      expectedCount: EXPECTED_FIXTURE_COUNT,
    });
    const tuples = anchoredRootTuplesForReplayOutputs(outputs);
    const secondPass = await runReplayAnchoredRootTuples({
      fixturesRoot: FIXTURES_ROOT,
      expectedCount: EXPECTED_FIXTURE_COUNT,
    });

    expect(tuples).toHaveLength(EXPECTED_FIXTURE_COUNT);
    expect(secondPass).toEqual(tuples);
    expect(tuples.map(tupleKey)).toEqual([...tuples.map(tupleKey)].sort());

    for (const [index, output] of outputs.entries()) {
      const tuple = tuples[index];
      expect(tuple, `tuple ${index} must exist`).toBeDefined();
      if (tuple == null) {
        throw new Error(`missing anchored-root tuple at index ${index}`);
      }

      const expectedLeafHash = leafHash(output.receiptBytes);
      expect(tuple.receipt_id).toBe(output.scenario.name);
      expect(tuple.leaf_hash).toBe(expectedLeafHash);
      expect(tuple.root).toBe(expectedLeafHash);
      expect(tuple.inclusion_proof).toEqual({
        tree_size: 1,
        leaf_index: 0,
        audit_path: [],
      });
      expect(computeRootFromInclusionProof(tuple.leaf_hash, tuple.inclusion_proof)).toBe(
        tuple.root,
      );
      expect(verifyInclusionProof(tuple.leaf_hash, tuple.inclusion_proof, tuple.root)).toBe(true);
    }

    const canary = tuples.find((tuple) => tuple.receipt_id === CANARY_RECEIPT_ID);
    expect(canary).toBeDefined();
    expect(canary?.leaf_hash).toBe(CANARY_LEAF_HASH);
    expect(canary?.root).toBe(CANARY_LEAF_HASH);
  });

  it("fails closed when the fixture root is missing", async () => {
    await expect(runReplayAnchoredRootTuples({
      fixturesRoot: resolve(REPO_ROOT, "tests", "replay", "missing"),
      expectedCount: EXPECTED_FIXTURE_COUNT,
    })).rejects.toThrow("failed to stat replay fixture root");
  });

  it("fails closed when a receipt leaf byte is tampered", async () => {
    const outputs = await runReplayScenarios({
      fixturesRoot: FIXTURES_ROOT,
      expectedCount: EXPECTED_FIXTURE_COUNT,
    });
    const output = outputs.find((candidate) => candidate.scenario.name === CANARY_RECEIPT_ID);
    expect(output).toBeDefined();
    if (output == null) {
      throw new Error(`missing replay output for ${CANARY_RECEIPT_ID}`);
    }

    const tamperedLeafBytes = new Uint8Array(output.receiptBytes);
    tamperedLeafBytes[0] ^= 0x01;
    const changedBytes = tamperedLeafBytes.reduce(
      (count, byte, index) => count + (byte === output.receiptBytes[index] ? 0 : 1),
      0,
    );
    expect(changedBytes).toBe(1);

    const tamperedLeafHash = leafHash(tamperedLeafBytes);
    expect(tamperedLeafHash).not.toBe(output.anchoredRoot.leaf_hash);
    expect(
      verifyInclusionProof(
        tamperedLeafHash,
        output.anchoredRoot.inclusion_proof,
        output.anchoredRoot.root,
      ),
    ).toBe(false);
  });
});
