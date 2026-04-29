/**
 * Conformance: BROWSER_SUBSET_V1 selector unit tests.
 *
 * Asserts that the M08 verify-only subset (canonical: all,
 * receipt: verify_only, capability: verify_only) selects a non-empty
 * set of case IDs and that every selected ID exists in the M01
 * conformance corpus checked into `tests/bindings/vectors/`.
 *
 * The corpus path is resolved relative to the repo root via
 * `import.meta.url` so the test does not depend on a CWD.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  BROWSER_SUBSET_V1,
  BROWSER_SUBSET_TAG,
  selector,
  type ConformanceManifest,
} from "../src/browser-subset.js";

// /tmp/arc-m08p2-t5/sdks/typescript/packages/conformance/test/* -> repo root.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..", "..");
const VECTORS = resolve(REPO_ROOT, "tests", "bindings", "vectors");

function loadCategoryFile(category: "canonical" | "receipt" | "capability"): {
  cases: Array<{ id: string; verify_only?: boolean }>;
} {
  const path = resolve(VECTORS, category, "v1.json");
  const text = readFileSync(path, "utf-8");
  return JSON.parse(text);
}

function loadManifest(): ConformanceManifest {
  return {
    canonical: loadCategoryFile("canonical"),
    receipt: loadCategoryFile("receipt"),
    capability: loadCategoryFile("capability"),
  };
}

describe("BROWSER_SUBSET_V1 (M08 verify-only conformance subset)", () => {
  it("declares the canonical version tag", () => {
    expect(BROWSER_SUBSET_V1.tag).toBe("chio.conformance.browser-subset/v1");
    expect(BROWSER_SUBSET_TAG).toBe("chio.conformance.browser-subset/v1");
    expect(BROWSER_SUBSET_V1.version).toBe(1);
  });

  it("enumerates exactly three categories (canonical, receipt, capability)", () => {
    const keys = Object.keys(BROWSER_SUBSET_V1.categories).sort();
    expect(keys).toEqual(["canonical", "capability", "receipt"].sort());
  });

  it("selects 'all' for canonical and 'verify_only' for receipt and capability", () => {
    expect(BROWSER_SUBSET_V1.categories.canonical.mode).toBe("all");
    expect(BROWSER_SUBSET_V1.categories.receipt.mode).toBe("verify_only");
    expect(BROWSER_SUBSET_V1.categories.capability.mode).toBe("verify_only");
  });

  it("selector returns a non-empty subset for every category", () => {
    const manifest = loadManifest();
    const selection = selector(manifest);

    expect(selection.tag).toBe(BROWSER_SUBSET_TAG);
    expect(selection.version).toBe(1);

    expect(selection.categories.canonical.length).toBeGreaterThan(0);
    expect(selection.categories.receipt.length).toBeGreaterThan(0);
    expect(selection.categories.capability.length).toBeGreaterThan(0);
  });

  it("selector picks every canonical case (mode: all)", () => {
    const manifest = loadManifest();
    const selection = selector(manifest);

    const expected = manifest.canonical.cases.map((c) => c.id);
    expect(selection.categories.canonical).toEqual(expected);
  });

  it("selector picks only verify_only=true cases for receipt", () => {
    const manifest = loadManifest();
    const selection = selector(manifest);

    const expected = manifest.receipt.cases
      .filter((c) => c.verify_only === true)
      .map((c) => c.id);
    expect(selection.categories.receipt).toEqual(expected);
    // Must drop signing-only cases.
    expect(selection.categories.receipt.length).toBeLessThan(
      manifest.receipt.cases.length,
    );
  });

  it("selector picks only verify_only=true cases for capability", () => {
    const manifest = loadManifest();
    const selection = selector(manifest);

    const expected = manifest.capability.cases
      .filter((c) => c.verify_only === true)
      .map((c) => c.id);
    expect(selection.categories.capability).toEqual(expected);
    expect(selection.categories.capability.length).toBeLessThan(
      manifest.capability.cases.length,
    );
  });

  it("every selected case ID exists in the M01 vector corpus", () => {
    const manifest = loadManifest();
    const selection = selector(manifest);

    const canonicalIds = new Set(manifest.canonical.cases.map((c) => c.id));
    const receiptIds = new Set(manifest.receipt.cases.map((c) => c.id));
    const capabilityIds = new Set(manifest.capability.cases.map((c) => c.id));

    for (const id of selection.categories.canonical) {
      expect(canonicalIds.has(id), `canonical id ${id} missing in M01 corpus`).toBe(true);
    }
    for (const id of selection.categories.receipt) {
      expect(receiptIds.has(id), `receipt id ${id} missing in M01 corpus`).toBe(true);
    }
    for (const id of selection.categories.capability) {
      expect(capabilityIds.has(id), `capability id ${id} missing in M01 corpus`).toBe(true);
    }
  });

  it("selector is pure: input manifest is not mutated", () => {
    const manifest = loadManifest();
    const before = JSON.stringify(manifest);
    selector(manifest);
    const after = JSON.stringify(manifest);
    expect(after).toBe(before);
  });

  it("selector handles a synthetic manifest deterministically", () => {
    const synthetic: ConformanceManifest = {
      canonical: {
        cases: [
          { id: "c1" },
          { id: "c2" },
        ],
      },
      receipt: {
        cases: [
          { id: "r-verify", verify_only: true },
          { id: "r-sign" },
          { id: "r-verify-2", verify_only: true },
        ],
      },
      capability: {
        cases: [
          { id: "cap-sign" },
          { id: "cap-verify", verify_only: true },
        ],
      },
    };

    const result = selector(synthetic);
    expect(result.categories.canonical).toEqual(["c1", "c2"]);
    expect(result.categories.receipt).toEqual(["r-verify", "r-verify-2"]);
    expect(result.categories.capability).toEqual(["cap-verify"]);
  });
});
