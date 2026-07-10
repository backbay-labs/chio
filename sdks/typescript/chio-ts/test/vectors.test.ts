import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ChioInvariantError,
  canonicalizeJsonString,
  capabilityBodyCanonicalJson,
  parseCapabilityJson,
  parseReceiptJson,
  parseSignedManifestJson,
  receiptBodyCanonicalJson,
  receiptSigningBodyCanonicalJson,
  sha256HexUtf8,
  signJsonStringEd25519,
  signUtf8MessageEd25519,
  signedManifestBodyCanonicalJson,
  verifyCapability,
  verifyJsonStringSignatureEd25519,
  verifyReceipt,
  verifyReceiptWithTrustedSigners,
  verifySignedManifest,
  verifyUtf8MessageEd25519,
} from "../src/index.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

async function readJson(relativePath: string): Promise<unknown> {
  const absolutePath = resolve(repoRoot, relativePath);
  const raw = await readFile(absolutePath, "utf8");
  return JSON.parse(raw);
}

test("canonical vectors round-trip through the TS invariant helper", async () => {
  const fixture = await readJson("tests/bindings/vectors/canonical/v1.json") as {
    cases: Array<{
      id: string;
      input_json: string;
      canonical_json: string;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    assert.equal(
      canonicalizeJsonString(vectorCase.input_json),
      vectorCase.canonical_json,
      vectorCase.id,
    );
  }
});

test("canonical JSON rejects duplicate object keys", () => {
  assert.throws(
    () => canonicalizeJsonString('{"scope":"read","scope":"write"}'),
    (error) => error instanceof ChioInvariantError && /duplicate object key/.test(error.message),
  );
});

test("hashing vectors round-trip through the TS invariant helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/hashing/v1.json") as {
    cases: Array<{
      id: string;
      input_utf8: string;
      sha256_hex: string;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    assert.equal(sha256HexUtf8(vectorCase.input_utf8), vectorCase.sha256_hex, vectorCase.id);
  }
});

test("receipt vectors match the TS receipt helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: unknown;
      receipt_body_canonical_json: string;
      expected: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const receipt = parseReceiptJson(JSON.stringify(vectorCase.receipt));
    assert.equal(receiptBodyCanonicalJson(receipt), vectorCase.receipt_body_canonical_json, vectorCase.id);
    assert.deepEqual(verifyReceipt(receipt), vectorCase.expected, vectorCase.id);
  }
});

test("receipt vectors support trusted signer verification in TS", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: { kernel_key: string };
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");

  const verification = verifyReceiptWithTrustedSigners(vectorCase.receipt, [vectorCase.receipt.kernel_key]);

  assert.equal(verification.signer_trusted, true);
  assert.equal(verification.ok, true);
  assert.equal(verification.authorized, true);
});

test("TS receipt semantics ignore legacy metadata payloads", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    cases: Array<{
      id: string;
      receipt: unknown;
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");
  const receipt = JSON.parse(JSON.stringify(vectorCase.receipt));
  receipt.metadata = {
    receipt_semantics: {
      receiptKind: "trace_observation",
      boundaryClass: "detect_only",
    },
  };

  const verification = verifyReceiptWithTrustedSigners(receipt, [receipt.kernel_key]);

  assert.equal(verification.receipt_kind, "mediated_decision");
  assert.equal(verification.boundary_class, "prevent");
  assert.equal(verification.receipt_id_valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.authorized, false);
});

test("TS receipt signature validity fails when the content-addressed id mismatches", async () => {
  const fixture = await readJson("tests/bindings/vectors/receipt/v1.json") as {
    signing_key_seed_hex: string;
    cases: Array<{
      id: string;
      receipt: { id: string; kernel_key: string; signature: string };
    }>;
  };
  const vectorCase = fixture.cases.find((item) => item.id === "allow_receipt");
  assert.ok(vectorCase, "allow receipt vector must exist");
  const receipt = JSON.parse(JSON.stringify(vectorCase.receipt));
  receipt.id = "0000000000000000000000000000000000000000000000000000000000000000";
  receipt.signature = signJsonStringEd25519(
    receiptSigningBodyCanonicalJson(receipt),
    fixture.signing_key_seed_hex,
  ).signature_hex;

  const verification = verifyReceipt(receipt);

  assert.equal(verification.receipt_id_valid, false);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.ok, false);
});

test("signing vectors match the TS signing helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/signing/v1.json") as {
    signing_key_seed_hex: string;
    utf8_cases: Array<{
      id: string;
      input_utf8: string;
      public_key_hex: string;
      signature_hex: string;
      expected_verify: boolean;
      signing_key_seed_hex?: string;
    }>;
    json_cases: Array<{
      id: string;
      input_json: string;
      canonical_json: string;
      public_key_hex: string;
      signature_hex: string;
      expected_verify: boolean;
      signing_key_seed_hex?: string;
    }>;
  };

  for (const vectorCase of fixture.utf8_cases) {
    const seedHex = vectorCase.signing_key_seed_hex ?? fixture.signing_key_seed_hex;
    if (vectorCase.expected_verify) {
      assert.deepEqual(
        signUtf8MessageEd25519(vectorCase.input_utf8, seedHex),
        {
          public_key_hex: vectorCase.public_key_hex,
          signature_hex: vectorCase.signature_hex,
        },
        vectorCase.id,
      );
    }

    assert.equal(
      verifyUtf8MessageEd25519(
        vectorCase.input_utf8,
        vectorCase.public_key_hex,
        vectorCase.signature_hex,
      ),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }

  for (const vectorCase of fixture.json_cases) {
    const seedHex = vectorCase.signing_key_seed_hex ?? fixture.signing_key_seed_hex;
    assert.equal(canonicalizeJsonString(vectorCase.input_json), vectorCase.canonical_json, vectorCase.id);

    if (vectorCase.expected_verify) {
      assert.deepEqual(
        signJsonStringEd25519(vectorCase.input_json, seedHex),
        {
          canonical_json: vectorCase.canonical_json,
          public_key_hex: vectorCase.public_key_hex,
          signature_hex: vectorCase.signature_hex,
        },
        vectorCase.id,
      );
    }

    assert.equal(
      verifyJsonStringSignatureEd25519(
        vectorCase.input_json,
        vectorCase.public_key_hex,
        vectorCase.signature_hex,
      ),
      vectorCase.expected_verify,
      vectorCase.id,
    );
  }
});

test("capability vectors match the TS capability helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/capability/v1.json") as {
    cases: Array<{
      id: string;
      verify_at: number;
      capability: unknown;
      capability_body_canonical_json: string;
      expected: unknown;
      max_delegation_depth?: number;
      expected_with_max_delegation_depth?: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const capability = parseCapabilityJson(JSON.stringify(vectorCase.capability));
    assert.equal(
      capabilityBodyCanonicalJson(capability),
      vectorCase.capability_body_canonical_json,
      vectorCase.id,
    );
    assert.deepEqual(
      verifyCapability(capability, vectorCase.verify_at),
      vectorCase.expected,
      `${vectorCase.id} (no max depth)`,
    );
    if (vectorCase.max_delegation_depth !== undefined) {
      assert.deepEqual(
        verifyCapability(capability, vectorCase.verify_at, vectorCase.max_delegation_depth),
        vectorCase.expected_with_max_delegation_depth ?? vectorCase.expected,
        `${vectorCase.id} (max_delegation_depth=${vectorCase.max_delegation_depth})`,
      );
    }
  }
});

test("capability parser rejects non-object JSON", () => {
  for (const payload of ["null", "[]", "\"capability\"", "42"]) {
    assert.throws(
      () => parseCapabilityJson(payload),
      (error: unknown) =>
        error instanceof ChioInvariantError &&
        error.code === "json" &&
        error.message === "capability must be a JSON object",
      payload,
    );
  }
});

test("manifest vectors match the TS manifest helpers", async () => {
  const fixture = await readJson("tests/bindings/vectors/manifest/v1.json") as {
    cases: Array<{
      id: string;
      signed_manifest: unknown;
      manifest_body_canonical_json: string;
      expected: unknown;
    }>;
  };

  for (const vectorCase of fixture.cases) {
    const signedManifest = parseSignedManifestJson(JSON.stringify(vectorCase.signed_manifest));
    assert.equal(
      signedManifestBodyCanonicalJson(signedManifest),
      vectorCase.manifest_body_canonical_json,
      vectorCase.id,
    );
    assert.deepEqual(verifySignedManifest(signedManifest), vectorCase.expected, vectorCase.id);
  }
});
