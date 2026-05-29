import test from "node:test";
import assert from "node:assert/strict";

import { verifySignedManifest } from "../src/index.ts";
import type { SignedManifest } from "../src/index.ts";

test("signed manifest typing and verification preserve pricing metadata", () => {
  const signerKey = "11".repeat(32);
  const manifestKey = "22".repeat(32);
  const signature = "33".repeat(64);
  const signedManifest: SignedManifest = {
    manifest: {
      schema: "chio.manifest.v1",
      server_id: "srv-priced",
      name: "Priced Server",
      version: "1.0.0",
      tools: [
        {
          name: "greet",
          description: "Returns a greeting",
          input_schema: { type: "object" },
          pricing: {
            pricing_model: "per_invocation",
            unit_price: { units: 25, currency: "USD" },
            billing_unit: "invocation",
          },
          has_side_effects: false,
          latency_hint: "instant",
        },
      ],
      public_key: manifestKey,
    },
    signature,
    signer_key: signerKey,
  };

  assert.equal(
    signedManifest.manifest.tools[0].pricing?.unit_price?.units,
    25,
  );

  const verification = verifySignedManifest(signedManifest);
  assert.equal(verification.structure_valid, true);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.embedded_public_key_valid, true);
  assert.equal(verification.embedded_public_key_matches_signer, false);
});
