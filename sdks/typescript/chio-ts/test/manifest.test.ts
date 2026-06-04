import test from "node:test";
import assert from "node:assert/strict";

import {
  signJsonStringEd25519,
  verifySignedManifest,
  verifySignedManifestJson,
} from "../src/index.ts";
import type { SignedManifest } from "../src/index.ts";

function pricedSignedManifest(): SignedManifest {
  return {
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
      public_key: "22".repeat(32),
    },
    signature: "33".repeat(64),
    signer_key: "11".repeat(32),
  };
}

test("signed manifest typing and verification preserve pricing metadata", () => {
  const signedManifest = pricedSignedManifest();

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

test("manifest structure does not include embedded public key validity", () => {
  const signedManifest = pricedSignedManifest();
  signedManifest.manifest.public_key = "demo-placeholder";

  const verification = verifySignedManifest(signedManifest);

  assert.equal(verification.structure_valid, true);
  assert.equal(verification.embedded_public_key_valid, false);
  assert.equal(verification.embedded_public_key_matches_signer, false);
});

test("manifest structure rejects empty or padded identity fields", () => {
  for (const [field, value] of [
    ["server_id", ""],
    ["server_id", " srv-priced"],
    ["server_id", "srv-priced "],
    ["server_id", "srv\npriced"],
    ["name", ""],
    ["name", " Priced Server"],
    ["name", "Priced Server "],
    ["version", ""],
    ["version", " 1.0.0"],
    ["version", "1.0.0 "],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest[field] = value;

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `${field} ${JSON.stringify(value)}`,
    );
    assert.equal(verification.signature_valid, false);
    assert.equal(verification.embedded_public_key_valid, true);
  }
});

test("manifest structure rejects empty or padded tool names", () => {
  for (const name of ["", " greet", "greet "]) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest.tools[0].name = name;

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `name ${JSON.stringify(name)}`,
    );
  }
});

test("manifest structure rejects non-object tool schemas", () => {
  const badInputSchema = pricedSignedManifest();
  badInputSchema.manifest.tools[0].input_schema = [];
  assert.equal(verifySignedManifest(badInputSchema).structure_valid, false);

  const badOutputSchema = pricedSignedManifest();
  badOutputSchema.manifest.tools[0].output_schema = "not an object";
  assert.equal(verifySignedManifest(badOutputSchema).structure_valid, false);
});

test("manifest structure rejects non-object tool entries", () => {
  const signedManifest = pricedSignedManifest();
  (signedManifest.manifest.tools as unknown[])[0] = null;

  assert.equal(verifySignedManifest(signedManifest).structure_valid, false);
});

test("manifest structure rejects malformed pricing metadata", () => {
  for (const [label, pricing] of [
    [
      "per_invocation missing unit_price",
      { pricing_model: "per_invocation", billing_unit: "invocation" },
    ],
    [
      "per_unit missing billing_unit",
      { pricing_model: "per_unit", unit_price: { units: 25, currency: "USD" } },
    ],
    [
      "hybrid missing base_price",
      {
        pricing_model: "hybrid",
        unit_price: { units: 25, currency: "USD" },
        billing_unit: "document",
      },
    ],
    [
      "padded billing_unit",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 25, currency: "USD" },
        billing_unit: " invocation",
      },
    ],
    [
      "invalid currency",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 25, currency: "usd" },
        billing_unit: "invocation",
      },
    ],
    [
      "units above u64 max",
      {
        pricing_model: "per_invocation",
        unit_price: { units: 2 ** 64, currency: "USD" },
        billing_unit: "invocation",
      },
    ],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    (signedManifest.manifest.tools[0] as { pricing?: unknown }).pricing = pricing;

    assert.equal(
      verifySignedManifest(signedManifest).structure_valid,
      false,
      label,
    );
  }
});

test("manifest structure accepts Rust u64 pricing units above JS safe integer", () => {
  const signedManifest = pricedSignedManifest();
  const largeRustU64Units = Number.MAX_SAFE_INTEGER + 2;
  assert.equal(Number.isSafeInteger(largeRustU64Units), false);
  (signedManifest.manifest.tools[0] as { pricing?: { unit_price?: { units?: number } } })
    .pricing!.unit_price!.units = largeRustU64Units;

  assert.equal(verifySignedManifest(signedManifest).structure_valid, true);
});

test("signed manifest envelope rejects unknown top-level fields", () => {
  const signedManifest = pricedSignedManifest() as SignedManifest & {
    unsigned_policy_hint?: unknown;
  };
  signedManifest.unsigned_policy_hint = { allow: true };

  assert.equal(verifySignedManifest(signedManifest).structure_valid, false);
});

test("manifest structure accepts valid required permissions", () => {
  const signedManifest = pricedSignedManifest();
  signedManifest.manifest.required_permissions = {
    read_paths: ["/tmp/in"],
    write_paths: ["/tmp/out"],
    network_hosts: ["api.example.com"],
    environment_variables: ["TOKEN"],
  };

  const verification = verifySignedManifest(signedManifest);

  assert.equal(verification.structure_valid, true);
  assert.equal(verification.signature_valid, false);
  assert.equal(verification.embedded_public_key_valid, true);
});

test("manifest structure rejects invalid required permissions", () => {
  for (const [field, values] of [
    ["read_paths", [""]],
    ["write_paths", [" /tmp/out"]],
    ["network_hosts", ["api.example.com "]],
    ["environment_variables", ["TOKEN", "TOKEN"]],
    ["read_paths", ["/tmp/in\nbad"]],
    ["read_paths", [123]],
  ] as const) {
    const signedManifest = pricedSignedManifest();
    signedManifest.manifest.required_permissions = { [field]: values };

    const verification = verifySignedManifest(signedManifest);

    assert.equal(
      verification.structure_valid,
      false,
      `${field} ${JSON.stringify(values)}`,
    );
    assert.equal(verification.signature_valid, false);
    assert.equal(verification.embedded_public_key_valid, true);
  }
});

test("manifest structure rejects malformed required permissions object", () => {
  const unknownField = pricedSignedManifest();
  (unknownField.manifest as { required_permissions?: unknown }).required_permissions = {
    unknown: ["/tmp"],
  };
  assert.equal(verifySignedManifest(unknownField).structure_valid, false);

  const nonArrayValues = pricedSignedManifest();
  (nonArrayValues.manifest as { required_permissions?: unknown }).required_permissions = {
    read_paths: "/tmp",
  };
  assert.equal(verifySignedManifest(nonArrayValues).structure_valid, false);
});

test("signed manifest JSON verification is fail-soft for malformed envelopes", () => {
  for (const input of [
    "{}",
    "{\"manifest\":null,\"signature\":\"\",\"signer_key\":\"\"}",
  ]) {
    const verification = verifySignedManifestJson(input);

    assert.equal(verification.structure_valid, false);
    assert.equal(verification.signature_valid, false);
    assert.equal(verification.embedded_public_key_valid, false);
    assert.equal(verification.embedded_public_key_matches_signer, false);
  }
});

test("manifest structure rejects missing required tool fields and nested unknown fields", () => {
  const missingDescription = pricedSignedManifest();
  delete (missingDescription.manifest.tools[0] as { description?: unknown }).description;
  assert.equal(verifySignedManifest(missingDescription).structure_valid, false);

  const missingSideEffects = pricedSignedManifest();
  delete (missingSideEffects.manifest.tools[0] as { has_side_effects?: unknown }).has_side_effects;
  assert.equal(verifySignedManifest(missingSideEffects).structure_valid, false);

  const unknownManifestField = pricedSignedManifest();
  (unknownManifestField.manifest as { unsigned_policy_hint?: unknown }).unsigned_policy_hint = true;
  assert.equal(verifySignedManifest(unknownManifestField).structure_valid, false);

  const unknownToolField = pricedSignedManifest();
  (unknownToolField.manifest.tools[0] as { annotations?: unknown }).annotations = {};
  assert.equal(verifySignedManifest(unknownToolField).structure_valid, false);

  const unknownPricingField = pricedSignedManifest();
  (
    unknownPricingField.manifest.tools[0].pricing as {
      experimental_discount?: unknown;
    }
  ).experimental_discount = 10;
  assert.equal(verifySignedManifest(unknownPricingField).structure_valid, false);
});

test("manifest structure validates server_tools and latency_hint enum values", () => {
  const valid = pricedSignedManifest();
  (valid.manifest as { server_tools?: string[] }).server_tools = ["bash", "text_editor"];
  valid.manifest.tools[0].latency_hint = "fast";
  assert.equal(verifySignedManifest(valid).structure_valid, true);

  const duplicateServerTool = pricedSignedManifest();
  (duplicateServerTool.manifest as { server_tools?: string[] }).server_tools = ["bash", "bash"];
  assert.equal(verifySignedManifest(duplicateServerTool).structure_valid, false);

  const unknownServerTool = pricedSignedManifest();
  (unknownServerTool.manifest as { server_tools?: string[] }).server_tools = ["database"];
  assert.equal(verifySignedManifest(unknownServerTool).structure_valid, false);

  const invalidLatencyHint = pricedSignedManifest();
  (invalidLatencyHint.manifest.tools[0] as { latency_hint?: string }).latency_hint = "immediate";
  assert.equal(verifySignedManifest(invalidLatencyHint).structure_valid, false);
});

test("signed manifest JSON verification preserves raw large integer tokens", () => {
  const seedHex = "01".repeat(32);
  const publicKeyHex = signJsonStringEd25519("{}", seedHex).public_key_hex;
  const rawManifest =
    `{"schema":"chio.manifest.v1","server_id":"srv-large-u64","name":"Large U64","version":"1.0.0","tools":[{"name":"price","description":"Returns price","input_schema":{"type":"object"},"pricing":{"pricing_model":"per_invocation","unit_price":{"units":9223372036854775808,"currency":"USD"},"billing_unit":"invocation"},"has_side_effects":false}],"public_key":"${publicKeyHex}"}`;
  const signed = signJsonStringEd25519(rawManifest, seedHex);
  const signedManifestJson =
    `{"manifest":${rawManifest},"signature":"${signed.signature_hex}","signer_key":"${signed.public_key_hex}"}`;

  const jsonVerification = verifySignedManifestJson(signedManifestJson);
  assert.equal(jsonVerification.structure_valid, true);
  assert.equal(jsonVerification.signature_valid, true);
  assert.equal(jsonVerification.embedded_public_key_valid, true);
  assert.equal(jsonVerification.embedded_public_key_matches_signer, true);

  const objectVerification = verifySignedManifest(JSON.parse(signedManifestJson));
  assert.equal(objectVerification.structure_valid, true);
  assert.equal(objectVerification.signature_valid, false);
});
