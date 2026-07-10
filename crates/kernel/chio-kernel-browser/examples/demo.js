// Demo for chio-kernel-browser.
//
// This file is intentionally dependency-free: it loads the wasm module
// produced by `wasm-pack build --target web --release` and exercises
// the three portable entry points (`evaluate`, `sign_receipt`,
// `verify_capability`) with fixture JSON payloads.
//
// The demo.html page above provides the DOM scaffolding.

import init, {
  evaluate,
  sign_receipt,
  mint_signing_seed_hex,
} from "../pkg/chio_kernel_browser.js";

const $ = (id) => document.getElementById(id);

function log(el, value) {
  el.textContent =
    typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function nowMs() {
  return performance && performance.now ? performance.now() : Date.now();
}

let fixture = null;

// Capability-less evaluate request: the fixture pubkey does not match
// the signed payload, so kernel-core returns a structured deny verdict.
// Target round-trip latency: < 5 ms.
const FIXTURE_EVALUATE_REQUEST = {
  request: {
    request_id: "demo-req-1",
    tool_name: "echo",
    server_id: "srv-a",
    agent_id:
      "0000000000000000000000000000000000000000000000000000000000000000",
    arguments: { message: "hello from the browser" },
  },
  capability: {
    id: "demo-cap-1",
    issuer:
      "0000000000000000000000000000000000000000000000000000000000000000",
    subject:
      "0000000000000000000000000000000000000000000000000000000000000000",
    scope: {
      grants: [
        {
          server_id: "srv-a",
          tool_name: "echo",
          operations: ["invoke"],
          constraints: [],
          max_invocations: null,
          max_cost_per_invocation: null,
          max_total_cost: null,
          dpop_required: null,
        },
      ],
      resource_grants: [],
      prompt_grants: [],
    },
    issued_at: 1_700_000_000,
    expires_at: 1_700_100_000,
    delegation_chain: [],
    signature:
      "0000000000000000000000000000000000000000000000000000000000000000" +
      "0000000000000000000000000000000000000000000000000000000000000000",
  },
  trusted_issuers_hex: [
    "0000000000000000000000000000000000000000000000000000000000000000",
  ],
  clock_override_unix_secs: 1_700_000_500,
};

// WYSIWYS: the PUBLIC `sign_receipt` entry point requires the exact
// `canonical_content` preimage and recomputes `content_hash` inside the signer,
// refusing on mismatch. The demo therefore renders the content the human sees,
// derives `content_hash` from it, and ships the preimage as a `u8` array so the
// recompute gate passes. The plain `{body}`-only shape (no preimage, zeroed
// hash) now fails closed with `canonical_content_required`.
const CANONICAL_CONTENT = new TextEncoder().encode(
  JSON.stringify({ shown: "to-the-human" }),
);

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function buildFixtureReceiptBody() {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", CANONICAL_CONTENT),
  );
  return {
    body: {
      id: "demo-rcpt-1",
      timestamp: 1_700_000_500,
      capability_id: "demo-cap-1",
      tool_server: "srv-a",
      tool_name: "echo",
      action: {
        kind: "parameters",
        parameters: { msg: "hi" },
      },
      decision: "allow",
      content_hash: toHex(digest),
      policy_hash:
        "0000000000000000000000000000000000000000000000000000000000000000",
      evidence: [],
      metadata: null,
      trust_level: "mediated",
      tenant_id: null,
      kernel_key:
        "0000000000000000000000000000000000000000000000000000000000000000",
    },
    // Raw preimage bytes as a `u8` array, matching `SignReceiptRequestJson`.
    canonical_content: Array.from(CANONICAL_CONTENT),
  };
}

$("load").addEventListener("click", async () => {
  try {
    await init();
    fixture = true;
    log($("load-output"), "wasm module loaded");
    $("evaluate").disabled = false;
    $("sign").disabled = false;
  } catch (error) {
    log($("load-output"), "load failed: " + error);
  }
});

$("evaluate").addEventListener("click", () => {
  if (!fixture) {
    log($("evaluate-output"), "module not loaded yet");
    return;
  }
  try {
    const started = nowMs();
    const verdict = evaluate(JSON.stringify(FIXTURE_EVALUATE_REQUEST));
    const elapsed = nowMs() - started;
    const rendered = {
      elapsed_ms: elapsed,
      verdict,
    };
    log($("evaluate-output"), rendered);
  } catch (error) {
    log($("evaluate-output"), "evaluate threw: " + JSON.stringify(error));
  }
});

$("sign").addEventListener("click", async () => {
  if (!fixture) {
    log($("sign-output"), "module not loaded yet");
    return;
  }
  try {
    const fixtureReceiptBody = await buildFixtureReceiptBody();
    const seed = mint_signing_seed_hex();
    const started = nowMs();
    const receipt = sign_receipt(JSON.stringify(fixtureReceiptBody), seed);
    const elapsed = nowMs() - started;
    log($("sign-output"), {
      elapsed_ms: elapsed,
      seed_preview: seed.slice(0, 8) + "...",
      receipt,
    });
  } catch (error) {
    log($("sign-output"), "sign_receipt threw: " + JSON.stringify(error));
  }
});
