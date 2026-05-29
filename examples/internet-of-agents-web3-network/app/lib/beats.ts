// Narrative beat storyboard (12 beats).
//
// Hardcoded narrative beats. Future versions may source this from artifacts.

import type { Beat } from "./types";

export const BEATS: readonly Beat[] = [
  {
    n: 1,
    title: "Budget delegated",
    caption: "treasury -> procurement via signed capability envelope.",
    artifacts: ["chio/capabilities/treasury-budget-lorem.json", "chio/budgets/exposure.json"],
    edges: ["e1"],
  },
  {
    n: 2,
    title: "RFQ opens",
    caption: "market-broker publishes RFQ through chio api protect.",
    artifacts: ["market/rfq.json"],
    edges: ["e2", "e5"],
  },
  {
    n: 3,
    title: "Low-reputation bid rejected",
    caption: "Cheap bid denied on reputation.passport.compare.",
    artifacts: ["market/rejections/low-rep-lorem.json", "reputation/passport-compare-proofworks.json"],
    edges: [],
  },
  {
    n: 4,
    title: "Forged-passport bid denied",
    caption: "Malicious over-budget bid blocked at mediation boundary.",
    artifacts: ["adversarial/forged-passport.json", "guardrails/overspend.json"],
    edges: ["d1", "d2"],
    pause: true,
  },
  {
    n: 5,
    title: "ProofWorks selected",
    caption: "Selection rationale recorded with bid references.",
    artifacts: ["market/selection.json"],
    edges: ["e5"],
  },
  {
    n: 6,
    title: "Two-hop narrowing to CipherWorks",
    caption: "ProofWorks subcontracts under scoped capability.",
    artifacts: ["subcontracting/capability.json", "chio/receipts/lineage/subcontract-two-hop-lorem.json"],
    edges: ["e6"],
  },
  {
    n: 7,
    title: "Runtime attestation wobble",
    caption: "Sidecar degrades amber, re-attests, returns green.",
    artifacts: [
      "identity/runtime-degradation/proofworks-wobble-lorem.json",
      "identity/runtime-degradation/proofworks-reattest-lorem.json",
    ],
    edges: ["e5"],
  },
  {
    n: 8,
    title: "Signed human approval",
    caption: "Human-in-the-loop signs the budget envelope.",
    artifacts: ["approvals/signed-human-lorem.json"],
    edges: ["e7"],
  },
  {
    n: 9,
    title: "x402 payment proof",
    caption: "On-chain mediated proof anchors the payment.",
    artifacts: ["payments/x402-proof-lorem.json"],
    edges: ["e7"],
  },
  {
    n: 10,
    title: "Cross-rail settlement",
    caption: "Rails selected by policy compatibility.",
    artifacts: ["settlement/cross-rail-lorem.json", "rails/selection.json"],
    edges: ["e7"],
  },
  {
    n: 11,
    title: "Audit via read-only MCP",
    caption: "Auditor reads web3 evidence without write capability.",
    artifacts: ["chio/receipts/mcp/auditor-web3-evidence-lorem.json", "web3/validation-ladder.json"],
    edges: ["e8", "e9"],
  },
  {
    n: 12,
    title: "Bundle verified",
    caption: "Manifest hashes match; 6/6 denials fired; verdict PASS.",
    artifacts: ["review-result.json", "bundle-manifest.json"],
    edges: [],
  },
];
