// Narrative beat storyboard (12 beats). Hardcoded.

import type { Beat } from "./types";

export const BEATS: readonly Beat[] = [
  {
    n: 1,
    title: "Budget delegated",
    caption: "treasury -> procurement via signed capability envelope.",
    artifacts: ["chio/capabilities/root-treasury.json", "chio/budgets/budget-summary.json"],
    edges: ["e1"],
  },
  {
    n: 2,
    title: "RFQ opens",
    caption: "market-broker publishes RFQ through chio api protect.",
    artifacts: ["market/rfq-request.json"],
    edges: ["e2", "e5"],
  },
  {
    n: 3,
    title: "Low-reputation bid rejected",
    caption: "Cheap bid denied on reputation.passport.compare.",
    artifacts: ["reputation/provider-reputation-verdict.json", "reputation/provider-passport-comparison.json"],
    edges: [],
  },
  {
    n: 4,
    title: "Forged-passport bid denied",
    caption: "Malicious over-budget bid blocked at mediation boundary.",
    artifacts: ["adversarial/forged_passport-denial.json", "guardrails/overspend-denial.json"],
    edges: ["d1", "d2"],
    pause: true,
  },
  {
    n: 5,
    title: "ProofWorks selected",
    caption: "Selection rationale recorded with bid references.",
    artifacts: ["market/provider-selection.json"],
    edges: ["e5"],
  },
  {
    n: 6,
    title: "Two-hop narrowing to CipherWorks",
    caption: "ProofWorks subcontracts under scoped capability.",
    artifacts: ["subcontracting/delegated-capability.json", "chio/receipts/lineage-subcontractor-agent.json"],
    edges: ["e6"],
  },
  {
    n: 7,
    title: "Runtime attestation wobble",
    caption: "Sidecar degrades amber, re-attests, returns green.",
    artifacts: [
      "identity/runtime-degradation/provider-quarantine.json",
      "identity/runtime-degradation/reattestation.json",
    ],
    edges: ["e5"],
  },
  {
    n: 8,
    title: "Signed human approval",
    caption: "Human-in-the-loop signs the budget envelope.",
    artifacts: ["approvals/high-risk-release-decision.json"],
    edges: ["e7"],
  },
  {
    n: 9,
    title: "x402 payment proof",
    caption: "On-chain mediated proof anchors the payment.",
    artifacts: ["payments/chio-payment-proof.json"],
    edges: ["e7"],
  },
  {
    n: 10,
    title: "Cross-rail settlement",
    caption: "Rails selected by policy compatibility.",
    artifacts: ["settlement/rail-selection.json", "chio/receipts/rail-selection.json"],
    edges: ["e7"],
  },
  {
    n: 11,
    title: "Audit via read-only MCP",
    caption: "Auditor reads web3 evidence without write capability.",
    artifacts: ["chio/receipts/web3-evidence-mcp.json", "web3/validation-index.json"],
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
