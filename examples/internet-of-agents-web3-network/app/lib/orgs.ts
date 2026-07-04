// Demo org layout for the four-quadrant graph. Hardcoded ensemble.

import type { Edge, Org, Topology } from "./types";

export const DEMO_ORGS: Record<string, Org> = {
  atlas: {
    id: "atlas",
    name: "Atlas Treasury",
    role: "Buyer",
    quadrant: "tl",
    trustControlUrl: "https://atlas.example.invalid/.chio/trust",
    color: "#7dd3fc",
    workloads: [
      { id: "atlas.treasury", name: "treasury", kind: "workload" },
      { id: "atlas.procurement", name: "procurement", kind: "workload" },
      { id: "atlas.approver", name: "approver-signer", kind: "workload" },
    ],
    sidecars: [
      { id: "atlas.mkt-broker", name: "market-broker", guards: "atlas.procurement" },
    ],
    mcp: [{ id: "atlas.mcp.review", name: "provider-review", direction: "out" }],
  },
  proofworks: {
    id: "proofworks",
    name: "ProofWorks",
    role: "Provider",
    quadrant: "tr",
    trustControlUrl: "https://proofworks.example.invalid/.chio/trust",
    color: "#5eead4",
    workloads: [
      { id: "proofworks.provider", name: "provider", kind: "workload" },
      { id: "proofworks.delegator", name: "delegator", kind: "workload" },
    ],
    sidecars: [
      { id: "proofworks.subcontract-desk", name: "subcontract-desk", guards: "proofworks.delegator" },
    ],
    mcp: [{ id: "proofworks.mcp.review", name: "subcontractor-review", direction: "out" }],
  },
  cipherworks: {
    id: "cipherworks",
    name: "CipherWorks",
    role: "Subcontractor",
    quadrant: "br",
    trustControlUrl: "https://cipherworks.example.invalid/.chio/trust",
    color: "#a78bfa",
    workloads: [
      { id: "cipherworks.subcontractor", name: "subcontractor", kind: "workload" },
      { id: "cipherworks.attestor", name: "attestor", kind: "workload" },
    ],
    sidecars: [],
    mcp: [],
  },
  meridian: {
    id: "meridian",
    name: "Meridian Rails",
    role: "Settlement + Auditor",
    quadrant: "bl",
    trustControlUrl: "https://meridian.example.invalid/.chio/trust",
    color: "#fbbf24",
    workloads: [
      { id: "meridian.settlement", name: "settlement", kind: "workload" },
      { id: "meridian.auditor", name: "auditor", kind: "workload" },
    ],
    sidecars: [
      { id: "meridian.settlement-desk", name: "settlement-desk", guards: "meridian.settlement" },
    ],
    mcp: [{ id: "meridian.mcp.web3", name: "web3-evidence", direction: "in" }],
  },
};

export const DEMO_EDGES: Edge[] = [
  { id: "e1", from: "atlas.treasury", to: "atlas.procurement", kind: "intra", label: "budget-delegation" },
  { id: "e2", from: "atlas.procurement", to: "atlas.mkt-broker", kind: "intra", label: "local" },
  { id: "e3", from: "proofworks.provider", to: "proofworks.delegator", kind: "intra", label: "local" },
  { id: "e4", from: "meridian.settlement", to: "meridian.settlement-desk", kind: "intra", label: "local" },
  {
    id: "e5",
    from: "atlas.mkt-broker",
    to: "proofworks.provider",
    kind: "mediated",
    label: "rfq/award",
    scope: "market.rfq.respond",
    ttl: "15m",
  },
  {
    id: "e6",
    from: "proofworks.subcontract-desk",
    to: "cipherworks.subcontractor",
    kind: "delegation",
    label: "two-hop-subcontract",
    scope: "subcontract.execute",
    ttl: "10m",
  },
  {
    id: "e7",
    from: "atlas.approver",
    to: "meridian.settlement-desk",
    kind: "mediated",
    label: "approval+x402",
    scope: "payment.settle",
    ttl: "5m",
  },
  { id: "e8", from: "meridian.auditor", to: "meridian.mcp.web3", kind: "intra", label: "evidence.read" },
  {
    id: "e9",
    from: "meridian.mcp.web3",
    to: "cipherworks.attestor",
    kind: "mediated",
    label: "attestation-read",
    scope: "attestation.read",
    ttl: "1h",
  },
  {
    id: "d1",
    from: "atlas.mkt-broker",
    to: "proofworks.provider",
    kind: "denial",
    label: "forged-passport",
    reason: "identity.passport.signature.invalid",
  },
  {
    id: "d2",
    from: "atlas.mkt-broker",
    to: "proofworks.provider",
    kind: "denial",
    label: "over-budget-bid",
    reason: "budget.envelope.exceeded",
  },
];

/**
 * Merge the bundle-provided topology with the demo ensemble. The bundle
 * topology may carry a sparse `orgs` map keyed by id (with name/role/trust
 * fields), in which case those overrides are copied onto the demo layout.
 */
export function mergeTopology(bundleTopology: Topology): Topology {
  const mergedOrgs: Record<string, Org> = {};
  for (const [id, base] of Object.entries(DEMO_ORGS)) {
    const bundleOrg = bundleTopology.orgs?.[id];
    if (bundleOrg && typeof bundleOrg === "object") {
      mergedOrgs[id] = { ...base, ...(bundleOrg as Partial<Org>), id: base.id, quadrant: base.quadrant };
    } else {
      mergedOrgs[id] = base;
    }
  }
  // Drop bundle orgs that are not in the demo set: they have no layout coordinates.
  const edges = Array.isArray(bundleTopology.edges) && bundleTopology.edges.length > 0
    ? bundleTopology.edges
    : DEMO_EDGES;
  return { orgs: mergedOrgs, edges };
}
