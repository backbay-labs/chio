// Shared types for the Chio Evidence Console.
//
// These model the artifact contract emitted by `orchestrate.py`. The normative
// sources are `internet_web3/artifacts.py::ArtifactStore.write_manifest`,
// `internet_web3/scenario.py::_build_summary`, and
// `internet_web3/verify.py::verify_bundle`. Keep these shapes in sync.

export type Verdict = "PASS" | "FAIL" | string;

/**
 * review-result.json as emitted by verify.py. `manifest`, `capabilities`,
 * `web3`, and `chio` are deeply-structured diagnostic sub-objects we do not
 * need to consume beyond treating them as unknown JSON.
 */
export interface ReviewResult {
  schema: string;
  bundle: string;
  ok: boolean;
  errors: string[];
  manifest?: unknown;
  capabilities?: unknown;
  web3?: unknown;
  chio?: unknown;
}

/**
 * summary.json produced by `internet_web3/scenario.py::_build_summary`.
 * Field names follow the Python source. Deeply nested blobs (service
 * topology, per-boundary counts) are typed loosely so the UI does not pin
 * a sub-schema that the orchestrator may refine later.
 */
export interface Summary {
  schema: string;
  example: string;
  order_id: string;
  agent_count: number;
  capability_count: number;
  capability_lineage_depth?: number;
  subcontract_lineage_depth?: number;
  receipt_counts_by_boundary: Record<string, number>;
  adversarial_denial_status: Record<string, string>;
  guardrail_denial_status: Record<string, string>;
  service_topology?: Record<string, string>;
  base_sepolia_smoke_status?: string;
  base_sepolia_attachment_status?: string;
  base_sepolia_live_smoke_included?: boolean;
  mainnet_blocked?: boolean;
  chio_mediated?: boolean;
  approval_status?: string;
  behavioral_baseline_status?: string;
  budget_exposure?: string;
  budget_reconciliation?: string;
  dispute_status?: string;
  federation_verdict?: string;
  historical_reputation_status?: string;
  mediation_status?: string;
  observability_status?: string;
  ops_assertions?: number;
  passport_verdict?: string;
  promotion_checks?: number;
  provider_review_verdict?: string;
  rail_selection_status?: string;
  reconciliation_status?: string;
  rejected_provider_count?: number;
  reputation_verdict?: string;
  rfq_selection_status?: string;
  runtime_degradation_status?: string;
  selected_provider_id?: string;
  selected_rail?: string;
  settlement_status?: string;
  subcontractor_review_verdict?: string;
  web3_local_e2e_status?: string;
  x402_payment_status?: string;
  // Allow additional fields so the UI tolerates orchestrator additions.
  [key: string]: unknown;
}

/**
 * Best-effort shape of `chio/budgets/budget-summary.json`. The `_wei` aliases
 * are not present today (units come out unit-less), so the UI treats both the
 * `Units` and `Wei` variants as optional. See
 * `internet_web3/budgeting.py::BudgetWorkflow.write_summary`.
 */
export interface BudgetSummary {
  schema?: string;
  authorizationStatus?: string;
  reconciliationStatus?: string;
  authorizedExposureUnits?: number;
  realizedSpendUnits?: number;
  source?: string;
  // Optional wei fields when the orchestrator emits them.
  delegated_wei?: string;
  remaining_wei?: string;
  [key: string]: unknown;
}

/**
 * bundle-manifest.json produced by artifacts.py. Raw hex hashes, integer
 * epoch `generated_at`.
 */
export interface Manifest {
  schema: string;
  generated_at: number;
  files: string[];
  sha256: Record<string, string>;
}

export type EdgeKind = "intra" | "mediated" | "delegation" | "denial";

export interface Edge {
  id: string;
  from: string;
  to: string;
  kind: EdgeKind;
  label: string;
  scope?: string;
  ttl?: string;
  reason?: string;
}

export type Quadrant = "tl" | "tr" | "bl" | "br";

export interface Workload {
  id: string;
  name: string;
  kind: string;
}

export interface Sidecar {
  id: string;
  name: string;
  guards?: string;
}

export interface Mcp {
  id: string;
  name: string;
  direction?: "in" | "out";
}

export interface Org {
  id: string;
  name: string;
  role: string;
  quadrant: Quadrant;
  trustControlUrl: string;
  color: string;
  workloads: Workload[];
  sidecars: Sidecar[];
  mcp: Mcp[];
}

export interface Topology {
  orgs: Record<string, Org>;
  edges: Edge[];
}

export interface Beat {
  n: number;
  title: string;
  caption: string;
  artifacts: string[];
  edges: string[];
  pause?: boolean;
}

export interface PulseSpec {
  key: number;
  edgeId: string;
  kind: string;
  label: string;
  duration: number;
  onDone: () => void;
}

/**
 * The object returned by `useBundle()`. All artifact bodies arrive lazily via
 * `fetchArtifact`; the three eager loads (manifest/summary/review) are always
 * populated once the provider resolves. `topology` is also eager.
 */
export interface Bundle {
  manifest: Manifest;
  summary: Summary;
  review: ReviewResult;
  topology: Topology;
  beats: Beat[];
  reviewOverride?: { verdict: Verdict };
}
