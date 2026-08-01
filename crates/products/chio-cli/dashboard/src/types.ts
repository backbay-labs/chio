// Mirror of API response shapes from the Chio receipt query and lineage endpoints.

// Comptroller surface shapes are generated from the published JSON Schema; do not hand-mirror them.
export type {
  ChioComptrollerSurfaceReport,
  ChioComptrollerSurfaceReport as ComptrollerSurfaceReport,
} from './generated/comptroller-surface'

export type DecisionKind = 'allow' | 'deny' | 'cancelled' | 'incomplete'

export interface FinancialMetadata {
  grant_index: number
  cost_charged: number
  currency: string
  budget_remaining: number
  budget_total: number
  delegation_depth: number
  root_budget_holder: string
  settlement_status: string
}

export interface AttributionMetadata {
  subject_key: string
  issuer_key: string
  delegation_depth: number
  grant_index?: number | null
}

export interface ReceiptAction {
  parameters: Record<string, unknown>
  parameter_hash: string
}

export type ReceiptDecision =
  | { verdict: 'allow' }
  | { verdict: 'deny'; reason: string; guard: string }
  | { verdict: 'cancelled'; reason: string }
  | { verdict: 'incomplete'; reason: string }

export type ReceiptDecisionKind = DecisionKind | 'none'

export interface ReceiptMetadata {
  financial?: FinancialMetadata
  attribution?: AttributionMetadata
}

export interface Receipt {
  id: string
  timestamp: number
  capability_id: string
  tool_server: string
  tool_name: string
  action: ReceiptAction
  decision?: ReceiptDecision
  receipt_kind?: 'mediated_decision' | 'trace_observation' | 'advisory_evaluation'
  boundary_class?: 'prevent' | 'detect_only' | 'advisory_only'
  metadata?: ReceiptMetadata
}

export interface ReceiptQueryResponse {
  totalCount: number
  nextCursor: number | null
  receipts: Receipt[]
}

export type ProofRoomVerdict = 'verified' | 'failed'
export type ProofRoomReportVerdict = ProofRoomVerdict | 'accepted' | 'rejected'

export interface ProofRoomArtifactRef {
  path: string
  sha256: string
  schema: string
}

export interface ProofRoomArtifact extends ProofRoomArtifactRef {
  media_type?: string
  artifact_class?: string
  sensitivity_class?: string
  producer?: string
  participates_in_primary_verdict?: boolean
  renderer_hint?: string
}

export interface ProofRoomManifestClaim {
  claim_id: string
  required_artifacts: string[]
  result: ProofRoomVerdict
  checker?: string
  proof_level?: string
  caveat?: string
  source_refs?: string[]
}

export interface ProofRoomNegativeCase {
  id: string
  path: string
  expected_failure_code: string
  observed_failure_code?: string
}

export interface ProofRoomReceiptCoverage {
  category: string
  status: 'covered' | 'excluded'
  artifact_path?: string
  terminal_status?: string
  exclusion_reason?: string
}

export interface ProofRoomBundleManifest {
  schema: 'chio.proof-room.bundle.v1'
  bundle_id: string
  fixture_id: string
  verifier_report_ref: ProofRoomArtifactRef
  proof_room_verifier_report_ref?: ProofRoomArtifactRef
  transaction_passport_ref?: ProofRoomArtifactRef
  evidence_graph_ref?: ProofRoomArtifactRef
  artifacts?: ProofRoomArtifact[]
  claims: ProofRoomManifestClaim[]
  negative_cases: ProofRoomNegativeCase[]
  receipt_coverage?: ProofRoomReceiptCoverage[]
  advisory_artifacts?: ProofRoomManifestPathReason[]
  excluded_artifacts?: ProofRoomManifestPathReason[]
  signature?: ProofRoomBundleSignature
}

export interface ProofRoomBundleSignature {
  kind: string
  signature_ref: string
}

export interface ProofRoomManifestPathReason {
  path: string
  reason: string
}

export interface ProofRoomRenderedClaim {
  claim_id: string
  source: string
  verdict: ProofRoomVerdict
  checker?: string
}

export interface ProofRoomLoadReport {
  schema: 'chio.proof-room.verifier-report.v1'
  id?: string
  verdict: ProofRoomReportVerdict
  bundle_id: string
  fixture_id: string
  source_verifier_report_ref: ProofRoomArtifactRef
  ui_verdict_source: string
  rendered_claims: ProofRoomRenderedClaim[]
}

export interface ProofRoomFixtureCatalogNegativeCase {
  id: string
  path: string
  expected_failure_code: string
  observed_failure_code?: string
}

export interface ProofRoomFixtureCatalogEntry {
  fixture_id: string
  bundle_id: string
  verdict: ProofRoomVerdict
  manifest_path: string
  load_report_path: string
  negative_cases: ProofRoomFixtureCatalogNegativeCase[]
}

export interface ProofRoomAvailableFixture {
  id: string
  kind: string
  path: string
  description: string
  negative_cases?: ProofRoomFixtureCatalogNegativeCase[]
  verifier_report: ProofRoomAvailableFixtureReport
}

export interface ProofRoomAvailableFixtureReport {
  path: string
  status: number
  verdict: ProofRoomReportVerdict
  failure_code?: string
  error?: string
}

export interface ProofRoomFixtureCatalog {
  schema: 'chio.proof-room.fixture-catalog.v1'
  fixtures: ProofRoomFixtureCatalogEntry[]
  available_fixtures?: ProofRoomAvailableFixture[]
}

export interface ProofRoomCanonicalVerifierReport {
  schema: string
  id?: string
  verdict?: string
  passport_id?: string
  passport_path?: string
  evidence_graph_path?: string
  verifier_policy_path?: string
  failure_code?: string
  error?: string
  verified_claims?: string[]
  rejected_checks?: ProofRoomRejectedCheck[]
  [key: string]: unknown
}

export interface ProofRoomRejectedCheck {
  code?: string
  message?: string
  task_id?: string
  [key: string]: unknown
}

export interface ProofRoomRiskFacility {
  facility_id?: string
  state?: string
  capital_currency?: string
  capital_units?: number
  reserve_currency?: string
  reserve_units?: number
  reserve_ref?: string
}

export interface ProofRoomRiskCoverage {
  coverage_id?: string
  order_id?: string
  subject?: string
  beneficiary_subject?: string
  currency?: string
  exposure_units?: number
  reserve_ref?: string
  status?: string
}

export interface ProofRoomRiskReconciliation {
  order_id?: string
  currency?: string
  exposure_units?: number
  reserve_units?: number
  consumed_reserve_units?: number
  payout_units?: number
  settlement_units?: number
  status?: string
}

export interface ProofRoomRiskReserveLedgerEntry {
  entry_id?: string
  receipt_ref?: string
  lane?: string
  reserve_ref?: string
  claim_id?: string
  currency?: string
  units?: number
  settlement_ref?: string
}

export interface ProofRoomRiskSanctionReserveLedgerEntry extends ProofRoomRiskReserveLedgerEntry {
  bridge_id?: string
  authority_receipt_ref?: string
  evidence_ref?: string
  jurisdiction_ref?: string
}

export interface ProofRoomRiskComptrollerReport {
  schema: 'chio.risk.comptroller-report.v1'
  id?: string
  facility?: ProofRoomRiskFacility
  coverage?: ProofRoomRiskCoverage
  reconciliation?: ProofRoomRiskReconciliation
  reserve_ledger?: ProofRoomRiskReserveLedgerEntry[]
  sanction_reserve_ledger?: ProofRoomRiskSanctionReserveLedgerEntry[]
}

export interface ProofRoomCommerceOrderContext {
  schema: 'chio.commerce.order-context.v1'
  id?: string
  order_id?: string
  buyer_subject?: string
  agent_subject?: string
  merchant_subject?: string
  quote_id?: string
  quote_amount_minor?: number
  quote_currency?: string
  current_state?: string
}

export interface ProofRoomCommercePaymentLifecycle {
  schema: 'chio.commerce.payment-lifecycle.v1'
  id?: string
  order_id?: string
  merchant_subject?: string
  psp?: string
  payment_intent_id?: string
  amount_minor?: number
  currency?: string
  payment_status?: string
}

export interface ProofRoomCommerceEvent {
  event_id?: string
  transition?: string
  prior_state?: string
  next_state?: string
  authority_receipt_ref?: string
}

export interface ProofRoomCommerceEventLog {
  schema: 'chio.commerce.event-log.v1'
  id?: string
  order_id?: string
  events?: ProofRoomCommerceEvent[]
}

export interface ProofRoomCommerceEvidence {
  orderContext?: ProofRoomCommerceOrderContext
  paymentLifecycle?: ProofRoomCommercePaymentLifecycle
  eventLog?: ProofRoomCommerceEventLog
}

export interface ProofRoomDisclosureCapsule {
  schema: 'chio.disclosure.capsule.v1'
  id?: string
  transaction_passport_ref?: string
  privacy_profile_ref?: string
  lineage_subgraph_ref?: string
  leakage_ledger_ref?: string
  disclosed_fields?: string[]
  hidden_predicates?: Array<string | ProofRoomHiddenPredicate>
}

export interface ProofRoomHiddenPredicate {
  predicate_id?: string
  kind?: string
  field?: string
  operator?: string
  operand?: string
  unit?: string
  result?: boolean
  proof_ref?: string
  projection_slot?: number
}

export interface ProofRoomLineageNode {
  id?: string
  kind?: string
  receipt_ref?: string
  artifact_sha256?: string
  artifact_schema?: string
  evidence_class?: string
  tenant_hash?: string
  source_table?: string
  source_id_hash?: string
  depth?: number
  parent_ids?: string[]
  disclosure_state?: string
}

export interface ProofRoomLineageEdge {
  edge_id?: string
  from?: string
  to?: string
  relation?: string
  kind?: string
  evidence_class?: string
  source_artifact_sha256?: string
  statement_sha256?: string
  disclosure_state?: string
}

export interface ProofRoomLineageRedaction {
  node_id?: string
  reason?: string
}

export interface ProofRoomSignedLineageSubgraph {
  schema: 'chio.lineage.signed-subgraph.v1'
  id?: string
  transaction_passport_ref?: string
  policy_profile_id?: string
  generated_at?: string
  audience?: string
  challenge_nonce?: string
  frontier_sha256?: string
  checkpoint_ref?: string
  checkpoint_inclusion_sha256?: string
  max_depth?: number
  required_evidence_class?: string
  lineage_anchor_ref?: string
  redaction_map_sha256?: string
  leakage_ledger_sha256?: string
  projection_manifest_sha256?: string
  root_receipt_ids?: string[]
  nodes?: ProofRoomLineageNode[]
  edges?: ProofRoomLineageEdge[]
  redactions?: ProofRoomLineageRedaction[]
  signature?: string
}

export interface ProofRoomLeakageLedgerEntry {
  entry_id?: string
  source?: string
  field?: string
  leakage_kind?: string
  disclosure_kind?: string
  sensitivity_class?: string
  value_class?: string
  reason?: string
  policy_rule?: string
  derived_inferences?: string[]
  cross_tenant_risk?: boolean
  mitigation?: string
  score?: number
  allowed_by_profile?: boolean
  residual_inference_note?: string
}

export interface ProofRoomLeakageLedger {
  schema: 'chio.disclosure.leakage-ledger.v1'
  id?: string
  transaction_passport_ref?: string
  privacy_profile_ref?: string
  policy_profile_id?: string
  subject_artifact_sha256?: string
  generated_at?: string
  audience?: string
  total_leakage_score?: number
  max_allowed_leakage_score?: number
  tenant_leakage_notice_ref?: string
  accepted?: boolean
  entries?: ProofRoomLeakageLedgerEntry[]
}

export interface ProofRoomDisclosureEvidence {
  capsule?: ProofRoomDisclosureCapsule
  signedLineageSubgraph?: ProofRoomSignedLineageSubgraph
  leakageLedger?: ProofRoomLeakageLedger
}

export interface ProofRoomSwarmTaskGraphNode {
  taskId?: string
  parentTaskId?: string
  routePlanRef?: string
  continuationTokenRef?: string
  budgetAllocationRef?: string
  depth?: number
}

export interface ProofRoomSwarmTaskGraphJoin {
  joinId?: string
  parentTaskIds?: string[]
  nextTaskId?: string
}

export interface ProofRoomSwarmTaskGraph {
  schema: 'chio.swarm.task-graph.v1'
  graphId?: string
  rootTransactionRef?: string
  plannerSubject?: string
  maxDepth?: number
  maxFanout?: number
  nodes?: ProofRoomSwarmTaskGraphNode[]
  joins?: ProofRoomSwarmTaskGraphJoin[]
  budgetPoolRef?: string
  revocationEpochRef?: string
}

export interface ProofRoomSwarmContinuationToken {
  schema: 'chio.swarm.continuation-token.v1'
  tokenId?: string
  graphId?: string
  childTaskId?: string
  parentTaskId?: string
  parentReceiptIds?: string[]
  routePlanReceiptId?: string
  budgetAllocationId?: string
  revocationEpochRef?: string
  mode?: string
}

export interface ProofRoomSwarmWitnessHop {
  attenuationRuleId?: string
  policyDigest?: string
  witnessSignature?: string
}

export interface ProofRoomSwarmWitnessChain {
  schema: 'chio.swarm.delegation-witness-chain.v1'
  chainId?: string
  graphId?: string
  parentTaskId?: string
  childTaskId?: string
  hops?: ProofRoomSwarmWitnessHop[]
}

export interface ProofRoomSwarmRoutePlanReceipt {
  schema: 'chio.swarm.route-plan-receipt.v1'
  routePlanId?: string
  graphId?: string
  taskId?: string
  selectedRoute?: string
  bridgeId?: string
  protocolTarget?: string
  egressConstraints?: string[]
  attenuationDecision?: string
}

export interface ProofRoomSwarmJoinReceipt {
  schema: 'chio.swarm.join-receipt.v1'
  joinId?: string
  graphId?: string
  expectedParentReceiptIds?: string[]
  actualParentReceiptIds?: string[]
  joinPredicate?: string
  nextTaskId?: string
}

export interface ProofRoomSwarmBudgetAllocation {
  allocationId?: string
  taskId?: string
  maxUnits?: number
}

export interface ProofRoomSwarmBudgetPool {
  schema: 'chio.swarm.budget-pool.v1'
  poolId?: string
  graphId?: string
  currency?: string
  totalUnits?: number
  allocations?: ProofRoomSwarmBudgetAllocation[]
}

export interface ProofRoomSwarmRevocationEpoch {
  schema: 'chio.swarm.revocation-epoch.v1'
  epochId?: string
  rootHash?: string
  revokedSubjects?: string[]
  revokedTaskIds?: string[]
}

export interface ProofRoomSwarmEvidence {
  taskGraph?: ProofRoomSwarmTaskGraph
  continuations?: ProofRoomSwarmContinuationToken[]
  witnessChains?: ProofRoomSwarmWitnessChain[]
  routePlans?: ProofRoomSwarmRoutePlanReceipt[]
  joinReceipt?: ProofRoomSwarmJoinReceipt
  budgetPool?: ProofRoomSwarmBudgetPool
  revocationEpoch?: ProofRoomSwarmRevocationEpoch
}

export interface ProofRoomWorkflowPreflightScope {
  actions?: string[]
  resources?: string[]
  route_refs?: string[]
  approval_refs?: string[]
  required_schemas?: string[]
  budget_minor?: number
  currency?: string
}

export interface ProofRoomWorkflowPreflightParentTask {
  task_id?: string
  scope?: ProofRoomWorkflowPreflightScope
}

export interface ProofRoomWorkflowPreflightChildTask {
  task_id?: string
  parent_task_id?: string
  requested_scope?: ProofRoomWorkflowPreflightScope
}

export interface ProofRoomWorkflowRoutePlan {
  route_ref?: string
  supported?: boolean
}

export interface ProofRoomWorkflowApproval {
  approval_ref?: string
  status?: string
}

export interface ProofRoomWorkflowRegistrySupport {
  supported_schemas?: string[]
}

export interface ProofRoomWorkflowBudgetPool {
  currency?: string
  total_minor?: number
}

export interface ProofRoomWorkflowRevocation {
  epoch_id?: string
  root_sha256?: string
  status?: string
}

export interface ProofRoomWorkflowPlanningArtifact {
  artifact_ref?: string
  artifact_class?: string
  satisfies_claims?: string[]
}

export interface ProofRoomWorkflowPreflightPlan {
  schema: 'chio.workflow.preflight-plan.v1'
  id?: string
  issued_at?: string
  parent_task?: ProofRoomWorkflowPreflightParentTask
  child_tasks?: ProofRoomWorkflowPreflightChildTask[]
  route_plans?: ProofRoomWorkflowRoutePlan[]
  approvals?: ProofRoomWorkflowApproval[]
  registry_support?: ProofRoomWorkflowRegistrySupport
  budget_pool?: ProofRoomWorkflowBudgetPool
  revocation?: ProofRoomWorkflowRevocation
  planning_artifacts?: ProofRoomWorkflowPlanningArtifact[]
}

export interface ProofRoomWorkflowPreflightCheck {
  code?: string
  message?: string
  task_id?: string
}

export interface ProofRoomWorkflowPreflightReport {
  schema: 'chio.workflow.preflight-report.v1'
  id?: string
  issued_at?: string
  plan_id?: string
  verdict?: string
  evidence_class?: string
  verified_claims?: string[]
  rejected_checks?: ProofRoomWorkflowPreflightCheck[]
  live_authority_claims?: string[]
}

export interface ProofRoomWorkflowPreflightEvidence {
  plan?: ProofRoomWorkflowPreflightPlan
  report?: ProofRoomWorkflowPreflightReport
}

export interface ProofRoomEnterpriseExportArtifact {
  role?: string
  path?: string
  sha256?: string
}

export interface ProofRoomEnterpriseEvidenceExportBundle {
  schema: 'chio.enterprise.evidence-export-bundle.v1'
  id?: string
  issued_at?: string
  passport_id?: string
  risk_comptroller_report_ref?: string
  approval_case_ref?: string
  bundle_digest?: string
  artifacts?: ProofRoomEnterpriseExportArtifact[]
}

export interface ProofRoomEnterpriseFieldClassification {
  field?: string
  classification?: string
  export_action?: string
}

export interface ProofRoomEnterpriseDataGovernanceReport {
  schema: 'chio.enterprise.data-governance-report.v1'
  id?: string
  issued_at?: string
  passport_id?: string
  risk_comptroller_report_ref?: string
  allowed_regions?: string[]
  observed_region?: string
  retention_class?: string
  legal_hold_status?: string
  redaction_profile_ref?: string
  disclosure_capsule_ref?: string
  leakage_ledger_ref?: string
  field_classifications?: ProofRoomEnterpriseFieldClassification[]
}

export interface ProofRoomEnterpriseTelemetryEvent {
  event_id?: string
  event_kind?: string
  artifact_ref?: string
  artifact_sha256?: string
}

export interface ProofRoomEnterpriseTelemetryProjection {
  schema: 'chio.enterprise.telemetry-projection.v1'
  id?: string
  issued_at?: string
  passport_id?: string
  risk_comptroller_report_ref?: string
  events?: ProofRoomEnterpriseTelemetryEvent[]
}

export interface ProofRoomEnterpriseApprovalCase {
  schema: 'chio.enterprise.approval-case.v1'
  id?: string
  issued_at?: string
  passport_id?: string
  risk_comptroller_report_ref?: string
  decision?: string
  decision_subject?: string
  approvers?: string[]
  required_quorum?: number
  expires_at?: string
}

export interface ProofRoomEnterpriseControl {
  control_id?: string
  control_family?: string
  claim_ref?: string
  gate_ref?: string
}

export interface ProofRoomEnterpriseControlEvidenceMap {
  schema: 'chio.enterprise.control-evidence-map.v1'
  id?: string
  issued_at?: string
  passport_id?: string
  risk_comptroller_report_ref?: string
  controls?: ProofRoomEnterpriseControl[]
}

export interface ProofRoomEnterpriseEvidence {
  exportBundle?: ProofRoomEnterpriseEvidenceExportBundle
  dataGovernanceReport?: ProofRoomEnterpriseDataGovernanceReport
  telemetryProjection?: ProofRoomEnterpriseTelemetryProjection
  approvalCase?: ProofRoomEnterpriseApprovalCase
  controlEvidenceMap?: ProofRoomEnterpriseControlEvidenceMap
}

export interface ProofRoomTrustMarketCandidate {
  subject?: string
  jurisdiction_ref?: string
  excluded?: boolean
}

export interface ProofRoomTrustMarketDiscoverySnapshot {
  schema: 'chio.commerce.provider-discovery-snapshot.v1'
  id?: string
  passport_id?: string
  order_id?: string
  market_scope?: string
  provider_candidates?: ProofRoomTrustMarketCandidate[]
  discovery_authority_ref?: string
}

export interface ProofRoomTrustMarketRankingResult {
  provider_subject?: string
  rank?: number
  total_score?: number
}

export interface ProofRoomTrustMarketProviderSelection {
  schema: 'chio.commerce.provider-selection-report.v1'
  id?: string
  passport_id?: string
  order_id?: string
  discovery_snapshot_ref?: string
  selected_provider_subject?: string
  scorecard_ref?: string
  sla_commitment_ref?: string
  risk_report_ref?: string
  selection_reason_codes?: string[]
  ranking_results?: ProofRoomTrustMarketRankingResult[]
}

export interface ProofRoomTrustMarketScoreComponent {
  component?: string
  score?: number
  weight?: number
  evidence_ref?: string
  stale?: boolean
}

export interface ProofRoomTrustMarketScorecard {
  schema: 'chio.trust.scorecard-snapshot.v1'
  id?: string
  subject?: string
  scope?: string
  component_scores?: ProofRoomTrustMarketScoreComponent[]
  computed_score?: number
  downgrade_reasons?: string[]
}

export interface ProofRoomTrustMarketReputationImport {
  schema: 'chio.trust.reputation-import-report.v1'
  id?: string
  subject?: string
  source_network?: string
  issuer?: string
  local_weight?: number
  import_verdict?: string
  usage?: string
}

export interface ProofRoomTrustMarketMetricDefinition {
  metric?: string
  target?: number
  unit?: string
}

export interface ProofRoomTrustMarketSlaCommitment {
  schema: 'chio.commerce.sla-commitment.v1'
  id?: string
  order_id?: string
  provider_subject?: string
  buyer_subject?: string
  service_scope?: string
  collateral_position_ref?: string
  guarantee_decision_ref?: string
  metric_definitions?: ProofRoomTrustMarketMetricDefinition[]
}

export interface ProofRoomTrustMarketMetricResult {
  metric?: string
  value?: number
  unit?: string
  passed?: boolean
}

export interface ProofRoomTrustMarketSlaPerformance {
  schema: 'chio.commerce.sla-performance-report.v1'
  id?: string
  sla_ref?: string
  order_id?: string
  provider_subject?: string
  computed_metric_results?: ProofRoomTrustMarketMetricResult[]
  breach_verdict?: string
}

export interface ProofRoomTrustMarketCollateralPosition {
  schema: 'chio.risk.collateral-position-report.v1'
  id?: string
  subject?: string
  order_id?: string
  currency_or_asset?: string
  amount?: number
  source_type?: string
  available_amount?: number
}

export interface ProofRoomTrustMarketGuaranteeDecision {
  schema: 'chio.risk.guarantee-decision.v1'
  id?: string
  order_id?: string
  provider_subject?: string
  beneficiary_subject?: string
  guarantee_type?: string
  maximum_remedy?: number
  currency?: string
  backing_refs?: string[]
  adjudication_jurisdiction_ref?: string
  verdict?: string
}

export interface ProofRoomTrustMarketJurisdictionReceipt {
  schema: 'chio.risk.adjudication-jurisdiction-receipt.v1'
  id?: string
  jurisdiction_id?: string
  order_id?: string
  policy_ref?: string
  covered_dispute_types?: string[]
  adjudicator_subjects?: string[]
  slash_authority_refs?: string[]
}

export interface ProofRoomTrustMarketEvidence {
  discoverySnapshot?: ProofRoomTrustMarketDiscoverySnapshot
  providerSelection?: ProofRoomTrustMarketProviderSelection
  scorecard?: ProofRoomTrustMarketScorecard
  reputationImport?: ProofRoomTrustMarketReputationImport
  slaCommitment?: ProofRoomTrustMarketSlaCommitment
  slaPerformance?: ProofRoomTrustMarketSlaPerformance
  collateralPosition?: ProofRoomTrustMarketCollateralPosition
  guaranteeDecision?: ProofRoomTrustMarketGuaranteeDecision
  jurisdictionReceipt?: ProofRoomTrustMarketJurisdictionReceipt
}

export interface ProofRoomRuntimeExecutionLease {
  schema: 'chio.runtime.execution-lease.v1'
  lease_id?: string
  tool_server_id?: string
  tool_instance_id?: string
  tool_manifest_digest?: string
  sandbox_attestation_ref?: string
  request_digest?: string
  revocation_freshness_ref?: string
  policy_digest?: string
  nonce?: string
  side_effect_class?: string
  issued_at?: string
  expires_at?: string
}

export interface ProofRoomRuntimeRevocationFreshnessProof {
  schema: 'chio.runtime.revocation-freshness-proof.v1'
  proof_id?: string
  oracle_id?: string
  epoch_id?: string
  epoch_root?: string
  sequence?: number
  fetched_at?: string
  max_staleness_ms?: number
  revoked_leaf_result?: boolean
  signature?: string
}

export interface ProofRoomRuntimeSandboxAttestation {
  schema: 'chio.runtime.sandbox-attestation.v1'
  attestation_id?: string
  tool_server_id?: string
  tool_instance_id?: string
  tool_manifest_digest?: string
  sandbox_profile_digest?: string
  egress_policy_digest?: string
  started_at?: string
  expires_at?: string
  attester?: string
  signature?: string
}

export interface ProofRoomRuntimeToolServerAck {
  schema: 'chio.runtime.tool-server-ack.v1'
  ack_id?: string
  lease_id?: string
  tool_server_id?: string
  tool_instance_id?: string
  sandbox_attestation_ref?: string
  nonce?: string
  terminal_status?: string
  issued_at?: string
  signature?: string
}

export interface ProofRoomRuntimeEvidence {
  executionLease?: ProofRoomRuntimeExecutionLease
  revocationFreshnessProof?: ProofRoomRuntimeRevocationFreshnessProof
  sandboxAttestation?: ProofRoomRuntimeSandboxAttestation
  toolServerAck?: ProofRoomRuntimeToolServerAck
}

export interface ProofRoomCryptoKeyState {
  schema: 'chio.trust.key-state.v1'
  key_ref?: string
  status?: string
  epoch?: number
  valid_from?: number
  valid_until?: number
}

export interface ProofRoomCryptoRevocationSnapshot {
  schema: 'chio.trust.revocation-snapshot.v1'
  snapshot_ref?: string
  status?: string
  issued_at?: number
  expires_at?: number
}

export interface ProofRoomCryptoVerificationContext {
  schema: 'chio.crypto.verification-context.v1'
  context_id?: string
  artifact_ref?: string
  proof_mechanism?: string
  issuer?: string
  issuer_key_ref?: string
  key_state?: ProofRoomCryptoKeyState
  algorithm?: string
  suite?: string
  hash_algorithm?: string
  canonicalization?: string
  signature_ref?: string
  verification_time?: number
  revocation_snapshot?: ProofRoomCryptoRevocationSnapshot
  audience?: string
  nonce_hex?: string
  nonce_replay_status?: string
  holder_binding_ref?: string
  holder_binding_status?: string
  transparency_state?: string
  presentation_created_at?: number
}

export interface ProofRoomCryptoVerifierPrivacyProfile {
  schema: 'chio.disclosure.verifier-privacy-profile.v1'
  profile_id?: string
  allowed_proof_mechanisms?: string[]
  required_holder_binding?: string
  allowed_issuer_keys?: string[]
  required_key_epoch_min?: number
  forbidden_key_epochs?: number[]
  required_status_freshness_seconds?: number
  required_audience?: string
  nonce_policy?: string
  allowed_algorithms?: string[]
  forbidden_algorithms?: string[]
  required_transparency_state?: string
  max_presentation_age_seconds?: number
}

export interface ProofRoomCryptoTransparencyInclusionProof {
  schema: 'chio.transparency.inclusion-proof.v1'
  proof_id?: string
  log_id?: string
  artifact_ref?: string
  root_hash?: string
  leaf_hash?: string
  tree_size?: number
  leaf_index?: number
  checkpoint?: string
  inclusion_path?: string[]
  verified_at?: number
}

export interface ProofRoomCryptoContextReport {
  schema: 'chio.disclosure.crypto-context-report.v1'
  id?: string
  context_id?: string
  artifact_ref?: string
  verdict?: string
  evidence_class?: string
  cryptographic_proof_verified?: boolean
  verified_claims?: string[]
  rejected_checks?: string[]
  disclosed_fields?: string[]
}

export interface ProofRoomCryptoContextEvidence {
  verificationContext?: ProofRoomCryptoVerificationContext
  keyState?: ProofRoomCryptoKeyState
  revocationSnapshot?: ProofRoomCryptoRevocationSnapshot
  privacyProfile?: ProofRoomCryptoVerifierPrivacyProfile
  transparencyProof?: ProofRoomCryptoTransparencyInclusionProof
  cryptoContextReport?: ProofRoomCryptoContextReport
}

export interface ProofRoomSettlementAmount {
  units?: number
  currency?: string
}

export interface ProofRoomSettlementObservedExecution {
  externalReferenceId?: string
  observedAt?: number
}

export interface ProofRoomSettlementOracleEvidence {
  source?: string
  base?: string
  quote?: string
}

export interface ProofRoomSettlementReceipt {
  execution_receipt_id?: string
  lifecycle_state?: string
  settlement_reference?: string
  settled_amount?: ProofRoomSettlementAmount
  observed_execution?: ProofRoomSettlementObservedExecution
  oracle_evidence?: ProofRoomSettlementOracleEvidence
}

export interface ProofRoomSettlementEscrowSnapshot {
  escrow_id?: string
  escrow_contract?: string
  beneficiary_address?: string
  locked_amount?: ProofRoomSettlementAmount
  released_amount?: ProofRoomSettlementAmount
}

export interface ProofRoomSettlementBondSnapshot {
  bond_vault_contract?: string
  posted_amount?: ProofRoomSettlementAmount
  minimum_required_amount?: ProofRoomSettlementAmount
}

export interface ProofRoomSettlementChainSnapshot {
  observed_block_number?: number
  latest_block_number?: number
  registry_root?: string
  escrow?: ProofRoomSettlementEscrowSnapshot
  bond?: ProofRoomSettlementBondSnapshot
}

export interface ProofRoomSettlementDisputeSnapshot {
  dispute_id?: string
  posture?: string
  open_dispute_count?: number
}

export interface ProofRoomPublicSettlementProofBundle {
  schema: 'chio.web3-settlement-proof-bundle.v1'
  bundle_id?: string
  transaction_passport_id?: string
  commerce_order_id?: string
  chain_id?: string
  required_confirmations?: number
  observed_confirmations?: number
  dispute_posture?: string
  settlement_receipt?: ProofRoomSettlementReceipt
  chain_snapshot?: ProofRoomSettlementChainSnapshot
  dispute_snapshot?: ProofRoomSettlementDisputeSnapshot
}

export interface ProofRoomPublicSettlementVerifierReport {
  schema: 'chio.public-settlement-verifier-report.v1'
  id?: string
  verdict?: string
  bundle_id?: string
  transaction_passport_id?: string
  commerce_order_id?: string
  recomputed_settlement_state?: string
  chain_context?: {
    chain_id?: string
    settlement_path?: string
    settlement_reference?: string
    observed_block_number?: number
    registry_root?: string
    escrow_id?: string
    bond_vault_contract?: string
    posted_bond_amount?: ProofRoomSettlementAmount
    minimum_bond_amount?: ProofRoomSettlementAmount
    block_hash?: string
    anchor_tx_hash?: string
    settlement_tx_hash?: string
    beneficiary_address?: string
    beneficiary_chio_identity?: string
  }
  public_witness?: {
    witness_id?: string
    mode?: string
    body_hash?: string
    observed_at?: number
  }
  finality_decision?: {
    status?: string
    required_confirmations?: number
    observed_confirmations?: number
  }
  dispute_context?: {
    dispute_id?: string
    posture?: string
    observed_at?: number
    challenge_window_secs?: number
    window_closed_at?: number
    open_dispute_count?: number
  }
  dispute_posture?: string
  trust_market_context?: {
    collateral_position_ref?: string
    guarantee_decision_ref?: string
    sla_remedy_ref?: string
    slash_authority_ref?: string
  }
  verified_claims?: string[]
}

export interface ProofRoomAgentWebEnvelope {
  schema: 'chio.agent-web-proof-envelope.v1'
  envelope_id?: string
  transaction_passport_ref?: string
  source_protocol?: string
  source_protocol_version?: string
  external_subject?: string
  external_subject_path?: string
  external_subject_digest?: string
  external_subject_signature_ref?: string
  projection_manifest_ref?: string
  chio_claim_refs?: string[]
  receipt_refs?: string[]
  limitations?: string[]
}

export interface ProofRoomAgentWebProjectionManifest {
  schema: 'chio.agent-web.external-projection-manifest.v1'
  projection_id?: string
  source_protocol?: string
  source_version?: string
  digest_algorithm?: string
  signature_algorithm?: string
  requires_external_signature?: boolean
  unsupported_claims?: string[]
  copy_limitations?: string[]
}

export interface ProofRoomAgentWebProjection {
  envelope: ProofRoomAgentWebEnvelope
  projectionManifest?: ProofRoomAgentWebProjectionManifest
}

export interface ProofRoomStaticBundle {
  manifest: ProofRoomBundleManifest
  loadReport: ProofRoomLoadReport
  verifierReport: ProofRoomCanonicalVerifierReport
  commerceEvidence?: ProofRoomCommerceEvidence
  disclosureEvidence?: ProofRoomDisclosureEvidence
  swarmEvidence?: ProofRoomSwarmEvidence
  workflowPreflightEvidence?: ProofRoomWorkflowPreflightEvidence
  enterpriseEvidence?: ProofRoomEnterpriseEvidence
  trustMarketEvidence?: ProofRoomTrustMarketEvidence
  runtimeEvidence?: ProofRoomRuntimeEvidence
  cryptoContextEvidence?: ProofRoomCryptoContextEvidence
  publicSettlementProof?: ProofRoomPublicSettlementProofBundle
  publicSettlementVerifierReport?: ProofRoomPublicSettlementVerifierReport
  riskReport?: ProofRoomRiskComptrollerReport
  agentWebProjections?: ProofRoomAgentWebProjection[]
}

export type AnalyticsTimeBucket = 'hour' | 'day'

export interface ReceiptAnalyticsMetrics {
  totalReceipts: number
  allowCount: number
  denyCount: number
  cancelledCount: number
  incompleteCount: number
  totalCostCharged: number
  totalAttemptedCost: number
  reliabilityScore?: number
  complianceRate?: number
  budgetUtilizationRate?: number
}

export interface AgentAnalyticsRow {
  subjectKey: string
  metrics: ReceiptAnalyticsMetrics
}

export interface ToolAnalyticsRow {
  toolServer: string
  toolName: string
  metrics: ReceiptAnalyticsMetrics
}

export interface TimeAnalyticsRow {
  bucketStart: number
  bucketEnd: number
  metrics: ReceiptAnalyticsMetrics
}

export interface ReceiptAnalyticsResponse {
  summary: ReceiptAnalyticsMetrics
  byAgent: AgentAnalyticsRow[]
  byTool: ToolAnalyticsRow[]
  byTime: TimeAnalyticsRow[]
}

export interface CostAttributionSummary {
  matchingReceipts: number
  returnedReceipts: number
  totalCostCharged: number
  totalAttemptedCost: number
  maxDelegationDepth: number
  distinctRootSubjects: number
  distinctLeafSubjects: number
  lineageGapCount: number
  truncated: boolean
}

export interface RootCostAttributionRow {
  rootSubjectKey: string
  receiptCount: number
  totalCostCharged: number
  totalAttemptedCost: number
  distinctLeafSubjects: number
  maxDelegationDepth: number
}

export interface LeafCostAttributionRow {
  rootSubjectKey: string
  leafSubjectKey: string
  receiptCount: number
  totalCostCharged: number
  totalAttemptedCost: number
  maxDelegationDepth: number
}

export interface CostAttributionReceiptRow {
  seq: number
  receiptId: string
  timestamp: number
  capabilityId: string
  toolServer: string
  toolName: string
  decisionKind: string
  rootSubjectKey?: string
  leafSubjectKey?: string
  grantIndex?: number
  delegationDepth: number
  costCharged: number
  attemptedCost?: number
  currency: string
  budgetTotal?: number
  budgetRemaining?: number
  settlementStatus?: string
  paymentReference?: string
  lineageComplete: boolean
  chain: Array<{
    capabilityId: string
    subjectKey: string
    issuerKey: string
    delegationDepth: number
    parentCapabilityId?: string
  }>
}

export interface CostAttributionReport {
  summary: CostAttributionSummary
  byRoot: RootCostAttributionRow[]
  byLeaf: LeafCostAttributionRow[]
  receipts: CostAttributionReceiptRow[]
}

export interface BudgetUtilizationSummary {
  matchingGrants: number
  returnedGrants: number
  distinctCapabilities: number
  distinctSubjects: number
  totalInvocations: number
  totalCostCharged: number
  nearLimitCount: number
  exhaustedCount: number
  rowsMissingScope: number
  rowsMissingLineage: number
  truncated: boolean
}

export interface BudgetUtilizationRow {
  capabilityId: string
  grantIndex: number
  subjectKey?: string
  toolServer?: string
  toolName?: string
  invocationCount: number
  maxInvocations?: number
  totalCostCharged: number
  currency?: string
  maxTotalCostUnits?: number
  remainingCostUnits?: number
  invocationUtilizationRate?: number
  costUtilizationRate?: number
  nearLimit: boolean
  exhausted: boolean
  updatedAt: number
  scopeResolved: boolean
  scopeResolutionError?: string
}

export interface BudgetUtilizationReport {
  summary: BudgetUtilizationSummary
  rows: BudgetUtilizationRow[]
}

export type EvidenceChildReceiptScope =
  | 'full_query_window'
  | 'time_window_context_only'
  | 'omitted_no_join_path'

export interface ComplianceReport {
  matchingReceipts: number
  evidenceReadyReceipts: number
  uncheckpointedReceipts: number
  checkpointCoverageRate?: number
  lineageCoveredReceipts: number
  lineageGapReceipts: number
  lineageCoverageRate?: number
  pendingSettlementReceipts: number
  failedSettlementReceipts: number
  directEvidenceExportSupported: boolean
  childReceiptScope: EvidenceChildReceiptScope
  proofsComplete: boolean
  exportQuery: {
    capabilityId?: string
    agentSubject?: string
    since?: number
    until?: number
  }
  exportScopeNote?: string
}

export interface OperatorReport {
  generatedAt: number
  filters: {
    capabilityId?: string
    agentSubject?: string
    toolServer?: string
    toolName?: string
    since?: number
    until?: number
    groupLimit?: number
    timeBucket?: AnalyticsTimeBucket
    attributionLimit?: number
    budgetLimit?: number
  }
  activity: ReceiptAnalyticsResponse
  costAttribution: CostAttributionReport
  budgetUtilization: BudgetUtilizationReport
  compliance: ComplianceReport
  sharedEvidence: SharedEvidenceReferenceReport
}

export interface RelayDirectorySummary {
  activeVersion?: number | null
  activeBundleSha256?: string | null
  directorySha256?: string | null
  issuer?: string | null
  expiresAtUnixMs?: number | null
  removedPeerCount: number
  removedPeerIds: string[]
  rejectedCandidateCount: number
  lastRejectionCode?: string | null
  profile: string
}

export interface RelayQueueSummary {
  pending: number
  retry: number
  leased: number
  delivered: number
  deadLetter: number
  oldestPendingAgeMs?: number | null
  staleLeaseCount: number
  inboxCount: number
  cursorCount: number
  catchupEventCount: number
}

export interface RelayFailureSummary {
  code: string
  count: number
}

export interface RelayOperatorRecommendation {
  code: string
  severity: string
}

export interface RelayObservabilityReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  directory: RelayDirectorySummary
  queue: RelayQueueSummary
  recentFailures: RelayFailureSummary[]
  recommendations: RelayOperatorRecommendation[]
}

export interface RelayAlert {
  code: string
  state: 'firing' | 'suppressed' | 'resolved'
  severity: 'info' | 'warning' | 'critical'
  notificationRoute: string
  opsgenie: string
  dedupeKey: string
  runbook: string
  firstSeenUnixMs: number
  lastSeenUnixMs: number
  windowMs: number
  suppressedUntilUnixMs?: number | null
  sourceReportSha256: string
  eventEvidenceSha256: string[]
  recommendationCodes: string[]
  labels: Record<string, string>
}

export interface RelayAlertCheck {
  code: string
  accepted: boolean
  detail: string
}

export interface RelayAlertReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  sourceReportSha256: string
  alerts: RelayAlert[]
  checks: RelayAlertCheck[]
}

export interface RelayTrendPoint {
  code: string
  count: number
  firstSeenUnixMs: number
  lastSeenUnixMs: number
  severity: 'info' | 'warning' | 'critical'
}

export interface RelayTrendReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  sinceUnixMs: number
  untilUnixMs: number
  sourceReportCount: number
  eventReportCount: number
  points: RelayTrendPoint[]
}

export interface RelayAlertHandoffRouteReadiness {
  receiverId: string
  kind: 'alertmanager' | 'pagerduty' | 'opsgenie' | 'slack' | 'email' | 'webhook'
  targetRef: string
  notificationRoute: string
  opsgenie: string
  highestSeverity: 'info' | 'warning' | 'critical'
  alertCodes: string[]
  escalationRef: string
  ready: boolean
}

export interface RelayAlertHandoffReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  sourceAlertReportSha256: string
  sourceTrendReportSha256: string
  firingAlertCount: number
  suppressedAlertCount: number
  criticalFiringCount: number
  routes: RelayAlertHandoffRouteReadiness[]
  checks: RelayAlertCheck[]
}

export type RelayAlertDeliveryStatus =
  | 'delivered'
  | 'accepted'
  | 'failed'
  | 'delayed'
  | 'duplicate'
  | 'unknown'
  | 'operator_acknowledged'

export interface RelayAlertDeliveryResult {
  resultId: string
  receiverId: string
  kind: 'alertmanager' | 'pagerduty' | 'opsgenie' | 'slack' | 'email' | 'webhook'
  targetRef: string
  notificationRoute: string
  opsgenie: string
  alertCode: string
  dedupeKey: string
  severity: 'info' | 'warning' | 'critical'
  runbook: string
  status: RelayAlertDeliveryStatus
  observedAtUnixMs: number
  downstreamEvidenceSha256: string
}

export interface RelayAlertDeliveryReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  sourceHandoffReportSha256: string
  sourceAlertReportSha256: string
  sourceTrendReportSha256: string
  criticalFiringCount: number
  deliveredCount: number
  delayedCount: number
  failedCount: number
  unknownCount: number
  results: RelayAlertDeliveryResult[]
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssurancePackage {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  sourceAlertReportSha256: string
  sourceTrendReportSha256: string
  sourceHandoffReportSha256: string
  sourceNormalizationReportSha256: string
  sourceDeliveryReportSha256: string
  sourceAcknowledgementReportSha256: string
  sourceDriftReportSha256: string
  sourceReviewPacketSha256: string
  firingAlertCount: number
  criticalFiringAlertCount: number
  normalizedCount: number
  readyRouteCount: number
  deliveryAttentionCount: number
  acknowledgementPendingCount: number
  driftCount: number
  operatorActionCodes: string[]
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceExportReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  bundleId: string
  manifestSha256: string
  sourcePackageSha256: string
  artifactCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceReplayReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  bundleId: string
  sourcePackageSha256: string
  replayedPackageSha256: string
  mismatchCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceRetentionReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  retainedCount: number
  expiringSoonCount: number
  eligibleForDeleteCount: number
  blockedCount: number
  missingCount: number
  quarantineCount: number
  entries: Array<{
    bundleId: string
    artifactRole: string
    path: string
    state: string
    retainUntilUnixMs: number | null
    detail: string
  }>
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceArchiveReview {
  bundleId: string
  bundlePath: string
  manifestSha256: string | null
  sourcePackageSha256: string | null
  artifactCount: number
  state: 'archive_ready' | 'archive_blocked' | 'quarantine'
  code: string
  detail: string
  trustedExporterVerified: boolean
  replayMatched: boolean
  recoveryDrillAccepted: boolean
  routeReviewPresent: boolean
  retainedCount: number
  expiringSoonCount: number
  eligibleForDeleteCount: number
  legalHoldCount: number
  missingCount: number
  quarantineCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceArchiveReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  bundleCount: number
  archiveReadyCount: number
  archiveBlockedCount: number
  quarantineCount: number
  legalHoldCount: number
  eligibleForDeleteCount: number
  reviews: RelayAlertAssuranceArchiveReview[]
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceCloseoutReview {
  bundleId: string
  bundlePath: string
  manifestSha256: string | null
  artifactCount: number
  state: 'closeout_ready' | 'closeout_blocked' | 'quarantine'
  code: string
  detail: string
  verifiedBundle: boolean
  replayMatched: boolean
  retentionSafe: boolean
  recoveryDrillAccepted: boolean
  routeReviewPresent: boolean
  legalHoldCount: number
  eligibleForDeleteCount: number
  missingCount: number
  quarantineCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceCloseoutReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  bundleCount: number
  closeoutReadyCount: number
  closeoutBlockedCount: number
  quarantineCount: number
  legalHoldCount: number
  eligibleForDeleteCount: number
  reviews: RelayAlertAssuranceCloseoutReview[]
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceArchivePackageReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  packageId: string
  packageGeneration: number
  previousPackageManifestSha256?: string | null
  packageManifestSha256: string
  sourceArchiveReportSha256: string
  sourceCloseoutReportSha256: string
  packageMemberCount: number
  packageTotalByteCount: number
  bundleCount: number
  trustedPackagerVerified: boolean
  nestedExporterVerified: boolean
  sourceReportsMatched: boolean
  closeoutReadyVerified: boolean
  totalByteCountMatched: boolean
  extractable: boolean
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceArchiveExtractionReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  packageId: string
  packageManifestSha256: string
  plannedMemberCount: number
  extractedMemberCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssurancePhysicalArchiveDrillReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  evidenceId: string
  packageId: string
  packageReportSha256: string
  sampledMemberCount: number
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceRetentionHandoffReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  evidenceId: string
  packageId: string
  packageReportSha256: string
  targetSystemAlias: string
  readyForOperatorHandoff: boolean
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceExternalRetentionPackageReview {
  packageId: string
  packageGeneration: number
  packageManifestSha256: string
  packageReportSha256: string
  targetSystemAlias?: string | null
  sampleCoverageBasisPoints: number
  restoreStatus: string
  physicalReadbackStatus: string
  retentionHandoffStatus: string
  accepted: boolean
  code: string
}

export interface RelayAlertAssuranceExternalRetentionReviewReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  sinceUnixMs: number
  untilUnixMs: number
  packageCount: number
  readyCount: number
  latestPackageGeneration: number
  quarantineCount: number
  driftCount: number
  insufficientSampleCount: number
  reviews: RelayAlertAssuranceExternalRetentionPackageReview[]
  recommendations: RelayOperatorRecommendation[]
  checks: RelayAlertCheck[]
}

export interface RelayAlertAssuranceArchiveRestorePackageReview {
  packageId: string
  packageGeneration: number
  packageManifestSha256: string
  previousPackageManifestSha256?: string | null
  accepted: boolean
  code: string
}

export interface RelayAlertAssuranceArchiveRestoreDrillReport {
  schema: string
  accepted: boolean
  code: string
  localKernelId: string
  generatedAtUnixMs: number
  packageCount: number
  verifiedGenerationCount: number
  latestPackageGeneration: number
  quarantineCount: number
  blockedCount: number
  packages: RelayAlertAssuranceArchiveRestorePackageReview[]
  checks: RelayAlertCheck[]
}

export interface PassportVerification {
  subject: string
  issuer?: string | null
  issuers: string[]
  issuerCount: number
  credentialCount: number
  merkleRootCount: number
  enterpriseIdentityProvenance?: EnterpriseIdentityProvenance[]
  verifiedAt: number
  validUntil: string
}

export interface EnterpriseIdentityProvenance {
  providerId: string
  providerRecordId?: string
  providerKind: string
  federationMethod: 'jwt' | 'introspection' | 'scim' | 'saml'
  principal: string
  subjectKey: string
  clientId?: string
  objectId?: string
  tenantId?: string
  organizationId?: string
  groups?: string[]
  roles?: string[]
  sourceSubject?: string
  attributeSources?: Record<string, string>
  trustMaterialRef?: string
}

export interface PassportPolicyEvaluation {
  accepted: boolean
  matchedCredentialIndexes: number[]
  matchedIssuers?: string[]
}

export interface SharedEvidenceShareSummary {
  shareId: string
  manifestHash: string
  importedAt: number
  exportedAt: number
  issuer: string
  partner: string
  signerPublicKey: string
  requireProofs: boolean
  toolReceipts: number
  capabilityLineage: number
}

export interface SharedEvidenceReferenceSummary {
  matchingShares: number
  matchingReferences: number
  matchingLocalReceipts: number
  remoteToolReceipts: number
  remoteLineageRecords: number
  distinctRemoteSubjects: number
  proofRequiredShares: number
  truncated: boolean
}

export interface SharedEvidenceReferenceRow {
  share: SharedEvidenceShareSummary
  capabilityId: string
  subjectKey: string
  issuerKey: string
  delegationDepth: number
  parentCapabilityId?: string | null
  localAnchorCapabilityId?: string | null
  matchedLocalReceipts: number
  allowCount: number
  denyCount: number
  cancelledCount: number
  incompleteCount: number
  firstSeen?: number
  lastSeen?: number
}

export interface SharedEvidenceReferenceReport {
  summary: SharedEvidenceReferenceSummary
  references: SharedEvidenceReferenceRow[]
}

export interface LocalReputationInspectionSummary {
  subjectKey: string
  effectiveScore: number
  probationary: boolean
  scoringSource: string
  resolvedTier?: {
    name: string
  } | null
}

export interface ReputationMetricComparison {
  portable?: number
  local?: number
  localMinusPortable?: number
}

export interface PortableCredentialDrift {
  index: number
  issuer: string
  issuanceDate: string
  expirationDate: string
  attestationUntil: number
  receiptCount: number
  lineageRecords: number
  policyAccepted?: boolean
  metrics: {
    compositeScore: ReputationMetricComparison
    reliability: ReputationMetricComparison
    delegationHygiene: ReputationMetricComparison
    resourceStewardship: ReputationMetricComparison
  }
}

export interface PortableReputationComparison {
  subjectKey: string
  passportSubject: string
  subjectMatches: boolean
  comparedAt: number
  local: LocalReputationInspectionSummary
  passportVerification: PassportVerification
  passportEvaluation?: PassportPolicyEvaluation | null
  credentialDrifts: PortableCredentialDrift[]
  sharedEvidence: SharedEvidenceReferenceReport
}

export interface CapabilitySnapshot {
  capability_id: string
  subject_key: string
  issuer_key: string
  issued_at: number
  expires_at: number
  grants_json: string
  delegation_depth: number
  parent_capability_id: string | null
}

export interface Filters {
  agentSubject?: string
  toolServer?: string
  toolName?: string
  outcome?: DecisionKind | ''
  since?: number
  until?: number
}

export interface ReceiptAnalyticsFilters {
  capabilityId?: string
  agentSubject?: string
  toolServer?: string
  toolName?: string
  since?: number
  until?: number
  groupLimit?: number
  timeBucket?: AnalyticsTimeBucket
}

/**
 * Extract a DecisionKind label from a raw receipt decision value.
 */
export function decisionKind(decision?: ReceiptDecision): ReceiptDecisionKind {
  return decision?.verdict ?? 'none'
}

/**
 * Format a minor-unit integer as a currency string for display purposes only.
 * Uses string arithmetic -- never converts to float for monetary calculations.
 */
export function formatMinorUnits(amount: number, currency: string): string {
  const major = Math.floor(amount / 100)
  const minor = amount % 100
  const minorStr = minor.toString().padStart(2, '0')
  const prefix = currency === 'USD' ? '$' : `${currency} `
  return `${prefix}${major}.${minorStr}`
}

export function receiptSubjectKey(receipt: Receipt): string | null {
  return receipt.metadata?.attribution?.subject_key ?? null
}
