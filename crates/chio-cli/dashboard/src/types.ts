// Mirror of API response shapes from the Chio receipt query and lineage endpoints.

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
  | 'allow'
  | { verdict: 'allow' }
  | { deny: { reason: string; guard: string } }
  | { cancelled: Record<string, unknown> }
  | { incomplete: Record<string, unknown> }

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
  decision: ReceiptDecision
  metadata?: ReceiptMetadata
}

export interface ReceiptQueryResponse {
  totalCount: number
  nextCursor: number | null
  receipts: Receipt[]
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
export function decisionKind(decision: ReceiptDecision): DecisionKind {
  if (decision === 'allow') return 'allow'
  if (typeof decision === 'object' && 'verdict' in decision && decision.verdict === 'allow') {
    return 'allow'
  }
  if (typeof decision === 'object' && 'deny' in decision) return 'deny'
  if (typeof decision === 'object' && 'cancelled' in decision) return 'cancelled'
  return 'incomplete'
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
