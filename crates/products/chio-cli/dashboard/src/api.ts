// Typed fetch wrappers for Chio receipt query, analytics, lineage endpoints, and
// static Proof Room assets. Runtime API endpoints require Bearer auth. Static
// Proof Room assets are verifier outputs and are fetched without auth.

import type {
  CapabilitySnapshot,
  Filters,
  OperatorReport,
  PortableReputationComparison,
  Receipt,
  ReceiptAnalyticsFilters,
  ReceiptAnalyticsResponse,
  ReceiptQueryResponse,
  RelayAlertAssuranceArchiveReport,
  RelayAlertAssuranceArchiveExtractionReport,
  RelayAlertAssuranceArchivePackageReport,
  RelayAlertAssuranceCloseoutReport,
  RelayAlertAssuranceArchiveRestoreDrillReport,
  RelayAlertAssuranceExternalRetentionReviewReport,
  RelayAlertReport,
  RelayAlertDeliveryReport,
  RelayAlertAssuranceExportReport,
  RelayAlertHandoffReport,
  RelayAlertAssurancePackage,
  RelayAlertAssuranceReplayReport,
  RelayAlertAssuranceRetentionReport,
  RelayAlertAssurancePhysicalArchiveDrillReport,
  RelayAlertAssuranceRetentionHandoffReport,
  RelayObservabilityReport,
  RelayTrendReport,
  ProofRoomBundleManifest,
  ProofRoomCanonicalVerifierReport,
  ProofRoomAgentWebEnvelope,
  ProofRoomAgentWebProjection,
  ProofRoomAgentWebProjectionManifest,
  ProofRoomFixtureCatalog,
  ProofRoomFixtureCatalogNegativeCase,
  ProofRoomLoadReport,
  ProofRoomPublicSettlementProofBundle,
  ProofRoomPublicSettlementVerifierReport,
  ProofRoomRiskComptrollerReport,
  ProofRoomStaticBundle,
  ProofRoomWorkflowPreflightEvidence,
  ProofRoomWorkflowPreflightPlan,
  ProofRoomWorkflowPreflightReport,
} from './types'
import {
  COMMERCE_EVIDENCE_SPECS,
  CRYPTO_CONTEXT_EVIDENCE_SPECS,
  DISCLOSURE_EVIDENCE_SPECS,
  ENTERPRISE_EVIDENCE_SPECS,
  assertProofRoomBundleDsseSignature,
  assertProofRoomBundleRelativePath,
  assertProofRoomArtifactDigest,
  fetchProofRoomTrustedBundleSignerKeys,
  isUnsafeProofRoomPathSegment,
  manifestArtifactBySchemaOrHint,
  proofRoomArtifactReader,
  readProofRoomArtifact,
  readProofRoomArtifactEvidence,
  readProofRoomArtifacts,
  RUNTIME_EVIDENCE_SPECS,
  sha256Hex,
  SWARM_EVIDENCE_SPECS,
  TRUST_MARKET_EVIDENCE_SPECS,
  type ProofRoomArtifactReader,
  type ProofRoomArtifactEvidenceSpec,
  type ProofRoomArtifactSourceRef,
  type ProofRoomDsseSignature,
} from './proofRoomArtifactEvidence'

const TOKEN_KEY = 'chio_token'

/**
 * Read Bearer token from sessionStorage or URL query param.
 * Stores in sessionStorage for subsequent calls.
 * Returns empty string if neither source provides a token.
 */
export function getToken(): string {
  const stored = sessionStorage.getItem(TOKEN_KEY)
  if (stored) return stored

  const param = new URLSearchParams(window.location.search).get('token')
  if (param) {
    sessionStorage.setItem(TOKEN_KEY, param)
    // Remove only the token from the URL bar and history so it is not leaked via
    // the Referer header, browser history, or shoulder-surfing.
    const url = new URL(window.location.href)
    url.searchParams.delete('token')
    const search = url.searchParams.toString()
    window.history.replaceState(
      {},
      document.title,
      `${url.pathname}${search ? `?${search}` : ''}${url.hash}`,
    )
    return param
  }
  return ''
}

/**
 * Wraps fetch with Authorization header injection.
 */
async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch(path, { ...init, headers })
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`)
  }
  return res
}

/**
 * Build query string from a Filters object, omitting undefined/empty values.
 */
function buildQuery(params: Record<string, string | number | undefined | null>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null && v !== ''
  )
  if (entries.length === 0) return ''
  return '?' + entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&')
}

/**
 * Fetch a page of receipts using the filter and cursor parameters.
 */
export async function fetchReceipts(
  filters: Filters,
  cursor?: number | null,
  limit = 50,
): Promise<ReceiptQueryResponse> {
  const query = buildQuery({
    agentSubject: filters.agentSubject,
    toolServer: filters.toolServer,
    toolName: filters.toolName,
    outcome: filters.outcome || undefined,
    since: filters.since,
    until: filters.until,
    cursor: cursor ?? undefined,
    limit,
  })
  const res = await apiFetch(`/v1/receipts/query${query}`)
  return res.json() as Promise<ReceiptQueryResponse>
}

/**
 * Fetch a single capability snapshot by ID.
 */
export async function fetchLineage(capabilityId: string): Promise<CapabilitySnapshot> {
  const res = await apiFetch(`/v1/lineage/${encodeURIComponent(capabilityId)}`)
  return res.json() as Promise<CapabilitySnapshot>
}

/**
 * Fetch the full delegation chain (root-first) for a capability.
 */
export async function fetchDelegationChain(capabilityId: string): Promise<CapabilitySnapshot[]> {
  const res = await apiFetch(`/v1/lineage/${encodeURIComponent(capabilityId)}/chain`)
  return res.json() as Promise<CapabilitySnapshot[]>
}

/**
 * Fetch receipts for a specific agent subject key.
 */
export async function fetchAgentReceipts(
  subjectKey: string,
  cursor?: number | null,
  limit = 50,
): Promise<ReceiptQueryResponse> {
  const query = buildQuery({ cursor: cursor ?? undefined, limit })
  const encoded = encodeURIComponent(subjectKey)
  const res = await apiFetch(`/v1/agents/${encoded}/receipts${query}`)
  return res.json() as Promise<ReceiptQueryResponse>
}

/**
 * Fetch aggregate receipt analytics for the requested scope.
 */
export async function fetchReceiptAnalytics(
  filters: ReceiptAnalyticsFilters,
): Promise<ReceiptAnalyticsResponse> {
  const query = buildQuery({
    capabilityId: filters.capabilityId,
    agentSubject: filters.agentSubject,
    toolServer: filters.toolServer,
    toolName: filters.toolName,
    since: filters.since,
    until: filters.until,
    groupLimit: filters.groupLimit,
    timeBucket: filters.timeBucket,
  })
  const res = await apiFetch(`/v1/receipts/analytics${query}`)
  return res.json() as Promise<ReceiptAnalyticsResponse>
}

/**
 * Fetch a composed operator report for the current dashboard filters.
 */
export async function fetchOperatorReport(filters: Filters): Promise<OperatorReport> {
  const query = buildQuery({
    agentSubject: filters.agentSubject,
    toolServer: filters.toolServer,
    toolName: filters.toolName,
    since: filters.since,
    until: filters.until,
    groupLimit: 10,
    timeBucket: 'day',
    attributionLimit: 10,
    budgetLimit: 10,
  })
  const res = await apiFetch(`/v1/reports/operator${query}`)
  return res.json() as Promise<OperatorReport>
}

async function fetchStaticJson<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) {
    throw new Error(`Static asset request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<T>
}

async function fetchStaticText(path: string): Promise<{ contents: string; digestable: boolean }> {
  const res = await fetch(path)
  if (!res.ok) {
    throw new Error(`Static asset request failed: ${res.status} ${res.statusText}`)
  }
  if (typeof res.text === 'function') {
    return { contents: await res.text(), digestable: true }
  }
  return { contents: JSON.stringify(await res.json()), digestable: false }
}

function staticAssetPath(path: string, basePath = ''): string {
  assertProofRoomBundleRelativePath(path)
  const base = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath
  return base ? `${base}/${path}` : `/${path}`
}

function fixtureVerifierReportPath(path: string): string {
  const normalizedPath = path.startsWith('/') ? path.slice(1) : path
  if (
    !path.includes('\\')
    && normalizedPath.startsWith('proof-room-fixtures/')
    && !normalizedPath.split('/').some(isUnsafeProofRoomPathSegment)
  ) {
    return `/${normalizedPath}`
  }
  throw new Error(`unsafe Proof Room fixture verifier report path: ${path}`)
}

function assertProofRoomFixtureId(id: string, message: string): void {
  let decodedId: string
  try {
    decodedId = decodeURIComponent(id)
  } catch {
    throw new Error(message)
  }
  if (
    !id
    || id === '.'
    || id.includes('/')
    || id.includes('\\')
    || isUnsafeProofRoomPathSegment(id)
    || decodedId === '.'
    || decodedId.includes('/')
    || decodedId.includes('\\')
  ) {
    throw new Error(message)
  }
}

function assertProofRoomFixtureCatalogId(id: string): void {
  assertProofRoomFixtureId(id, 'Proof Room fixture catalog has unsafe fixture id')
}

function assertProofRoomFixtureCatalogPath(path: string, label: string): void {
  try {
    if (path.startsWith('/proof-room-fixtures/') || path.startsWith('proof-room-fixtures/')) {
      fixtureVerifierReportPath(path)
      return
    }
    assertProofRoomBundleRelativePath(path)
  } catch {
    throw new Error(`Proof Room fixture catalog has unsafe ${label}`)
  }
}

function assertProofRoomFixtureCatalogPaths(catalog: ProofRoomFixtureCatalog): void {
  for (const fixture of catalog.fixtures) {
    assertProofRoomFixtureCatalogId(fixture.fixture_id)
    assertProofRoomFixtureCatalogPath(fixture.manifest_path, 'manifest path')
    assertProofRoomFixtureCatalogPath(fixture.load_report_path, 'load report path')
    for (const negativeCase of fixture.negative_cases) {
      assertProofRoomFixtureCatalogPath(negativeCase.path, 'negative case path')
    }
  }
  for (const fixture of catalog.available_fixtures ?? []) {
    assertProofRoomFixtureCatalogId(fixture.id)
    assertProofRoomFixtureCatalogPath(fixture.path, 'fixture path')
    for (const negativeCase of fixture.negative_cases ?? []) {
      assertProofRoomFixtureCatalogPath(negativeCase.path, 'negative case path')
    }
    if (!fixture.verifier_report) {
      throw new Error('Proof Room fixture catalog available fixture is missing verifier report')
    }
    assertProofRoomFixtureCatalogPath(
      fixture.verifier_report.path,
      'verifier report path',
    )
  }
}

function normalizeProofRoomFixtureCatalogNegativeCases(
  negativeCases: ProofRoomFixtureCatalogNegativeCase[],
): ProofRoomFixtureCatalogNegativeCase[] {
  return negativeCases.map((negativeCase) => {
    assertProofRoomFixtureCatalogId(negativeCase.id)
    assertProofRoomFixtureCatalogPath(negativeCase.path, 'negative case path')
    if (negativeCase.path.startsWith('/proof-room-fixtures/') || negativeCase.path.startsWith('proof-room-fixtures/')) {
      return {
        ...negativeCase,
        path: negativeCase.path.startsWith('/') ? negativeCase.path.slice(1) : negativeCase.path,
      }
    }
    return {
      ...negativeCase,
      path: `proof-room-fixtures/${negativeCase.id}/${negativeCase.path}`,
    }
  })
}

function assertManifestAssetPath(path: string | undefined, label: string): void {
  if (path === undefined) {
    return
  }
  try {
    assertProofRoomBundleRelativePath(path)
  } catch {
    throw new Error(`${label} is unsafe`)
  }
}

function assertProofRoomManifestAssetPaths(manifest: ProofRoomBundleManifest): void {
  assertManifestAssetPath(manifest.verifier_report_ref.path, 'served verifier report path')
  assertManifestAssetPath(
    manifest.proof_room_verifier_report_ref?.path,
    'served load report path',
  )
  assertManifestAssetPath(
    manifest.transaction_passport_ref?.path,
    'served transaction passport path',
  )
  assertManifestAssetPath(manifest.evidence_graph_ref?.path, 'served evidence graph path')
  assertManifestAssetPath(manifest.signature?.signature_ref, 'served bundle signature path')

  for (const artifact of manifest.artifacts ?? []) {
    assertManifestAssetPath(artifact.path, 'served artifact path')
  }
  for (const claim of manifest.claims) {
    for (const artifactPath of claim.required_artifacts) {
      assertManifestAssetPath(artifactPath, 'served claim artifact path')
    }
    for (const sourcePath of claim.source_refs ?? []) {
      assertManifestAssetPath(sourcePath, 'served claim source path')
    }
  }
  for (const negativeCase of manifest.negative_cases) {
    assertManifestAssetPath(negativeCase.path, 'served negative case path')
  }
  for (const coverage of manifest.receipt_coverage ?? []) {
    assertManifestAssetPath(coverage.artifact_path, 'served receipt coverage path')
  }
  for (const artifact of manifest.advisory_artifacts ?? []) {
    assertManifestAssetPath(artifact.path, 'served advisory artifact path')
  }
  for (const artifact of manifest.excluded_artifacts ?? []) {
    assertManifestAssetPath(artifact.path, 'served excluded artifact path')
  }
}

const PROOF_ROOM_FIXTURE_VERIFIER_REPORT_SCHEMAS = new Set([
  'chio.transaction.verifier-report.v1',
  'chio.proof-room.fixture-error.v1',
  'chio.commerce.order-passport.v1',
  'chio.transaction.runtime-security-report.v1',
  'chio.disclosure.crypto-context-report.v1',
  'chio.disclosure.lineage-verifier-report.v1',
  'chio.swarm.authority-verifier-report.v1',
  'chio.public-settlement-verifier-report.v1',
  'chio.enterprise.export-verifier-report.v1',
  'chio.trust-market.context-verifier-report.v1',
  'chio.agent-web.interop-verifier-report.v1',
  'chio.workflow.preflight-report.v1',
])

interface ProofRoomTransactionPassport {
  schema: string
  id: string
  issued_at?: string
  evidence_graph_sha256: string
  evidence_graph_path: string
  verifier_policy_sha256: string
  verifier_policy_path: string
}

interface ProofRoomVerifierPolicy {
  required_claims?: unknown
}

interface ProofRoomEvidenceGraphNode {
  id?: string
  role?: string
  schema?: string
  path?: string
  sha256?: string
}

interface ProofRoomEvidenceGraph {
  schema?: string
  nodes?: ProofRoomEvidenceGraphNode[]
}

async function parseStaticJsonWithDigest<T>(
  path: string,
  expectedSha256: string,
  label: string,
): Promise<T> {
  const { contents, digestable } = await fetchStaticText(path)
  if (digestable) {
    await assertProofRoomArtifactDigest(contents, expectedSha256, label)
  }
  return JSON.parse(contents) as T
}

async function fetchStaticJsonWithDigest<T>(
  path: string,
): Promise<{ value: T; sha256: string }> {
  const { contents } = await fetchStaticText(path)
  return {
    value: JSON.parse(contents) as T,
    sha256: await sha256Hex(contents),
  }
}

function staticProofRoomArtifactReader(basePath: string): ProofRoomArtifactReader {
  return proofRoomArtifactReader((artifact: ProofRoomArtifactSourceRef) =>
    fetchStaticText(staticAssetPath(artifact.path, basePath)))
}

type ProofRoomArtifactSourceLabel = 'selected' | 'served'

async function readWorkflowPreflightEvidence(
  manifest: ProofRoomBundleManifest,
  verifierReport: ProofRoomCanonicalVerifierReport,
  sourceLabel: ProofRoomArtifactSourceLabel,
  readArtifact: ProofRoomArtifactReader,
): Promise<ProofRoomWorkflowPreflightEvidence | undefined> {
  const planArtifact = manifestArtifactBySchemaOrHint(
    manifest,
    'chio.workflow.preflight-plan.v1',
    'workflow-preflight-plan',
  )
  if (!planArtifact && verifierReport.schema !== 'chio.workflow.preflight-report.v1') {
    return undefined
  }

  const plan = planArtifact
    ? await readArtifact<ProofRoomWorkflowPreflightPlan>(
        planArtifact,
        `${sourceLabel} workflow preflight plan`,
      ).then((report) => {
        if (report.schema !== 'chio.workflow.preflight-plan.v1') {
          throw new Error(`${sourceLabel} workflow preflight plan has unsupported schema`)
        }
        return report
      })
    : undefined
  const report = verifierReport.schema === 'chio.workflow.preflight-report.v1'
    ? verifierReport as ProofRoomWorkflowPreflightReport
    : undefined

  return { plan, report }
}

async function readPublicSettlementProof(
  manifest: ProofRoomBundleManifest,
  sourceLabel: ProofRoomArtifactSourceLabel,
  readArtifact: ProofRoomArtifactReader,
): Promise<ProofRoomPublicSettlementProofBundle | undefined> {
  return readProofRoomArtifact<ProofRoomPublicSettlementProofBundle>(
    manifest,
    'chio.web3-settlement-proof-bundle.v1',
    'public-settlement-proof-bundle',
    'public settlement proof bundle',
    sourceLabel,
    readArtifact,
  )
}

function isPublicSettlementVerifierReport(
  value: unknown,
): value is ProofRoomPublicSettlementVerifierReport {
  return typeof value === 'object'
    && value !== null
    && (value as { schema?: unknown }).schema === 'chio.public-settlement-verifier-report.v1'
}

function readPublicSettlementVerifierReport(
  verifierReport: ProofRoomCanonicalVerifierReport,
): ProofRoomPublicSettlementVerifierReport | undefined {
  if (isPublicSettlementVerifierReport(verifierReport)) {
    return verifierReport
  }
  const familyReports = Array.isArray(verifierReport.family_reports)
    ? verifierReport.family_reports
    : []
  return familyReports.find(isPublicSettlementVerifierReport)
}

async function readAgentWebProjections(
  manifest: ProofRoomBundleManifest,
  sourceLabel: ProofRoomArtifactSourceLabel,
  readArtifact: ProofRoomArtifactReader,
): Promise<ProofRoomAgentWebProjection[]> {
  const artifacts = manifest.artifacts ?? []
  const envelopeArtifacts = artifacts.filter(
    (artifact) =>
      artifact.schema === 'chio.agent-web-proof-envelope.v1'
      || artifact.renderer_hint === 'agent-web-proof-envelope',
  )
  if (envelopeArtifacts.length === 0) {
    return []
  }

  const projectionManifests = await readProofRoomArtifacts<ProofRoomAgentWebProjectionManifest>(
    manifest,
    'chio.agent-web.external-projection-manifest.v1',
    'agent-web-projection-manifest',
    'Agent Web projection manifest',
    sourceLabel,
    readArtifact,
  )
  const preserveServedProjectionMatching = sourceLabel === 'served'
  const projectionById = new Map(
    projectionManifests
      .filter((report) => preserveServedProjectionMatching || typeof report.projection_id === 'string')
      .map((report) => [report.projection_id, report]),
  )

  const envelopes = await readProofRoomArtifacts<ProofRoomAgentWebEnvelope>(
    manifest,
    'chio.agent-web-proof-envelope.v1',
    'agent-web-proof-envelope',
    'Agent Web proof envelope',
    sourceLabel,
    readArtifact,
  )
  return envelopes.map((envelope) => ({
    envelope,
    projectionManifest: preserveServedProjectionMatching
      ? projectionById.get(envelope.projection_manifest_ref)
      : envelope.projection_manifest_ref
        ? projectionById.get(envelope.projection_manifest_ref)
        : undefined,
  }))
}

type ProofRoomBundleEvidence = Pick<
  ProofRoomStaticBundle,
  | 'commerceEvidence'
  | 'disclosureEvidence'
  | 'swarmEvidence'
  | 'workflowPreflightEvidence'
  | 'enterpriseEvidence'
  | 'trustMarketEvidence'
  | 'runtimeEvidence'
  | 'cryptoContextEvidence'
  | 'publicSettlementProof'
  | 'publicSettlementVerifierReport'
  | 'riskReport'
  | 'agentWebProjections'
>

type ProofRoomArtifactEvidenceKey =
  | 'commerceEvidence'
  | 'disclosureEvidence'
  | 'swarmEvidence'
  | 'enterpriseEvidence'
  | 'trustMarketEvidence'
  | 'runtimeEvidence'
  | 'cryptoContextEvidence'

type ProofRoomArtifactEvidenceReader = {
  key: ProofRoomArtifactEvidenceKey
  specs: readonly ProofRoomArtifactEvidenceSpec<Record<string, unknown>>[]
}

const PROOF_ROOM_ARTIFACT_EVIDENCE_READERS: readonly ProofRoomArtifactEvidenceReader[] = [
  { key: 'commerceEvidence', specs: COMMERCE_EVIDENCE_SPECS },
  { key: 'disclosureEvidence', specs: DISCLOSURE_EVIDENCE_SPECS },
  { key: 'swarmEvidence', specs: SWARM_EVIDENCE_SPECS },
  { key: 'enterpriseEvidence', specs: ENTERPRISE_EVIDENCE_SPECS },
  { key: 'trustMarketEvidence', specs: TRUST_MARKET_EVIDENCE_SPECS },
  { key: 'runtimeEvidence', specs: RUNTIME_EVIDENCE_SPECS },
  { key: 'cryptoContextEvidence', specs: CRYPTO_CONTEXT_EVIDENCE_SPECS },
]

async function readProofRoomArtifactEvidenceGroups(
  manifest: ProofRoomBundleManifest,
  sourceLabel: ProofRoomArtifactSourceLabel,
  readArtifact: ProofRoomArtifactReader,
): Promise<Pick<ProofRoomBundleEvidence, ProofRoomArtifactEvidenceKey>> {
  const entries = await Promise.all(
    PROOF_ROOM_ARTIFACT_EVIDENCE_READERS.map(async ({ key, specs }) => [
      key,
      await readProofRoomArtifactEvidence<Record<string, unknown>>(
        manifest,
        specs,
        sourceLabel,
        readArtifact,
      ),
    ] as const),
  )
  return Object.fromEntries(entries) as Pick<ProofRoomBundleEvidence, ProofRoomArtifactEvidenceKey>
}

export async function readProofRoomBundleEvidence(
  manifest: ProofRoomBundleManifest,
  verifierReport: ProofRoomCanonicalVerifierReport,
  sourceLabel: ProofRoomArtifactSourceLabel,
  readArtifact: ProofRoomArtifactReader,
): Promise<ProofRoomBundleEvidence> {
  const [
    artifactEvidence,
    workflowPreflightEvidence,
    publicSettlementProof,
    riskReport,
    agentWebProjections,
  ] = await Promise.all([
    readProofRoomArtifactEvidenceGroups(manifest, sourceLabel, readArtifact),
    readWorkflowPreflightEvidence(manifest, verifierReport, sourceLabel, readArtifact),
    readPublicSettlementProof(manifest, sourceLabel, readArtifact),
    readProofRoomArtifact<ProofRoomRiskComptrollerReport>(
      manifest,
      'chio.risk.comptroller-report.v1',
      'risk-comptroller-report',
      'risk comptroller report',
      sourceLabel,
      readArtifact,
    ),
    readAgentWebProjections(manifest, sourceLabel, readArtifact),
  ])

  return {
    ...artifactEvidence,
    workflowPreflightEvidence,
    publicSettlementProof,
    publicSettlementVerifierReport: readPublicSettlementVerifierReport(verifierReport),
    riskReport,
    agentWebProjections,
  }
}

async function fetchProofRoomBundleFromManifest(
  basePath: string,
  loadReportLabel: string,
  verifierReportLabel: string,
): Promise<ProofRoomStaticBundle> {
  const manifestText = (await fetchStaticText(staticAssetPath('manifest.json', basePath))).contents
  const manifest = JSON.parse(manifestText) as ProofRoomBundleManifest
  assertProofRoomManifestAssetPaths(manifest)
  await assertServedProofRoomBundleSignature(manifest, manifestText, basePath)
  const loadReportPath =
    manifest.proof_room_verifier_report_ref?.path ?? 'ui/proof-room-static/load-report.json'
  const loadReportRequest =
    manifest.proof_room_verifier_report_ref?.sha256
      ? parseStaticJsonWithDigest<ProofRoomLoadReport>(
          staticAssetPath(loadReportPath, basePath),
          manifest.proof_room_verifier_report_ref.sha256,
          loadReportLabel,
        )
      : fetchStaticJson<ProofRoomLoadReport>(staticAssetPath(loadReportPath, basePath))
  const [loadReport, verifierReport] = await Promise.all([
    loadReportRequest,
    parseStaticJsonWithDigest<ProofRoomCanonicalVerifierReport>(
      staticAssetPath(manifest.verifier_report_ref.path, basePath),
      manifest.verifier_report_ref.sha256,
      verifierReportLabel,
    ),
  ])
  return hydrateProofRoomBundle(manifest, loadReport, verifierReport, basePath)
}

async function assertServedProofRoomBundleSignature(
  manifest: ProofRoomBundleManifest,
  manifestText: string,
  basePath: string,
): Promise<void> {
  if (!manifest.signature) {
    throw new Error('served bundle signature missing')
  }
  if (manifest.signature.kind !== 'detached-dsse') {
    throw new Error('served bundle signature kind is unsupported')
  }
  if (!manifest.signature.signature_ref) {
    throw new Error('served bundle signature path is missing')
  }
  const signatureText = (await fetchStaticText(
    staticAssetPath(manifest.signature.signature_ref, basePath),
  )).contents
  const signature = JSON.parse(signatureText) as ProofRoomDsseSignature
  const trustedSignerKeys = await fetchProofRoomTrustedBundleSignerKeys('served bundle signature')
  await assertProofRoomBundleDsseSignature(
    signature,
    manifestText,
    'served bundle signature',
    trustedSignerKeys,
  )
}

export async function fetchProofRoomStaticBundle(): Promise<ProofRoomStaticBundle> {
  return fetchProofRoomBundleFromManifest('', 'served load report', 'served verifier report')
}

async function hydrateProofRoomBundle(
  manifest: ProofRoomBundleManifest,
  loadReport: ProofRoomLoadReport,
  verifierReport: ProofRoomCanonicalVerifierReport,
  basePath = '',
): Promise<ProofRoomStaticBundle> {
  assertProofRoomManifestAssetPaths(manifest)
  const evidence = await readProofRoomBundleEvidence(
    manifest,
    verifierReport,
    'served',
    staticProofRoomArtifactReader(basePath),
  )
  return {
    manifest,
    loadReport,
    verifierReport,
    ...evidence,
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === 'string')
    : []
}

function normalizeVerifierReportClaims(
  report: ProofRoomCanonicalVerifierReport,
): ProofRoomCanonicalVerifierReport {
  if (!report.verified_claims) {
    const camelCaseClaims = stringArray(report.verifiedClaims)
    if (camelCaseClaims.length > 0) {
      return { ...report, verified_claims: camelCaseClaims }
    }
  }
  return report
}

function evidenceGraphArtifacts(graph: ProofRoomEvidenceGraph) {
  return (graph.nodes ?? []).flatMap((node) => {
    if (!node.path || !node.sha256 || !node.schema) {
      return []
    }
    return [{
      path: node.path,
      sha256: node.sha256,
      schema: node.schema,
      renderer_hint: node.role,
    }]
  })
}

function fixtureRenderedVerdict(
  claimId: string,
  verifierReport: ProofRoomCanonicalVerifierReport,
): 'verified' | 'failed' {
  return (verifierReport.verified_claims ?? []).includes(claimId) ? 'verified' : 'failed'
}

function assertFixtureVerifierPolicyClaims(
  requiredClaims: string[],
  verifierReport: ProofRoomCanonicalVerifierReport,
): void {
  if (verifierReport.verdict !== 'verified' && verifierReport.verdict !== 'accepted') {
    return
  }
  const verifiedClaims = new Set(verifierReport.verified_claims ?? [])
  for (const claimId of requiredClaims) {
    if (!verifiedClaims.has(claimId)) {
      throw new Error(`fixture verifier report does not verify required claim: ${claimId}`)
    }
  }
}

export async function fetchProofRoomFixtureBundle(
  fixtureId: string,
  kind = 'transaction-passport',
  negativeCases: ProofRoomFixtureCatalogNegativeCase[] = [],
): Promise<ProofRoomStaticBundle> {
  assertProofRoomFixtureId(fixtureId, 'Proof Room fixture id is unsafe')
  const basePath = `/proof-room-fixtures/${encodeURIComponent(fixtureId)}`
  if (kind === 'proof-room') {
    return fetchProofRoomBundleFromManifest(
      `${basePath}/proof-room-bundle`,
      'fixture load report',
      'fixture verifier report',
    )
  }

  const passportPath = staticAssetPath('transaction-passport.json', basePath)
  const { value: passport, sha256: passportSha256 } =
    await fetchStaticJsonWithDigest<ProofRoomTransactionPassport>(passportPath)
  if (passport.schema !== 'chio.transaction-passport.v1') {
    throw new Error('fixture transaction passport has unsupported schema')
  }

  const [evidenceGraph, verifierPolicy, verifierReportFetch] = await Promise.all([
    parseStaticJsonWithDigest<ProofRoomEvidenceGraph>(
      staticAssetPath(passport.evidence_graph_path, basePath),
      passport.evidence_graph_sha256,
      'fixture evidence graph',
    ),
    parseStaticJsonWithDigest<ProofRoomVerifierPolicy>(
      staticAssetPath(passport.verifier_policy_path, basePath),
      passport.verifier_policy_sha256,
      'fixture verifier policy',
    ),
    fetchStaticJsonWithDigest<ProofRoomCanonicalVerifierReport>(
      staticAssetPath('verifier-report.json', basePath),
    ),
  ])
  if (!PROOF_ROOM_FIXTURE_VERIFIER_REPORT_SCHEMAS.has(verifierReportFetch.value.schema)) {
    throw new Error('fixture verifier report has unsupported schema')
  }
  const verifierReport = normalizeVerifierReportClaims(verifierReportFetch.value)
  const verifierReportSha256 = verifierReportFetch.sha256
  const requiredClaims = stringArray(verifierPolicy.required_claims)
  assertFixtureVerifierPolicyClaims(requiredClaims, verifierReport)
  const artifacts = evidenceGraphArtifacts(evidenceGraph)
  const normalizedNegativeCases = normalizeProofRoomFixtureCatalogNegativeCases(negativeCases)
  const rootArtifacts = [
    'transaction-passport.json',
    passport.evidence_graph_path,
    passport.verifier_policy_path,
    'verifier-report.json',
    ...artifacts.map((artifact) => artifact.path),
  ]
  const claims = requiredClaims.map((claimId) => ({
    claim_id: claimId,
    required_artifacts: Array.from(new Set(rootArtifacts)),
    result: fixtureRenderedVerdict(claimId, verifierReport),
    checker: 'fixture verifier report',
  }))
  const verifierReportRef = {
    path: 'verifier-report.json',
    sha256: verifierReportSha256,
    schema: verifierReport.schema,
  }
  const manifest: ProofRoomBundleManifest = {
    schema: 'chio.proof-room.bundle.v1',
    bundle_id: `proof-room-${fixtureId}`,
    fixture_id: fixtureId,
    verifier_report_ref: verifierReportRef,
    transaction_passport_ref: {
      path: 'transaction-passport.json',
      sha256: passportSha256,
      schema: passport.schema,
    },
    evidence_graph_ref: {
      path: passport.evidence_graph_path,
      sha256: passport.evidence_graph_sha256,
      schema: evidenceGraph.schema ?? 'chio.transaction.evidence-graph.v1',
    },
    artifacts,
    claims,
    negative_cases: normalizedNegativeCases,
  }
  const loadReport: ProofRoomLoadReport = {
    schema: 'chio.proof-room.verifier-report.v1',
    id: `proof-room-load-report-${fixtureId}`,
    verdict: verifierReport.verdict === 'accepted' || verifierReport.verdict === 'rejected'
      ? verifierReport.verdict
      : fixtureRenderedVerdict(requiredClaims[0] ?? '', verifierReport),
    bundle_id: manifest.bundle_id,
    fixture_id: fixtureId,
    source_verifier_report_ref: verifierReportRef,
    ui_verdict_source: 'verifier_report_ref',
    rendered_claims: claims.map((claim) => ({
      claim_id: claim.claim_id,
      source: verifierReportRef.path,
      verdict: claim.result,
    })),
  }

  return hydrateProofRoomBundle(manifest, loadReport, verifierReport, basePath)
}

export async function fetchProofRoomFixtureCatalog(): Promise<ProofRoomFixtureCatalog | null> {
  const res = await fetch('/proof-room-fixture-catalog.json')
  if (res.status === 404) {
    return null
  }
  if (!res.ok) {
    const statusText = res.statusText ? ` ${res.statusText}` : ''
    throw new Error(`Proof Room fixture catalog request failed: ${res.status}${statusText}`)
  }

  let catalog: ProofRoomFixtureCatalog
  try {
    catalog = await res.json() as ProofRoomFixtureCatalog
  } catch {
    throw new Error('Proof Room fixture catalog is not valid JSON')
  }
  if (catalog.schema !== 'chio.proof-room.fixture-catalog.v1') {
    throw new Error('Proof Room fixture catalog has unsupported schema')
  }
  assertProofRoomFixtureCatalogPaths(catalog)
  return catalog
}

export async function fetchProofRoomFixtureVerifierReport(
  path: string,
): Promise<ProofRoomCanonicalVerifierReport> {
  const res = await fetch(fixtureVerifierReportPath(path))
  let report: ProofRoomCanonicalVerifierReport
  try {
    report = await res.json() as ProofRoomCanonicalVerifierReport
  } catch (error: unknown) {
    if (!res.ok) {
      throw new Error(`Fixture verifier report request failed: ${res.status} ${res.statusText}`)
    }
    throw error
  }
  if (!PROOF_ROOM_FIXTURE_VERIFIER_REPORT_SCHEMAS.has(report.schema)) {
    throw new Error('fixture verifier report has unsupported schema')
  }
  if (!res.ok && report.schema !== 'chio.proof-room.fixture-error.v1') {
    throw new Error(`Fixture verifier report request failed: ${res.status} ${res.statusText}`)
  }
  return report
}

export async function fetchRelayObservabilityReport(): Promise<RelayObservabilityReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/observability', { headers })
  if (!res.ok) {
    throw new Error(`Relay observability request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayObservabilityReport>
}

export async function fetchRelayAlertReport(): Promise<RelayAlertReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alerts', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertReport>
}

export async function fetchRelayTrendReport(): Promise<RelayTrendReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/trends', { headers })
  if (!res.ok) {
    throw new Error(`Relay trend request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayTrendReport>
}

export async function fetchRelayAlertHandoffReport(): Promise<RelayAlertHandoffReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-handoff', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert handoff request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertHandoffReport>
}

export async function fetchRelayAlertDeliveryReport(): Promise<RelayAlertDeliveryReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-delivery', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert delivery request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertDeliveryReport>
}

export async function fetchRelayAlertAssurancePackage(): Promise<RelayAlertAssurancePackage> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssurancePackage>
}

export async function fetchRelayAlertAssuranceExportReport(): Promise<RelayAlertAssuranceExportReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/export', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance export request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceExportReport>
}

export async function fetchRelayAlertAssuranceReplayReport(): Promise<RelayAlertAssuranceReplayReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/replay', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance replay request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceReplayReport>
}

export async function fetchRelayAlertAssuranceRetentionReport(): Promise<RelayAlertAssuranceRetentionReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/retention', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance retention request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceRetentionReport>
}

export async function fetchRelayAlertAssuranceArchiveReport(): Promise<RelayAlertAssuranceArchiveReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/archive', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance archive request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceArchiveReport>
}

export async function fetchRelayAlertAssuranceCloseoutReport(): Promise<RelayAlertAssuranceCloseoutReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/closeout', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance closeout request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceCloseoutReport>
}

export async function fetchRelayAlertAssuranceArchivePackageReport(): Promise<RelayAlertAssuranceArchivePackageReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/archive-package', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance archive package request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceArchivePackageReport>
}

export async function fetchRelayAlertAssuranceArchiveExtractionReport(): Promise<RelayAlertAssuranceArchiveExtractionReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/archive-extraction', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance archive extraction request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceArchiveExtractionReport>
}

export async function fetchRelayAlertAssurancePhysicalArchiveDrillReport(): Promise<RelayAlertAssurancePhysicalArchiveDrillReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/physical-archive', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance physical archive request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssurancePhysicalArchiveDrillReport>
}

export async function fetchRelayAlertAssuranceRetentionHandoffReport(): Promise<RelayAlertAssuranceRetentionHandoffReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/retention-handoff', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance retention handoff request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceRetentionHandoffReport>
}

export async function fetchRelayAlertAssuranceArchiveRestoreDrillReport(): Promise<RelayAlertAssuranceArchiveRestoreDrillReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/archive-restore-drill', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance archive restore drill request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceArchiveRestoreDrillReport>
}

export async function fetchRelayAlertAssuranceExternalRetentionReviewReport(): Promise<RelayAlertAssuranceExternalRetentionReviewReport> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  const res = await fetch('/v1/chio/pheromone/alert-assurance/external-retention-review', { headers })
  if (!res.ok) {
    throw new Error(`Relay alert assurance external retention request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayAlertAssuranceExternalRetentionReviewReport>
}

/**
 * Compare a portable passport artifact against the live local reputation view for one subject.
 */
export async function fetchReputationComparison(
  subjectKey: string,
  passport: unknown,
): Promise<PortableReputationComparison> {
  const encoded = encodeURIComponent(subjectKey)
  const res = await apiFetch(`/v1/reputation/compare/${encoded}`, {
    method: 'POST',
    body: JSON.stringify({ passport }),
  })
  return res.json() as Promise<PortableReputationComparison>
}

/**
 * Fetch backend-side cost history for an agent.
 * Returns an array of { time: string (date label), cost: number (minor units) }.
 */
export async function fetchAgentCostSeries(
  subjectKey: string,
): Promise<{ time: string; cost: number }[]> {
  const analytics = await fetchReceiptAnalytics({
    agentSubject: subjectKey,
    groupLimit: 180,
    timeBucket: 'day',
  })

  return analytics.byTime.map((bucket) => ({
    time: new Date(bucket.bucketStart * 1000).toISOString().slice(0, 10),
    cost: bucket.metrics.totalCostCharged,
  }))
}

// Re-export Receipt type for convenience
export type {
  Receipt,
  ReceiptAnalyticsResponse,
  ReceiptQueryResponse,
  CapabilitySnapshot,
  OperatorReport,
  Filters,
  PortableReputationComparison,
}
