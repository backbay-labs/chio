// Typed fetch wrappers for Chio receipt query, analytics, and lineage endpoints.
// All endpoints require Bearer auth. Token is read from URL ?token= param on
// first load and stored in sessionStorage for subsequent calls.

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
} from './types'

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
    // Remove the token from the URL bar and history so it is not leaked via
    // the Referer header, browser history, or shoulder-surfing.
    window.history.replaceState({}, document.title, window.location.pathname)
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
