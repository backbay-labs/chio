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
  RelayObservabilityReport,
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
  const res = await fetch('/v1/chiodos/pheromone/observability', { headers })
  if (!res.ok) {
    throw new Error(`Relay observability request failed: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<RelayObservabilityReport>
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
