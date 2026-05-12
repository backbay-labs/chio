import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  fetchAgentCostSeries,
  fetchOperatorReport,
  fetchRelayAlertDeliveryReport,
  fetchRelayAlertHandoffReport,
  fetchRelayAlertReport,
  fetchRelayObservabilityReport,
  fetchRelayTrendReport,
  fetchReputationComparison,
  fetchReceiptAnalytics,
  getToken,
} from './api'
import { decisionKind, receiptSubjectKey, type Receipt } from './types'

describe('dashboard api helpers', () => {
  beforeEach(() => {
    sessionStorage.clear()
    vi.restoreAllMocks()
    window.history.replaceState({}, '', '/')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('stores token from the URL and removes it from the visible location', () => {
    window.history.replaceState({}, '', '/?token=secret-token')

    expect(getToken()).toBe('secret-token')
    expect(sessionStorage.getItem('chio_token')).toBe('secret-token')
    expect(window.location.pathname).toBe('/')
    expect(window.location.search).toBe('')
  })

  it('calls the backend analytics endpoint with auth headers', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        summary: {
          totalReceipts: 1,
          allowCount: 1,
          denyCount: 0,
          cancelledCount: 0,
          incompleteCount: 0,
          totalCostCharged: 250,
          totalAttemptedCost: 250,
        },
        byAgent: [],
        byTool: [],
        byTime: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchReceiptAnalytics({
      agentSubject: 'agent-a',
      groupLimit: 10,
      timeBucket: 'day',
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/receipts/analytics?agentSubject=agent-a&groupLimit=10&timeBucket=day',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('maps backend analytics buckets into sparkline points', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          summary: {
            totalReceipts: 2,
            allowCount: 2,
            denyCount: 0,
            cancelledCount: 0,
            incompleteCount: 0,
            totalCostCharged: 750,
            totalAttemptedCost: 750,
          },
          byAgent: [],
          byTool: [],
          byTime: [
            {
              bucketStart: 1_728_864_000,
              bucketEnd: 1_728_950_400,
              metrics: {
                totalReceipts: 1,
                allowCount: 1,
                denyCount: 0,
                cancelledCount: 0,
                incompleteCount: 0,
                totalCostCharged: 500,
                totalAttemptedCost: 500,
              },
            },
            {
              bucketStart: 1_728_950_400,
              bucketEnd: 1_729_036_800,
              metrics: {
                totalReceipts: 1,
                allowCount: 1,
                denyCount: 0,
                cancelledCount: 0,
                incompleteCount: 0,
                totalCostCharged: 250,
                totalAttemptedCost: 250,
              },
            },
          ],
        }),
      }),
    )

    await expect(fetchAgentCostSeries('agent-a')).resolves.toEqual([
      { time: '2024-10-14', cost: 500 },
      { time: '2024-10-15', cost: 250 },
    ])
  })

  it('calls the backend operator report endpoint with dashboard defaults', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        generatedAt: 1_700_000_000,
        filters: {},
        activity: {
          summary: {
            totalReceipts: 0,
            allowCount: 0,
            denyCount: 0,
            cancelledCount: 0,
            incompleteCount: 0,
            totalCostCharged: 0,
            totalAttemptedCost: 0,
          },
          byAgent: [],
          byTool: [],
          byTime: [],
        },
        costAttribution: {
          summary: {
            matchingReceipts: 0,
            returnedReceipts: 0,
            totalCostCharged: 0,
            totalAttemptedCost: 0,
            maxDelegationDepth: 0,
            distinctRootSubjects: 0,
            distinctLeafSubjects: 0,
            lineageGapCount: 0,
            truncated: false,
          },
          byRoot: [],
          byLeaf: [],
          receipts: [],
        },
        budgetUtilization: {
          summary: {
            matchingGrants: 0,
            returnedGrants: 0,
            distinctCapabilities: 0,
            distinctSubjects: 0,
            totalInvocations: 0,
            totalCostCharged: 0,
            nearLimitCount: 0,
            exhaustedCount: 0,
            rowsMissingScope: 0,
            rowsMissingLineage: 0,
            truncated: false,
          },
          rows: [],
        },
        compliance: {
          matchingReceipts: 0,
          evidenceReadyReceipts: 0,
          uncheckpointedReceipts: 0,
          lineageCoveredReceipts: 0,
          lineageGapReceipts: 0,
          pendingSettlementReceipts: 0,
          failedSettlementReceipts: 0,
          directEvidenceExportSupported: true,
          childReceiptScope: 'full_query_window',
          proofsComplete: true,
          exportQuery: {},
        },
        sharedEvidence: {
          summary: {
            matchingShares: 0,
            matchingReferences: 0,
            matchingLocalReceipts: 0,
            remoteToolReceipts: 0,
            remoteLineageRecords: 0,
            distinctRemoteSubjects: 0,
            proofRequiredShares: 0,
            truncated: false,
          },
          references: [],
        },
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchOperatorReport({
      agentSubject: 'agent-a',
      toolServer: 'shell',
      toolName: 'bash',
      since: 123,
      until: 456,
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/reports/operator?agentSubject=agent-a&toolServer=shell&toolName=bash&since=123&until=456&groupLimit=10&timeBucket=day&attributionLimit=10&budgetLimit=10',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay observability with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-observability-report.v1',
        accepted: true,
        code: 'accepted',
        localKernelId: 'did:chio:buyer-kernel',
        generatedAtUnixMs: 1_766_000_000_500,
        directory: {
          activeVersion: 2,
          activeBundleSha256: 'a'.repeat(64),
          directorySha256: 'b'.repeat(64),
          issuer: 'did:chio:relay-ops',
          expiresAtUnixMs: 1_766_000_060_500,
          removedPeerCount: 0,
          removedPeerIds: [],
          rejectedCandidateCount: 0,
          lastRejectionCode: null,
          profile: 'production',
        },
        queue: {
          pending: 0,
          retry: 0,
          leased: 0,
          delivered: 0,
          deadLetter: 0,
          oldestPendingAgeMs: null,
          staleLeaseCount: 0,
          inboxCount: 0,
          cursorCount: 0,
          catchupEventCount: 0,
        },
        recentFailures: [],
        recommendations: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayObservabilityReport()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chiodos/pheromone/observability',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('surfaces relay observability fetch failures without consuming callers', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      }),
    )

    await expect(fetchRelayObservabilityReport()).rejects.toThrow(
      'Relay observability request failed: 503 Service Unavailable',
    )
  })

  it('fetches relay alert reports with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-alert-report.v1',
        accepted: true,
        code: 'accepted',
        localKernelId: 'did:chio:buyer-kernel',
        generatedAtUnixMs: 1_766_000_060_000,
        sourceReportSha256: 'a'.repeat(64),
        alerts: [],
        checks: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayAlertReport()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chiodos/pheromone/alerts',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay trend reports with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-trend-report.v1',
        accepted: true,
        code: 'accepted',
        localKernelId: 'did:chio:buyer-kernel',
        sinceUnixMs: 1_766_000_000_000,
        untilUnixMs: 1_766_001_000_000,
        sourceReportCount: 0,
        eventReportCount: 0,
        points: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayTrendReport()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chiodos/pheromone/trends',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay alert handoff reports with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-alert-handoff-report.v1',
        accepted: true,
        code: 'accepted',
        localKernelId: 'did:chio:buyer-kernel',
        generatedAtUnixMs: 1_766_000_060_000,
        sourceAlertReportSha256: 'a'.repeat(64),
        sourceTrendReportSha256: 'b'.repeat(64),
        firingAlertCount: 0,
        suppressedAlertCount: 0,
        criticalFiringCount: 0,
        routes: [],
        checks: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayAlertHandoffReport()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chiodos/pheromone/alert-handoff',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay alert delivery reports with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-alert-delivery-report.v1',
        accepted: true,
        code: 'accepted',
        localKernelId: 'did:chio:buyer-kernel',
        generatedAtUnixMs: 1_766_000_060_000,
        sourceHandoffReportSha256: 'c'.repeat(64),
        sourceAlertReportSha256: 'a'.repeat(64),
        sourceTrendReportSha256: 'b'.repeat(64),
        criticalFiringCount: 0,
        deliveredCount: 0,
        delayedCount: 0,
        failedCount: 0,
        unknownCount: 0,
        results: [],
        checks: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayAlertDeliveryReport()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chiodos/pheromone/alert-delivery',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('posts portable reputation comparison requests with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        subjectKey: 'agent-a',
        passportSubject: 'did:chio:agent-a',
        subjectMatches: true,
        comparedAt: 1_700_000_000,
        local: {
          subjectKey: 'agent-a',
          effectiveScore: 0.82,
          probationary: false,
          scoringSource: 'issuance_policy',
        },
        passportVerification: {
          subject: 'did:chio:agent-a',
          issuer: 'did:chio:issuer-a',
          issuers: ['did:chio:issuer-a'],
          issuerCount: 1,
          credentialCount: 1,
          merkleRootCount: 1,
          verifiedAt: 1_700_000_000,
          validUntil: '2026-03-30T00:00:00Z',
        },
        credentialDrifts: [],
        sharedEvidence: {
          summary: {
            matchingShares: 0,
            matchingReferences: 0,
            matchingLocalReceipts: 0,
            remoteToolReceipts: 0,
            remoteLineageRecords: 0,
            distinctRemoteSubjects: 0,
            proofRequiredShares: 0,
            truncated: false,
          },
          references: [],
        },
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchReputationComparison('agent-a', { schema: 'chio.agent-passport.v1' })

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/reputation/compare/agent-a',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          passport: { schema: 'chio.agent-passport.v1' },
        }),
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('extracts the analytics subject from receipt attribution metadata', () => {
    const receipt = {
      id: 'r-1',
      timestamp: 1,
      capability_id: 'cap-123',
      tool_server: 'shell',
      tool_name: 'bash',
      action: {
        parameters: {},
        parameter_hash: 'hash',
      },
      decision: 'allow',
      metadata: {
        attribution: {
          subject_key: 'agent-subject',
          issuer_key: 'issuer-subject',
          delegation_depth: 1,
          grant_index: 0,
        },
      },
    } satisfies Receipt

    expect(receiptSubjectKey(receipt)).toBe('agent-subject')
  })

  it('classifies tagged allow decisions from receipt query responses', () => {
    expect(decisionKind({ verdict: 'allow' })).toBe('allow')
  })
})
