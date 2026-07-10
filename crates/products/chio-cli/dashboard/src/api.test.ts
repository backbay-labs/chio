import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  fetchAgentCostSeries,
  fetchOperatorReport,
  fetchProofRoomFixtureBundle,
  fetchProofRoomFixtureCatalog,
  fetchProofRoomStaticBundle,
  fetchRelayAlertAssuranceArchiveExtractionReport,
  fetchRelayAlertAssuranceArchivePackageReport,
  fetchRelayAlertAssuranceArchiveReport,
  fetchRelayAlertAssuranceArchiveRestoreDrillReport,
  fetchRelayAlertAssuranceCloseoutReport,
  fetchRelayAlertAssuranceExternalRetentionReviewReport,
  fetchRelayAlertAssuranceExportReport,
  fetchRelayAlertAssurancePackage,
  fetchRelayAlertAssurancePhysicalArchiveDrillReport,
  fetchRelayAlertAssuranceReplayReport,
  fetchRelayAlertAssuranceRetentionHandoffReport,
  fetchRelayAlertAssuranceRetentionReport,
  fetchRelayAlertDeliveryReport,
  fetchRelayAlertHandoffReport,
  fetchRelayAlertReport,
  fetchRelayObservabilityReport,
  fetchRelayTrendReport,
  fetchReputationComparison,
  fetchReceiptAnalytics,
  getToken,
} from './api'
import { sha256Hex } from './proofRoomArtifactEvidence'
import { decisionKind, receiptSubjectKey, type Receipt } from './types'

const proofRoomBundlePayloadType = 'application/vnd.chio.proof-room.bundle.v1+json'

function bytesToHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0)
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

function dssePreAuthEncoding(payloadType: string, payload: string): Uint8Array {
  const encoder = new TextEncoder()
  const payloadTypeBytes = encoder.encode(payloadType)
  const payloadBytes = encoder.encode(payload)
  return concatBytes([
    encoder.encode(`DSSEv1 ${payloadTypeBytes.byteLength} `),
    payloadTypeBytes,
    encoder.encode(` ${payloadBytes.byteLength} `),
    payloadBytes,
  ])
}

interface SignedProofRoomBundleSignature {
  signatureJson: string
  signerKeyId: string
}

async function signedProofRoomBundleSignature(
  manifestJson: string,
): Promise<SignedProofRoomBundleSignature> {
  const keypair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const signerKeyId = bytesToHex(await crypto.subtle.exportKey('raw', keypair.publicKey))
  const signatureBytes = await crypto.subtle.sign(
    { name: 'Ed25519' },
    keypair.privateKey,
    dssePreAuthEncoding(proofRoomBundlePayloadType, manifestJson),
  )
  return {
    signerKeyId,
    signatureJson: JSON.stringify({
      payloadType: proofRoomBundlePayloadType,
      payloadRef: {
        path: 'manifest.json',
        schema: 'chio.proof-room.bundle.v1',
        sha256: await sha256Hex(manifestJson),
      },
      signatures: [{ keyid: signerKeyId, sig: bytesToHex(signatureBytes) }],
    }),
  }
}

async function signedProofRoomBundleSignatureJson(manifestJson: string): Promise<string> {
  return (await signedProofRoomBundleSignature(manifestJson)).signatureJson
}

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
      '/v1/chio/pheromone/observability',
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
      '/v1/chio/pheromone/alerts',
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
      '/v1/chio/pheromone/trends',
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
      '/v1/chio/pheromone/alert-handoff',
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
      '/v1/chio/pheromone/alert-delivery',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay alert assurance packages with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schema: 'chio.pheromone.relay-alert-assurance-package.v1',
        accepted: false,
        code: 'assurance_attention_required',
        localKernelId: 'did:chio:buyer-kernel',
        generatedAtUnixMs: 1_766_000_090_000,
        sourceAlertReportSha256: 'a'.repeat(64),
        sourceTrendReportSha256: 'b'.repeat(64),
        sourceHandoffReportSha256: 'c'.repeat(64),
        sourceNormalizationReportSha256: 'd'.repeat(64),
        sourceDeliveryReportSha256: 'e'.repeat(64),
        sourceAcknowledgementReportSha256: 'f'.repeat(64),
        sourceDriftReportSha256: '1'.repeat(64),
        sourceReviewPacketSha256: '2'.repeat(64),
        firingAlertCount: 1,
        criticalFiringAlertCount: 1,
        normalizedCount: 1,
        readyRouteCount: 1,
        deliveryAttentionCount: 0,
        acknowledgementPendingCount: 0,
        driftCount: 0,
        operatorActionCodes: ['active_alerts_present'],
        checks: [],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayAlertAssurancePackage()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/chio/pheromone/alert-assurance',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
  })

  it('fetches relay alert assurance lifecycle reports with bearer auth', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ accepted: true }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRelayAlertAssuranceExportReport()
    await fetchRelayAlertAssuranceReplayReport()
    await fetchRelayAlertAssuranceRetentionReport()
    await fetchRelayAlertAssuranceArchiveReport()
    await fetchRelayAlertAssuranceCloseoutReport()
    await fetchRelayAlertAssuranceArchivePackageReport()
    await fetchRelayAlertAssuranceArchiveExtractionReport()
    await fetchRelayAlertAssuranceArchiveRestoreDrillReport()
    await fetchRelayAlertAssurancePhysicalArchiveDrillReport()
    await fetchRelayAlertAssuranceRetentionHandoffReport()
    await fetchRelayAlertAssuranceExternalRetentionReviewReport()

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/v1/chio/pheromone/alert-assurance/export',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer bearer-token',
          'Content-Type': 'application/json',
        }),
      }),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/v1/chio/pheromone/alert-assurance/replay',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      '/v1/chio/pheromone/alert-assurance/retention',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      4,
      '/v1/chio/pheromone/alert-assurance/archive',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      5,
      '/v1/chio/pheromone/alert-assurance/closeout',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      6,
      '/v1/chio/pheromone/alert-assurance/archive-package',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      7,
      '/v1/chio/pheromone/alert-assurance/archive-extraction',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      8,
      '/v1/chio/pheromone/alert-assurance/archive-restore-drill',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      9,
      '/v1/chio/pheromone/alert-assurance/physical-archive',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      10,
      '/v1/chio/pheromone/alert-assurance/retention-handoff',
      expect.anything(),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      11,
      '/v1/chio/pheromone/alert-assurance/external-retention-review',
      expect.anything(),
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

  it('rejects served Proof Room manifests with unsafe excluded artifact paths', async () => {
    const routes: Record<string, unknown> = {
      '/manifest.json': {
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        proof_room_verifier_report_ref: {
          path: 'ui/proof-room-static/load-report.json',
          sha256: '2'.repeat(64),
          schema: 'chio.proof-room.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
        excluded_artifacts: [
          {
            path: '../outside.json',
            reason: 'outside bundle',
          },
        ],
      },
      '/ui/proof-room-static/load-report.json': {
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        source_verifier_report_ref: {
          path: 'verifier/report.json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      },
      '/verifier/report.json': {
        schema: 'chio.transaction.verifier-report.v1',
        verdict: 'verified',
        verified_claims: [],
      },
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve({
      ok: true,
      json: async () => routes[path],
    })))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served excluded artifact path is unsafe',
    )
  })

  it('rejects served Proof Room manifests with dot segments in artifact paths', async () => {
    const routes: Record<string, unknown> = {
      '/manifest.json': {
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        verifier_report_ref: {
          path: 'verifier/./report.json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        proof_room_verifier_report_ref: {
          path: 'ui/proof-room-static/load-report.json',
          sha256: '2'.repeat(64),
          schema: 'chio.proof-room.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
      },
      '/ui/proof-room-static/load-report.json': {
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        source_verifier_report_ref: {
          path: 'verifier/./report.json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      },
      '/verifier/./report.json': {
        schema: 'chio.transaction.verifier-report.v1',
        verdict: 'verified',
        verified_claims: [],
      },
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve({
      ok: true,
      json: async () => routes[path],
    })))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served verifier report path is unsafe',
    )
  })

  it('rejects served Proof Room manifests with whitespace in artifact paths', async () => {
    const routes: Record<string, unknown> = {
      '/manifest.json': {
        schema: 'chio.proof-room.bundle.v1',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        verifier_report_ref: {
          path: 'verifier/report json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        proof_room_verifier_report_ref: {
          path: 'ui/proof-room-static/load-report.json',
          sha256: '2'.repeat(64),
          schema: 'chio.proof-room.verifier-report.v1',
        },
        claims: [],
        negative_cases: [],
      },
      '/ui/proof-room-static/load-report.json': {
        schema: 'chio.proof-room.verifier-report.v1',
        verdict: 'verified',
        bundle_id: 'served-proof-room',
        fixture_id: 'single-call-authority',
        source_verifier_report_ref: {
          path: 'verifier/report json',
          sha256: '1'.repeat(64),
          schema: 'chio.transaction.verifier-report.v1',
        },
        ui_verdict_source: 'verifier_report_ref',
        rendered_claims: [],
      },
      '/verifier/report json': {
        schema: 'chio.transaction.verifier-report.v1',
        verdict: 'verified',
        verified_claims: [],
      },
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve({
      ok: true,
      json: async () => routes[path],
    })))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served verifier report path is unsafe',
    )
  })

  it('rejects served Proof Room bundles with forged detached signatures', async () => {
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      verdict: 'verified',
      verified_claims: [],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [],
      negative_cases: [],
    })
    const manifestDigest = await sha256Hex(manifestJson)
    const signatureJson = JSON.stringify({
      payloadType: 'application/vnd.chio.proof-room.bundle.v1+json',
      payloadRef: {
        path: 'manifest.json',
        schema: 'chio.proof-room.bundle.v1',
        sha256: manifestDigest,
      },
      signatures: [{ keyid: '1'.repeat(64), sig: '0'.repeat(128) }],
    })
    const routes: Record<string, string> = {
      '/manifest.json': manifestJson,
      '/ui/proof-room-static/load-report.json': loadReportJson,
      '/verifier/report.json': verifierReportJson,
      '/bundle-signature.dsse.json': signatureJson,
      '/proof-room-trusted-bundle-signers.json': JSON.stringify({
        schema: 'chio.proof-room.trusted-bundle-signers.v1',
        keys: ['1'.repeat(64)],
      }),
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (!Object.prototype.hasOwnProperty.call(routes, path)) {
        return Promise.resolve({
          ok: false,
          status: 404,
          json: async () => ({}),
          text: async () => '',
        })
      }
      return Promise.resolve({
        ok: true,
        json: async () => JSON.parse(routes[path]),
        text: async () => routes[path],
      })
    }))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served bundle signature verification failed',
    )
  })

  it('rejects served Proof Room bundles signed outside trust roots', async () => {
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      verdict: 'verified',
      verified_claims: [],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const trustedKeyId = '2'.repeat(64)
    const trustRootsJson = JSON.stringify({
      schema: 'chio.proof.first-run.trust-roots.v1',
      id: 'served-trust-roots',
      trust_domain: 'did:chio:proof-room-served',
      roots: [{
        subject: 'did:chio:trusted-served-signer',
        key_id: trustedKeyId,
        key_digest: await sha256Hex(trustedKeyId),
      }],
      signature: 'sig-served-trust-roots',
    })
    const trustRootsDigest = await sha256Hex(trustRootsJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      artifacts: [{
        path: 'artifacts/authority/trust-roots.json',
        sha256: trustRootsDigest,
        schema: 'chio.proof.first-run.trust-roots.v1',
        renderer_hint: 'trust-roots',
      }],
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [],
      negative_cases: [],
    })
    const signatureJson = await signedProofRoomBundleSignatureJson(manifestJson)
    const routes: Record<string, string> = {
      '/manifest.json': manifestJson,
      '/ui/proof-room-static/load-report.json': loadReportJson,
      '/verifier/report.json': verifierReportJson,
      '/artifacts/authority/trust-roots.json': trustRootsJson,
      '/bundle-signature.dsse.json': signatureJson,
      '/proof-room-trusted-bundle-signers.json': JSON.stringify({
        schema: 'chio.proof-room.trusted-bundle-signers.v1',
        keys: [trustedKeyId],
      }),
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (!Object.prototype.hasOwnProperty.call(routes, path)) {
        return Promise.resolve({
          ok: false,
          status: 404,
          json: async () => ({}),
          text: async () => '',
        })
      }
      return Promise.resolve({
        ok: true,
        json: async () => JSON.parse(routes[path]),
        text: async () => routes[path],
      })
    }))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served bundle signature signer is not trusted',
    )
  })

  it('rejects served Proof Room bundles trusted only by bundle-local roots', async () => {
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      verdict: 'verified',
      verified_claims: [],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const keypair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify'],
    ) as CryptoKeyPair
    const signerKeyId = bytesToHex(await crypto.subtle.exportKey('raw', keypair.publicKey))
    const trustRootsJson = JSON.stringify({
      schema: 'chio.proof.first-run.trust-roots.v1',
      id: 'served-trust-roots',
      trust_domain: 'did:chio:proof-room-served',
      roots: [{
        subject: 'did:chio:bundle-local-signer',
        key_id: signerKeyId,
        key_digest: await sha256Hex(signerKeyId),
      }],
      signature: 'sig-served-trust-roots',
    })
    const trustRootsDigest = await sha256Hex(trustRootsJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      artifacts: [{
        path: 'artifacts/authority/trust-roots.json',
        sha256: trustRootsDigest,
        schema: 'chio.proof.first-run.trust-roots.v1',
        renderer_hint: 'trust-roots',
      }],
      signature: {
        kind: 'detached-dsse',
        signature_ref: 'bundle-signature.dsse.json',
      },
      claims: [],
      negative_cases: [],
    })
    const signatureBytes = await crypto.subtle.sign(
      { name: 'Ed25519' },
      keypair.privateKey,
      dssePreAuthEncoding(proofRoomBundlePayloadType, manifestJson),
    )
    const signatureJson = JSON.stringify({
      payloadType: proofRoomBundlePayloadType,
      payloadRef: {
        path: 'manifest.json',
        schema: 'chio.proof-room.bundle.v1',
        sha256: await sha256Hex(manifestJson),
      },
      signatures: [{ keyid: signerKeyId, sig: bytesToHex(signatureBytes) }],
    })
    const routes: Record<string, string> = {
      '/manifest.json': manifestJson,
      '/ui/proof-room-static/load-report.json': loadReportJson,
      '/verifier/report.json': verifierReportJson,
      '/artifacts/authority/trust-roots.json': trustRootsJson,
      '/bundle-signature.dsse.json': signatureJson,
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (!Object.prototype.hasOwnProperty.call(routes, path)) {
        return Promise.resolve({
          ok: false,
          status: 404,
          json: async () => ({}),
          text: async () => '',
        })
      }
      return Promise.resolve({
        ok: true,
        json: async () => JSON.parse(routes[path]),
        text: async () => routes[path],
      })
    }))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served bundle signature trusted signer config missing',
    )
  })

  it('rejects served Proof Room bundles without detached signatures', async () => {
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      verdict: 'verified',
      verified_claims: [],
    })
    const verifierReportDigest = await sha256Hex(verifierReportJson)
    const loadReportJson = JSON.stringify({
      schema: 'chio.proof-room.verifier-report.v1',
      verdict: 'verified',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      source_verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      ui_verdict_source: 'verifier_report_ref',
      rendered_claims: [],
    })
    const loadReportDigest = await sha256Hex(loadReportJson)
    const manifestJson = JSON.stringify({
      schema: 'chio.proof-room.bundle.v1',
      bundle_id: 'served-proof-room',
      fixture_id: 'single-call-authority',
      verifier_report_ref: {
        path: 'verifier/report.json',
        sha256: verifierReportDigest,
        schema: 'chio.transaction.verifier-report.v1',
      },
      proof_room_verifier_report_ref: {
        path: 'ui/proof-room-static/load-report.json',
        sha256: loadReportDigest,
        schema: 'chio.proof-room.verifier-report.v1',
      },
      claims: [],
      negative_cases: [],
    })
    const routes: Record<string, string> = {
      '/manifest.json': manifestJson,
      '/ui/proof-room-static/load-report.json': loadReportJson,
      '/verifier/report.json': verifierReportJson,
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve({
      ok: true,
      json: async () => JSON.parse(routes[path]),
      text: async () => routes[path],
    })))

    await expect(fetchProofRoomStaticBundle()).rejects.toThrow(
      'served bundle signature missing',
    )
  })

  it('rejects fixture catalogs with unsafe fixture ids', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true,
      json: async () => ({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: '../outside',
            kind: 'minimal-passport',
            path: 'fixtures/proof-room/minimal-passport/valid',
            description: 'unsafe fixture id',
            verifier_report: {
              path: '/proof-room-fixtures/minimal-passport/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
        ],
      }),
    })))

    await expect(fetchProofRoomFixtureCatalog()).rejects.toThrow(
      'Proof Room fixture catalog has unsafe fixture id',
    )
  })

  it('rejects fixture catalogs with available fixtures missing verifier reports', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true,
      json: async () => ({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'commerce-transaction-passport',
            kind: 'generated-proof-room',
            path: 'generated/commerce-transaction-passport',
            description: 'uninspectable generated fixture',
          },
        ],
      }),
    })))

    await expect(fetchProofRoomFixtureCatalog()).rejects.toThrow(
      'Proof Room fixture catalog available fixture is missing verifier report',
    )
  })

  it('rejects fixture catalogs with unsafe verifier report paths', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true,
      json: async () => ({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'minimal-passport-valid',
            kind: 'minimal-passport',
            path: 'fixtures/proof-room/minimal-passport/valid',
            description: 'unsafe report path',
            verifier_report: {
              path: '/proof-room-fixtures/%2e/verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
        ],
      }),
    })))

    await expect(fetchProofRoomFixtureCatalog()).rejects.toThrow(
      'Proof Room fixture catalog has unsafe verifier report path',
    )
  })

  it('rejects fixture catalogs with empty verifier report path segments', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true,
      json: async () => ({
        schema: 'chio.proof-room.fixture-catalog.v1',
        fixtures: [],
        available_fixtures: [
          {
            id: 'minimal-passport-valid',
            kind: 'minimal-passport',
            path: 'fixtures/proof-room/minimal-passport/valid',
            description: 'unsafe report path',
            verifier_report: {
              path: '/proof-room-fixtures//verifier-report.json',
              status: 200,
              verdict: 'verified',
            },
          },
        ],
      }),
    })))

    await expect(fetchProofRoomFixtureCatalog()).rejects.toThrow(
      'Proof Room fixture catalog has unsafe verifier report path',
    )
  })

  it('rejects direct fixture bundle loads with unsafe fixture ids before fetching', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(fetchProofRoomFixtureBundle('../outside')).rejects.toThrow(
      'Proof Room fixture id is unsafe',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('keeps fixture catalog negative case assets bound to their advertised fixture ids', async () => {
    const evidenceGraphJson = JSON.stringify({
      schema: 'chio.transaction.evidence-graph.v1',
      nodes: [],
    })
    const evidenceGraphDigest = await sha256Hex(evidenceGraphJson)
    const verifierPolicyJson = JSON.stringify({
      schema: 'chio.transaction.verifier-policy.v1',
      required_claims: ['claim.transaction.passport_root_verified'],
    })
    const verifierPolicyDigest = await sha256Hex(verifierPolicyJson)
    const passportJson = JSON.stringify({
      schema: 'chio.transaction-passport.v1',
      id: 'passport-minimal-valid',
      evidence_graph_path: 'evidence-graph.json',
      evidence_graph_sha256: evidenceGraphDigest,
      verifier_policy_path: 'verifier-policy.json',
      verifier_policy_sha256: verifierPolicyDigest,
    })
    const verifierReportJson = JSON.stringify({
      schema: 'chio.transaction.verifier-report.v1',
      verdict: 'verified',
      verified_claims: ['claim.transaction.passport_root_verified'],
    })
    const routes: Record<string, string> = {
      '/proof-room-fixtures/minimal-passport-valid/transaction-passport.json': passportJson,
      '/proof-room-fixtures/minimal-passport-valid/evidence-graph.json': evidenceGraphJson,
      '/proof-room-fixtures/minimal-passport-valid/verifier-policy.json': verifierPolicyJson,
      '/proof-room-fixtures/minimal-passport-valid/verifier-report.json': verifierReportJson,
    }
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => JSON.parse(routes[path]),
      text: async () => routes[path],
    })))

    const bundle = await fetchProofRoomFixtureBundle(
      'minimal-passport-valid',
      'transaction-passport',
      [
        {
          id: 'minimal-passport-policy-digest-mismatch',
          path: 'transaction-passport.json',
          expected_failure_code: 'verifier policy digest mismatch',
          observed_failure_code: 'verifier policy digest mismatch',
        },
      ],
    )

    expect(bundle.manifest.negative_cases[0].path).toBe(
      'proof-room-fixtures/minimal-passport-policy-digest-mismatch/transaction-passport.json',
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
      decision: { verdict: 'allow' },
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
