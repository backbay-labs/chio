import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { RelayAlertAssuranceSummary } from './RelayAlertAssuranceSummary'

async function renderIntoDocument(node: ReactNode): Promise<HTMLDivElement> {
  const container = document.createElement('div')
  document.body.appendChild(container)
  const root = createRoot(container)
  await act(async () => {
    root.render(node)
    await Promise.resolve()
  })
  return container
}

async function waitForText(container: HTMLElement, text: string): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    if (container.textContent?.includes(text)) return
    await act(async () => {
      await Promise.resolve()
    })
  }

  throw new Error(`timed out waiting for text: ${text}`)
}

function assurancePackage(overrides = {}) {
  return {
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
    firingAlertCount: 3,
    criticalFiringAlertCount: 2,
    normalizedCount: 3,
    readyRouteCount: 2,
    deliveryAttentionCount: 0,
    acknowledgementPendingCount: 0,
    driftCount: 0,
    operatorActionCodes: ['active_alerts_present'],
    checks: [{ code: 'alert_assurance_chain', accepted: false, detail: 'bound' }],
    ...overrides,
  }
}

function exportReport(overrides = {}) {
  return {
    schema: 'chio.pheromone.relay-alert-assurance-export-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_100_000,
    bundleId: 'relay-alert-assurance-export',
    manifestSha256: '3'.repeat(64),
    sourcePackageSha256: '4'.repeat(64),
    artifactCount: 11,
    checks: [{ code: 'export_manifest_signed', accepted: true, detail: 'signed' }],
    ...overrides,
  }
}

function replayReport(overrides = {}) {
  return {
    schema: 'chio.pheromone.relay-alert-assurance-replay-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_100_000,
    bundleId: 'relay-alert-assurance-export',
    sourcePackageSha256: '4'.repeat(64),
    replayedPackageSha256: '4'.repeat(64),
    mismatchCount: 0,
    checks: [{ code: 'assurance_replay', accepted: true, detail: 'matched' }],
    ...overrides,
  }
}

function retentionReport(overrides = {}) {
  return {
    schema: 'chio.pheromone.relay-alert-assurance-retention-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_100_000,
    retainedCount: 10,
    expiringSoonCount: 0,
    eligibleForDeleteCount: 0,
    blockedCount: 1,
    missingCount: 0,
    quarantineCount: 0,
    entries: [],
    checks: [{ code: 'retention_plan_only', accepted: true, detail: 'dry run' }],
    ...overrides,
  }
}

function mockAssuranceFetch(overrides: {
  packageReport?: Record<string, unknown>
  exportReport?: Record<string, unknown>
  replayReport?: Record<string, unknown>
  retentionReport?: Record<string, unknown>
} = {}) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      if (url.endsWith('/export')) {
        return Promise.resolve({ ok: true, json: async () => exportReport(overrides.exportReport) })
      }
      if (url.endsWith('/replay')) {
        return Promise.resolve({ ok: true, json: async () => replayReport(overrides.replayReport) })
      }
      if (url.endsWith('/retention')) {
        return Promise.resolve({
          ok: true,
          json: async () => retentionReport(overrides.retentionReport),
        })
      }
      return Promise.resolve({
        ok: true,
        json: async () => assurancePackage(overrides.packageReport),
      })
    }),
  )
}

describe('RelayAlertAssuranceSummary', () => {
  it('renders assurance state without hiding firing alerts', async () => {
    mockAssuranceFetch()

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay Alert Assurance')
    expect(container.textContent).toContain('assurance_attention_required')
    expect(container.textContent).toContain('2 critical firing')
    expect(container.textContent).toContain('active_alerts_present')
    expect(container.textContent).toContain('Export Lifecycle')
    expect(container.textContent).toContain('retention 1 blocked')
  })

  it('renders unknown when the assurance report is missing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    )

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay alert assurance unknown')
    expect(container.textContent).toContain('Firing alert and delivery state remain visible')
  })

  it('renders accepted all-clear packages', async () => {
    mockAssuranceFetch({
      packageReport: {
        accepted: true,
        code: 'accepted',
        firingAlertCount: 0,
        criticalFiringAlertCount: 0,
        operatorActionCodes: ['ready'],
      },
    })

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay Alert Assurance')
    expect(container.textContent).toContain('accepted')
    expect(container.textContent).toContain('ready')
  })

  it('renders lifecycle unknown without hiding the assurance package', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url === '/v1/chiodos/pheromone/alert-assurance') {
          return Promise.resolve({ ok: true, json: async () => assurancePackage() })
        }
        return Promise.resolve({ ok: false, status: 404, statusText: 'Not Found' })
      }),
    )

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay Alert Assurance')
    expect(container.textContent).toContain('Export Lifecycle')
    expect(container.textContent).toContain('unknown')
    expect(container.textContent).toContain('active_alerts_present')
  })
})
