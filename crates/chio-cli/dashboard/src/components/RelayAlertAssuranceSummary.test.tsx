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

describe('RelayAlertAssuranceSummary', () => {
  it('renders assurance state without hiding firing alerts', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => assurancePackage(),
      }),
    )

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay Alert Assurance')
    expect(container.textContent).toContain('assurance_attention_required')
    expect(container.textContent).toContain('2 critical firing')
    expect(container.textContent).toContain('active_alerts_present')
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
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () =>
          assurancePackage({
            accepted: true,
            code: 'accepted',
            firingAlertCount: 0,
            criticalFiringAlertCount: 0,
            operatorActionCodes: ['ready'],
          }),
      }),
    )

    const container = await renderIntoDocument(<RelayAlertAssuranceSummary />)

    await waitForText(container, 'Relay Alert Assurance')
    expect(container.textContent).toContain('accepted')
    expect(container.textContent).toContain('ready')
  })
})
