import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { RelayAlertDeliverySummary } from './RelayAlertDeliverySummary'

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

function handoffReport() {
  return {
    schema: 'chio.pheromone.relay-alert-handoff-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_060_000,
    sourceAlertReportSha256: 'a'.repeat(64),
    sourceTrendReportSha256: 'b'.repeat(64),
    firingAlertCount: 2,
    suppressedAlertCount: 0,
    criticalFiringCount: 2,
    routes: [
      {
        receiverId: 'alertmanager-pagerduty-primary',
        kind: 'alertmanager',
        targetRef: 'alertmanager:pagerduty-primary',
        notificationRoute: 'pagerduty-primary',
        opsgenie: 'relay-oncall',
        highestSeverity: 'critical',
        alertCodes: ['dead_letters_present', 'endpoint_denied'],
        escalationRef: 'relay-critical-page',
        ready: true,
      },
    ],
    checks: [{ code: 'handoff_dry_run', accepted: true, detail: 'routeable' }],
  }
}

function deliveryReport(overrides = {}) {
  return {
    schema: 'chio.pheromone.relay-alert-delivery-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_060_000,
    sourceHandoffReportSha256: 'c'.repeat(64),
    sourceAlertReportSha256: 'a'.repeat(64),
    sourceTrendReportSha256: 'b'.repeat(64),
    criticalFiringCount: 2,
    deliveredCount: 2,
    delayedCount: 0,
    failedCount: 0,
    unknownCount: 0,
    results: [
      {
        resultId: 'delivery:dead-letters',
        receiverId: 'alertmanager-pagerduty-primary',
        kind: 'alertmanager',
        targetRef: 'alertmanager:pagerduty-primary',
        notificationRoute: 'pagerduty-primary',
        opsgenie: 'relay-oncall',
        alertCode: 'dead_letters_present',
        dedupeKey: 'chiodos-relay:buyer:dead-letters',
        severity: 'critical',
        runbook: 'docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md',
        status: 'delivered',
        observedAtUnixMs: 1_766_000_060_000,
        downstreamEvidenceSha256: 'd'.repeat(64),
      },
      {
        resultId: 'delivery:endpoint-denied',
        receiverId: 'alertmanager-pagerduty-primary',
        kind: 'alertmanager',
        targetRef: 'alertmanager:pagerduty-primary',
        notificationRoute: 'pagerduty-primary',
        opsgenie: 'relay-oncall',
        alertCode: 'endpoint_denied',
        dedupeKey: 'chiodos-relay:buyer:endpoint-denied',
        severity: 'critical',
        runbook: 'docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md',
        status: 'accepted',
        observedAtUnixMs: 1_766_000_060_000,
        downstreamEvidenceSha256: 'e'.repeat(64),
      },
    ],
    checks: [{ code: 'delivery_evidence', accepted: true, detail: 'covered' }],
    ...overrides,
  }
}

describe('RelayAlertDeliverySummary', () => {
  it('renders handoff and delivery cards', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => handoffReport(),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => deliveryReport(),
        }),
    )

    const container = await renderIntoDocument(<RelayAlertDeliverySummary />)

    await waitForText(container, 'Relay Alert Delivery')
    expect(container.textContent).toContain('2 critical firing')
    expect(container.textContent).toContain('1 routes / 2 alerts')
    expect(container.textContent).toContain('2 delivered')
    expect(container.textContent).toContain('0 failed')
  })

  it('renders delivery unknown without hiding handoff state', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => handoffReport(),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        }),
    )

    const container = await renderIntoDocument(<RelayAlertDeliverySummary />)

    await waitForText(container, 'Relay Alert Delivery')
    expect(container.textContent).toContain('2 critical firing')
    expect(container.textContent).toContain('unknown')
  })

  it('renders failed and delayed delivery evidence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => handoffReport(),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () =>
            deliveryReport({
              accepted: false,
              code: 'delivery_attention_required',
              deliveredCount: 0,
              delayedCount: 1,
              failedCount: 1,
            }),
        }),
    )

    const container = await renderIntoDocument(<RelayAlertDeliverySummary />)

    await waitForText(container, 'delivery_attention_required')
    expect(container.textContent).toContain('0 delivered')
    expect(container.textContent).toContain('1 failed')
    expect(container.textContent).toContain('1 delayed')
  })

  it('renders unknown when handoff and delivery are both missing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    )

    const container = await renderIntoDocument(<RelayAlertDeliverySummary />)

    await waitForText(container, 'Relay alert delivery unknown')
    expect(container.textContent).toContain('Receipt dashboard data remains available')
  })
})
