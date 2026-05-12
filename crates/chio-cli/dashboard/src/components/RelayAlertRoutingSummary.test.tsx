import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { RelayAlertRoutingSummary } from './RelayAlertRoutingSummary'
import type { RelayAlert, RelayTrendPoint } from '../types'

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

function relayAlert(overrides: Partial<RelayAlert> = {}): RelayAlert {
  const severity = overrides.severity ?? 'critical'
  const notificationRoute = overrides.notificationRoute ?? 'pagerduty-primary'
  const opsgenie = overrides.opsgenie ?? 'relay-oncall'
  return {
    code: overrides.code ?? 'dead_letters_present',
    state: overrides.state ?? 'firing',
    severity,
    notificationRoute,
    opsgenie,
    dedupeKey: overrides.dedupeKey ?? 'relay-dead-letters',
    runbook: overrides.runbook ?? 'docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md',
    firstSeenUnixMs: overrides.firstSeenUnixMs ?? 1_766_000_000_500,
    lastSeenUnixMs: overrides.lastSeenUnixMs ?? 1_766_000_060_000,
    windowMs: overrides.windowMs ?? 300_000,
    suppressedUntilUnixMs: overrides.suppressedUntilUnixMs ?? null,
    sourceReportSha256: overrides.sourceReportSha256 ?? 'a'.repeat(64),
    eventEvidenceSha256: overrides.eventEvidenceSha256 ?? ['b'.repeat(64)],
    recommendationCodes: overrides.recommendationCodes ?? ['dead_letters_present'],
    labels: {
      notification_route: notificationRoute,
      opsgenie,
      service: 'chiodos-pheromone-relay',
      severity,
      ...overrides.labels,
    },
  }
}

function alertReport(alerts: RelayAlert[]) {
  return {
    schema: 'chio.pheromone.relay-alert-report.v1',
    accepted: alerts.every((alert) => alert.state !== 'firing'),
    code: alerts.some((alert) => alert.state === 'firing') ? 'alerts_firing' : 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    generatedAtUnixMs: 1_766_000_060_000,
    sourceReportSha256: 'a'.repeat(64),
    alerts,
    checks: [{ code: 'source_report', accepted: true, detail: 'hash-bound' }],
  }
}

function trendReport(points: RelayTrendPoint[] = []) {
  return {
    schema: 'chio.pheromone.relay-trend-report.v1',
    accepted: true,
    code: 'accepted',
    localKernelId: 'did:chio:buyer-kernel',
    sinceUnixMs: 1_766_000_000_000,
    untilUnixMs: 1_766_001_000_000,
    sourceReportCount: 2,
    eventReportCount: 1,
    points,
  }
}

describe('RelayAlertRoutingSummary', () => {
  it('renders routeable alert and trend cards', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            schema: 'chio.pheromone.relay-alert-report.v1',
            accepted: false,
            code: 'alerts_firing',
            localKernelId: 'did:chio:buyer-kernel',
            generatedAtUnixMs: 1_766_000_060_000,
            sourceReportSha256: 'a'.repeat(64),
            alerts: [
              {
                code: 'dead_letters_present',
                state: 'firing',
                severity: 'critical',
                notificationRoute: 'pagerduty-primary',
                opsgenie: 'relay-oncall',
                dedupeKey: 'relay-dead-letters',
                runbook: 'docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md',
                firstSeenUnixMs: 1_766_000_000_500,
                lastSeenUnixMs: 1_766_000_060_000,
                windowMs: 300_000,
                suppressedUntilUnixMs: null,
                sourceReportSha256: 'a'.repeat(64),
                eventEvidenceSha256: ['b'.repeat(64)],
                recommendationCodes: ['dead_letters_present'],
                labels: {
                  notification_route: 'pagerduty-primary',
                  opsgenie: 'relay-oncall',
                  service: 'chiodos-pheromone-relay',
                  severity: 'critical',
                },
              },
              {
                code: 'stale_leases_present',
                state: 'suppressed',
                severity: 'warning',
                notificationRoute: 'slack-ops-digest',
                opsgenie: 'relay-oncall',
                dedupeKey: 'relay-stale-leases',
                runbook: 'docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md',
                firstSeenUnixMs: 1_766_000_000_500,
                lastSeenUnixMs: 1_766_000_060_000,
                windowMs: 300_000,
                suppressedUntilUnixMs: 1_766_000_300_000,
                sourceReportSha256: 'a'.repeat(64),
                eventEvidenceSha256: [],
                recommendationCodes: ['stale_leases_present'],
                labels: {
                  notification_route: 'slack-ops-digest',
                  opsgenie: 'relay-oncall',
                  service: 'chiodos-pheromone-relay',
                  severity: 'warning',
                },
              },
            ],
            checks: [{ code: 'source_report', accepted: true, detail: 'hash-bound' }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            schema: 'chio.pheromone.relay-trend-report.v1',
            accepted: true,
            code: 'accepted',
            localKernelId: 'did:chio:buyer-kernel',
            sinceUnixMs: 1_766_000_000_000,
            untilUnixMs: 1_766_001_000_000,
            sourceReportCount: 2,
            eventReportCount: 1,
            points: [
              {
                code: 'dead_letters_present',
                count: 2,
                firstSeenUnixMs: 1_766_000_000_500,
                lastSeenUnixMs: 1_766_000_060_000,
                severity: 'critical',
              },
            ],
          }),
        }),
    )

    const container = await renderIntoDocument(<RelayAlertRoutingSummary />)

    await waitForText(container, 'Relay Alerts')
    expect(container.textContent).toContain('alerts_firing')
    expect(container.textContent).toContain('1 firing')
    expect(container.textContent).toContain('1 suppressed')
    expect(container.textContent).toContain('pagerduty-primary')
    expect(container.textContent).toContain('dead_letters_present')
  })

  it('renders unknown when alert reports are not available', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    )

    const container = await renderIntoDocument(<RelayAlertRoutingSummary />)

    await waitForText(container, 'Relay alert routing unknown')
    expect(container.textContent).toContain('Receipt dashboard data remains available')
  })

  it('keeps firing alerts visible when the trend report is missing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () => alertReport([relayAlert()]),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        }),
    )

    const container = await renderIntoDocument(<RelayAlertRoutingSummary />)

    await waitForText(container, 'Relay Alerts')
    expect(container.textContent).toContain('alerts_firing')
    expect(container.textContent).toContain('pagerduty-primary')
    expect(container.textContent).toContain('none')
  })

  it('selects the primary route from the highest-severity firing alert', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce({
          ok: true,
          json: async () =>
            alertReport([
              relayAlert({
                code: 'retries_pending',
                severity: 'info',
                notificationRoute: 'slack-ops-digest',
                eventEvidenceSha256: [],
                recommendationCodes: ['retries_pending'],
              }),
              relayAlert({
                code: 'endpoint_denied',
                severity: 'critical',
                notificationRoute: 'pagerduty-primary',
                recommendationCodes: ['endpoint_denied'],
              }),
            ]),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => trendReport(),
        }),
    )

    const container = await renderIntoDocument(<RelayAlertRoutingSummary />)

    await waitForText(container, 'Relay Alerts')
    expect(container.textContent).toContain('pagerduty-primary')
    expect(container.textContent).not.toContain('no ops route')
  })
})
