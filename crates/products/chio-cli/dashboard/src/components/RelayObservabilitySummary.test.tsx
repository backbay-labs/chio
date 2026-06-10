import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { RelayObservabilitySummary } from './RelayObservabilitySummary'

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

describe('RelayObservabilitySummary', () => {
  it('renders relay pressure cards from the canonical report', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          schema: 'chio.pheromone.relay-observability-report.v1',
          accepted: false,
          code: 'degraded',
          localKernelId: 'did:chio:buyer-kernel',
          generatedAtUnixMs: 1_766_000_000_500,
          directory: {
            activeVersion: 2,
            activeBundleSha256: 'a'.repeat(64),
            directorySha256: 'b'.repeat(64),
            issuer: 'did:chio:relay-ops',
            expiresAtUnixMs: 1_766_000_060_500,
            removedPeerCount: 1,
            removedPeerIds: ['did:chio:removed-peer'],
            rejectedCandidateCount: 1,
            lastRejectionCode: 'peer_directory_rollback',
            profile: 'production',
          },
          queue: {
            pending: 2,
            retry: 1,
            leased: 0,
            delivered: 7,
            deadLetter: 1,
            oldestPendingAgeMs: 60000,
            staleLeaseCount: 1,
            inboxCount: 4,
            cursorCount: 2,
            catchupEventCount: 3,
          },
          recentFailures: [{ code: 'relay_nonce_replay', count: 2 }],
          recommendations: [{ code: 'dead_letters_present', severity: 'warning' }],
        }),
      }),
    )

    const container = await renderIntoDocument(<RelayObservabilitySummary />)

    await waitForText(container, 'Relay Observability')
    expect(container.textContent).toContain('Directory v2')
    expect(container.textContent).toContain('1 removed peer')
    expect(container.textContent).toContain('Dead Letters')
    expect(container.textContent).toContain('relay_nonce_replay')
  })

  it('renders unknown when relay observability is not available', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    )

    const container = await renderIntoDocument(<RelayObservabilitySummary />)

    await waitForText(container, 'Relay observability unknown')
    expect(container.textContent).toContain('Receipt dashboard data remains available')
  })
})
