import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { DelegationChain } from './DelegationChain'

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
  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (container.textContent?.includes(text)) {
      return
    }
    await act(async () => {
      await Promise.resolve()
    })
  }

  throw new Error(`timed out waiting for text: ${text}`)
}

describe('DelegationChain operator paths', () => {
  it('shows an explicit empty state when no lineage exists', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => [],
      }),
    )

    const container = await renderIntoDocument(<DelegationChain capabilityId="cap-empty" />)
    await waitForText(container, 'No delegation chain available.')

    expect(container.textContent).toContain('No delegation chain available.')
  })

  it('surfaces lineage fetch failures to the operator', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      }),
    )

    const container = await renderIntoDocument(<DelegationChain capabilityId="cap-failure" />)
    await waitForText(container, 'Error: API error 503: Service Unavailable')

    expect(container.textContent).toContain('Error: API error 503: Service Unavailable')
  })
})
