import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import App from './App'

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

describe('App operator paths', () => {
  it('shows token guidance before issuing unauthenticated queries', async () => {
    sessionStorage.clear()
    window.history.replaceState({}, '', '/')
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Bearer token required')

    expect(container.textContent).toContain('Bearer token required')
    expect(container.textContent).toContain('Provide a trust-control bearer token via')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('renders the empty receipt state when the corpus has no matches', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    window.history.replaceState({}, '', '/')
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request) => {
      const url = String(input)
      if (url.startsWith('/v1/receipts/query')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            totalCount: 0,
            nextCursor: null,
            receipts: [],
          }),
        })
      }
      if (url.startsWith('/v1/reports/operator')) {
        return Promise.resolve({
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
          }),
        })
      }
      if (url.startsWith('/v1/chiodos/pheromone/observability')) {
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'No receipts found')

    expect(container.textContent).toContain('No receipts found')
  })

  it('renders the operator report summary for authenticated users', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    window.history.replaceState({}, '', '/')
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request) => {
      const url = String(input)
      if (url.startsWith('/v1/receipts/query')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            totalCount: 1,
            nextCursor: null,
            receipts: [{
              id: 'r-1',
              timestamp: 1,
              capability_id: 'cap-1',
              tool_server: 'shell',
              tool_name: 'bash',
              action: { parameters: {}, parameter_hash: 'hash' },
              decision: 'allow',
            }],
          }),
        })
      }
      if (url.startsWith('/v1/reports/operator')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            generatedAt: 1_700_000_000,
            filters: {},
            activity: {
              summary: {
                totalReceipts: 12,
                allowCount: 10,
                denyCount: 2,
                cancelledCount: 0,
                incompleteCount: 0,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
              },
              byAgent: [],
              byTool: [],
              byTime: [],
            },
            costAttribution: {
              summary: {
                matchingReceipts: 12,
                returnedReceipts: 10,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
                maxDelegationDepth: 2,
                distinctRootSubjects: 1,
                distinctLeafSubjects: 2,
                lineageGapCount: 0,
                truncated: false,
              },
              byRoot: [{
                rootSubjectKey: 'agent-root-abcdef0123456789',
                receiptCount: 12,
                totalCostCharged: 1250,
                totalAttemptedCost: 1400,
                distinctLeafSubjects: 2,
                maxDelegationDepth: 2,
              }],
              byLeaf: [],
              receipts: [],
            },
            budgetUtilization: {
              summary: {
                matchingGrants: 3,
                returnedGrants: 3,
                distinctCapabilities: 2,
                distinctSubjects: 2,
                totalInvocations: 12,
                totalCostCharged: 1250,
                nearLimitCount: 1,
                exhaustedCount: 0,
                rowsMissingScope: 0,
                rowsMissingLineage: 0,
                truncated: false,
              },
              rows: [],
            },
            compliance: {
              matchingReceipts: 12,
              evidenceReadyReceipts: 12,
              uncheckpointedReceipts: 0,
              checkpointCoverageRate: 1,
              lineageCoveredReceipts: 12,
              lineageGapReceipts: 0,
              lineageCoverageRate: 1,
              pendingSettlementReceipts: 1,
              failedSettlementReceipts: 0,
              directEvidenceExportSupported: true,
              childReceiptScope: 'full_query_window',
              proofsComplete: true,
              exportQuery: {},
            },
          }),
        })
      }
      if (url.startsWith('/v1/chiodos/pheromone/observability')) {
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
      }
      return Promise.reject(new Error(`unexpected fetch: ${url}`))
    }))

    const container = await renderIntoDocument(<App />)
    await waitForText(container, 'Operator Report')

    expect(container.textContent).toContain('Budget Pressure')
    expect(container.textContent).toContain('Settlement And Export')
    expect(container.textContent).toContain('10 allow')
    expect(container.textContent).toContain('1 pending settlement')
  })
})
