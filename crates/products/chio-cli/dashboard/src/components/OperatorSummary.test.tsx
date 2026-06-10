import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { OperatorSummary } from './OperatorSummary'

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

describe('OperatorSummary', () => {
  it('renders shared evidence metrics from the operator report', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          generatedAt: 1_700_000_000,
          filters: {},
          activity: {
            summary: {
              totalReceipts: 4,
              allowCount: 3,
              denyCount: 1,
              cancelledCount: 0,
              incompleteCount: 0,
              totalCostCharged: 500,
              totalAttemptedCost: 600,
            },
            byAgent: [],
            byTool: [],
            byTime: [],
          },
          costAttribution: {
            summary: {
              matchingReceipts: 4,
              returnedReceipts: 4,
              totalCostCharged: 500,
              totalAttemptedCost: 600,
              maxDelegationDepth: 2,
              distinctRootSubjects: 1,
              distinctLeafSubjects: 1,
              lineageGapCount: 0,
              truncated: false,
            },
            byRoot: [
              {
                rootSubjectKey: 'root-subject-key',
                receiptCount: 4,
                totalCostCharged: 500,
                totalAttemptedCost: 600,
                distinctLeafSubjects: 1,
                maxDelegationDepth: 2,
              },
            ],
            byLeaf: [],
            receipts: [],
          },
          budgetUtilization: {
            summary: {
              matchingGrants: 1,
              returnedGrants: 1,
              distinctCapabilities: 1,
              distinctSubjects: 1,
              totalInvocations: 4,
              totalCostCharged: 500,
              nearLimitCount: 0,
              exhaustedCount: 0,
              rowsMissingScope: 0,
              rowsMissingLineage: 0,
              truncated: false,
            },
            rows: [],
          },
          compliance: {
            matchingReceipts: 4,
            evidenceReadyReceipts: 4,
            uncheckpointedReceipts: 0,
            checkpointCoverageRate: 1,
            lineageCoveredReceipts: 4,
            lineageGapReceipts: 0,
            lineageCoverageRate: 1,
            pendingSettlementReceipts: 0,
            failedSettlementReceipts: 0,
            directEvidenceExportSupported: true,
            childReceiptScope: 'full_query_window',
            proofsComplete: true,
            exportQuery: {},
          },
          sharedEvidence: {
            summary: {
              matchingShares: 1,
              matchingReferences: 2,
              matchingLocalReceipts: 4,
              remoteToolReceipts: 6,
              remoteLineageRecords: 3,
              distinctRemoteSubjects: 1,
              proofRequiredShares: 1,
              truncated: false,
            },
            references: [
              {
                share: {
                  shareId: 'share-xyz',
                  manifestHash: 'manifest-xyz',
                  importedAt: 1_700_000_100,
                  exportedAt: 1_700_000_050,
                  issuer: 'org-alpha',
                  partner: 'org-beta',
                  signerPublicKey: 'pubkey-xyz',
                  requireProofs: true,
                  toolReceipts: 6,
                  capabilityLineage: 3,
                },
                capabilityId: 'cap-remote-1',
                subjectKey: 'remote-subject',
                issuerKey: 'remote-issuer',
                delegationDepth: 0,
                localAnchorCapabilityId: 'cap-local-1',
                matchedLocalReceipts: 4,
                allowCount: 3,
                denyCount: 1,
                cancelledCount: 0,
                incompleteCount: 0,
                firstSeen: 1_700_000_101,
                lastSeen: 1_700_000_120,
              },
            ],
          },
        }),
      }),
    )

    const container = await renderIntoDocument(
      <OperatorSummary filters={{ agentSubject: 'agent-a' }} />,
    )

    await waitForText(container, 'Shared Evidence')
    expect(container.textContent).toContain('2 remote references')
    expect(container.textContent).toContain('4 local receipts')
    expect(container.textContent).toContain('org-beta')
  })
})
