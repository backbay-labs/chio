import type { ReactNode } from 'react'
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { describe, expect, it, vi } from 'vitest'

import { PortableReputationPanel } from './PortableReputationPanel'

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

async function waitForEnabled(button: HTMLButtonElement): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    if (!button.disabled) return
    await act(async () => {
      await Promise.resolve()
    })
  }

  throw new Error('timed out waiting for compare button to enable')
}

describe('PortableReputationPanel', () => {
  it('shows operator guidance when no subject is selected', async () => {
    const container = await renderIntoDocument(<PortableReputationPanel />)
    expect(container.textContent).toContain('Set an Agent Subject filter to enable comparison')
  })

  it('uploads a passport and renders comparison drift from the backend', async () => {
    sessionStorage.setItem('chio_token', 'bearer-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
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
            resolvedTier: { name: 'trusted' },
          },
          passportVerification: {
            subject: 'did:chio:agent-a',
            issuer: null,
            issuers: ['did:chio:issuer-a', 'did:chio:issuer-b'],
            issuerCount: 2,
            credentialCount: 1,
            merkleRootCount: 1,
            verifiedAt: 1_700_000_000,
            validUntil: '2026-03-30T00:00:00Z',
          },
          passportEvaluation: {
            accepted: true,
            matchedCredentialIndexes: [0],
          },
          credentialDrifts: [
            {
              index: 0,
              issuer: 'did:chio:issuer-a',
              issuanceDate: '2026-03-01T00:00:00Z',
              expirationDate: '2026-03-30T00:00:00Z',
              attestationUntil: 1_700_000_000,
              receiptCount: 2,
              lineageRecords: 1,
              policyAccepted: true,
              metrics: {
                compositeScore: { localMinusPortable: 0 },
                reliability: { localMinusPortable: 0.05 },
                delegationHygiene: { localMinusPortable: -0.02 },
                resourceStewardship: { localMinusPortable: 0.01 },
              },
            },
          ],
          sharedEvidence: {
            summary: {
              matchingShares: 1,
              matchingReferences: 1,
              matchingLocalReceipts: 2,
              remoteToolReceipts: 4,
              remoteLineageRecords: 3,
              distinctRemoteSubjects: 1,
              proofRequiredShares: 1,
              truncated: false,
            },
            references: [
              {
                share: {
                  shareId: 'share-1',
                  manifestHash: 'manifest-1',
                  importedAt: 1_700_000_100,
                  exportedAt: 1_700_000_050,
                  issuer: 'org-alpha',
                  partner: 'org-beta',
                  signerPublicKey: 'pubkey-1',
                  requireProofs: true,
                  toolReceipts: 4,
                  capabilityLineage: 3,
                },
                capabilityId: 'cap-remote-1',
                subjectKey: 'remote-subject',
                issuerKey: 'remote-issuer',
                delegationDepth: 0,
                localAnchorCapabilityId: 'cap-local-1',
                matchedLocalReceipts: 2,
                allowCount: 2,
                denyCount: 0,
                cancelledCount: 0,
                incompleteCount: 0,
                firstSeen: 1_700_000_110,
                lastSeen: 1_700_000_120,
              },
            ],
          },
        }),
      }),
    )

    const container = await renderIntoDocument(<PortableReputationPanel subjectKey="agent-a" />)
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    const button = container.querySelector('button') as HTMLButtonElement
    const file = new File([JSON.stringify({ schema: 'chio.agent-passport.v1' })], 'passport.json', {
      type: 'application/json',
    })

    await act(async () => {
      Object.defineProperty(input, 'files', {
        configurable: true,
        value: [file],
      })
      input.dispatchEvent(new Event('change', { bubbles: true }))
      await Promise.resolve()
    })
    await waitForText(container, 'passport.json')
    await waitForEnabled(button)

    await act(async () => {
      button.click()
      await Promise.resolve()
    })

    await waitForText(container, 'Accepted')
    expect(container.textContent).toContain('Accepted')
    expect(container.textContent).toContain('Subject Match')
    expect(container.textContent).toContain('Composite 0.000')
    expect(container.textContent).toContain('Reliability +0.050')
    expect(container.textContent).toContain('2 issuer(s)')
    expect(container.textContent).toContain('Shared Evidence References')
    expect(container.textContent).toContain('org-beta')
  })
})
