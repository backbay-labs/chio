import { type ChangeEvent, useState } from 'react'

import { fetchReputationComparison } from '../api'
import type { PortableReputationComparison } from '../types'

interface PortableReputationPanelProps {
  subjectKey?: string
}

async function readFileText(file: File): Promise<string> {
  if (typeof file.text === 'function') {
    return file.text()
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Failed to read passport file'))
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '')
    reader.readAsText(file)
  })
}

function driftLabel(value?: number): string {
  if (value === undefined) return '--'
  const prefix = value > 0 ? '+' : ''
  return `${prefix}${value.toFixed(3)}`
}

export function PortableReputationPanel({ subjectKey }: PortableReputationPanelProps) {
  const [passportText, setPassportText] = useState<string | null>(null)
  const [passportName, setPassportName] = useState<string | null>(null)
  const [comparison, setComparison] = useState<PortableReputationComparison | null>(null)
  const [readingPassport, setReadingPassport] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handlePassportChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) {
      setPassportText(null)
      setPassportName(null)
      setComparison(null)
      setReadingPassport(false)
      return
    }

    setReadingPassport(true)
    try {
      const text = await readFileText(file)
      setPassportName(file.name)
      setPassportText(text)
      setComparison(null)
      setError(null)
    } finally {
      setReadingPassport(false)
    }
  }

  async function handleCompare() {
    if (!subjectKey) {
      setError('Set an Agent Subject filter before comparing portable reputation.')
      return
    }
    if (!passportText) {
      setError('Upload a passport JSON file before running comparison.')
      return
    }

    setLoading(true)
    setError(null)
    try {
      const passport = JSON.parse(passportText)
      const next = await fetchReputationComparison(subjectKey, passport)
      setComparison(next)
    } catch (nextError) {
      setComparison(null)
      setError(nextError instanceof Error ? nextError.message : String(nextError))
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="portable-reputation-panel" aria-label="Portable reputation comparison">
      <div className="operator-summary-header">
        <div>
          <h2>Portable Reputation Comparison</h2>
          <p>Compare a passport artifact against the live local score for the selected subject.</p>
        </div>
      </div>

      <div className="portable-compare-controls">
        <div className="portable-compare-subject">
          <span className="operator-card-label">Agent Subject</span>
          <strong>{subjectKey || 'Set an Agent Subject filter to enable comparison'}</strong>
        </div>
        <label className="portable-compare-upload">
          <span className="operator-card-label">Passport JSON</span>
          <input type="file" accept="application/json,.json" onChange={handlePassportChange} />
          <span>{readingPassport ? 'Reading passport…' : passportName || 'No file selected'}</span>
        </label>
        <button
          className="btn-page"
          type="button"
          onClick={handleCompare}
          disabled={loading || readingPassport || !subjectKey || !passportText}
        >
          {loading ? 'Comparing...' : readingPassport ? 'Loading Passport...' : 'Run Comparison'}
        </button>
      </div>

      {error && <div className="operator-summary-state operator-summary-error">{error}</div>}

      {comparison && (
        <div className="portable-compare-grid">
          {(() => {
            const sharedEvidence = comparison.sharedEvidence ?? {
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
            }

            return (
              <>
          <article className="operator-card">
            <span className="operator-card-label">Subject Match</span>
            <strong className="operator-card-value">
              {comparison.subjectMatches ? 'Match' : 'Mismatch'}
            </strong>
            <div className="operator-card-metrics">
              <span>Local {comparison.subjectKey}</span>
              <span>Passport {comparison.passportSubject}</span>
            </div>
          </article>

          <article className="operator-card">
            <span className="operator-card-label">Local Score</span>
            <strong className="operator-card-value">
              {comparison.local.effectiveScore.toFixed(3)}
            </strong>
            <div className="operator-card-metrics">
              <span>{comparison.local.scoringSource}</span>
              <span>{comparison.local.probationary ? 'probationary' : 'stable'}</span>
              <span>{comparison.local.resolvedTier?.name ?? 'no tier'}</span>
            </div>
          </article>

          <article className="operator-card">
            <span className="operator-card-label">Portable Policy</span>
            <strong className="operator-card-value">
              {comparison.passportEvaluation
                ? comparison.passportEvaluation.accepted
                  ? 'Accepted'
                  : 'Rejected'
                : 'Not evaluated'}
            </strong>
            <div className="operator-card-metrics">
              <span>{comparison.passportVerification.credentialCount} credential(s)</span>
              <span>{comparison.passportVerification.issuerCount} issuer(s)</span>
              <span>
                {comparison.passportVerification.issuer ??
                  comparison.passportVerification.issuers.join(', ')}
              </span>
            </div>
          </article>

          <article className="operator-card operator-card-wide">
            <span className="operator-card-label">Credential Drift</span>
            <div className="portable-compare-list">
              {comparison.credentialDrifts.map((credential) => (
                <div className="portable-compare-row" key={`${credential.issuer}-${credential.index}`}>
                  <div>
                    <strong>{credential.issuer}</strong>
                    <div className="operator-card-caption">
                      receipt_count {credential.receiptCount}, lineage_records {credential.lineageRecords}
                    </div>
                  </div>
                  <div className="portable-compare-metrics">
                    <span>Composite {driftLabel(credential.metrics.compositeScore.localMinusPortable)}</span>
                    <span>Reliability {driftLabel(credential.metrics.reliability.localMinusPortable)}</span>
                    <span>Delegation {driftLabel(credential.metrics.delegationHygiene.localMinusPortable)}</span>
                    <span>Stewardship {driftLabel(credential.metrics.resourceStewardship.localMinusPortable)}</span>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="operator-card operator-card-wide">
            <span className="operator-card-label">Shared Evidence References</span>
            <strong className="operator-card-value">
              {sharedEvidence.summary.matchingShares}
            </strong>
            <div className="operator-card-metrics">
              <span>{sharedEvidence.summary.matchingReferences} references</span>
              <span>{sharedEvidence.summary.matchingLocalReceipts} local receipts</span>
              <span>{sharedEvidence.summary.remoteLineageRecords} remote lineage</span>
            </div>
            <div className="portable-compare-list">
              {sharedEvidence.references.map((reference) => (
                <div
                  className="portable-compare-row"
                  key={`${reference.share.shareId}-${reference.capabilityId}`}
                >
                  <div>
                    <strong>{reference.share.partner}</strong>
                    <div className="operator-card-caption">
                      share {reference.share.shareId}, remote capability {reference.capabilityId}
                    </div>
                  </div>
                  <div className="portable-compare-metrics">
                    <span>Receipts {reference.matchedLocalReceipts}</span>
                    <span>Allow {reference.allowCount}</span>
                    <span>Deny {reference.denyCount}</span>
                    <span>Anchor {reference.localAnchorCapabilityId ?? '--'}</span>
                  </div>
                </div>
              ))}
            </div>
          </article>
              </>
            )
          })()}
        </div>
      )}
    </section>
  )
}
