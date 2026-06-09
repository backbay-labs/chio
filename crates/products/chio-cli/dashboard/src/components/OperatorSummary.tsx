import { useEffect, useState } from 'react'

import { fetchOperatorReport } from '../api'
import type { Filters, OperatorReport } from '../types'
import { formatMinorUnits } from '../types'

interface OperatorSummaryProps {
  filters: Filters
}

function formatRate(rate?: number): string {
  if (rate === undefined) return '--'
  return `${Math.round(rate * 100)}%`
}

function abbreviate(value: string): string {
  if (value.length <= 18) return value
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

function summaryCurrency(report: OperatorReport): string {
  const rowCurrency = report.budgetUtilization.rows.find((row) => row.currency)?.currency
  if (rowCurrency) return rowCurrency
  return 'USD'
}

export function OperatorSummary({ filters }: OperatorSummaryProps) {
  const [report, setReport] = useState<OperatorReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)

    fetchOperatorReport(filters)
      .then((next) => {
        if (!cancelled) {
          setReport(next)
          setLoading(false)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err))
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [filters])

  if (loading) {
    return <section className="operator-summary-state">Loading operator report...</section>
  }

  if (error) {
    return (
      <section className="operator-summary-state operator-summary-error">
        Operator report unavailable: {error}
      </section>
    )
  }

  if (!report) {
    return null
  }

  const activity = report.activity.summary
  const budget = report.budgetUtilization.summary
  const compliance = report.compliance
  const sharedEvidenceReport = report.sharedEvidence ?? {
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
  const sharedEvidence = sharedEvidenceReport.summary
  const topRoot = report.costAttribution.byRoot[0]
  const currency = summaryCurrency(report)

  return (
    <section className="operator-summary" aria-label="Operator report">
      <div className="operator-summary-header">
        <div>
          <h2>Operator Report</h2>
          <p>Activity, budget pressure, and evidence readiness for the current filter set.</p>
        </div>
        <div className="operator-summary-stamp">
          Generated {new Date(report.generatedAt * 1000).toLocaleString()}
        </div>
      </div>

      <div className="operator-summary-grid">
        <article className="operator-card">
          <span className="operator-card-label">Activity</span>
          <strong className="operator-card-value">{activity.totalReceipts}</strong>
          <div className="operator-card-metrics">
            <span>{activity.allowCount} allow</span>
            <span>{activity.denyCount} deny</span>
            <span>{activity.incompleteCount} incomplete</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Spend</span>
          <strong className="operator-card-value">
            {formatMinorUnits(activity.totalCostCharged, currency)}
          </strong>
          <div className="operator-card-metrics">
            <span>Attempted {formatMinorUnits(activity.totalAttemptedCost, currency)}</span>
            <span>{report.costAttribution.summary.distinctRootSubjects} roots</span>
          </div>
          {topRoot && (
            <div className="operator-card-caption">
              Top root {abbreviate(topRoot.rootSubjectKey)}
            </div>
          )}
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Budget Pressure</span>
          <strong className="operator-card-value">{budget.matchingGrants}</strong>
          <div className="operator-card-metrics">
            <span>{budget.nearLimitCount} near limit</span>
            <span>{budget.exhaustedCount} exhausted</span>
            <span>{budget.distinctCapabilities} capabilities</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Compliance</span>
          <strong className="operator-card-value">
            {formatRate(compliance.checkpointCoverageRate)}
          </strong>
          <div className="operator-card-metrics">
            <span>{compliance.evidenceReadyReceipts} checkpointed</span>
            <span>{formatRate(compliance.lineageCoverageRate)} lineage</span>
            <span>{compliance.uncheckpointedReceipts} uncheckpointed</span>
          </div>
        </article>

        <article className="operator-card operator-card-wide">
          <span className="operator-card-label">Settlement And Export</span>
          <strong className="operator-card-value">
            {compliance.proofsComplete ? 'Proofs complete' : 'Proof coverage incomplete'}
          </strong>
          <div className="operator-card-metrics">
            <span>{compliance.pendingSettlementReceipts} pending settlement</span>
            <span>{compliance.failedSettlementReceipts} failed settlement</span>
            <span>
              {compliance.directEvidenceExportSupported
                ? 'Exact export supported'
                : 'Export scope caveat'}
            </span>
          </div>
          {compliance.exportScopeNote && (
            <div className="operator-card-caption">{compliance.exportScopeNote}</div>
          )}
        </article>

        <article className="operator-card operator-card-wide">
          <span className="operator-card-label">Shared Evidence</span>
          <strong className="operator-card-value">{sharedEvidence.matchingShares}</strong>
          <div className="operator-card-metrics">
            <span>{sharedEvidence.matchingReferences} remote references</span>
            <span>{sharedEvidence.matchingLocalReceipts} local receipts</span>
            <span>{sharedEvidence.remoteLineageRecords} remote lineage rows</span>
          </div>
          {sharedEvidenceReport.references[0] && (
            <div className="operator-card-caption">
              Latest share {abbreviate(sharedEvidenceReport.references[0].share.shareId)} from{' '}
              {sharedEvidenceReport.references[0].share.partner}
            </div>
          )}
        </article>
      </div>
    </section>
  )
}
