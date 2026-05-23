import { useEffect, useState } from 'react'

import {
  fetchRelayAlertAssuranceArchiveReport,
  fetchRelayAlertAssuranceCloseoutReport,
  fetchRelayAlertAssuranceExportReport,
  fetchRelayAlertAssurancePackage,
  fetchRelayAlertAssuranceReplayReport,
  fetchRelayAlertAssuranceRetentionReport,
} from '../api'
import type {
  RelayAlertAssuranceArchiveReport,
  RelayAlertAssuranceCloseoutReport,
  RelayAlertAssuranceExportReport,
  RelayAlertAssurancePackage,
  RelayAlertAssuranceReplayReport,
  RelayAlertAssuranceRetentionReport,
} from '../types'

function statusLabel(report: RelayAlertAssurancePackage): string {
  if (report.accepted) return 'accepted'
  return report.code
}

function actionSummary(report: RelayAlertAssurancePackage): string {
  if (report.operatorActionCodes.length === 0) return 'none'
  return report.operatorActionCodes.slice(0, 2).join(', ')
}

export function RelayAlertAssuranceSummary() {
  const [state, setState] = useState<{
    packageReport: RelayAlertAssurancePackage | null
    exportReport: RelayAlertAssuranceExportReport | null
    replayReport: RelayAlertAssuranceReplayReport | null
    retentionReport: RelayAlertAssuranceRetentionReport | null
    archiveReport: RelayAlertAssuranceArchiveReport | null
    closeoutReport: RelayAlertAssuranceCloseoutReport | null
  }>({
    packageReport: null,
    exportReport: null,
    replayReport: null,
    retentionReport: null,
    archiveReport: null,
    closeoutReport: null,
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    Promise.allSettled([
      fetchRelayAlertAssurancePackage(),
      fetchRelayAlertAssuranceExportReport(),
      fetchRelayAlertAssuranceReplayReport(),
      fetchRelayAlertAssuranceRetentionReport(),
      fetchRelayAlertAssuranceArchiveReport(),
      fetchRelayAlertAssuranceCloseoutReport(),
    ])
      .then(([packageResult, exportResult, replayResult, retentionResult, archiveResult, closeoutResult]) => {
        if (!cancelled) {
          setState({
            packageReport: packageResult.status === 'fulfilled' ? packageResult.value : null,
            exportReport: exportResult.status === 'fulfilled' ? exportResult.value : null,
            replayReport: replayResult.status === 'fulfilled' ? replayResult.value : null,
            retentionReport: retentionResult.status === 'fulfilled' ? retentionResult.value : null,
            archiveReport: archiveResult.status === 'fulfilled' ? archiveResult.value : null,
            closeoutReport: closeoutResult.status === 'fulfilled' ? closeoutResult.value : null,
          })
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({
            packageReport: null,
            exportReport: null,
            replayReport: null,
            retentionReport: null,
            archiveReport: null,
            closeoutReport: null,
          })
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <section className="operator-summary-state">Loading relay alert assurance...</section>
  }

  if (!state.packageReport) {
    return (
      <section className="operator-summary-state">
        Relay alert assurance unknown. Firing alert and delivery state remain visible.
      </section>
    )
  }

  const report = state.packageReport
  const exportStatus = state.exportReport?.accepted ? 'verified' : (state.exportReport?.code ?? 'unknown')
  const replayStatus = state.replayReport?.accepted ? 'matched' : (state.replayReport?.code ?? 'unknown')
  const retentionStatus = state.retentionReport
    ? `${state.retentionReport.blockedCount} blocked`
    : 'unknown'
  const archiveStatus = state.archiveReport
    ? `${state.archiveReport.archiveReadyCount} ready`
    : 'unknown'
  const closeoutStatus = state.closeoutReport
    ? `${state.closeoutReport.closeoutBlockedCount} blocked`
    : 'unknown'
  const firstArchiveReview = state.archiveReport?.reviews[0]
  const bundleLabel = firstArchiveReview?.bundleId ?? 'unknown'

  return (
    <section className="operator-summary relay-alert-assurance" aria-label="Relay alert assurance">
      <div className="operator-summary-header">
        <div>
          <h2>Relay Alert Assurance</h2>
          <p>Bound operator package over alert, handoff, delivery, drift, and review evidence.</p>
        </div>
        <div className="operator-summary-stamp">
          Generated {new Date(report.generatedAtUnixMs).toLocaleString()}
        </div>
      </div>

      <div className="operator-summary-grid">
        <article className="operator-card">
          <span className="operator-card-label">Assurance</span>
          <strong className="operator-card-value">{statusLabel(report)}</strong>
          <div className="operator-card-metrics">
            <span>{report.criticalFiringAlertCount} critical firing</span>
            <span>{report.readyRouteCount} ready routes</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Evidence Chain</span>
          <strong className="operator-card-value">{report.normalizedCount}</strong>
          <div className="operator-card-metrics">
            <span>{report.deliveryAttentionCount} delivery attention</span>
            <span>{report.driftCount} drift</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Operator Action</span>
          <strong className="operator-card-value">{actionSummary(report)}</strong>
          <div className="operator-card-metrics">
            <span>{report.firingAlertCount} firing alerts</span>
            <span>{report.acknowledgementPendingCount} pending ack</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Export Lifecycle</span>
          <strong className="operator-card-value">{exportStatus}</strong>
          <div className="operator-card-metrics">
            <span>replay {replayStatus}</span>
            <span>retention {retentionStatus}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Archive Closeout</span>
          <strong className="operator-card-value">{closeoutStatus}</strong>
          <div className="operator-card-metrics">
            <span>archive {archiveStatus}</span>
            <span>bundle {bundleLabel}</span>
          </div>
          <div className="operator-card-metrics">
            <span>{state.archiveReport?.quarantineCount ?? 0} quarantine</span>
            <span>{state.closeoutReport?.legalHoldCount ?? 0} legal hold</span>
            <span>{state.closeoutReport?.eligibleForDeleteCount ?? 0} eligible</span>
          </div>
        </article>
      </div>
    </section>
  )
}
