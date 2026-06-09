import { useEffect, useState } from 'react'

import {
  fetchRelayAlertAssuranceArchiveExtractionReport,
  fetchRelayAlertAssuranceArchivePackageReport,
  fetchRelayAlertAssuranceArchiveReport,
  fetchRelayAlertAssuranceArchiveRestoreDrillReport,
  fetchRelayAlertAssuranceCloseoutReport,
  fetchRelayAlertAssuranceExternalRetentionReviewReport,
  fetchRelayAlertAssuranceExportReport,
  fetchRelayAlertAssurancePackage,
  fetchRelayAlertAssurancePhysicalArchiveDrillReport,
  fetchRelayAlertAssuranceReplayReport,
  fetchRelayAlertAssuranceRetentionReport,
  fetchRelayAlertAssuranceRetentionHandoffReport,
} from '../api'
import type {
  RelayAlertAssuranceArchiveExtractionReport,
  RelayAlertAssuranceArchivePackageReport,
  RelayAlertAssuranceArchiveReport,
  RelayAlertAssuranceArchiveRestoreDrillReport,
  RelayAlertAssuranceCloseoutReport,
  RelayAlertAssuranceExternalRetentionReviewReport,
  RelayAlertAssuranceExportReport,
  RelayAlertAssurancePackage,
  RelayAlertAssurancePhysicalArchiveDrillReport,
  RelayAlertAssuranceReplayReport,
  RelayAlertAssuranceRetentionHandoffReport,
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
    archivePackageReport: RelayAlertAssuranceArchivePackageReport | null
    extractionReport: RelayAlertAssuranceArchiveExtractionReport | null
    restoreReport: RelayAlertAssuranceArchiveRestoreDrillReport | null
    physicalArchiveReport: RelayAlertAssurancePhysicalArchiveDrillReport | null
    retentionHandoffReport: RelayAlertAssuranceRetentionHandoffReport | null
    externalRetentionReport: RelayAlertAssuranceExternalRetentionReviewReport | null
  }>({
    packageReport: null,
    exportReport: null,
    replayReport: null,
    retentionReport: null,
    archiveReport: null,
    closeoutReport: null,
    archivePackageReport: null,
    extractionReport: null,
    restoreReport: null,
    physicalArchiveReport: null,
    retentionHandoffReport: null,
    externalRetentionReport: null,
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
      fetchRelayAlertAssuranceArchivePackageReport(),
      fetchRelayAlertAssuranceArchiveExtractionReport(),
      fetchRelayAlertAssuranceArchiveRestoreDrillReport(),
      fetchRelayAlertAssurancePhysicalArchiveDrillReport(),
      fetchRelayAlertAssuranceRetentionHandoffReport(),
      fetchRelayAlertAssuranceExternalRetentionReviewReport(),
    ])
      .then(([
        packageResult,
        exportResult,
        replayResult,
        retentionResult,
        archiveResult,
        closeoutResult,
        archivePackageResult,
        extractionResult,
        restoreResult,
        physicalArchiveResult,
        retentionHandoffResult,
        externalRetentionResult,
      ]) => {
        if (!cancelled) {
          setState({
            packageReport: packageResult.status === 'fulfilled' ? packageResult.value : null,
            exportReport: exportResult.status === 'fulfilled' ? exportResult.value : null,
            replayReport: replayResult.status === 'fulfilled' ? replayResult.value : null,
            retentionReport: retentionResult.status === 'fulfilled' ? retentionResult.value : null,
            archiveReport: archiveResult.status === 'fulfilled' ? archiveResult.value : null,
            closeoutReport: closeoutResult.status === 'fulfilled' ? closeoutResult.value : null,
            archivePackageReport: archivePackageResult.status === 'fulfilled' ? archivePackageResult.value : null,
            extractionReport: extractionResult.status === 'fulfilled' ? extractionResult.value : null,
            restoreReport: restoreResult.status === 'fulfilled' ? restoreResult.value : null,
            physicalArchiveReport: physicalArchiveResult.status === 'fulfilled' ? physicalArchiveResult.value : null,
            retentionHandoffReport: retentionHandoffResult.status === 'fulfilled' ? retentionHandoffResult.value : null,
            externalRetentionReport:
              externalRetentionResult.status === 'fulfilled' ? externalRetentionResult.value : null,
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
            archivePackageReport: null,
            extractionReport: null,
            restoreReport: null,
            physicalArchiveReport: null,
            retentionHandoffReport: null,
            externalRetentionReport: null,
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
  const archivePackageStatus = state.archivePackageReport?.accepted
    ? 'verified'
    : (state.archivePackageReport?.code ?? 'unknown')
  const extractionStatus = state.extractionReport?.accepted
    ? 'safe'
    : (state.extractionReport?.code ?? 'unknown')
  const restoreStatus = state.restoreReport?.accepted
    ? 'ready'
    : (state.restoreReport?.code ?? 'unknown')
  const physicalStatus = state.physicalArchiveReport?.accepted
    ? 'readback'
    : (state.physicalArchiveReport?.code ?? 'unknown')
  const handoffStatus = state.retentionHandoffReport?.accepted
    ? 'ready'
    : (state.retentionHandoffReport?.code ?? 'unknown')
  const externalRetentionStatus = state.externalRetentionReport?.accepted
    ? 'ready'
    : (state.externalRetentionReport?.code ?? 'unknown')

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

        <article className="operator-card">
          <span className="operator-card-label">Archive Package</span>
          <strong className="operator-card-value">{archivePackageStatus}</strong>
          <div className="operator-card-metrics">
            <span>extraction {extractionStatus}</span>
            <span>generation {state.archivePackageReport?.packageGeneration ?? 'unknown'}</span>
          </div>
          <div className="operator-card-metrics">
            <span>restore {restoreStatus}</span>
            <span>{state.restoreReport?.quarantineCount ?? 0} quarantine</span>
          </div>
          <div className="operator-card-metrics">
            <span>{state.archivePackageReport?.packageMemberCount ?? 0} members</span>
            <span>readback {physicalStatus}</span>
            <span>handoff {handoffStatus}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">External Retention</span>
          <strong className="operator-card-value">{externalRetentionStatus}</strong>
          <div className="operator-card-metrics">
            <span>
              {state.externalRetentionReport?.readyCount ?? 0}/
              {state.externalRetentionReport?.packageCount ?? 0} ready
            </span>
            <span>latest generation {state.externalRetentionReport?.latestPackageGeneration ?? 'unknown'}</span>
          </div>
          <div className="operator-card-metrics">
            <span>{state.externalRetentionReport?.quarantineCount ?? 0} quarantine</span>
            <span>{state.externalRetentionReport?.driftCount ?? 0} drift</span>
            <span>{state.externalRetentionReport?.insufficientSampleCount ?? 0} insufficient sample</span>
          </div>
        </article>
      </div>
    </section>
  )
}
