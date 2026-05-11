import { useEffect, useState } from 'react'

import { fetchRelayObservabilityReport } from '../api'
import type { RelayObservabilityReport } from '../types'

function formatDuration(ms?: number | null): string {
  if (ms === undefined || ms === null) return 'unknown'
  if (ms < 60_000) return `${Math.round(ms / 1_000)}s`
  return `${Math.round(ms / 60_000)}m`
}

function plural(count: number, singular: string): string {
  return count === 1 ? `1 ${singular}` : `${count} ${singular}s`
}

function latestFailure(report: RelayObservabilityReport): string {
  const failure = report.recentFailures[0]
  if (!failure) return 'none'
  return `${failure.code} (${failure.count})`
}

export function RelayObservabilitySummary() {
  const [report, setReport] = useState<RelayObservabilityReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setUnavailable(false)
    fetchRelayObservabilityReport()
      .then((next) => {
        if (!cancelled) {
          setReport(next)
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setReport(null)
          setUnavailable(true)
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <section className="operator-summary-state">Loading relay observability...</section>
  }

  if (unavailable || !report) {
    return (
      <section className="operator-summary-state">
        Relay observability unknown. Receipt dashboard data remains available.
      </section>
    )
  }

  const directoryLabel = report.directory.activeVersion
    ? `Directory v${report.directory.activeVersion}`
    : 'Directory unknown'

  return (
    <section className="operator-summary relay-observability" aria-label="Relay observability">
      <div className="operator-summary-header">
        <div>
          <h2>Relay Observability</h2>
          <p>Verifier-owned directory state and local relay pressure from the canonical report.</p>
        </div>
        <div className="operator-summary-stamp">
          Generated {new Date(report.generatedAtUnixMs).toLocaleString()}
        </div>
      </div>

      <div className="operator-summary-grid">
        <article className="operator-card">
          <span className="operator-card-label">Directory</span>
          <strong className="operator-card-value">{directoryLabel}</strong>
          <div className="operator-card-metrics">
            <span>{plural(report.directory.removedPeerCount, 'removed peer')}</span>
            <span>{report.directory.rejectedCandidateCount} rejected candidates</span>
            <span>{report.directory.profile}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Outbox Pressure</span>
          <strong className="operator-card-value">
            {report.queue.pending + report.queue.retry + report.queue.leased}
          </strong>
          <div className="operator-card-metrics">
            <span>{report.queue.retry} retry</span>
            <span>{report.queue.leased} leased</span>
            <span>oldest {formatDuration(report.queue.oldestPendingAgeMs)}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Dead Letters</span>
          <strong className="operator-card-value">{report.queue.deadLetter}</strong>
          <div className="operator-card-metrics">
            <span>{report.queue.staleLeaseCount} stale leases</span>
            <span>{report.queue.inboxCount} inbox</span>
            <span>{report.queue.cursorCount} cursors</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Recent Failures</span>
          <strong className="operator-card-value">{latestFailure(report)}</strong>
          <div className="operator-card-metrics">
            <span>{report.recommendations.length} recommendations</span>
            <span>{report.accepted ? 'accepted' : report.code}</span>
          </div>
        </article>
      </div>
    </section>
  )
}
