import { useEffect, useState } from 'react'

import { fetchRelayAlertReport, fetchRelayTrendReport } from '../api'
import type { RelayAlert, RelayAlertReport, RelayTrendReport } from '../types'

interface RelayAlertRoutingState {
  alertReport: RelayAlertReport | null
  trendReport: RelayTrendReport | null
}

function countAlerts(alerts: RelayAlert[], state: RelayAlert['state']): number {
  return alerts.filter((alert) => alert.state === state).length
}

function topTrend(report: RelayTrendReport | null): string {
  const point = report?.points[0]
  if (!point) return 'none'
  return `${point.code} (${point.count})`
}

function severityRank(alert: RelayAlert): number {
  if (alert.severity === 'critical') return 3
  if (alert.severity === 'warning') return 2
  return 1
}

function primaryFiringAlert(alerts: RelayAlert[]): RelayAlert | undefined {
  let primary: RelayAlert | undefined
  for (const alert of alerts) {
    if (alert.state !== 'firing') continue
    if (!primary || severityRank(alert) > severityRank(primary)) {
      primary = alert
    }
  }
  return primary
}

export function RelayAlertRoutingSummary() {
  const [state, setState] = useState<RelayAlertRoutingState>({
    alertReport: null,
    trendReport: null,
  })
  const [loading, setLoading] = useState(true)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setUnavailable(false)

    Promise.allSettled([fetchRelayAlertReport(), fetchRelayTrendReport()])
      .then(([alertResult, trendResult]) => {
        if (!cancelled) {
          const alertReport = alertResult.status === 'fulfilled' ? alertResult.value : null
          const trendReport = trendResult.status === 'fulfilled' ? trendResult.value : null
          setState({ alertReport, trendReport })
          setUnavailable(alertReport === null)
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({ alertReport: null, trendReport: null })
          setUnavailable(true)
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <section className="operator-summary-state">Loading relay alerts...</section>
  }

  if (unavailable || !state.alertReport) {
    return (
      <section className="operator-summary-state">
        Relay alert routing unknown. Receipt dashboard data remains available.
      </section>
    )
  }

  const firing = countAlerts(state.alertReport.alerts, 'firing')
  const suppressed = countAlerts(state.alertReport.alerts, 'suppressed')
  const critical = state.alertReport.alerts.filter((alert) => alert.severity === 'critical').length
  const primary = primaryFiringAlert(state.alertReport.alerts)

  return (
    <section className="operator-summary relay-alert-routing" aria-label="Relay alert routing">
      <div className="operator-summary-header">
        <div>
          <h2>Relay Alerts</h2>
          <p>Routeable alert state and long-horizon trends from canonical relay reports.</p>
        </div>
        <div className="operator-summary-stamp">
          Generated {new Date(state.alertReport.generatedAtUnixMs).toLocaleString()}
        </div>
      </div>

      <div className="operator-summary-grid">
        <article className="operator-card">
          <span className="operator-card-label">Alert State</span>
          <strong className="operator-card-value">{state.alertReport.code}</strong>
          <div className="operator-card-metrics">
            <span>{firing} firing</span>
            <span>{suppressed} suppressed</span>
            <span>{critical} critical</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Primary Route</span>
          <strong className="operator-card-value">
            {primary?.notificationRoute ?? 'none'}
          </strong>
          <div className="operator-card-metrics">
            <span>{primary?.opsgenie ?? 'no ops route'}</span>
            <span>{state.alertReport.accepted ? 'accepted' : 'attention needed'}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Trend Window</span>
          <strong className="operator-card-value">{topTrend(state.trendReport)}</strong>
          <div className="operator-card-metrics">
            <span>{state.trendReport?.sourceReportCount ?? 0} reports</span>
            <span>{state.trendReport?.eventReportCount ?? 0} events</span>
          </div>
        </article>
      </div>
    </section>
  )
}
