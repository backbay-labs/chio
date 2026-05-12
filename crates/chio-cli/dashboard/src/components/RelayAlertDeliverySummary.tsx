import { useEffect, useState } from 'react'

import { fetchRelayAlertDeliveryReport, fetchRelayAlertHandoffReport } from '../api'
import type { RelayAlertDeliveryReport, RelayAlertHandoffReport } from '../types'

interface RelayAlertDeliveryState {
  handoffReport: RelayAlertHandoffReport | null
  deliveryReport: RelayAlertDeliveryReport | null
}

function deliveryStatus(report: RelayAlertDeliveryReport | null): string {
  if (!report) return 'unknown'
  if (report.accepted) return 'accepted'
  return report.code
}

function routeCoverage(report: RelayAlertHandoffReport | null): string {
  const routeCount = report?.routes.length ?? 0
  const alertCount = report?.routes.reduce((count, route) => count + route.alertCodes.length, 0) ?? 0
  return `${routeCount} routes / ${alertCount} alerts`
}

export function RelayAlertDeliverySummary() {
  const [state, setState] = useState<RelayAlertDeliveryState>({
    handoffReport: null,
    deliveryReport: null,
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)

    Promise.allSettled([fetchRelayAlertHandoffReport(), fetchRelayAlertDeliveryReport()])
      .then(([handoffResult, deliveryResult]) => {
        if (!cancelled) {
          setState({
            handoffReport: handoffResult.status === 'fulfilled' ? handoffResult.value : null,
            deliveryReport: deliveryResult.status === 'fulfilled' ? deliveryResult.value : null,
          })
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({ handoffReport: null, deliveryReport: null })
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) {
    return <section className="operator-summary-state">Loading relay alert delivery...</section>
  }

  if (!state.handoffReport && !state.deliveryReport) {
    return (
      <section className="operator-summary-state">
        Relay alert delivery unknown. Receipt dashboard data remains available.
      </section>
    )
  }

  const handoff = state.handoffReport
  const delivery = state.deliveryReport
  const deliveryUnknown = delivery === null

  return (
    <section className="operator-summary relay-alert-delivery" aria-label="Relay alert delivery">
      <div className="operator-summary-header">
        <div>
          <h2>Relay Alert Delivery</h2>
          <p>Downstream handoff and delivery evidence from local operator reports.</p>
        </div>
        <div className="operator-summary-stamp">
          Generated{' '}
          {new Date((delivery ?? handoff)?.generatedAtUnixMs ?? Date.now()).toLocaleString()}
        </div>
      </div>

      <div className="operator-summary-grid">
        <article className="operator-card">
          <span className="operator-card-label">Handoff</span>
          <strong className="operator-card-value">{handoff?.code ?? 'unknown'}</strong>
          <div className="operator-card-metrics">
            <span>{handoff?.criticalFiringCount ?? 0} critical firing</span>
            <span>{routeCoverage(handoff)}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Delivery</span>
          <strong className="operator-card-value">{deliveryStatus(delivery)}</strong>
          <div className="operator-card-metrics">
            <span>{delivery?.deliveredCount ?? 0} delivered</span>
            <span>{deliveryUnknown ? 'unknown' : `${delivery?.failedCount ?? 0} failed`}</span>
          </div>
        </article>

        <article className="operator-card">
          <span className="operator-card-label">Downstream Evidence</span>
          <strong className="operator-card-value">{delivery?.results.length ?? 0}</strong>
          <div className="operator-card-metrics">
            <span>{delivery?.delayedCount ?? 0} delayed</span>
            <span>{delivery?.unknownCount ?? 0} unknown</span>
          </div>
        </article>
      </div>
    </section>
  )
}
