import { useEffect, useState } from 'react'
import { getToken } from './api'
import type { Filters } from './types'
import { FilterSidebar } from './components/FilterSidebar'
import { ReceiptTable } from './components/ReceiptTable'

const INITIAL_FILTERS: Filters = {
  agentSubject: '',
  toolServer: '',
  toolName: '',
  outcome: '',
  since: undefined,
  until: undefined,
}

export default function App() {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  const [token, setToken] = useState<string | null>(null)

  useEffect(() => {
    setToken(getToken())
  }, [])

  const missingToken = token !== null && token.length === 0

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>Chio Receipt Dashboard</h1>
      </header>
      {token === null ? (
        <div className="main-content">
          <div className="state-loading">Checking dashboard access...</div>
        </div>
      ) : missingToken ? (
        <div className="main-content">
          <section className="auth-notice">
            <h2>Bearer token required</h2>
            <p>
              Provide a trust-control bearer token via <code>?token=&lt;value&gt;</code> on the
              first load, or set <code>sessionStorage.chio_token</code> before opening the
              dashboard.
            </p>
            <pre className="detail-json">http://localhost:7391/?token=my-service-token</pre>
          </section>
        </div>
      ) : (
        <div className="app-body">
          <FilterSidebar filters={filters} onFiltersChange={setFilters} />
          <ReceiptTable filters={filters} />
        </div>
      )}
    </div>
  )
}
