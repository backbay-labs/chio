import { Suspense, lazy, useEffect, useRef, useState } from 'react'
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { format } from 'date-fns'
import { fetchAgentCostSeries, fetchLineage, fetchReceipts } from '../api'
import type { Filters, Receipt } from '../types'
import { decisionKind, formatMinorUnits, receiptSubjectKey } from '../types'
import { OperatorSummary } from './OperatorSummary'
import { PortableReputationPanel } from './PortableReputationPanel'
import { RelayAlertRoutingSummary } from './RelayAlertRoutingSummary'
import { RelayObservabilitySummary } from './RelayObservabilitySummary'

const DelegationChain = lazy(async () => {
  const module = await import('./DelegationChain')
  return { default: module.DelegationChain }
})

const BudgetSparkline = lazy(async () => {
  const module = await import('./BudgetSparkline')
  return { default: module.BudgetSparkline }
})

interface ReceiptTableProps {
  filters: Filters
}

interface DetailPanelProps {
  receipt: Receipt
  onClose: () => void
}

function decisionBadgeClass(kind: string): string {
  switch (kind) {
    case 'allow': return 'badge badge-allow'
    case 'deny': return 'badge badge-deny'
    case 'cancelled': return 'badge badge-cancelled'
    default: return 'badge badge-incomplete'
  }
}

function DetailPanel({ receipt, onClose }: DetailPanelProps) {
  const financial = receipt.metadata?.financial
  const kind = decisionKind(receipt.decision)
  const [sparkData, setSparkData] = useState<{ time: string; cost: number }[]>([])
  const subjectKey = receiptSubjectKey(receipt)

  useEffect(() => {
    let cancelled = false

    if (!financial) {
      setSparkData([])
      return () => {
        cancelled = true
      }
    }

    async function loadSparkData() {
      try {
        let resolvedSubjectKey = subjectKey
        if (!resolvedSubjectKey) {
          const snapshot = await fetchLineage(receipt.capability_id)
          resolvedSubjectKey = snapshot.subject_key
        }

        if (!resolvedSubjectKey) {
          if (!cancelled) {
            setSparkData([])
          }
          return
        }

        const data = await fetchAgentCostSeries(resolvedSubjectKey)
        if (!cancelled) {
          setSparkData(data)
        }
      } catch {
        if (!cancelled) {
          setSparkData([])
        }
      }
    }

    void loadSparkData()

    return () => {
      cancelled = true
    }
  }, [receipt.capability_id, financial, subjectKey])

  return (
    <aside className="detail-panel">
      <div className="detail-panel-header">
        <span>Receipt Detail</span>
        <button className="btn-close" onClick={onClose} aria-label="Close">
          &times;
        </button>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Decision</div>
        <span className={decisionBadgeClass(kind)}>
          {kind.charAt(0).toUpperCase() + kind.slice(1)}
        </span>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Tool</div>
        <span>{receipt.tool_server} / {receipt.tool_name}</span>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Timestamp</div>
        <span>{format(new Date(receipt.timestamp * 1000), 'yyyy-MM-dd HH:mm:ss')}</span>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Capability ID</div>
        <span
          title={receipt.capability_id}
          style={{ wordBreak: 'break-all', fontSize: 12 }}
        >
          {receipt.capability_id}
        </span>
      </div>

      {subjectKey && (
        <div className="detail-section">
          <div className="detail-section-title">Agent Subject</div>
          <span title={subjectKey} style={{ wordBreak: 'break-all', fontSize: 12 }}>
            {subjectKey}
          </span>
        </div>
      )}

      {financial && (
        <div className="detail-section">
          <div className="detail-section-title">Financial</div>
          <div style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div>Cost: <strong>{formatMinorUnits(financial.cost_charged, financial.currency)}</strong></div>
            <div>Remaining: {formatMinorUnits(financial.budget_remaining, financial.currency)}</div>
            <div>Budget: {formatMinorUnits(financial.budget_total, financial.currency)}</div>
            <div>Depth: {financial.delegation_depth}</div>
            <div>Settlement: {financial.settlement_status}</div>
          </div>
        </div>
      )}

      {financial && (
        <div className="detail-section">
          <div className="detail-section-title">Cost over Time</div>
          <Suspense fallback={<div className="sparkline-placeholder">Loading chart...</div>}>
            <BudgetSparkline data={sparkData} />
          </Suspense>
        </div>
      )}

      <div className="detail-section">
        <div className="detail-section-title">Delegation Chain</div>
        <Suspense fallback={<div className="state-loading">Loading chain...</div>}>
          <DelegationChain capabilityId={receipt.capability_id} />
        </Suspense>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Parameters</div>
        <pre className="detail-json">
          {JSON.stringify(receipt.action.parameters, null, 2)}
        </pre>
      </div>

      <div className="detail-section">
        <div className="detail-section-title">Full Receipt</div>
        <pre className="detail-json">
          {JSON.stringify(receipt, null, 2)}
        </pre>
      </div>
    </aside>
  )
}

const columnHelper = createColumnHelper<Receipt>()

const columns = [
  columnHelper.accessor('timestamp', {
    header: 'Time',
    cell: (info) =>
      format(new Date(info.getValue() * 1000), 'yyyy-MM-dd HH:mm:ss'),
  }),
  columnHelper.accessor(
    (row) => `${row.tool_server}/${row.tool_name}`,
    {
      id: 'tool',
      header: 'Tool',
      cell: (info) => info.getValue(),
    },
  ),
  columnHelper.accessor('decision', {
    header: 'Outcome',
    cell: (info) => {
      const kind = decisionKind(info.getValue())
      return (
        <span className={decisionBadgeClass(kind)}>
          {kind.charAt(0).toUpperCase() + kind.slice(1)}
        </span>
      )
    },
  }),
  columnHelper.accessor('capability_id', {
    header: 'Capability',
    cell: (info) => (
      <span
        className="truncated"
        title={info.getValue()}
      >
        {info.getValue().slice(0, 8)}
      </span>
    ),
  }),
  columnHelper.accessor(
    (row) => row.metadata?.financial?.cost_charged,
    {
      id: 'cost',
      header: 'Cost',
      cell: (info) => {
        const value = info.getValue()
        if (value === undefined) return '--'
        const row = info.row.original
        const currency = row.metadata?.financial?.currency ?? 'USD'
        return formatMinorUnits(value, currency)
      },
    },
  ),
]

/**
 * Receipt table with server-side cursor pagination and a detail panel.
 * Uses TanStack Table 8 with manualPagination: true.
 */
export function ReceiptTable({ filters }: ReceiptTableProps) {
  const [receipts, setReceipts] = useState<Receipt[]>([])
  const [totalCount, setTotalCount] = useState(0)
  const [nextCursor, setNextCursor] = useState<number | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [cursorStack, setCursorStack] = useState<(number | null)[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedReceipt, setSelectedReceipt] = useState<Receipt | null>(null)

  // Track filters as a ref to detect changes (reset cursor when filters change)
  const prevFiltersRef = useRef<string>('')

  useEffect(() => {
    const filtersJson = JSON.stringify(filters)
    if (filtersJson !== prevFiltersRef.current) {
      // Filters changed -- reset to first page
      prevFiltersRef.current = filtersJson
      setCursor(null)
      setCursorStack([])
    }
  }, [filters])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)

    fetchReceipts(filters, cursor, 50)
      .then((result) => {
        if (!cancelled) {
          setReceipts(result.receipts)
          setTotalCount(result.totalCount)
          setNextCursor(result.nextCursor)
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
  }, [filters, cursor])

  const table = useReactTable({
    data: receipts,
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    pageCount: -1,
  })

  function handleNext() {
    if (nextCursor === null) return
    setCursorStack((stack) => [...stack, cursor])
    setCursor(nextCursor)
  }

  function handlePrevious() {
    if (cursorStack.length === 0) return
    const stack = [...cursorStack]
    const prev = stack.pop() ?? null
    setCursorStack(stack)
    setCursor(prev)
  }

  if (loading) {
    return (
      <div className="main-content">
        <div className="state-loading">Loading receipts...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="main-content">
        <div className="state-error">Error loading receipts: {error}</div>
      </div>
    )
  }

  return (
    <div className="main-content" style={{ flexDirection: 'row', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="receipt-table-container">
          <OperatorSummary filters={filters} />
          <RelayObservabilitySummary />
          <RelayAlertRoutingSummary />
          <PortableReputationPanel subjectKey={filters.agentSubject || undefined} />
          {receipts.length === 0 ? (
            <div className="state-empty">No receipts found</div>
          ) : (
            <table className="receipt-table">
              <thead>
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id}>
                    {headerGroup.headers.map((header) => (
                      <th key={header.id}>
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelectedReceipt(row.original)}
                    style={{ cursor: 'pointer' }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="pagination">
          <span className="pagination-info">
            {totalCount} total receipt{totalCount !== 1 ? 's' : ''}
          </span>
          <button
            className="btn-page"
            onClick={handlePrevious}
            disabled={cursorStack.length === 0}
          >
            Previous
          </button>
          <button
            className="btn-page"
            onClick={handleNext}
            disabled={nextCursor === null}
          >
            Next
          </button>
        </div>
      </div>

      {selectedReceipt && (
        <DetailPanel
          receipt={selectedReceipt}
          onClose={() => setSelectedReceipt(null)}
        />
      )}
    </div>
  )
}
