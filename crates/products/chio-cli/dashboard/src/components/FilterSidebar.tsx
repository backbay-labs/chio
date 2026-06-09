import { Filter } from 'lucide-react'
import type { Filters } from '../types'

interface FilterSidebarProps {
  filters: Filters
  onFiltersChange: (filters: Filters) => void
}

const EMPTY_FILTERS: Filters = {
  agentSubject: '',
  toolServer: '',
  toolName: '',
  outcome: '',
  since: undefined,
  until: undefined,
}

/**
 * Convert a datetime-local input string (YYYY-MM-DDTHH:mm) to Unix seconds.
 * Returns undefined if the string is empty or invalid.
 */
function toUnixSeconds(value: string): number | undefined {
  if (!value) return undefined
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) return undefined
  return Math.floor(ms / 1000)
}

/**
 * Convert Unix seconds to a datetime-local input string (YYYY-MM-DDTHH:mm).
 * Returns empty string if value is undefined.
 */
function fromUnixSeconds(value: number | undefined): string {
  if (value === undefined) return ''
  // Use local time -- datetime-local inputs are always in local timezone
  const d = new Date(value * 1000)
  const pad = (n: number) => n.toString().padStart(2, '0')
  const yyyy = d.getFullYear()
  const mm = pad(d.getMonth() + 1)
  const dd = pad(d.getDate())
  const hh = pad(d.getHours())
  const min = pad(d.getMinutes())
  return `${yyyy}-${mm}-${dd}T${hh}:${min}`
}

export function FilterSidebar({ filters, onFiltersChange }: FilterSidebarProps) {
  function set<K extends keyof Filters>(key: K, value: Filters[K]) {
    onFiltersChange({ ...filters, [key]: value })
  }

  function clearFilters() {
    onFiltersChange(EMPTY_FILTERS)
  }

  return (
    <aside className="filter-sidebar">
      <div className="filter-sidebar-header">
        <Filter size={14} />
        <span>Filters</span>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-agent">Agent Subject</label>
        <input
          id="filter-agent"
          type="text"
          placeholder="hex key..."
          value={filters.agentSubject ?? ''}
          onChange={(e) => set('agentSubject', e.target.value)}
        />
      </div>

      <div className="filter-group">
        <label htmlFor="filter-tool-server">Tool Server</label>
        <input
          id="filter-tool-server"
          type="text"
          placeholder="server name..."
          value={filters.toolServer ?? ''}
          onChange={(e) => set('toolServer', e.target.value)}
        />
      </div>

      <div className="filter-group">
        <label htmlFor="filter-tool-name">Tool Name</label>
        <input
          id="filter-tool-name"
          type="text"
          placeholder="tool name..."
          value={filters.toolName ?? ''}
          onChange={(e) => set('toolName', e.target.value)}
        />
      </div>

      <div className="filter-group">
        <label htmlFor="filter-outcome">Outcome</label>
        <select
          id="filter-outcome"
          value={filters.outcome ?? ''}
          onChange={(e) => set('outcome', e.target.value as Filters['outcome'])}
        >
          <option value="">All</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="cancelled">Cancelled</option>
          <option value="incomplete">Incomplete</option>
        </select>
      </div>

      <div className="filter-group">
        <label htmlFor="filter-since">Since</label>
        <input
          id="filter-since"
          type="datetime-local"
          value={fromUnixSeconds(filters.since)}
          onChange={(e) => set('since', toUnixSeconds(e.target.value))}
        />
      </div>

      <div className="filter-group">
        <label htmlFor="filter-until">Until</label>
        <input
          id="filter-until"
          type="datetime-local"
          value={fromUnixSeconds(filters.until)}
          onChange={(e) => set('until', toUnixSeconds(e.target.value))}
        />
      </div>

      <button className="btn-clear" onClick={clearFilters}>
        Clear Filters
      </button>
    </aside>
  )
}
