import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { fetchDelegationChain } from '../api'
import type { CapabilitySnapshot } from '../types'

interface DelegationChainProps {
  capabilityId: string
}

interface ChainNodeProps {
  snapshot: CapabilitySnapshot
  isRoot: boolean
}

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString()
}

function truncateKey(key: string): string {
  if (key.length <= 16) return key
  return `${key.slice(0, 8)}...${key.slice(-8)}`
}

function ChainNode({ snapshot, isRoot }: ChainNodeProps) {
  const [expanded, setExpanded] = useState(isRoot)
  const [grantsExpanded, setGrantsExpanded] = useState(false)

  return (
    <div className="chain-node">
      <div
        className="chain-node-header"
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span title={snapshot.capability_id}>
          {truncateKey(snapshot.capability_id)}
        </span>
        {isRoot && <span className="chain-root-label">Root</span>}
        <span style={{ marginLeft: 'auto', color: 'var(--color-text-muted)' }}>
          depth {snapshot.delegation_depth}
        </span>
      </div>

      {expanded && (
        <div className="chain-node-body">
          <div className="chain-field">
            <span className="chain-field-label">Subject</span>
            <span title={snapshot.subject_key}>{truncateKey(snapshot.subject_key)}</span>
          </div>
          <div className="chain-field">
            <span className="chain-field-label">Issuer</span>
            <span title={snapshot.issuer_key}>{truncateKey(snapshot.issuer_key)}</span>
          </div>
          <div className="chain-field">
            <span className="chain-field-label">Issued at</span>
            <span>{formatTimestamp(snapshot.issued_at)}</span>
          </div>
          <div className="chain-field">
            <span className="chain-field-label">Expires at</span>
            <span>{formatTimestamp(snapshot.expires_at)}</span>
          </div>

          <div className="chain-field" style={{ flexDirection: 'column', gap: 4 }}>
            <button
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--color-primary)',
                fontSize: 12,
                textAlign: 'left',
                padding: 0,
              }}
              onClick={() => setGrantsExpanded((v) => !v)}
            >
              {grantsExpanded ? <ChevronDown size={12} style={{ display: 'inline' }} /> : <ChevronRight size={12} style={{ display: 'inline' }} />}
              {' '}Grants JSON
            </button>
            {grantsExpanded && (
              <pre className="detail-json">{snapshot.grants_json}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * Fetches and renders the full delegation chain for a capability.
 * Displays a vertical list from root to leaf with expandable grant details.
 */
export function DelegationChain({ capabilityId }: DelegationChainProps) {
  const [chain, setChain] = useState<CapabilitySnapshot[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)

    fetchDelegationChain(capabilityId)
      .then((data) => {
        if (!cancelled) {
          setChain(data)
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
  }, [capabilityId])

  if (loading) {
    return <div className="state-loading">Loading chain...</div>
  }

  if (error) {
    return <div className="state-error">Error: {error}</div>
  }

  if (!chain || chain.length === 0) {
    return (
      <div>
        <span className="chain-root-label">Root capability</span>
        <p style={{ marginTop: 8, fontSize: 12, color: 'var(--color-text-muted)' }}>
          No delegation chain available.
        </p>
      </div>
    )
  }

  return (
    <div>
      {chain.map((snapshot, index) => (
        <ChainNode
          key={snapshot.capability_id}
          snapshot={snapshot}
          isRoot={index === 0}
        />
      ))}
    </div>
  )
}
