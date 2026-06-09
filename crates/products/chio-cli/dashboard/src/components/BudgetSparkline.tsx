interface BudgetSparklineProps {
  data: { time: string; cost: number }[]
}

/**
 * Formats a minor-unit integer for display in the sparkline tooltip.
 * Uses integer arithmetic only -- no float conversion for monetary values.
 */
function formatCost(value: number): string {
  const major = Math.floor(value / 100)
  const minor = (value % 100).toString().padStart(2, '0')
  return `$${major}.${minor}`
}

interface Point {
  x: number
  y: number
  time: string
  cost: number
}

function toPoints(data: { time: string; cost: number }[]): Point[] {
  const width = 160
  const height = 60
  const padding = 4
  const min = Math.min(...data.map((entry) => entry.cost))
  const max = Math.max(...data.map((entry) => entry.cost))
  const range = Math.max(max - min, 1)

  return data.map((entry, index) => {
    const x =
      data.length === 1
        ? width / 2
        : padding + (index * (width - padding * 2)) / (data.length - 1)
    const normalized = (entry.cost - min) / range
    const y = height - padding - normalized * (height - padding * 2)

    return {
      x,
      y,
      time: entry.time,
      cost: entry.cost,
    }
  })
}

/**
 * Renders a lightweight SVG sparkline for cost over time.
 * Shows "No cost data" placeholder when data array is empty.
 */
export function BudgetSparkline({ data }: BudgetSparklineProps) {
  if (data.length === 0) {
    return <div className="sparkline-placeholder">No cost data</div>
  }

  const width = 160
  const height = 60
  const baselineY = height - 4
  const points = toPoints(data)
  const linePoints = points.map((point) => `${point.x},${point.y}`).join(' ')
  const areaPoints = [
    `${points[0].x},${baselineY}`,
    ...points.map((point) => `${point.x},${point.y}`),
    `${points[points.length - 1].x},${baselineY}`,
  ].join(' ')

  return (
    <svg
      width="100%"
      height="60"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label="Cost over time sparkline"
    >
      <defs>
        <linearGradient id="sparkline-fill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="#c7d2fe" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#e0e7ff" stopOpacity="0.25" />
        </linearGradient>
      </defs>
      <polyline
        points={areaPoints}
        fill="url(#sparkline-fill)"
        stroke="none"
      />
      <polyline
        points={linePoints}
        fill="none"
        stroke="#4f46e5"
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {points.map((point) => (
        <circle key={`${point.time}-${point.cost}`} cx={point.x} cy={point.y} r="2" fill="#4338ca">
          <title>{`${point.time}: ${formatCost(point.cost)}`}</title>
        </circle>
      ))}
    </svg>
  )
}
