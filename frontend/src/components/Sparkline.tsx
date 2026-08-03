interface SparklineProps {
  data: number[]
  color?: string
}

// Hand-rolled, not a chart-library dependency - mirrors the rest of this
// app's "no new npm package for a 15-line SVG" stance (see AttackGraphView).
export function Sparkline({ data, color = 'var(--primary)' }: SparklineProps) {
  const w = 240
  const h = 60
  if (data.length < 2) {
    return <svg viewBox={`0 0 ${w} ${h}`} className="h-16 w-full" />
  }
  const max = Math.max(...data)
  const min = Math.min(...data)
  const step = w / (data.length - 1)
  const points = data
    .map((v, i) => `${i * step},${h - ((v - min) / (max - min || 1)) * (h - 6) - 3}`)
    .join(' ')
  const gradientId = 'sparkline-fill'
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-16 w-full">
      <defs>
        <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline fill={`url(#${gradientId})`} stroke="none" points={`0,${h} ${points} ${w},${h}`} />
      <polyline fill="none" stroke={color} strokeWidth="1.5" points={points} />
    </svg>
  )
}
