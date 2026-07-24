// Fixed status palette (validated for CVD-safety + contrast), never themed
// or reused for categorical series. See dataviz skill references/palette.md.
export const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  low: { bg: '#0ca30c', text: '#ffffff' },
  medium: { bg: '#fab219', text: '#1a1a19' },
  high: { bg: '#ec835a', text: '#1a1a19' },
  critical: { bg: '#d03b3b', text: '#ffffff' },
}

const STATUS_STYLES: Record<string, string> = {
  open: 'bg-blue-600/80 text-blue-50',
  closed: 'bg-emerald-700/80 text-emerald-50',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.low
  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide"
      style={{ backgroundColor: colors.bg, color: colors.text }}
    >
      {severity}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.open
  return <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide ${style}`}>{status}</span>
}
