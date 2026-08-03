import { Badge } from '@/components/ui/badge'

// Fixed status palette (validated for CVD-safety + contrast), never themed
// or reused for categorical series. See dataviz skill references/palette.md.
// Kept as plain hex (not the CSS --severity-* custom properties) since this
// object is also consumed directly as SVG/Recharts fill values, not just
// class names - both are tuned to read as the same color family.
export const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  low: { bg: '#3ecf8e', text: '#0d1f16' },
  medium: { bg: '#eab64e', text: '#241a04' },
  high: { bg: '#f0854a', text: '#2a1004' },
  critical: { bg: '#e2555a', text: '#ffffff' },
}

const STATUS_STYLES: Record<string, string> = {
  open: 'bg-primary/15 text-primary border-primary/30',
  closed: 'bg-severity-low/15 text-severity-low border-severity-low/30',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.low
  return (
    <Badge
      variant="outline"
      className="uppercase tracking-wide font-semibold border-transparent"
      style={{ backgroundColor: colors.bg, color: colors.text }}
    >
      {severity}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.open
  return (
    <Badge variant="outline" className={`uppercase tracking-wide font-semibold ${style}`}>
      {status}
    </Badge>
  )
}
