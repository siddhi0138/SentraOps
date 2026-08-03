import type { ComponentType, ReactNode } from 'react'
import { Card, CardAction, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface StatCardProps {
  label: string
  value: ReactNode
  accent?: string
  icon?: ComponentType<{ className?: string }>
}

// Matches shadcn's own official dashboard-01 block's section-cards pattern
// (subtle gradient card, CardDescription/CardTitle/CardAction), not a
// hand-invented shape - adapted to this app's own severity/accent colors.
export function StatCard({ label, value, accent, icon: Icon }: StatCardProps) {
  return (
    <Card className="bg-gradient-to-t from-primary/5 to-card shadow-xs">
      <CardHeader>
        <CardDescription className="font-mono text-[10.5px] uppercase tracking-widest">{label}</CardDescription>
        <CardTitle className={cn('text-2xl font-semibold tabular-nums @[250px]/card:text-3xl', accent ?? 'text-foreground')}>
          {value}
        </CardTitle>
        {Icon && (
          <CardAction>
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <Icon className="h-3.5 w-3.5" />
            </div>
          </CardAction>
        )}
      </CardHeader>
    </Card>
  )
}
