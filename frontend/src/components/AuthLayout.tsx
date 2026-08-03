import type { ReactNode } from 'react'
import { Activity } from 'lucide-react'

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background grid-bg flex items-center justify-center px-4">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(640px circle at 50% 0%, color-mix(in oklch, var(--primary) 14%, transparent), transparent 70%)',
        }}
      />
      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2">
          <div className="relative flex h-12 w-12 items-center justify-center rounded-xl bg-primary/15 text-primary glow-primary">
            <Activity className="h-6 w-6 text-glow" />
            <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-background bg-severity-low pulse-dot" />
          </div>
          <div className="text-center">
            <p className="font-mono text-lg font-semibold text-foreground">SentraOps</p>
            <p className="text-[11px] uppercase tracking-[0.14em] text-muted-foreground">AI Security Ops</p>
          </div>
        </div>
        {children}
      </div>
    </div>
  )
}
