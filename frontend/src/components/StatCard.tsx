import type { ReactNode } from 'react'

export function StatCard({ label, value, accent }: { label: string; value: ReactNode; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
      <span className={`text-2xl font-semibold ${accent ?? 'text-slate-100'}`}>{value}</span>
    </div>
  )
}
