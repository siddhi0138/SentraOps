import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { StatCard } from '../components/StatCard'
import type { AiObservabilitySummary } from '../api/types'

function formatCost(usd: number): string {
  if (usd === 0) return '$0'
  if (usd < 0.01) return `$${usd.toFixed(6)}`
  return `$${usd.toFixed(4)}`
}

export function AiObservabilityPage() {
  const [summary, setSummary] = useState<AiObservabilitySummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setSummary(await api.getAiObservabilitySummary())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load AI observability summary')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (loading || !summary) {
    return <div className="text-muted-foreground">Loading AI observability...</div>
  }

  const sortedFeatures = [...summary.features].sort((a, b) => b.calls_success + b.calls_error - (a.calls_success + a.calls_error))

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-foreground">AI Observability</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real usage, latency, and estimated cost for every Groq call this platform makes - agents, chat,
            explanations, and briefings alike - read live off this process's own metrics.
          </p>
        </div>
        <button
          onClick={() => void load()}
          className="rounded-lg bg-border hover:bg-muted-foreground text-white text-sm font-medium px-4 py-2 transition"
        >
          Refresh
        </button>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Calls" value={summary.totals.calls} />
        <StatCard label="Estimated Cost" value={formatCost(summary.totals.estimated_cost_usd)} />
        <StatCard label="Prompt Tokens" value={summary.totals.prompt_tokens.toLocaleString()} />
        <StatCard label="Completion Tokens" value={summary.totals.completion_tokens.toLocaleString()} />
      </div>

      <div className="panel overflow-x-auto">
        <h2 className="text-sm font-medium text-foreground p-4 pb-2">By Feature</h2>
        {sortedFeatures.length === 0 ? (
          <p className="text-sm text-muted-foreground px-4 pb-4">No AI calls recorded yet in this process.</p>
        ) : (
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="text-xs text-muted-foreground uppercase tracking-wide border-y border-secondary">
                <th className="text-left font-medium px-4 py-2">Feature</th>
                <th className="text-right font-medium px-4 py-2">Calls</th>
                <th className="text-right font-medium px-4 py-2">Success Rate</th>
                <th className="text-right font-medium px-4 py-2">Avg Latency</th>
                <th className="text-right font-medium px-4 py-2">Tokens (P/C)</th>
                <th className="text-right font-medium px-4 py-2">Est. Cost</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {sortedFeatures.map((row) => (
                <tr key={row.feature}>
                  <td className="px-4 py-2.5 text-foreground">{row.feature}</td>
                  <td className="px-4 py-2.5 text-right text-foreground">{row.calls_success + row.calls_error}</td>
                  <td
                    className={`px-4 py-2.5 text-right ${
                      row.success_rate_pct === null
                        ? 'text-muted-foreground'
                        : row.success_rate_pct >= 95
                          ? 'text-severity-low'
                          : row.success_rate_pct >= 80
                            ? 'text-severity-high'
                            : 'text-destructive'
                    }`}
                  >
                    {row.success_rate_pct === null ? '-' : `${row.success_rate_pct}%`}
                  </td>
                  <td className="px-4 py-2.5 text-right text-foreground">
                    {row.avg_duration_seconds === null ? '-' : `${row.avg_duration_seconds}s`}
                  </td>
                  <td className="px-4 py-2.5 text-right text-muted-foreground">
                    {row.prompt_tokens.toLocaleString()} / {row.completion_tokens.toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 text-right text-foreground">{formatCost(row.estimated_cost_usd)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
