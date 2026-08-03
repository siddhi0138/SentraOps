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
    return <div className="text-slate-400">Loading AI observability...</div>
  }

  const sortedFeatures = [...summary.features].sort((a, b) => b.calls_success + b.calls_error - (a.calls_success + a.calls_error))

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">AI Observability</h1>
          <p className="text-sm text-slate-500 mt-1">
            Real usage, latency, and estimated cost for every Groq call this platform makes - agents, chat,
            explanations, and briefings alike - read live off this process's own metrics.
          </p>
        </div>
        <button
          onClick={() => void load()}
          className="rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-4 py-2 transition"
        >
          Refresh
        </button>
      </div>

      {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Calls" value={summary.totals.calls} />
        <StatCard label="Estimated Cost" value={formatCost(summary.totals.estimated_cost_usd)} />
        <StatCard label="Prompt Tokens" value={summary.totals.prompt_tokens.toLocaleString()} />
        <StatCard label="Completion Tokens" value={summary.totals.completion_tokens.toLocaleString()} />
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-x-auto">
        <h2 className="text-sm font-medium text-slate-300 p-4 pb-2">By Feature</h2>
        {sortedFeatures.length === 0 ? (
          <p className="text-sm text-slate-500 px-4 pb-4">No AI calls recorded yet in this process.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 uppercase tracking-wide border-y border-slate-800">
                <th className="text-left font-medium px-4 py-2">Feature</th>
                <th className="text-right font-medium px-4 py-2">Calls</th>
                <th className="text-right font-medium px-4 py-2">Success Rate</th>
                <th className="text-right font-medium px-4 py-2">Avg Latency</th>
                <th className="text-right font-medium px-4 py-2">Tokens (P/C)</th>
                <th className="text-right font-medium px-4 py-2">Est. Cost</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {sortedFeatures.map((row) => (
                <tr key={row.feature}>
                  <td className="px-4 py-2.5 text-slate-100">{row.feature}</td>
                  <td className="px-4 py-2.5 text-right text-slate-300">{row.calls_success + row.calls_error}</td>
                  <td
                    className={`px-4 py-2.5 text-right ${
                      row.success_rate_pct === null
                        ? 'text-slate-500'
                        : row.success_rate_pct >= 95
                          ? 'text-emerald-400'
                          : row.success_rate_pct >= 80
                            ? 'text-orange-400'
                            : 'text-red-400'
                    }`}
                  >
                    {row.success_rate_pct === null ? '-' : `${row.success_rate_pct}%`}
                  </td>
                  <td className="px-4 py-2.5 text-right text-slate-300">
                    {row.avg_duration_seconds === null ? '-' : `${row.avg_duration_seconds}s`}
                  </td>
                  <td className="px-4 py-2.5 text-right text-slate-400">
                    {row.prompt_tokens.toLocaleString()} / {row.completion_tokens.toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 text-right text-slate-300">{formatCost(row.estimated_cost_usd)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
