import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, ApiError } from '../api/client'
import { StatCard } from '../components/StatCard'
import type { EvaluationSummary, LearningStats } from '../api/types'

const RATING_COLORS: Record<string, string> = {
  accurate: '#0ca30c',
  false_positive: '#d03b3b',
  missed_detection: '#fab219',
}

const RATING_LABELS: Record<string, string> = {
  accurate: 'Accurate',
  false_positive: 'False Positive',
  missed_detection: 'Missed Detection',
}

export function LearningLoopPage() {
  const [stats, setStats] = useState<LearningStats | null>(null)
  const [evaluation, setEvaluation] = useState<EvaluationSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [statsRes, evalRes] = await Promise.all([api.getLearningStats(), api.getEvaluationSummary()])
      setStats(statsRes)
      setEvaluation(evalRes)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load learning loop stats')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  if (loading || !stats) {
    return <div className="text-muted-foreground">Loading learning loop...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Learning Loop</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Real analyst judgments on past AI investigations - no model retraining happens here, but corrections
          (false positives / missed detections, with notes) are fed back into future Detection Agent runs as
          institutional memory. Rate an investigation from an incident's detail page.
        </p>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Feedback" value={stats.total_feedback} />
        <StatCard
          label="Accuracy Rate"
          value={stats.accuracy_rate !== null ? `${stats.accuracy_rate}%` : '—'}
          accent={stats.accuracy_rate !== null && stats.accuracy_rate < 70 ? 'text-destructive' : undefined}
        />
        <StatCard label="False Positives" value={stats.counts.false_positive} />
        <StatCard label="Missed Detections" value={stats.counts.missed_detection} />
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-4">Feedback Trend (last 30 days)</h2>
        {stats.trend.length === 0 ? (
          <p className="text-sm text-muted-foreground">No feedback recorded in the last 30 days.</p>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={stats.trend} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2c2c2a" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <YAxis allowDecimals={false} tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                contentStyle={{ background: '#1a1a19', border: '1px solid #383835', borderRadius: 8, fontSize: 12 }}
              />
              <Legend
                wrapperStyle={{ fontSize: 12 }}
                formatter={(value: string) => RATING_LABELS[value] ?? value}
              />
              {(['accurate', 'false_positive', 'missed_detection'] as const).map((rating) => (
                <Bar key={rating} dataKey={rating} stackId="feedback" fill={RATING_COLORS[rating]} name={rating} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {evaluation && (
        <div className="panel p-4 space-y-4">
          <div>
            <h2 className="text-sm font-medium text-foreground">Investigation Evaluation</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Real numbers cross-referenced from what this platform already recorded - investigation timing,
              analyst accuracy ratings, and human approve/reject decisions. Not a per-agent breakdown: an analyst
              rates one investigation as a whole, never judges a single agent's contribution separately.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Investigations Run" value={evaluation.total_investigations} />
            <StatCard
              label="Avg Investigation Time"
              value={evaluation.avg_investigation_duration_seconds !== null ? `${evaluation.avg_investigation_duration_seconds}s` : '—'}
            />
            <StatCard
              label="Human Override Rate"
              value={evaluation.human_override_rate_pct !== null ? `${evaluation.human_override_rate_pct}%` : '—'}
              accent={evaluation.human_override_rate_pct !== null && evaluation.human_override_rate_pct > 30 ? 'text-severity-high' : undefined}
            />
            <StatCard
              label="Actions Reviewed"
              value={`${evaluation.proposed_actions_reviewed} (${evaluation.proposed_actions_rejected} rejected)`}
            />
          </div>

          <div>
            <h3 className="text-xs uppercase tracking-wide text-muted-foreground mb-2">Duration & Confidence by Outcome</h3>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[480px] text-sm">
                <thead>
                  <tr className="text-xs text-muted-foreground border-b border-secondary">
                    <th className="text-left font-medium py-1.5">Rating</th>
                    <th className="text-right font-medium py-1.5">Rated</th>
                    <th className="text-right font-medium py-1.5">Avg Duration</th>
                    <th className="text-right font-medium py-1.5">Avg Detection Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-secondary">
                  {(['accurate', 'false_positive', 'missed_detection'] as const).map((rating) => {
                    const bucket = evaluation.accuracy_correlation[rating]
                    return (
                      <tr key={rating}>
                        <td className="py-1.5 text-foreground">{RATING_LABELS[rating]}</td>
                        <td className="py-1.5 text-right text-muted-foreground">{bucket.rated_investigations}</td>
                        <td className="py-1.5 text-right text-muted-foreground">
                          {bucket.avg_duration_seconds !== null ? `${bucket.avg_duration_seconds}s` : '—'}
                        </td>
                        <td className="py-1.5 text-right text-muted-foreground">
                          {bucket.avg_detection_confidence !== null ? `${bucket.avg_detection_confidence}%` : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
