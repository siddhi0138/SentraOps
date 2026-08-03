import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, ApiError } from '../api/client'
import { StatCard } from '../components/StatCard'
import type { PredictiveBriefing, PredictiveSummary } from '../api/types'

const DIRECTION_COLOR: Record<string, string> = {
  rising: 'text-severity-high',
  worsening: 'text-destructive',
  falling: 'text-severity-low',
  improving: 'text-severity-low',
  stable: 'text-foreground',
  none: 'text-muted-foreground',
  insufficient_data: 'text-muted-foreground',
}

export function PredictiveThreatDetectionPage() {
  const [summary, setSummary] = useState<PredictiveSummary | null>(null)
  const [briefing, setBriefing] = useState<PredictiveBriefing | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setSummary(await api.getPredictiveSummary())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load predictive summary')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function generateBriefing() {
    setGenerating(true)
    setError(null)
    try {
      const res = await api.getPredictiveBriefing()
      setBriefing(res.briefing)
      setSummary(res.summary)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate briefing')
    } finally {
      setGenerating(false)
    }
  }

  if (loading || !summary) {
    return <div className="text-muted-foreground">Loading predictive threat detection...</div>
  }

  const { anomalous_entities, privilege_escalation_trend, risk_drift } = summary

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Predictive Threat Detection</h1>
          <p className="text-sm text-muted-foreground mt-1">
            What's likely, not just what already happened - real statistical signals computed from this
            organization's own history, not a fabricated forecast.
          </p>
        </div>
        <button
          onClick={() => void generateBriefing()}
          disabled={generating}
          className="rounded-lg bg-primary hover:bg-primary disabled:opacity-50 text-white text-sm font-medium px-4 py-2 transition"
        >
          {generating ? 'Generating...' : 'Generate AI Briefing'}
        </button>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      {briefing && (
        <div className="rounded-xl border border-primary/60 bg-primary/20 p-5 space-y-2">
          <p className="text-sm font-medium text-primary">{briefing.headline}</p>
          <p className="text-sm text-foreground">{briefing.summary}</p>
          {briefing.likely_scenarios.length > 0 && (
            <ul className="list-disc list-inside text-sm text-foreground space-y-0.5">
              {briefing.likely_scenarios.map((scenario, i) => (
                <li key={i}>{scenario}</li>
              ))}
            </ul>
          )}
          <p className="text-xs text-muted-foreground pt-1">Recommended watch: {briefing.recommended_watch}</p>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Actors Analyzed" value={anomalous_entities.entities_analyzed} />
        <StatCard
          label="Anomalies Flagged"
          value={anomalous_entities.anomalies.length}
          accent={anomalous_entities.anomalies.length > 0 ? 'text-severity-high' : undefined}
        />
        <StatCard
          label="Privilege Escalation Trend"
          value={privilege_escalation_trend.direction}
          accent={DIRECTION_COLOR[privilege_escalation_trend.direction]}
        />
        <StatCard label="Risk Drift" value={risk_drift.direction} accent={DIRECTION_COLOR[risk_drift.direction]} />
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-3">Anomalous User/Host Activity</h2>
        {anomalous_entities.status === 'insufficient_data' ? (
          <p className="text-sm text-muted-foreground">
            Not enough distinct user/host activity yet to fit an anomaly model ({anomalous_entities.entities_analyzed}{' '}
            analyzed).
          </p>
        ) : anomalous_entities.anomalies.length === 0 ? (
          <p className="text-sm text-muted-foreground">No anomalies flagged out of {anomalous_entities.entities_analyzed} actors analyzed.</p>
        ) : (
          <div className="divide-y divide-secondary">
            {anomalous_entities.anomalies.map((a) => (
              <div key={`${a.host}:${a.username}`} className="py-2.5">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-foreground">
                    {a.username}
                    <span className="text-muted-foreground"> @ {a.host}</span>
                  </p>
                  <span className="text-xs text-severity-high">score {a.anomaly_score}</span>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">{a.reasons.join(' · ')}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-4">
          Privilege Escalation Trend (last 30 days)
          <span className="text-xs text-muted-foreground font-normal ml-2">
            &middot; slope {privilege_escalation_trend.slope_per_day}/day &middot; {privilege_escalation_trend.total} total
          </span>
        </h2>
        {privilege_escalation_trend.daily_counts.length === 0 ? (
          <p className="text-sm text-muted-foreground">No privilege escalation events in the last 30 days.</p>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={privilege_escalation_trend.daily_counts} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2c2c2a" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <YAxis allowDecimals={false} tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                contentStyle={{ background: '#1a1a19', border: '1px solid #383835', borderRadius: 8, fontSize: 12 }}
              />
              <Bar dataKey="count" fill="#fb923c" name="privilege escalation events" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-3">Risk Drift</h2>
        {risk_drift.direction === 'insufficient_data' ? (
          <p className="text-sm text-muted-foreground">Not enough incident history yet to compare recent vs. prior risk.</p>
        ) : (
          <p className="text-sm text-foreground">
            Recent average risk score <span className="text-foreground font-medium">{risk_drift.recent_average}</span> vs.
            prior average <span className="text-foreground font-medium">{risk_drift.prior_average}</span> - drift{' '}
            <span className={DIRECTION_COLOR[risk_drift.direction]}>{risk_drift.drift}</span>.
          </p>
        )}
      </div>
    </div>
  )
}
