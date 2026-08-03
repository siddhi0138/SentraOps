import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { SEVERITY_COLORS, SeverityBadge } from '../components/Badge'
import { StatCard } from '../components/StatCard'
import { usePersistentState } from '../hooks/usePersistentState'
import type { ExecutiveBriefing, ExecutiveSummary } from '../api/types'

export function ExecutiveDashboardPage() {
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null)
  const [briefing, setBriefing] = usePersistentState<ExecutiveBriefing>('executive-briefing')
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setSummary(await api.getExecutiveSummary())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load executive summary')
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
      const res = await api.getExecutiveBriefing()
      setBriefing(res.briefing)
      setSummary(res.summary)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate briefing')
    } finally {
      setGenerating(false)
    }
  }

  if (loading || !summary) {
    return <div className="text-muted-foreground">Loading executive dashboard...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Executive Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">Business-level security posture, not per-alert detail.</p>
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
          {briefing.key_risks.length > 0 && (
            <ul className="list-disc list-inside text-sm text-foreground space-y-0.5">
              {briefing.key_risks.map((risk, i) => (
                <li key={i}>{risk}</li>
              ))}
            </ul>
          )}
          <p className="text-xs text-muted-foreground pt-1">Recommended focus: {briefing.recommended_focus}</p>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          label="Open Critical"
          value={summary.open_critical_incidents}
          accent={summary.open_critical_incidents > 0 ? 'text-destructive' : undefined}
        />
        <StatCard
          label="Open High Risk"
          value={summary.open_high_incidents}
          accent={summary.open_high_incidents > 0 ? 'text-severity-high' : undefined}
        />
        <StatCard label="Actions Awaiting Approval" value={summary.pending_actions} />
        <StatCard label="AI Investigations Running" value={summary.running_investigations} />
        <StatCard label="Threat Indicators Tracked" value={summary.threat_indicators_tracked} />
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-4">
          Incident Trend (last 14 days)
          {summary.mean_time_to_close_hours !== null && (
            <span className="text-xs text-muted-foreground font-normal ml-2">
              &middot; avg time to close: {summary.mean_time_to_close_hours}h
            </span>
          )}
        </h2>
        {summary.incident_trend.length === 0 ? (
          <p className="text-sm text-muted-foreground">No incidents in the last 14 days.</p>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={summary.incident_trend} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2c2c2a" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <YAxis allowDecimals={false} tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                contentStyle={{ background: '#1a1a19', border: '1px solid #383835', borderRadius: 8, fontSize: 12 }}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {(['low', 'medium', 'high', 'critical'] as const).map((level) => (
                <Bar key={level} dataKey={level} stackId="risk" fill={SEVERITY_COLORS[level].bg} name={level} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-3">Top Open Incidents by Risk</h2>
        {summary.top_incidents.length === 0 ? (
          <p className="text-sm text-muted-foreground">No open incidents.</p>
        ) : (
          <div className="divide-y divide-secondary">
            {summary.top_incidents.map((incident) => (
              <Link
                key={incident.id}
                to={`/incidents/${incident.id}`}
                className="flex items-center justify-between py-2.5 hover:bg-secondary/40 -mx-2 px-2 rounded transition"
              >
                <div className="min-w-0">
                  <p className="text-sm text-foreground truncate">{incident.title}</p>
                  <p className="text-xs text-muted-foreground">{incident.affected_hosts.join(', ')}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-4">
                  <span className="text-xs text-muted-foreground">{incident.risk_score}/100</span>
                  <SeverityBadge severity={incident.risk_level} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
