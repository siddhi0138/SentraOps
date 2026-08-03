import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Link } from 'react-router-dom'
import { AlertTriangle, Bot, ChevronRight, ListChecks, Server, ShieldAlert, Sparkles, Zap } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SEVERITY_COLORS, SeverityBadge, StatusBadge } from '../components/Badge'
import { StatCard } from '../components/StatCard'
import { Sparkline } from '../components/Sparkline'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import type { AgentRunListItem, Asset, EventItem, Severity, Stats } from '../api/types'

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']

const AGENT_STATUS_DOT: Record<string, string> = {
  running: 'bg-severity-medium',
  completed: 'bg-severity-low',
  failed: 'bg-severity-critical',
}

// Buckets real event timestamps into N equal-width windows spanning the
// data's own min→max range (not "last 24h vs now") - this demo/simulated
// data is usually from a fixed point in the past, so anchoring to wall-clock
// "now" would just show an empty trend. Real volume, real time axis, just
// not calendar-anchored.
function bucketEventVolume(events: EventItem[], buckets = 16): number[] {
  if (events.length === 0) return []
  const times = events.map((e) => new Date(e.timestamp).getTime()).sort((a, b) => a - b)
  const min = times[0]
  const max = times[times.length - 1]
  const span = max - min || 1
  const counts = new Array(buckets).fill(0)
  for (const t of times) {
    const idx = Math.min(buckets - 1, Math.floor(((t - min) / span) * buckets))
    counts[idx] += 1
  }
  return counts
}

export function DashboardPage() {
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [stats, setStats] = useState<Stats | null>(null)
  const [spark, setSpark] = useState<number[]>([])
  const [topAssets, setTopAssets] = useState<Asset[]>([])
  const [latestRun, setLatestRun] = useState<AgentRunListItem | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [working, setWorking] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [statsResult, eventsResult, assetsResult, runsResult] = await Promise.all([
        api.getStats(),
        api.listEvents({ limit: 300 }),
        api.listAssets({ limit: 100 }),
        api.listAllAgentRuns({ limit: 1 }),
      ])
      setStats(statsResult)
      setSpark(bucketEventVolume(eventsResult.events))
      setTopAssets([...assetsResult.assets].sort((a, b) => b.event_count - a.event_count).slice(0, 4))
      setLatestRun(runsResult.runs[0] ?? null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadData()
  }, [loadData])

  // Ingest -> correlate -> a real 6-agent investigation on the highest-risk
  // resulting incident -> graph sync, all real backend calls chained
  // together. Any account gets a fully populated demo from one click,
  // not just the one this was manually curl'd into during development -
  // AI Team, Attack Graph, and Digital Twin all have real data afterward
  // without needing separate manual steps most people won't know to do.
  async function handleSimulateAndCorrelate() {
    setWorking(true)
    setActionError(null)
    setActionMessage(null)
    try {
      await api.simulate('phishing_ransomware')
      const result = await api.correlate()
      setActionMessage(`Simulated an attack and created ${result.incidents_created} incident(s). Running AI investigation…`)

      const topIncident = [...result.incidents].sort((a, b) => b.risk_score - a.risk_score)[0]
      if (topIncident) {
        await api.investigateIncident(topIncident.id)
        setActionMessage(`Simulated an attack, created ${result.incidents_created} incident(s), and ran a full AI investigation on "${topIncident.title}".`)
      }

      await api.syncGraph().catch(() => {})
      await loadData()
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Action failed')
    } finally {
      setWorking(false)
    }
  }

  if (loading || !stats) {
    return <div className="text-muted-foreground text-sm">Loading dashboard…</div>
  }

  const severityCounts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: stats.severity_distribution[severity] ?? 0,
  }))

  const posture = stats.critical_incidents > 0 ? 'Critical' : stats.open_incidents > 0 ? 'Elevated' : 'Nominal'
  const postureColor =
    stats.critical_incidents > 0 ? 'text-severity-critical' : stats.open_incidents > 0 ? 'text-primary' : 'text-severity-low'

  return (
    <div className="space-y-6">
      {actionMessage && (
        <Alert className="border-severity-low/30 bg-severity-low/10 text-severity-low">
          <Sparkles className="h-4 w-4" />
          <AlertDescription className="text-severity-low">{actionMessage}</AlertDescription>
        </Alert>
      )}
      {actionError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{actionError}</AlertDescription>
        </Alert>
      )}

      {/* Hero row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="panel relative overflow-hidden p-6 lg:col-span-2">
          <div className="grid-bg pointer-events-none absolute inset-0 opacity-40" />
          <div className="relative flex flex-wrap items-start justify-between gap-6">
            <div>
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-muted-foreground">
                <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-severity-low" />
                Live · {stats.total_events} events ingested
              </div>
              <h1 className="text-glow mt-3 text-3xl font-semibold tracking-tight md:text-4xl">
                Threat posture: <span className={postureColor}>{posture}</span>
              </h1>
              <p className="mt-2 max-w-xl text-sm text-muted-foreground">
                {stats.critical_incidents} critical incident{stats.critical_incidents === 1 ? '' : 's'}, {stats.open_incidents}{' '}
                open overall, correlated from {stats.total_events} ingested events across {stats.total_incidents} total incident
                {stats.total_incidents === 1 ? '' : 's'}.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                {canAct && (
                  <Button onClick={handleSimulateAndCorrelate} disabled={working}>
                    <Zap className="h-4 w-4" />
                    {working ? 'Running…' : 'Simulate attack + correlate'}
                  </Button>
                )}
                <Button variant="outline" render={<Link to="/ai-analyst" />}>
                  <Bot className="h-4 w-4" />
                  Ask AI Analyst
                </Button>
              </div>
            </div>
            {spark.length > 1 && (
              <div className="w-full md:w-64">
                <div className="mb-1 text-xs text-muted-foreground">Event volume · this dataset</div>
                <Sparkline data={spark} />
              </div>
            )}
          </div>
        </div>

        {/* AI Analyst quick status - real latest run, not a fabricated gauge */}
        <div className="panel p-6">
          <div className="flex items-center gap-2">
            <Bot className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">AI Analyst</h3>
          </div>
          {latestRun ? (
            <>
              <div className="mt-3 flex items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${AGENT_STATUS_DOT[latestRun.status] ?? 'bg-muted-foreground'} ${latestRun.status === 'running' ? 'pulse-dot' : ''}`} />
                <span className="text-xs uppercase tracking-widest text-muted-foreground">{latestRun.status}</span>
              </div>
              <Link to={`/incidents/${latestRun.incident_id}`} className="mt-2 block truncate text-sm text-foreground hover:text-primary">
                {latestRun.incident_title ?? `Incident #${latestRun.incident_id}`}
              </Link>
              <p className="mt-1 text-xs text-muted-foreground">{latestRun.stage ?? 'Investigation'}</p>
            </>
          ) : (
            <p className="mt-3 text-sm text-muted-foreground">No investigations run yet. Open an incident to run the AI Security Team.</p>
          )}
          <Button variant="outline" size="sm" className="mt-4 w-full" render={<Link to="/ai-team" />}>
            View AI Team
          </Button>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Events" value={stats.total_events} icon={ListChecks} />
        <StatCard
          label="Open Incidents"
          value={stats.open_incidents}
          accent={stats.open_incidents > 0 ? 'text-primary' : undefined}
          icon={ShieldAlert}
        />
        <StatCard
          label="Critical Incidents"
          value={stats.critical_incidents}
          accent={stats.critical_incidents > 0 ? 'text-severity-critical' : undefined}
          icon={AlertTriangle}
        />
        <StatCard label="Total Incidents" value={stats.total_incidents} icon={Sparkles} />
      </div>

      {/* Two column: incident stream + right rail */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="panel xl:col-span-2">
          <CardHeader>
            <CardTitle className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
              Live incident stream
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.recent_incidents.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No incidents yet.{canAct ? ' Try "Simulate attack + correlate" above.' : ''}
              </p>
            ) : (
              <div className="-mt-2 divide-y divide-border">
                {stats.recent_incidents.map((incident) => (
                  <Link
                    key={incident.id}
                    to={`/incidents/${incident.id}`}
                    className="-mx-2 flex items-center gap-4 rounded-md px-2 py-2.5 transition hover:bg-muted"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-foreground">{incident.title}</p>
                      <p className="font-mono text-xs text-muted-foreground">{incident.affected_hosts.join(', ')}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={incident.risk_level} />
                      <StatusBadge status={incident.status} />
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card className="panel">
            <CardHeader>
              <CardTitle className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Event Severity Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={severityCounts} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="severity" tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
                  <YAxis allowDecimals={false} tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
                  <Tooltip
                    cursor={{ fill: 'var(--muted)' }}
                    contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: 'var(--foreground)', textTransform: 'capitalize' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={48}>
                    {severityCounts.map((entry) => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity].bg} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <div className="panel p-5">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Top targeted assets</h3>
            </div>
            {topAssets.length === 0 ? (
              <p className="mt-3 text-sm text-muted-foreground">No assets seen yet.</p>
            ) : (
              <ul className="mt-4 space-y-3 text-sm">
                {topAssets.map((asset) => (
                  <li key={asset.id} className="flex items-center gap-3">
                    <Server className="h-4 w-4 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate">{asset.host}</div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
                        {asset.department ?? asset.os ?? 'unclassified'}
                      </div>
                    </div>
                    <span className="rounded bg-secondary px-2 py-0.5 font-mono text-xs">{asset.event_count}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
