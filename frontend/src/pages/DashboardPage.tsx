import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Link } from 'react-router-dom'
import { AlertTriangle, ListChecks, ShieldAlert, Sparkles, Zap } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SEVERITY_COLORS, SeverityBadge, StatusBadge } from '../components/Badge'
import { StatCard } from '../components/StatCard'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import type { Severity, Stats } from '../api/types'

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']

export function DashboardPage() {
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [working, setWorking] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      setStats(await api.getStats())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadData()
  }, [loadData])

  async function handleSimulateAndCorrelate() {
    setWorking(true)
    setActionError(null)
    setActionMessage(null)
    try {
      await api.simulate('phishing_ransomware')
      const result = await api.correlate()
      setActionMessage(`Simulated an attack and created ${result.incidents_created} incident(s).`)
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Security Overview</h1>
          <p className="text-sm text-muted-foreground">Live telemetry across every ingested source.</p>
        </div>
        {canAct && (
          <Button onClick={handleSimulateAndCorrelate} disabled={working}>
            <Zap className="h-4 w-4" />
            {working ? 'Running…' : 'Simulate attack + correlate'}
          </Button>
        )}
      </div>

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

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
            Event Severity Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={severityCounts} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="severity" tick={{ fill: 'var(--muted-foreground)', fontSize: 12 }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
              <YAxis allowDecimals={false} tick={{ fill: 'var(--muted-foreground)', fontSize: 12 }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
              <Tooltip
                cursor={{ fill: 'var(--muted)' }}
                contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: 'var(--foreground)', textTransform: 'capitalize' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={64}>
                {severityCounts.map((entry) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity].bg} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Recent Incidents</CardTitle>
        </CardHeader>
        <CardContent>
          {stats.recent_incidents.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No incidents yet.{canAct ? ' Try "Simulate attack + correlate" above.' : ''}
            </p>
          ) : (
            <div className="divide-y divide-border -mt-2">
              {stats.recent_incidents.map((incident) => (
                <Link
                  key={incident.id}
                  to={`/incidents/${incident.id}`}
                  className="-mx-2 flex items-center justify-between rounded-md px-2 py-2.5 transition hover:bg-muted"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm text-foreground">{incident.title}</p>
                    <p className="font-mono text-xs text-muted-foreground">{incident.affected_hosts.join(', ')}</p>
                  </div>
                  <div className="ml-4 flex shrink-0 items-center gap-2">
                    <SeverityBadge severity={incident.risk_level} />
                    <StatusBadge status={incident.status} />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
