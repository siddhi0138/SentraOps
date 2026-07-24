import { useCallback, useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SEVERITY_COLORS, SeverityBadge, StatusBadge } from '../components/Badge'
import { StatCard } from '../components/StatCard'
import type { EventItem, IncidentSummary, Severity } from '../api/types'

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']

export function DashboardPage() {
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [events, setEvents] = useState<EventItem[]>([])
  const [totalEvents, setTotalEvents] = useState(0)
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [working, setWorking] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [eventsRes, incidentsRes] = await Promise.all([
        api.listEvents({ limit: 500 }),
        api.listIncidents({ limit: 500 }),
      ])
      setEvents(eventsRes.events)
      setTotalEvents(eventsRes.total)
      setIncidents(incidentsRes.incidents)
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

  const severityCounts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: events.filter((e) => e.severity === severity).length,
  }))

  const openIncidents = incidents.filter((i) => i.status === 'open')
  const criticalIncidents = incidents.filter((i) => i.risk_level === 'critical')
  const recentIncidents = [...incidents]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5)

  if (loading) {
    return <div className="text-slate-400">Loading dashboard...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Security Overview</h1>
        {canAct && (
          <button
            onClick={handleSimulateAndCorrelate}
            disabled={working}
            className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 transition"
          >
            {working ? 'Running...' : 'Simulate attack + correlate'}
          </button>
        )}
      </div>

      {actionMessage && (
        <p className="text-sm text-emerald-400 bg-emerald-950/40 border border-emerald-900 rounded-lg px-3 py-2">{actionMessage}</p>
      )}
      {actionError && (
        <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{actionError}</p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Events" value={totalEvents} />
        <StatCard label="Open Incidents" value={openIncidents.length} accent={openIncidents.length > 0 ? 'text-blue-400' : undefined} />
        <StatCard
          label="Critical Incidents"
          value={criticalIncidents.length}
          accent={criticalIncidents.length > 0 ? 'text-red-400' : undefined}
        />
        <StatCard label="Total Incidents" value={incidents.length} />
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="text-sm font-medium text-slate-300 mb-4">Event Severity Distribution</h2>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={severityCounts} margin={{ top: 4, right: 8, left: -16, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2c2c2a" vertical={false} />
            <XAxis dataKey="severity" tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
            <YAxis allowDecimals={false} tick={{ fill: '#898781', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#383835' }} />
            <Tooltip
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              contentStyle={{ background: '#1a1a19', border: '1px solid #383835', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#ffffff', textTransform: 'capitalize' }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={64}>
              {severityCounts.map((entry) => (
                <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity].bg} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="text-sm font-medium text-slate-300 mb-3">Recent Incidents</h2>
        {recentIncidents.length === 0 ? (
          <p className="text-sm text-slate-500">
            No incidents yet.{canAct ? ' Try "Simulate attack + correlate" above.' : ''}
          </p>
        ) : (
          <div className="divide-y divide-slate-800">
            {recentIncidents.map((incident) => (
              <Link
                key={incident.id}
                to={`/incidents/${incident.id}`}
                className="flex items-center justify-between py-2.5 hover:bg-slate-800/40 -mx-2 px-2 rounded transition"
              >
                <div className="min-w-0">
                  <p className="text-sm text-slate-100 truncate">{incident.title}</p>
                  <p className="text-xs text-slate-500">{incident.affected_hosts.join(', ')}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-4">
                  <SeverityBadge severity={incident.risk_level} />
                  <StatusBadge status={incident.status} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
