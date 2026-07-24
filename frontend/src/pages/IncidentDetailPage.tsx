import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge, StatusBadge } from '../components/Badge'
import type { IncidentDetail } from '../api/types'

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updating, setUpdating] = useState(false)
  const [showReport, setShowReport] = useState(false)

  const load = useCallback(async () => {
    if (!id) return
    setLoading(true)
    setError(null)
    try {
      setIncident(await api.getIncident(Number(id)))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load incident')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    void load()
  }, [load])

  async function toggleStatus() {
    if (!incident) return
    setUpdating(true)
    try {
      const next = incident.status === 'open' ? 'closed' : 'open'
      setIncident(await api.updateIncidentStatus(incident.id, next))
    } finally {
      setUpdating(false)
    }
  }

  if (loading) return <div className="text-slate-400">Loading incident...</div>
  if (error) return <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>
  if (!incident) return null

  const alerts = incident.timeline.filter((e) => e.severity !== 'low')

  return (
    <div className="space-y-6">
      <Link to="/incidents" className="text-sm text-slate-400 hover:text-slate-200">
        &larr; Back to incidents
      </Link>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">{incident.title}</h1>
            <p className="text-sm text-slate-500 mt-1">
              Created {incident.created_at} &middot; {incident.event_count} events
            </p>
          </div>
          {canAct && (
            <button
              onClick={toggleStatus}
              disabled={updating}
              className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-sm px-3 py-1.5 transition shrink-0"
            >
              {incident.status === 'open' ? 'Close incident' : 'Reopen incident'}
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={incident.risk_level} />
          <StatusBadge status={incident.status} />
          <span className="text-sm text-slate-400">Confidence: {incident.confidence}%</span>
          <span className="text-sm text-slate-400">Risk score: {incident.risk_score}/100</span>
        </div>

        <div className="grid grid-cols-2 gap-4 pt-2 text-sm">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected hosts</p>
            <p className="text-slate-200">{incident.affected_hosts.join(', ') || '-'}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected users</p>
            <p className="text-slate-200">{incident.affected_users.join(', ') || '-'}</p>
          </div>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Timeline</h2>
          <ol className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {incident.timeline.map((event) => (
              <li key={event.id} className="text-sm border-l-2 border-slate-800 pl-3">
                <p className="text-xs font-mono text-slate-500">{event.timestamp}</p>
                <p className="text-slate-200">
                  [{event.host}] {event.username ?? 'unknown'}: {event.message}
                </p>
                <div className="mt-1">
                  <SeverityBadge severity={event.severity} />
                </div>
              </li>
            ))}
          </ol>
        </div>

        <div className="space-y-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Alerts ({alerts.length})</h2>
            <ul className="space-y-1.5 text-sm">
              {alerts.map((event) => (
                <li key={event.id} className="flex items-start gap-2">
                  <SeverityBadge severity={event.severity} />
                  <span className="text-slate-300">{event.message}</span>
                </li>
              ))}
            </ul>
          </div>

          {incident.threat_intel.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-medium text-slate-300 mb-3">Threat Intelligence</h2>
              <ul className="space-y-2 text-sm">
                {incident.threat_intel.map((ti) => (
                  <li key={ti.indicator}>
                    <p className="font-mono text-slate-200">{ti.indicator}</p>
                    <p className="text-slate-400">
                      {ti.verdict} &middot; {ti.confidence}% confidence &middot; {ti.source}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Recommended Actions</h2>
            <ul className="space-y-1.5 text-sm text-slate-300 list-disc list-inside">
              {incident.recommended_actions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <button
          onClick={() => setShowReport((v) => !v)}
          className="text-sm font-medium text-slate-300 hover:text-white transition"
        >
          {showReport ? 'Hide' : 'Show'} full report
        </button>
        {showReport && (
          <pre className="mt-3 text-xs text-slate-300 whitespace-pre-wrap font-mono bg-slate-950 rounded-lg p-4 overflow-x-auto">
            {incident.report}
          </pre>
        )}
      </div>
    </div>
  )
}
