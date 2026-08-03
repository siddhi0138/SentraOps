import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { SeverityBadge, StatusBadge } from '../components/Badge'
import type { IncidentSummary } from '../api/types'

const PAGE_SIZE = 25

export function IncidentsPage() {
  const [status, setStatus] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [offset, setOffset] = useState(0)
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => setOffset(0), [status, riskLevel])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .listIncidents({ status: status || undefined, risk_level: riskLevel || undefined, limit: PAGE_SIZE, offset })
      .then((res) => {
        if (cancelled) return
        setIncidents(res.incidents)
        setTotal(res.total)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [status, riskLevel, offset])

  const hasNext = offset + PAGE_SIZE < total
  const hasPrev = offset > 0

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-lg font-semibold text-slate-100">Incidents</h1>
        <div className="flex gap-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
          <select
            value={riskLevel}
            onChange={(e) => setRiskLevel(e.target.value)}
            className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All risk levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <button
            onClick={() => api.downloadIncidentsCsv({ status: status || undefined, risk_level: riskLevel || undefined })}
            className="rounded-lg border border-slate-700 hover:bg-slate-800 text-sm px-3 py-1.5 transition"
          >
            Export CSV
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-500 border-b border-slate-800">
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="px-4 py-2 font-medium">Confidence</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Assignee</th>
                <th className="px-4 py-2 font-medium">Hosts</th>
                <th className="px-4 py-2 font-medium">Events</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-2">
                    <Link to={`/incidents/${incident.id}`} className="text-indigo-400 hover:underline">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-slate-300">{incident.confidence}%</td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={incident.risk_level} /> <span className="text-slate-500 text-xs">{incident.risk_score}</span>
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={incident.status} />
                  </td>
                  <td className="px-4 py-2 text-slate-400">{incident.assignee_email ?? '-'}</td>
                  <td className="px-4 py-2 text-slate-300">{incident.affected_hosts.join(', ')}</td>
                  <td className="px-4 py-2 text-slate-400">{incident.event_count}</td>
                  <td className="px-4 py-2 whitespace-nowrap text-slate-400 font-mono text-xs">{incident.created_at}</td>
                </tr>
              ))}
              {!loading && incidents.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    No incidents match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 text-sm text-slate-400">
          <span>
            {total === 0 ? '0' : `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)}`} of {total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={!hasPrev}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              className="px-3 py-1 rounded-lg border border-slate-700 disabled:opacity-40 hover:bg-slate-800 transition"
            >
              Previous
            </button>
            <button
              disabled={!hasNext}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
              className="px-3 py-1 rounded-lg border border-slate-700 disabled:opacity-40 hover:bg-slate-800 transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
