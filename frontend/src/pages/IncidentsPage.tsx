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
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-lg font-semibold text-foreground">Incidents</h1>
        <div className="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
          <select
            value={riskLevel}
            onChange={(e) => setRiskLevel(e.target.value)}
            className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="">All risk levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <button
            onClick={() => api.downloadIncidentsCsv({ status: status || undefined, risk_level: riskLevel || undefined })}
            className="col-span-2 rounded-lg border border-border hover:bg-secondary text-sm px-3 py-1.5 transition sm:col-span-1"
          >
            Export CSV
          </button>
        </div>
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground border-b border-secondary">
                <th className="px-4 py-2 font-medium">Title</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Confidence</th>
                <th className="px-4 py-2 font-medium">Risk</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">Assignee</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">Hosts</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Events</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-secondary/40">
                  <td className="px-4 py-2">
                    <Link to={`/incidents/${incident.id}`} className="text-primary hover:underline">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="hidden px-4 py-2 text-foreground md:table-cell">{incident.confidence}%</td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={incident.risk_level} /> <span className="text-muted-foreground text-xs">{incident.risk_score}</span>
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={incident.status} />
                  </td>
                  <td className="hidden px-4 py-2 text-muted-foreground lg:table-cell">{incident.assignee_email ?? '-'}</td>
                  <td className="hidden px-4 py-2 text-foreground lg:table-cell">{incident.affected_hosts.join(', ')}</td>
                  <td className="hidden px-4 py-2 text-muted-foreground sm:table-cell">{incident.event_count}</td>
                  <td className="hidden px-4 py-2 whitespace-nowrap text-muted-foreground font-mono text-xs md:table-cell">{incident.created_at}</td>
                </tr>
              ))}
              {!loading && incidents.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">
                    No incidents match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between px-4 py-3 border-t border-secondary text-sm text-muted-foreground">
          <span>
            {total === 0 ? '0' : `${offset + 1}-${Math.min(offset + PAGE_SIZE, total)}`} of {total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={!hasPrev}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              className="px-3 py-1 rounded-lg border border-border disabled:opacity-40 hover:bg-secondary transition"
            >
              Previous
            </button>
            <button
              disabled={!hasNext}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
              className="px-3 py-1 rounded-lg border border-border disabled:opacity-40 hover:bg-secondary transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
