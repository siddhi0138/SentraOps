import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { SeverityBadge } from '../components/Badge'
import type { EventItem } from '../api/types'

const PAGE_SIZE = 25
const SEVERITIES = ['low', 'medium', 'high', 'critical']

export function EventsPage() {
  const [q, setQ] = useState('')
  const [debouncedQ, setDebouncedQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const [events, setEvents] = useState<EventItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q), 300)
    return () => clearTimeout(timer)
  }, [q])

  useEffect(() => {
    setOffset(0)
  }, [debouncedQ, severity])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .listEvents({ q: debouncedQ || undefined, severity: severity || undefined, limit: PAGE_SIZE, offset })
      .then((res) => {
        if (cancelled) return
        setEvents(res.events)
        setTotal(res.total)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [debouncedQ, severity, offset])

  const hasNext = offset + PAGE_SIZE < total
  const hasPrev = offset > 0

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-lg font-semibold text-slate-100">Events</h1>
        <div className="flex gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search user, host, IP, message..."
            className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 w-72 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-500 border-b border-slate-800">
                <th className="px-4 py-2 font-medium">Timestamp</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">User</th>
                <th className="px-4 py-2 font-medium">Source IP</th>
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Message</th>
                <th className="px-4 py-2 font-medium">Incident</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {events.map((event) => (
                <tr key={event.id} className="hover:bg-slate-800/40">
                  <td className="px-4 py-2 whitespace-nowrap text-slate-400 font-mono text-xs">{event.timestamp}</td>
                  <td className="px-4 py-2 text-slate-200">{event.host}</td>
                  <td className="px-4 py-2 text-slate-300">{event.username ?? '-'}</td>
                  <td className="px-4 py-2 text-slate-400 font-mono text-xs">{event.source_ip ?? '-'}</td>
                  <td className="px-4 py-2 text-slate-300">{event.event_type}</td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td className="px-4 py-2 text-slate-300 max-w-md truncate" title={event.message}>
                    {event.message}
                  </td>
                  <td className="px-4 py-2">
                    {event.incident_id ? (
                      <Link to={`/incidents/${event.incident_id}`} className="text-indigo-400 hover:underline">
                        #{event.incident_id}
                      </Link>
                    ) : (
                      <span className="text-slate-600">-</span>
                    )}
                  </td>
                </tr>
              ))}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    No events match these filters.
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
