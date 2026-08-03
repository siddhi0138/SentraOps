import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { SeverityBadge } from '../components/Badge'
import type { EventExplanation, EventItem, QueryFilters } from '../api/types'

const PAGE_SIZE = 25
const SEVERITIES = ['low', 'medium', 'high', 'critical']

export function EventsPage() {
  const [searchParams] = useSearchParams()
  const [q, setQ] = useState(() => searchParams.get('q') ?? '')
  const [debouncedQ, setDebouncedQ] = useState(() => searchParams.get('q') ?? '')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const [events, setEvents] = useState<EventItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [explainTarget, setExplainTarget] = useState<EventItem | null>(null)
  const [explanation, setExplanation] = useState<EventExplanation | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState<string | null>(null)

  const [nlQuestion, setNlQuestion] = useState('')
  const [nlFilters, setNlFilters] = useState<QueryFilters | null>(null)
  const [nlLoading, setNlLoading] = useState(false)
  const [nlError, setNlError] = useState<string | null>(null)

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q), 300)
    return () => clearTimeout(timer)
  }, [q])

  useEffect(() => {
    setOffset(0)
  }, [debouncedQ, severity])

  useEffect(() => {
    if (nlFilters) return // AI search results are fetched separately below
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
  }, [debouncedQ, severity, offset, nlFilters])

  async function runNlSearch() {
    if (!nlQuestion.trim()) return
    setNlLoading(true)
    setNlError(null)
    try {
      const res = await api.naturalLanguageQuery(nlQuestion)
      setNlFilters(res.filters)
      setEvents(res.events)
      setTotal(res.total)
      setOffset(0)
    } catch (err) {
      setNlError(err instanceof ApiError ? err.message : 'Failed to run AI search')
    } finally {
      setNlLoading(false)
    }
  }

  function clearNlSearch() {
    setNlFilters(null)
    setNlQuestion('')
    setNlError(null)
  }

  const hasNext = offset + PAGE_SIZE < total
  const hasPrev = offset > 0

  function openExplain(event: EventItem) {
    setExplainTarget(event)
    setExplanation(null)
    setExplainError(null)
    setExplaining(true)
    api
      .explainEvent(event.id)
      .then(setExplanation)
      .catch((err) => setExplainError(err instanceof ApiError ? err.message : 'Failed to generate AI explanation'))
      .finally(() => setExplaining(false))
  }

  function closeExplain() {
    setExplainTarget(null)
    setExplanation(null)
    setExplainError(null)
  }

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
          <button
            onClick={() => api.downloadEventsCsv({ q: debouncedQ || undefined, severity: severity || undefined })}
            className="rounded-lg border border-slate-700 hover:bg-slate-800 text-sm px-3 py-1.5 transition"
          >
            Export CSV
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <input
          value={nlQuestion}
          onChange={(e) => setNlQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runNlSearch()}
          placeholder="Ask AI, e.g. 'failed logins from admin accounts today'"
          className="flex-1 rounded-lg bg-indigo-950/30 border border-indigo-900 px-3 py-1.5 text-sm text-slate-100 placeholder:text-indigo-400/60 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <button
          onClick={() => void runNlSearch()}
          disabled={nlLoading || !nlQuestion.trim()}
          className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 disabled:opacity-50 text-sm px-3 py-1.5 transition text-indigo-300"
        >
          {nlLoading ? 'Thinking...' : 'Ask AI'}
        </button>
        {nlFilters && (
          <button onClick={clearNlSearch} className="rounded-lg border border-slate-700 hover:bg-slate-800 text-sm px-3 py-1.5 transition">
            Clear
          </button>
        )}
      </div>

      {nlError && <p className="text-sm text-rose-400">{nlError}</p>}

      {nlFilters && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-indigo-300">
          <span className="text-indigo-400/70">AI interpreted this as:</span>
          {Object.entries(nlFilters).every(([, v]) => !v) && <span className="text-indigo-400/70">no specific filters - showing everything</span>}
          {Object.entries(nlFilters)
            .filter(([, v]) => v)
            .map(([key, value]) => (
              <span key={key} className="rounded-full border border-indigo-800 bg-indigo-950/40 px-2 py-0.5">
                {key}: {value}
              </span>
            ))}
        </div>
      )}

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
                <th className="px-4 py-2 font-medium"></th>
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
                  <td className="px-4 py-2 whitespace-nowrap">
                    <button
                      onClick={() => openExplain(event)}
                      className="rounded-lg border border-indigo-800 hover:bg-indigo-900/40 text-xs px-2.5 py-1 transition text-indigo-300"
                    >
                      Explain
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-slate-500">
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
              disabled={!hasPrev || !!nlFilters}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              className="px-3 py-1 rounded-lg border border-slate-700 disabled:opacity-40 hover:bg-slate-800 transition"
            >
              Previous
            </button>
            <button
              disabled={!hasNext || !!nlFilters}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
              className="px-3 py-1 rounded-lg border border-slate-700 disabled:opacity-40 hover:bg-slate-800 transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {explainTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={closeExplain}
        >
          <div
            className="w-full max-w-lg rounded-xl border border-indigo-900/60 bg-slate-900 p-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-indigo-300">AI Event Explanation</h2>
              <button onClick={closeExplain} className="text-slate-500 hover:text-slate-300 text-sm">
                Close
              </button>
            </div>
            <p className="text-xs text-slate-500 mb-3 font-mono truncate" title={explainTarget.message}>
              {explainTarget.message}
            </p>

            {explaining && <p className="text-sm text-slate-400">Analyzing...</p>}
            {explainError && <p className="text-sm text-rose-400">{explainError}</p>}
            {explanation && (
              <div className="space-y-3">
                <p className="text-sm text-slate-200">{explanation.explanation}</p>
                <div className="flex items-center gap-2 text-xs">
                  <span
                    className={`rounded-full px-2 py-0.5 font-medium ${
                      explanation.is_suspicious
                        ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                        : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                    }`}
                  >
                    {explanation.is_suspicious ? 'Suspicious' : 'Likely benign'}
                  </span>
                </div>
                {explanation.recommended_action && (
                  <p className="text-xs text-slate-400">
                    <span className="text-slate-500">Recommended: </span>
                    {explanation.recommended_action}
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
