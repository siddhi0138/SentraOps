import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { SeverityBadge } from '../components/Badge'
import { usePersistentState } from '../hooks/usePersistentState'
import type { EventExplanation, EventItem, QueryFilters } from '../api/types'

interface NlSearchResult {
  question: string
  filters: QueryFilters
  events: EventItem[]
  total: number
}

const PAGE_SIZE = 25
const SEVERITIES = ['low', 'medium', 'high', 'critical']

export function EventsPage() {
  const [searchParams] = useSearchParams()
  const [q, setQ] = useState(() => searchParams.get('q') ?? '')
  const [debouncedQ, setDebouncedQ] = useState(() => searchParams.get('q') ?? '')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const [nlResult, setNlResult] = usePersistentState<NlSearchResult>('events-ai-search')
  const [events, setEvents] = useState<EventItem[]>(() => nlResult?.events ?? [])
  const [total, setTotal] = useState(() => nlResult?.total ?? 0)
  const [loading, setLoading] = useState(true)
  const [explainTarget, setExplainTarget] = useState<EventItem | null>(null)
  const [explanation, setExplanation] = useState<EventExplanation | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState<string | null>(null)

  const [nlQuestion, setNlQuestion] = useState(() => nlResult?.question ?? '')
  const [nlLoading, setNlLoading] = useState(false)
  const [nlError, setNlError] = useState<string | null>(null)
  const nlFilters = nlResult?.filters ?? null

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
      setNlResult({ question: nlQuestion, filters: res.filters, events: res.events, total: res.total })
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
    setNlResult(null)
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
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-lg font-semibold text-foreground">Events</h1>
        <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search user, host, IP, message..."
            className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground w-full sm:w-72 focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <div className="grid grid-cols-2 gap-2 sm:contents">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
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
              className="rounded-lg border border-border hover:bg-secondary text-sm px-3 py-1.5 transition"
            >
              Export CSV
            </button>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <input
          value={nlQuestion}
          onChange={(e) => setNlQuestion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runNlSearch()}
          placeholder="Ask AI, e.g. 'failed logins from admin accounts today'"
          className="rounded-lg bg-primary/30 border border-primary px-3 py-1.5 text-sm text-foreground placeholder:text-primary/60 focus:outline-none focus:ring-2 focus:ring-primary sm:flex-1"
        />
        <div className="flex gap-2">
          <button
            onClick={() => void runNlSearch()}
            disabled={nlLoading || !nlQuestion.trim()}
            className="flex-1 rounded-lg border border-primary hover:bg-primary/40 disabled:opacity-50 text-sm px-3 py-1.5 transition text-primary sm:flex-none"
          >
            {nlLoading ? 'Thinking...' : 'Ask AI'}
          </button>
          {nlFilters && (
            <button onClick={clearNlSearch} className="rounded-lg border border-border hover:bg-secondary text-sm px-3 py-1.5 transition">
              Clear
            </button>
          )}
        </div>
      </div>

      {nlError && <p className="text-sm text-destructive">{nlError}</p>}

      {nlFilters && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-primary">
          <span className="text-primary/70">AI interpreted this as:</span>
          {Object.entries(nlFilters).every(([, v]) => !v) && <span className="text-primary/70">no specific filters - showing everything</span>}
          {Object.entries(nlFilters)
            .filter(([, v]) => v)
            .map(([key, value]) => (
              <span key={key} className="rounded-full border border-primary bg-primary/40 px-2 py-0.5">
                {key}: {value}
              </span>
            ))}
        </div>
      )}

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground border-b border-secondary">
                <th className="hidden px-4 py-2 font-medium md:table-cell">Timestamp</th>
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">User</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">Source IP</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Type</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Message</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Incident</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {events.map((event) => (
                <tr key={event.id} className="hover:bg-secondary/40">
                  <td className="hidden px-4 py-2 whitespace-nowrap text-muted-foreground font-mono text-xs md:table-cell">{event.timestamp}</td>
                  <td className="px-4 py-2 text-foreground">{event.host}</td>
                  <td className="hidden px-4 py-2 text-foreground lg:table-cell">{event.username ?? '-'}</td>
                  <td className="hidden px-4 py-2 text-muted-foreground font-mono text-xs lg:table-cell">{event.source_ip ?? '-'}</td>
                  <td className="hidden px-4 py-2 text-foreground sm:table-cell">{event.event_type}</td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td className="hidden px-4 py-2 text-foreground max-w-md truncate md:table-cell" title={event.message}>
                    {event.message}
                  </td>
                  <td className="hidden px-4 py-2 sm:table-cell">
                    {event.incident_id ? (
                      <Link to={`/incidents/${event.incident_id}`} className="text-primary hover:underline">
                        #{event.incident_id}
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap">
                    <button
                      onClick={() => openExplain(event)}
                      className="rounded-lg border border-primary hover:bg-primary/40 text-xs px-2.5 py-1 transition text-primary"
                    >
                      Explain
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-muted-foreground">
                    No events match these filters.
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
              disabled={!hasPrev || !!nlFilters}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              className="px-3 py-1 rounded-lg border border-border disabled:opacity-40 hover:bg-secondary transition"
            >
              Previous
            </button>
            <button
              disabled={!hasNext || !!nlFilters}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
              className="px-3 py-1 rounded-lg border border-border disabled:opacity-40 hover:bg-secondary transition"
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
            className="w-full max-w-lg rounded-xl border border-primary/60 bg-card p-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-primary">AI Event Explanation</h2>
              <button onClick={closeExplain} className="text-muted-foreground hover:text-foreground text-sm">
                Close
              </button>
            </div>
            <p className="text-xs text-muted-foreground mb-3 font-mono truncate" title={explainTarget.message}>
              {explainTarget.message}
            </p>

            {explaining && <p className="text-sm text-muted-foreground">Analyzing...</p>}
            {explainError && <p className="text-sm text-destructive">{explainError}</p>}
            {explanation && (
              <div className="space-y-3">
                <p className="text-sm text-foreground">{explanation.explanation}</p>
                <div className="flex items-center gap-2 text-xs">
                  <span
                    className={`rounded-full px-2 py-0.5 font-medium ${
                      explanation.is_suspicious
                        ? 'bg-destructive/60 text-destructive border border-destructive'
                        : 'bg-severity-low/60 text-severity-low border border-severity-low'
                    }`}
                  >
                    {explanation.is_suspicious ? 'Suspicious' : 'Likely benign'}
                  </span>
                </div>
                {explanation.recommended_action && (
                  <p className="text-xs text-muted-foreground">
                    <span className="text-muted-foreground">Recommended: </span>
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
