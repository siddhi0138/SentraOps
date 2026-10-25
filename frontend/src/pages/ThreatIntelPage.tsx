import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import { AttackGraphView } from '../components/AttackGraphView'
import type { GraphData, ThreatIndicator, ThreatIndicatorType } from '../api/types'

const TYPE_OPTIONS: { value: ThreatIndicatorType | ''; label: string }[] = [
  { value: '', label: 'All types' },
  { value: 'ip', label: 'IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash', label: 'Hash' },
]

export function ThreatIntelPage() {
  const { user } = useAuth()
  const canAct = roleCanAct(user?.role)

  const [indicators, setIndicators] = useState<ThreatIndicator[]>([])
  const [q, setQ] = useState('')
  const [type, setType] = useState<ThreatIndicatorType | ''>('')
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const [graph, setGraph] = useState<GraphData | null>(null)
  const [graphLoading, setGraphLoading] = useState(true)
  const [graphSyncing, setGraphSyncing] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.listThreatIndicators({ q: q || undefined, indicator_type: type || undefined })
      setIndicators(res.indicators)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load indicators')
    } finally {
      setLoading(false)
    }
  }, [q, type])

  useEffect(() => {
    void load()
  }, [load])

  async function sync() {
    setSyncing(true)
    setMessage(null)
    setError(null)
    try {
      const res = await api.syncThreatIntel()
      setMessage(`Synced ${res.synced} indicator(s) from URLhaus`)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sync failed')
    } finally {
      setSyncing(false)
    }
  }

  const loadGraph = useCallback(async () => {
    setGraphLoading(true)
    try {
      setGraph(await api.getThreatIntelGraph())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load relationship graph')
    } finally {
      setGraphLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadGraph()
  }, [loadGraph])

  async function syncGraph() {
    setGraphSyncing(true)
    setError(null)
    try {
      const res = await api.syncThreatIntelGraph()
      setMessage(`Synced relationship graph: ${res.indicators} indicators, ${res.tag_links} tag links, ${res.incident_matches} incident matches`)
      await loadGraph()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Graph sync failed')
    } finally {
      setGraphSyncing(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Threat Intel Hub</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Known-bad indicators every organization's correlation engine matches ingested events against - shared
            across tenants, the way a commercial threat-intel feed is one subscription, not a per-customer copy.
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void sync()}
            disabled={syncing}
            className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-sm px-3 py-1.5 transition"
          >
            {syncing ? 'Syncing...' : 'Sync URLhaus Feed'}
          </button>
        )}
      </div>

      {message && <p className="text-sm text-severity-low">{message}</p>}
      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      <div className="flex flex-wrap gap-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search indicator..."
          className="flex-1 min-w-[200px] rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value as ThreatIndicatorType | '')}
          className="rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground"
        >
          {TYPE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {loading && <p className="text-muted-foreground text-sm">Loading...</p>}

      {!loading && (
        <div className="panel divide-y divide-secondary">
          {indicators.length === 0 && <p className="text-sm text-muted-foreground p-4">No indicators found.</p>}
          {indicators.map((ind) => (
            <div key={ind.id} className="p-4 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm text-foreground font-mono truncate">{ind.indicator}</p>
                <p className="text-sm text-muted-foreground mt-0.5">{ind.verdict}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {ind.source} &middot; last seen {ind.last_seen}
                  {ind.tags && ` · tags: ${ind.tags}`}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0 text-xs">
                <span className="uppercase tracking-wide text-muted-foreground">{ind.indicator_type}</span>
                <span className="text-foreground">{ind.confidence}% confidence</span>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="panel p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-sm font-medium text-foreground">Relationship Graph</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              How indicators relate through shared tags and sources, and which have actually matched in this
              organization's real incidents - the graph is queryable, not just a decorative view.
            </p>
          </div>
          {canAct && (
            <button
              onClick={() => void syncGraph()}
              disabled={graphSyncing}
              className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-sm px-3 py-1.5 transition shrink-0"
            >
              {graphSyncing ? 'Syncing...' : 'Sync Graph'}
            </button>
          )}
        </div>
        {graphLoading || !graph ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : (
          <AttackGraphView data={graph} />
        )}
      </div>
    </div>
  )
}
