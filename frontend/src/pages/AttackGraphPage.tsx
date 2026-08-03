import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AttackGraphView } from '../components/AttackGraphView'
import type { GraphData, GraphNode } from '../api/types'

type EntityType = 'host' | 'user' | 'ip'

export function AttackGraphPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [syncing, setSyncing] = useState(false)
  const [syncMessage, setSyncMessage] = useState<string | null>(null)

  const [entityType, setEntityType] = useState<EntityType>('host')
  const [entityValue, setEntityValue] = useState('')
  const [hops, setHops] = useState(2)
  const [searching, setSearching] = useState(false)
  const [viewingEntity, setViewingEntity] = useState<string | null>(null)

  async function loadFullGraph() {
    setLoading(true)
    setError(null)
    setViewingEntity(null)
    try {
      setGraph(await api.getFullGraph())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load attack graph')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadFullGraph()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleSync() {
    setSyncing(true)
    setError(null)
    setSyncMessage(null)
    try {
      const result = await api.syncGraph()
      setSyncMessage(`Synced ${result.incidents} incidents / ${result.events_processed} events`)
      await loadFullGraph()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sync failed')
    } finally {
      setSyncing(false)
    }
  }

  async function handleSearch() {
    if (!entityValue.trim()) return
    setSearching(true)
    setError(null)
    try {
      const result = await api.getEntityBlastRadius(entityType, entityValue.trim(), hops)
      setGraph(result)
      setViewingEntity(`${entityType}:${entityValue.trim()}`)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Search failed')
    } finally {
      setSearching(false)
    }
  }

  function handleNodeClick(node: GraphNode) {
    if (node.label === 'Incident' && node.id !== undefined) {
      navigate(`/incidents/${node.id}`)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Attack Graph</h1>
          <p className="text-sm text-slate-500 mt-1">
            How hosts, users, IPs, and incidents connect across the whole platform - not just within one incident.
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void handleSync()}
            disabled={syncing}
            className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-sm px-3 py-1.5 transition"
          >
            {syncing ? 'Syncing...' : 'Sync Graph'}
          </button>
        )}
      </div>

      {syncMessage && <p className="text-sm text-emerald-400">{syncMessage}</p>}
      {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs uppercase tracking-wide text-slate-500 mb-1">Entity type</label>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as EntityType)}
            className="rounded bg-slate-800 border border-slate-700 px-2 py-1.5 text-sm text-slate-100"
          >
            <option value="host">Host</option>
            <option value="user">User</option>
            <option value="ip">IP</option>
          </select>
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className="block text-xs uppercase tracking-wide text-slate-500 mb-1">Value</label>
          <input
            value={entityValue}
            onChange={(e) => setEntityValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="e.g. FINANCE-PC-21"
            className="w-full rounded bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <div>
          <label className="block text-xs uppercase tracking-wide text-slate-500 mb-1">Hops</label>
          <select
            value={hops}
            onChange={(e) => setHops(Number(e.target.value))}
            className="rounded bg-slate-800 border border-slate-700 px-2 py-1.5 text-sm text-slate-100"
          >
            {[1, 2, 3, 4].map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={() => void handleSearch()}
          disabled={searching || !entityValue.trim()}
          className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
        >
          {searching ? 'Searching...' : 'Blast Radius'}
        </button>
        {viewingEntity && (
          <button onClick={() => void loadFullGraph()} className="text-sm text-slate-400 hover:text-slate-200 transition">
            &larr; Back to full graph
          </button>
        )}
      </div>

      {viewingEntity && (
        <p className="text-sm text-slate-400">
          Showing everything within {hops} hop{hops === 1 ? '' : 's'} of <span className="text-slate-200">{viewingEntity}</span>
        </p>
      )}

      {loading && <p className="text-slate-400 text-sm">Loading...</p>}
      {!loading && graph && <AttackGraphView data={graph} onNodeClick={handleNodeClick} />}
    </div>
  )
}
