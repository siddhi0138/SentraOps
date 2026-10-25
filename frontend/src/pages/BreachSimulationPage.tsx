import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import { SeverityBadge } from '../components/Badge'
import type { BasTechnique } from '../api/types'
import { usePersistentState } from '../hooks/usePersistentState'

export function BreachSimulationPage() {
  const { user } = useAuth()
  const canAct = roleCanAct(user?.role)

  const [techniques, setTechniques] = useState<BasTechnique[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [tearingDown, setTearingDown] = useState(false)
  const [message, setMessage] = usePersistentState<string>('bas-message')
  const [error, setError] = useState<string | null>(null)
  const [lastMode, setLastMode] = usePersistentState<'real' | 'simulated'>('bas-last-mode')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.listBasTechniques()
      setTechniques(res.techniques)
      setSelected(new Set(res.techniques.map((t) => t.id)))
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load techniques')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function run() {
    setRunning(true)
    setMessage(null)
    setError(null)
    setLastMode(null)
    try {
      const res = await api.runBasCampaign([...selected])
      const correlateResult = await api.correlate()
      await api.syncGraph().catch(() => {})
      setLastMode(res.mode)
      const verb =
        res.mode === 'simulated'
          ? `Simulated ${res.ran} technique(s) - nothing was executed (no Kubernetes cluster is available here)`
          : `Ran ${res.ran} technique(s) against a real sandboxed target pod`
      setMessage(
        `${verb} - ${res.ingested} event(s) ingested, ${correlateResult.incidents_created} incident(s) created. ` +
          'Check the Incidents page for AI investigation.'
      )
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Run failed')
    } finally {
      setRunning(false)
    }
  }

  async function teardown() {
    setTearingDown(true)
    setMessage(null)
    setError(null)
    try {
      const res = await api.teardownBasTarget()
      setMessage(res.deleted ? 'Target pod deleted.' : 'No target pod was running.')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Teardown failed')
    } finally {
      setTearingDown(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Breach & Attack Simulation</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Executes real MITRE ATT&CK techniques inside a real, disposable Kubernetes pod - genuine attacker behavior
          against a sandboxed target you own. The real command output flows through the same ingestion, correlation,
          and AI investigation pipeline as any other log source. When no cluster is available (for example on a free
          hosting plan), the run uses sample output instead and is clearly marked as simulated.
        </p>
      </div>

      {message && (
        <p className="text-sm text-severity-low">
          {lastMode === 'simulated' && (
            <span className="mr-2 rounded border border-primary px-1.5 py-0.5 text-xs font-mono text-primary">
              SIMULATED
            </span>
          )}
          {message}
        </p>
      )}
      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}
      {loading && <p className="text-muted-foreground text-sm">Loading techniques...</p>}

      {!loading && (
        <div className="panel divide-y divide-secondary">
          {techniques.map((t) => (
            <label key={t.id} className="p-4 flex items-center justify-between gap-4 cursor-pointer">
              <div className="flex items-center gap-3 min-w-0">
                <input
                  type="checkbox"
                  checked={selected.has(t.id)}
                  onChange={() => toggle(t.id)}
                  disabled={!canAct}
                  className="shrink-0"
                />
                <div className="min-w-0">
                  <p className="text-sm text-foreground">
                    <span className="font-mono text-muted-foreground">{t.id}</span> {t.name}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5 capitalize">{t.category.replace(/-/g, ' ')}</p>
                </div>
              </div>
              <SeverityBadge severity={t.severity} />
            </label>
          ))}
        </div>
      )}

      {canAct && (
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => void run()}
            disabled={running || selected.size === 0}
            className="rounded-lg bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50 text-sm px-4 py-2 transition"
          >
            {running ? 'Running...' : `Run ${selected.size} technique(s)`}
          </button>
          <button
            onClick={() => void teardown()}
            disabled={tearingDown}
            className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-sm px-4 py-2 transition"
          >
            {tearingDown ? 'Tearing down...' : 'Tear down target pod'}
          </button>
        </div>
      )}
    </div>
  )
}
