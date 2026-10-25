import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import { SeverityBadge } from '../components/Badge'
import type { BasTechnique } from '../api/types'

export function BreachSimulationPage() {
  const { user } = useAuth()
  const canAct = roleCanAct(user?.role)

  const [techniques, setTechniques] = useState<BasTechnique[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [tearingDown, setTearingDown] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notConfigured, setNotConfigured] = useState(false)

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
    setNotConfigured(false)
    try {
      const res = await api.runBasCampaign([...selected])
      const correlateResult = await api.correlate()
      await api.syncGraph().catch(() => {})
      setMessage(
        `Ran ${res.ran} technique(s) against a real sandboxed target pod - ${res.ingested} event(s) ingested, ` +
          `${correlateResult.incidents_created} incident(s) created. Check the Incidents page for AI investigation.`
      )
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) {
        setNotConfigured(true)
      } else {
        setError(err instanceof ApiError ? err.message : 'Run failed')
      }
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
          against a sandboxed target you own, not synthetic canned data. The real command output flows through the
          same ingestion, correlation, and AI investigation pipeline as any other log source.
        </p>
      </div>

      {message && <p className="text-sm text-severity-low">{message}</p>}
      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}
      {notConfigured && (
        <p className="text-sm text-muted-foreground bg-card/60 border border-secondary rounded-lg px-3 py-2">
          BAS isn't available here - it only runs when SentraOps itself is deployed to a Kubernetes cluster (see
          deploy/helm/), not under plain <code>docker compose up</code>.
        </p>
      )}

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
            {running ? 'Running against target pod...' : `Run ${selected.size} technique(s)`}
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
