import { useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { AttackGraphView } from '../components/AttackGraphView'
import { StatCard } from '../components/StatCard'
import { usePersistentState } from '../hooks/usePersistentState'
import type { DigitalTwinNarrative, DigitalTwinSimulation } from '../api/types'

type EntityType = 'host' | 'user' | 'ip'

interface TwinState {
  entityType: EntityType
  entityValue: string
  hops: number
  simulation: DigitalTwinSimulation | null
  narrative: DigitalTwinNarrative | null
}

const CONFIDENCE_COLOR: Record<string, string> = {
  low: 'text-muted-foreground',
  medium: 'text-severity-high',
  high: 'text-destructive',
}

export function DigitalTwinPage() {
  // Real generated simulations/narratives, kept across a refresh like the
  // rest of this app's AI output - previously this whole page silently
  // re-ran the default auto-simulation on every reload, discarding
  // whatever the user had actually asked for.
  const [twin, setTwin] = usePersistentState<TwinState>('digital-twin-state')
  const entityType = twin?.entityType ?? 'host'
  const entityValue = twin?.entityValue ?? ''
  const hops = twin?.hops ?? 2
  const simulation = twin?.simulation ?? null
  const narrative = twin?.narrative ?? null

  const [simulating, setSimulating] = useState(false)
  const [narrating, setNarrating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function patchTwin(patch: Partial<TwinState>) {
    setTwin((prev) => ({
      entityType: prev?.entityType ?? 'host',
      entityValue: prev?.entityValue ?? '',
      hops: prev?.hops ?? 2,
      simulation: prev?.simulation ?? null,
      narrative: prev?.narrative ?? null,
      ...patch,
    }))
  }

  async function runSimulate(type: EntityType, value: string, hopsValue: number) {
    if (!value.trim()) return
    setSimulating(true)
    setError(null)
    patchTwin({ entityType: type, entityValue: value, hops: hopsValue, narrative: null })
    try {
      const result = await api.simulateCompromise(type, value.trim(), hopsValue)
      patchTwin({ entityType: type, entityValue: value, hops: hopsValue, simulation: result, narrative: null })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  function handleSimulate() {
    return runSimulate(entityType, entityValue, hops)
  }

  // The page is a query tool, not a dashboard - it has nothing to show until
  // someone picks an entity. Auto-fill with this org's most-referenced real
  // host and run it once, the first time this page is ever opened in this
  // session (real data, not a fabricated placeholder) - but only when there
  // is no persisted state yet, so it never overwrites what the user already
  // generated on a later visit/refresh.
  useEffect(() => {
    if (twin) return
    let cancelled = false
    api
      .listAssets({ limit: 20 })
      .then((res) => {
        if (cancelled || res.assets.length === 0) return
        const top = [...res.assets].sort((a, b) => b.event_count - a.event_count)[0].host
        void runSimulate('host', top, 2)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleNarrative() {
    if (!entityValue.trim()) return
    setNarrating(true)
    setError(null)
    try {
      const res = await api.getDigitalTwinNarrative(entityType, entityValue.trim(), hops)
      patchTwin({ simulation: res.simulation, narrative: res.narrative })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate narrative')
    } finally {
      setNarrating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Security Digital Twin</h1>
        <p className="text-sm text-muted-foreground mt-1">
          "What happens if this is compromised?" - a read-only simulation over this organization's real attack
          graph and asset data. Nothing here touches production.
        </p>
      </div>

      <div className="panel p-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Entity type</label>
          <select
            value={entityType}
            onChange={(e) => patchTwin({ entityType: e.target.value as EntityType })}
            className="bg-secondary border border-border rounded-lg px-3 py-1.5 text-sm text-foreground"
          >
            <option value="host">Host</option>
            <option value="user">User</option>
            <option value="ip">IP</option>
          </select>
        </div>
        <div className="flex-1 min-w-[160px]">
          <label className="block text-xs text-muted-foreground mb-1">Value</label>
          <input
            value={entityValue}
            onChange={(e) => patchTwin({ entityValue: e.target.value })}
            onKeyDown={(e) => e.key === 'Enter' && void handleSimulate()}
            placeholder="e.g. FINANCE-PC-21"
            className="w-full bg-secondary border border-border rounded-lg px-3 py-1.5 text-sm text-foreground"
          />
        </div>
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Hops</label>
          <input
            type="number"
            min={1}
            max={4}
            value={hops}
            onChange={(e) => patchTwin({ hops: Number(e.target.value) })}
            className="w-16 bg-secondary border border-border rounded-lg px-3 py-1.5 text-sm text-foreground"
          />
        </div>
        <button
          onClick={() => void handleSimulate()}
          disabled={simulating || !entityValue.trim()}
          className="rounded-lg bg-border hover:bg-muted-foreground disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
        >
          {simulating ? 'Simulating...' : 'Simulate Compromise'}
        </button>
        <button
          onClick={() => void handleNarrative()}
          disabled={narrating || !entityValue.trim()}
          className="rounded-lg bg-primary hover:bg-primary disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
        >
          {narrating ? 'Generating...' : 'Generate AI Narrative'}
        </button>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      {narrative && (
        <div className="rounded-xl border border-primary/60 bg-primary/20 p-5 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-primary">Predicted lateral movement</p>
            <span className={`text-xs ${CONFIDENCE_COLOR[narrative.confidence]}`}>confidence: {narrative.confidence}</span>
          </div>
          <p className="text-sm text-foreground">{narrative.lateral_movement_narrative}</p>
          {narrative.affected_systems.length > 0 && (
            <p className="text-xs text-muted-foreground">Affected systems: {narrative.affected_systems.join(', ')}</p>
          )}
          <p className="text-sm text-foreground pt-1">{narrative.business_impact}</p>
          <p className="text-xs text-muted-foreground">Estimated recovery: {narrative.estimated_recovery}</p>
        </div>
      )}

      {simulation && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Reachable Hosts" value={simulation.reachable_hosts} />
            <StatCard label="Reachable Users" value={simulation.reachable_users} />
            <StatCard label="Related Incidents" value={simulation.related_incidents} />
            <StatCard
              label="Business Impact"
              value={`${simulation.business_impact_pct}%`}
              accent={simulation.business_impact_pct >= 60 ? 'text-destructive' : simulation.business_impact_pct >= 30 ? 'text-severity-high' : undefined}
            />
          </div>

          <div className="panel p-4">
            <h2 className="text-sm font-medium text-foreground mb-3">Affected Assets</h2>
            {simulation.affected_assets.length === 0 ? (
              <p className="text-sm text-muted-foreground">No reachable hosts found for this entity.</p>
            ) : (
              <div className="divide-y divide-secondary">
                {simulation.affected_assets.map((a) => (
                  <div key={a.host} className="flex items-center justify-between py-2.5">
                    <div>
                      <p className="text-sm text-foreground">{a.host}</p>
                      <p className="text-xs text-muted-foreground">
                        {a.department ?? 'unknown department'} &middot; {a.owner ?? 'unowned'}
                      </p>
                    </div>
                    <span className="text-xs text-muted-foreground">{a.criticality}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="panel p-4">
            <h2 className="text-sm font-medium text-foreground mb-3">Blast Radius Graph</h2>
            <AttackGraphView data={simulation.graph} />
          </div>
        </>
      )}
    </div>
  )
}
