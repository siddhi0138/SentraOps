import { useState } from 'react'
import { api, ApiError } from '../api/client'
import { AttackGraphView } from '../components/AttackGraphView'
import { StatCard } from '../components/StatCard'
import type { DigitalTwinNarrative, DigitalTwinSimulation } from '../api/types'

type EntityType = 'host' | 'user' | 'ip'

const CONFIDENCE_COLOR: Record<string, string> = {
  low: 'text-slate-400',
  medium: 'text-orange-400',
  high: 'text-red-400',
}

export function DigitalTwinPage() {
  const [entityType, setEntityType] = useState<EntityType>('host')
  const [entityValue, setEntityValue] = useState('')
  const [hops, setHops] = useState(2)

  const [simulation, setSimulation] = useState<DigitalTwinSimulation | null>(null)
  const [narrative, setNarrative] = useState<DigitalTwinNarrative | null>(null)
  const [simulating, setSimulating] = useState(false)
  const [narrating, setNarrating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSimulate() {
    if (!entityValue.trim()) return
    setSimulating(true)
    setError(null)
    setNarrative(null)
    try {
      setSimulation(await api.simulateCompromise(entityType, entityValue.trim(), hops))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  async function handleNarrative() {
    if (!entityValue.trim()) return
    setNarrating(true)
    setError(null)
    try {
      const res = await api.getDigitalTwinNarrative(entityType, entityValue.trim(), hops)
      setSimulation(res.simulation)
      setNarrative(res.narrative)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate narrative')
    } finally {
      setNarrating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-100">Security Digital Twin</h1>
        <p className="text-sm text-slate-500 mt-1">
          "What happens if this is compromised?" - a read-only simulation over this organization's real attack
          graph and asset data. Nothing here touches production.
        </p>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="block text-xs text-slate-500 mb-1">Entity type</label>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as EntityType)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100"
          >
            <option value="host">Host</option>
            <option value="user">User</option>
            <option value="ip">IP</option>
          </select>
        </div>
        <div className="flex-1 min-w-[160px]">
          <label className="block text-xs text-slate-500 mb-1">Value</label>
          <input
            value={entityValue}
            onChange={(e) => setEntityValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void handleSimulate()}
            placeholder="e.g. FINANCE-PC-21"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1">Hops</label>
          <input
            type="number"
            min={1}
            max={4}
            value={hops}
            onChange={(e) => setHops(Number(e.target.value))}
            className="w-16 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100"
          />
        </div>
        <button
          onClick={() => void handleSimulate()}
          disabled={simulating || !entityValue.trim()}
          className="rounded-lg bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
        >
          {simulating ? 'Simulating...' : 'Simulate Compromise'}
        </button>
        <button
          onClick={() => void handleNarrative()}
          disabled={narrating || !entityValue.trim()}
          className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
        >
          {narrating ? 'Generating...' : 'Generate AI Narrative'}
        </button>
      </div>

      {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

      {narrative && (
        <div className="rounded-xl border border-indigo-900/60 bg-indigo-950/20 p-5 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-indigo-300">Predicted lateral movement</p>
            <span className={`text-xs ${CONFIDENCE_COLOR[narrative.confidence]}`}>confidence: {narrative.confidence}</span>
          </div>
          <p className="text-sm text-slate-300">{narrative.lateral_movement_narrative}</p>
          {narrative.affected_systems.length > 0 && (
            <p className="text-xs text-slate-400">Affected systems: {narrative.affected_systems.join(', ')}</p>
          )}
          <p className="text-sm text-slate-300 pt-1">{narrative.business_impact}</p>
          <p className="text-xs text-slate-500">Estimated recovery: {narrative.estimated_recovery}</p>
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
              accent={simulation.business_impact_pct >= 60 ? 'text-red-400' : simulation.business_impact_pct >= 30 ? 'text-orange-400' : undefined}
            />
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Affected Assets</h2>
            {simulation.affected_assets.length === 0 ? (
              <p className="text-sm text-slate-500">No reachable hosts found for this entity.</p>
            ) : (
              <div className="divide-y divide-slate-800">
                {simulation.affected_assets.map((a) => (
                  <div key={a.host} className="flex items-center justify-between py-2.5">
                    <div>
                      <p className="text-sm text-slate-100">{a.host}</p>
                      <p className="text-xs text-slate-500">
                        {a.department ?? 'unknown department'} &middot; {a.owner ?? 'unowned'}
                      </p>
                    </div>
                    <span className="text-xs text-slate-400">{a.criticality}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Blast Radius Graph</h2>
            <AttackGraphView data={simulation.graph} />
          </div>
        </>
      )}
    </div>
  )
}
