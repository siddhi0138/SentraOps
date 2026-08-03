import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { isAdminRole } from '../auth/roles'
import type { Playbook } from '../api/types'

const CATEGORY_LABELS: Record<string, string> = {
  'threat-type': 'Threat-Type Playbooks',
  compliance: 'Compliance Playbooks',
  'reporting-style': 'Reporting Style',
}

export function AIMarketplacePage() {
  const { user } = useAuth()
  const isAdmin = isAdminRole(user?.role)

  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.listMarketplacePlaybooks()
      setPlaybooks(res.playbooks)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load marketplace')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function toggle(playbook: Playbook) {
    setBusyId(playbook.id)
    try {
      if (playbook.installed) {
        await api.uninstallPlaybook(playbook.id)
      } else {
        await api.installPlaybook(playbook.id)
      }
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update playbook')
    } finally {
      setBusyId(null)
    }
  }

  const byCategory = playbooks.reduce<Record<string, Playbook[]>>((acc, p) => {
    ;(acc[p.category] ??= []).push(p)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">AI Marketplace</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Installable playbooks that customize how the AI explains incidents - each one only ever adds guidance
          text to an already-audited prompt, never new code execution. See Integrations for connector/response-action
          plugins.
        </p>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}
      {loading && <p className="text-muted-foreground text-sm">Loading...</p>}

      {!loading &&
        Object.entries(byCategory).map(([category, items]) => (
          <div key={category} className="space-y-2">
            <h2 className="text-sm font-medium text-foreground">{CATEGORY_LABELS[category] ?? category}</h2>
            <div className="grid md:grid-cols-2 gap-3">
              {items.map((playbook) => (
                <div key={playbook.id} className="panel p-4 flex flex-col gap-2">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-sm text-foreground font-medium">{playbook.name}</p>
                    {playbook.installed && (
                      <span className="shrink-0 text-xs px-2 py-0.5 rounded bg-severity-low/80 text-severity-low">
                        Installed
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground flex-1">{playbook.description}</p>
                  {isAdmin && (
                    <button
                      onClick={() => void toggle(playbook)}
                      disabled={busyId === playbook.id}
                      className={`self-start rounded-lg border text-xs px-3 py-1.5 transition disabled:opacity-50 ${
                        playbook.installed
                          ? 'border-destructive hover:bg-destructive/40 text-destructive'
                          : 'border-primary hover:bg-primary/40 text-primary'
                      }`}
                    >
                      {playbook.installed ? 'Uninstall' : 'Install'}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
    </div>
  )
}
