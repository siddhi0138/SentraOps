import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { isAdminRole } from '../auth/roles'
import type { ApiKeyCreated, ApiKeySummary, AuditLogEntryItem, OrganizationSettings } from '../api/types'

function OrgSettingsSection({ org, isAdmin, onChange }: { org: OrganizationSettings; isAdmin: boolean; onChange: () => void }) {
  const [name, setName] = useState(org.name)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  async function saveName() {
    if (!name.trim() || name === org.name) return
    setBusy(true)
    try {
      await api.renameOrganization(name.trim())
      setMessage('Organization renamed.')
      onChange()
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Failed to rename organization')
    } finally {
      setBusy(false)
    }
  }

  async function rotateCode() {
    setBusy(true)
    try {
      await api.rotateInviteCode()
      setMessage('Invite code rotated - the old code no longer works.')
      onChange()
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Failed to rotate invite code')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-medium text-foreground">Organization Settings</h2>
      {message && <p className="text-xs text-muted-foreground">{message}</p>}
      {isAdmin ? (
        <>
          <div className="flex gap-2 max-w-md">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground"
            />
            <button
              onClick={() => void saveName()}
              disabled={busy}
              className="rounded-lg border border-primary hover:bg-primary/40 disabled:opacity-50 text-xs px-3 py-1.5 text-primary transition"
            >
              Save
            </button>
          </div>
          <div className="flex items-center gap-3">
            <p className="text-sm text-muted-foreground">
              Invite code: <span className="font-mono text-foreground">{org.slug}</span>
            </p>
            <button
              onClick={() => void rotateCode()}
              disabled={busy}
              className="rounded-lg border border-severity-medium hover:bg-severity-medium/40 disabled:opacity-50 text-xs px-2.5 py-1 text-severity-medium transition"
            >
              Rotate Invite Code
            </button>
          </div>
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          {org.name} &middot; invite code <span className="font-mono text-foreground">{org.slug}</span>
        </p>
      )}
    </div>
  )
}

function ApiKeysSection() {
  const [keys, setKeys] = useState<ApiKeySummary[]>([])
  const [newName, setNewName] = useState('')
  const [justCreated, setJustCreated] = useState<ApiKeyCreated | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    const res = await api.listApiKeys()
    setKeys(res.api_keys)
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function create() {
    if (!newName.trim()) return
    setBusy(true)
    setError(null)
    try {
      const created = await api.createApiKey(newName.trim())
      setJustCreated(created)
      setNewName('')
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create API key')
    } finally {
      setBusy(false)
    }
  }

  async function revoke(id: number) {
    setBusy(true)
    try {
      await api.revokeApiKey(id)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke API key')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-medium text-foreground">API Keys</h2>
      <p className="text-xs text-muted-foreground">For programmatic access (CI, external integrations) - alternative to a JWT login.</p>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {justCreated && (
        <div className="rounded-lg border border-severity-low bg-severity-low/30 p-3 space-y-1">
          <p className="text-xs text-severity-low">
            Copy this key now - it will not be shown again: <button onClick={() => setJustCreated(null)} className="float-right text-muted-foreground hover:text-foreground">dismiss</button>
          </p>
          <code className="block text-sm text-foreground break-all">{justCreated.key}</code>
        </div>
      )}

      <div className="flex gap-2 max-w-md">
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Key name (e.g. CI Pipeline)"
          className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <button
          onClick={() => void create()}
          disabled={busy}
          className="rounded-lg border border-primary hover:bg-primary/40 disabled:opacity-50 text-xs px-3 py-1.5 text-primary transition"
        >
          Create
        </button>
      </div>

      <div className="divide-y divide-secondary">
        {keys.map((key) => (
          <div key={key.id} className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm text-foreground">
                {key.name} <span className="font-mono text-xs text-muted-foreground">{key.key_prefix}...</span>
              </p>
              <p className="text-xs text-muted-foreground">
                acts as {key.acts_as_email} &middot; {key.last_used_at ? `last used ${key.last_used_at}` : 'never used'}
              </p>
            </div>
            {key.revoked ? (
              <span className="text-xs text-destructive">Revoked</span>
            ) : (
              <button
                onClick={() => void revoke(key.id)}
                disabled={busy}
                className="rounded-lg border border-destructive hover:bg-destructive/40 disabled:opacity-50 text-xs px-2.5 py-1 text-destructive transition"
              >
                Revoke
              </button>
            )}
          </div>
        ))}
        {keys.length === 0 && <p className="text-sm text-muted-foreground py-2">No API keys yet.</p>}
      </div>
    </div>
  )
}

function AuditLogSection() {
  const [entries, setEntries] = useState<AuditLogEntryItem[]>([])

  useEffect(() => {
    void api.listAuditLog().then((res) => setEntries(res.entries))
  }, [])

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-medium text-foreground">Audit Log</h2>
      <div className="divide-y divide-secondary">
        {entries.map((entry) => (
          <div key={entry.id} className="py-2 text-sm">
            <span className="text-foreground">{entry.action.replace(/_/g, ' ')}</span>
            <span className="text-muted-foreground"> by {entry.actor_email} &middot; {entry.created_at}</span>
            <pre className="text-xs text-muted-foreground mt-1 whitespace-pre-wrap">{JSON.stringify(entry.details)}</pre>
          </div>
        ))}
        {entries.length === 0 && <p className="text-sm text-muted-foreground py-2">No audit entries yet.</p>}
      </div>
    </div>
  )
}

export function EnterpriseAdminPage() {
  const { user } = useAuth()
  const isAdmin = isAdminRole(user?.role)

  const [org, setOrg] = useState<OrganizationSettings | null>(null)
  const [loading, setLoading] = useState(true)

  const loadOrg = useCallback(async () => {
    setOrg(await api.getCurrentOrganization())
  }, [])

  useEffect(() => {
    void loadOrg().finally(() => setLoading(false))
  }, [loadOrg])

  if (loading || !org) {
    return <div className="text-muted-foreground">Loading enterprise admin...</div>
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Enterprise Administration</h1>
        <p className="text-sm text-muted-foreground mt-1">Organization settings, API keys, and the security audit log.</p>
      </div>
      <OrgSettingsSection org={org} isAdmin={isAdmin} onChange={() => void loadOrg()} />
      {isAdmin ? (
        <>
          <ApiKeysSection />
          <AuditLogSection />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">API keys and the audit log are only visible to organization admins.</p>
      )}
    </div>
  )
}
