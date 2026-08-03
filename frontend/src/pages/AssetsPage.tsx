import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct } from '../auth/roles'
import { SeverityBadge } from '../components/Badge'
import type { Asset, Severity } from '../api/types'

const CRITICALITIES: Severity[] = ['low', 'medium', 'high', 'critical']

function AssetRow({ asset, canEdit, onSaved }: { asset: Asset; canEdit: boolean; onSaved: (updated: Asset) => void }) {
  const [editing, setEditing] = useState(false)
  const [department, setDepartment] = useState(asset.department ?? '')
  const [owner, setOwner] = useState(asset.owner ?? '')
  const [os, setOs] = useState(asset.os ?? '')
  const [criticality, setCriticality] = useState<Severity>(asset.criticality)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  async function save() {
    setSaving(true)
    setSaveError(null)
    try {
      const updated = await api.updateAsset(asset.id, { department, owner, os, criticality })
      onSaved(updated)
      setEditing(false)
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  if (!editing) {
    return (
      <tr className="hover:bg-secondary/40">
        <td className="px-4 py-2 text-foreground">{asset.host}</td>
        <td className="px-4 py-2">
          <SeverityBadge severity={asset.criticality} />
        </td>
        <td className="hidden px-4 py-2 text-foreground md:table-cell">{asset.department ?? '-'}</td>
        <td className="hidden px-4 py-2 text-foreground md:table-cell">{asset.owner ?? '-'}</td>
        <td className="hidden px-4 py-2 text-foreground lg:table-cell">{asset.os ?? '-'}</td>
        <td className="hidden px-4 py-2 text-muted-foreground sm:table-cell">{asset.event_count}</td>
        <td className="hidden px-4 py-2 whitespace-nowrap text-muted-foreground font-mono text-xs lg:table-cell">{asset.last_seen}</td>
        <td className="px-4 py-2">
          {canEdit && (
            <button onClick={() => setEditing(true)} className="text-primary hover:underline text-xs">
              Edit
            </button>
          )}
        </td>
      </tr>
    )
  }

  return (
    <tr className="bg-secondary/40">
      <td className="px-4 py-2 text-foreground">{asset.host}</td>
      <td className="px-4 py-2">
        <select
          value={criticality}
          onChange={(e) => setCriticality(e.target.value as Severity)}
          className="rounded bg-secondary border border-border px-2 py-1 text-xs text-foreground"
        >
          {CRITICALITIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-2">
        <input value={department} onChange={(e) => setDepartment(e.target.value)} className="w-28 rounded bg-secondary border border-border px-2 py-1 text-xs text-foreground" />
      </td>
      <td className="px-4 py-2">
        <input value={owner} onChange={(e) => setOwner(e.target.value)} className="w-28 rounded bg-secondary border border-border px-2 py-1 text-xs text-foreground" />
      </td>
      <td className="px-4 py-2">
        <input value={os} onChange={(e) => setOs(e.target.value)} className="w-28 rounded bg-secondary border border-border px-2 py-1 text-xs text-foreground" />
      </td>
      <td className="px-4 py-2 text-muted-foreground">{asset.event_count}</td>
      <td className="px-4 py-2 whitespace-nowrap text-muted-foreground font-mono text-xs">{asset.last_seen}</td>
      <td className="px-4 py-2">
        <div className="flex gap-2">
          <button disabled={saving} onClick={save} className="text-severity-low hover:underline text-xs disabled:opacity-50">
            Save
          </button>
          <button onClick={() => setEditing(false)} className="text-muted-foreground hover:underline text-xs">
            Cancel
          </button>
        </div>
        {saveError && <p className="text-destructive text-xs mt-1">{saveError}</p>}
      </td>
    </tr>
  )
}

export function AssetsPage() {
  const { user } = useAuth()
  const canEdit = canAct(user?.role)

  const [searchParams] = useSearchParams()
  const [q, setQ] = useState(() => searchParams.get('q') ?? '')
  const [debouncedQ, setDebouncedQ] = useState(() => searchParams.get('q') ?? '')
  const [assets, setAssets] = useState<Asset[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q), 300)
    return () => clearTimeout(timer)
  }, [q])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .listAssets({ q: debouncedQ || undefined, limit: 200 })
      .then((res) => {
        if (cancelled) return
        setAssets(res.assets)
        setTotal(res.total)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [debouncedQ])

  function handleSaved(updated: Asset) {
    setAssets((prev) => prev.map((a) => (a.id === updated.id ? updated : a)))
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-lg font-semibold text-foreground">Assets</h1>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search host, department, owner..."
          className="rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground w-full sm:w-72 focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground border-b border-secondary">
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Criticality</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Department</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Owner</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">OS</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Events</th>
                <th className="hidden px-4 py-2 font-medium lg:table-cell">Last Seen</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-secondary">
              {assets.map((asset) => (
                <AssetRow key={asset.id} asset={asset} canEdit={canEdit} onSaved={handleSaved} />
              ))}
              {!loading && assets.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">
                    No assets discovered yet. Assets appear automatically as logs are ingested.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-3 border-t border-secondary text-sm text-muted-foreground">{total} total</div>
      </div>
    </div>
  )
}
