import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
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
      <tr className="hover:bg-slate-800/40">
        <td className="px-4 py-2 text-slate-200">{asset.host}</td>
        <td className="px-4 py-2">
          <SeverityBadge severity={asset.criticality} />
        </td>
        <td className="px-4 py-2 text-slate-300">{asset.department ?? '-'}</td>
        <td className="px-4 py-2 text-slate-300">{asset.owner ?? '-'}</td>
        <td className="px-4 py-2 text-slate-300">{asset.os ?? '-'}</td>
        <td className="px-4 py-2 text-slate-400">{asset.event_count}</td>
        <td className="px-4 py-2 whitespace-nowrap text-slate-400 font-mono text-xs">{asset.last_seen}</td>
        <td className="px-4 py-2">
          {canEdit && (
            <button onClick={() => setEditing(true)} className="text-indigo-400 hover:underline text-xs">
              Edit
            </button>
          )}
        </td>
      </tr>
    )
  }

  return (
    <tr className="bg-slate-800/40">
      <td className="px-4 py-2 text-slate-200">{asset.host}</td>
      <td className="px-4 py-2">
        <select
          value={criticality}
          onChange={(e) => setCriticality(e.target.value as Severity)}
          className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100"
        >
          {CRITICALITIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </td>
      <td className="px-4 py-2">
        <input value={department} onChange={(e) => setDepartment(e.target.value)} className="w-28 rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100" />
      </td>
      <td className="px-4 py-2">
        <input value={owner} onChange={(e) => setOwner(e.target.value)} className="w-28 rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100" />
      </td>
      <td className="px-4 py-2">
        <input value={os} onChange={(e) => setOs(e.target.value)} className="w-28 rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100" />
      </td>
      <td className="px-4 py-2 text-slate-400">{asset.event_count}</td>
      <td className="px-4 py-2 whitespace-nowrap text-slate-400 font-mono text-xs">{asset.last_seen}</td>
      <td className="px-4 py-2">
        <div className="flex gap-2">
          <button disabled={saving} onClick={save} className="text-emerald-400 hover:underline text-xs disabled:opacity-50">
            Save
          </button>
          <button onClick={() => setEditing(false)} className="text-slate-400 hover:underline text-xs">
            Cancel
          </button>
        </div>
        {saveError && <p className="text-red-400 text-xs mt-1">{saveError}</p>}
      </td>
    </tr>
  )
}

export function AssetsPage() {
  const { user } = useAuth()
  const canEdit = user?.role === 'admin' || user?.role === 'analyst'

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
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-lg font-semibold text-slate-100">Assets</h1>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search host, department, owner..."
          className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 w-72 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-500 border-b border-slate-800">
                <th className="px-4 py-2 font-medium">Host</th>
                <th className="px-4 py-2 font-medium">Criticality</th>
                <th className="px-4 py-2 font-medium">Department</th>
                <th className="px-4 py-2 font-medium">Owner</th>
                <th className="px-4 py-2 font-medium">OS</th>
                <th className="px-4 py-2 font-medium">Events</th>
                <th className="px-4 py-2 font-medium">Last Seen</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {assets.map((asset) => (
                <AssetRow key={asset.id} asset={asset} canEdit={canEdit} onSaved={handleSaved} />
              ))}
              {!loading && assets.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                    No assets discovered yet. Assets appear automatically as logs are ingested.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-3 border-t border-slate-800 text-sm text-slate-400">{total} total</div>
      </div>
    </div>
  )
}
