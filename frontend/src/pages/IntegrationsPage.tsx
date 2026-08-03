import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import type {
  ConnectorInstance,
  ConnectorPluginType,
  ResponseActionInstance,
  ResponseActionPluginType,
  StreamingStatus,
} from '../api/types'

function StreamingSection({ canAct }: { canAct: boolean }) {
  const [status, setStatus] = useState<StreamingStatus | null>(null)
  const [sending, setSending] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const load = useCallback(async () => {
    setStatus(await api.getStreamingStatus())
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Only poll for a short window right after sending a test log, long
  // enough to watch `pending` drop back to zero as the Celery worker
  // drains it - not a permanent poll, since nothing else in this UI
  // publishes onto the stream continuously.
  function pollBriefly() {
    if (pollRef.current) clearInterval(pollRef.current)
    let ticks = 0
    pollRef.current = setInterval(() => {
      ticks += 1
      void load()
      if (ticks >= 6 && pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }, 1000)
  }

  useEffect(() => () => {
    if (pollRef.current) clearInterval(pollRef.current)
  }, [])

  async function sendTestLog() {
    setSending(true)
    try {
      await api.sendTestStreamLog()
      await load()
      pollBriefly()
    } finally {
      setSending(false)
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-slate-200">Real-Time Streaming Ingestion</h2>
      <p className="text-xs text-slate-500">
        High-volume log sources can publish onto a Redis Stream instead of waiting on a synchronous ingest request -
        a separate Celery worker drains it moments later (Redis Streams + a dispatched consumer standing in for a
        Kafka + Spark Streaming pipeline).
      </p>
      {status && (
        <div className="flex gap-4 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-sm">
          <span className="text-slate-300">
            Queued: <span className="font-mono text-slate-100">{status.queued}</span>
          </span>
          <span className="text-slate-300">
            Awaiting processing: <span className="font-mono text-slate-100">{status.pending}</span>
          </span>
        </div>
      )}
      {canAct && (
        <button
          onClick={() => void sendTestLog()}
          disabled={sending}
          className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 disabled:opacity-50 text-xs px-3 py-1.5 text-indigo-300 transition"
        >
          {sending ? 'Sending...' : 'Send Test Log via Stream'}
        </button>
      )}
    </div>
  )
}

function ConfigForm({
  fields,
  config,
  onChange,
}: {
  fields: string[]
  config: Record<string, string>
  onChange: (config: Record<string, string>) => void
}) {
  if (fields.length === 0) return <p className="text-xs text-slate-500">No configuration needed.</p>
  return (
    <div className="space-y-2">
      {fields.map((field) => (
        <input
          key={field}
          placeholder={field}
          value={config[field] ?? ''}
          onChange={(e) => onChange({ ...config, [field]: e.target.value })}
          className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600"
        />
      ))}
    </div>
  )
}

function ConnectorsSection({ canCreate, canOperate }: { canCreate: boolean; canOperate: boolean }) {
  const [plugins, setPlugins] = useState<ConnectorPluginType[]>([])
  const [instances, setInstances] = useState<ConnectorInstance[]>([])
  const [pluginKey, setPluginKey] = useState('')
  const [name, setName] = useState('')
  const [config, setConfig] = useState<Record<string, string>>({})
  const [busyId, setBusyId] = useState<number | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const load = useCallback(async () => {
    const [pluginsRes, instancesRes] = await Promise.all([api.listConnectorPlugins(), api.listConnectors()])
    setPlugins(pluginsRes.connectors)
    setInstances(instancesRes.connectors)
    if (!pluginKey && pluginsRes.connectors[0]) setPluginKey(pluginsRes.connectors[0].key)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const selectedPlugin = plugins.find((p) => p.key === pluginKey)

  async function create() {
    if (!name.trim() || !pluginKey) return
    try {
      await api.createConnector({ plugin_key: pluginKey, name, config })
      setName('')
      setConfig({})
      await load()
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : 'Failed to create connector')
    }
  }

  async function test(id: number) {
    setBusyId(id)
    try {
      const res = await api.testConnector(id)
      setMessage(`${res.ok ? 'Connected' : 'Failed'}: ${res.message}`)
    } finally {
      setBusyId(null)
    }
  }

  async function sync(id: number) {
    setBusyId(id)
    try {
      const res = await api.syncConnector(id)
      setMessage(`Ingested ${res.ingested} event(s), skipped ${res.skipped}`)
      await load()
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-slate-200">Connectors</h2>
      <p className="text-xs text-slate-500">
        Real, keyless log-source integrations that pull data into the platform through the same ingestion pipeline as
        file uploads.
      </p>

      {message && <p className="text-xs text-slate-400 bg-slate-900/60 border border-slate-800 rounded-lg px-3 py-2">{message}</p>}

      {canCreate && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
          <div className="flex gap-2">
            <select
              value={pluginKey}
              onChange={(e) => {
                setPluginKey(e.target.value)
                setConfig({})
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
            >
              {plugins.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.display_name}
                </option>
              ))}
            </select>
            <input
              placeholder="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600"
            />
          </div>
          {selectedPlugin && (
            <ConfigForm fields={selectedPlugin.config_fields} config={config} onChange={setConfig} />
          )}
          <button
            onClick={() => void create()}
            className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 text-xs px-3 py-1.5 text-indigo-300 transition"
          >
            Add Connector
          </button>
        </div>
      )}

      <div className="space-y-2">
        {instances.map((c) => (
          <div key={c.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-sm text-slate-200">
                  {c.name} <span className="text-xs text-slate-500">({c.plugin_key})</span>
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {c.last_sync_at
                    ? `Last sync ${c.last_sync_status}: ${c.last_sync_message ?? ''} (${c.last_sync_at})`
                    : 'Never synced'}
                </p>
              </div>
              {canOperate && (
                <div className="flex gap-2 shrink-0">
                  <button
                    onClick={() => void test(c.id)}
                    disabled={busyId === c.id}
                    className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-xs px-2.5 py-1 text-slate-300 transition"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => void sync(c.id)}
                    disabled={busyId === c.id}
                    className="rounded-lg border border-emerald-700 hover:bg-emerald-900/40 disabled:opacity-50 text-xs px-2.5 py-1 text-emerald-300 transition"
                  >
                    {busyId === c.id ? 'Syncing...' : 'Sync Now'}
                  </button>
                </div>
              )}
            </div>
          </div>
        ))}
        {instances.length === 0 && <p className="text-sm text-slate-500">No connectors configured yet.</p>}
      </div>
    </div>
  )
}

function ResponseActionsSection({ canCreate }: { canCreate: boolean }) {
  const [plugins, setPlugins] = useState<ResponseActionPluginType[]>([])
  const [instances, setInstances] = useState<ResponseActionInstance[]>([])
  const [pluginKey, setPluginKey] = useState('')
  const [name, setName] = useState('')
  const [config, setConfig] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    const [pluginsRes, instancesRes] = await Promise.all([
      api.listResponseActionPlugins(),
      api.listResponseActionInstances(),
    ])
    setPlugins(pluginsRes.actions)
    setInstances(instancesRes.actions)
    if (!pluginKey && pluginsRes.actions[0]) setPluginKey(pluginsRes.actions[0].key)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const selectedPlugin = plugins.find((p) => p.key === pluginKey)

  async function create() {
    if (!name.trim() || !pluginKey) return
    await api.createResponseActionInstance({ plugin_key: pluginKey, name, config })
    setName('')
    setConfig({})
    await load()
  }

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-medium text-slate-200">Response Action Integrations</h2>
      <p className="text-xs text-slate-500">
        Where an <em>approved</em> proposed action actually gets executed. Nothing here ever fires automatically -
        the AI only proposes, a human approves, and a human then hits Execute on the incident page.
      </p>

      {canCreate && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
          <div className="flex gap-2">
            <select
              value={pluginKey}
              onChange={(e) => {
                setPluginKey(e.target.value)
                setConfig({})
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
            >
              {plugins.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.display_name}
                </option>
              ))}
            </select>
            <input
              placeholder="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600"
            />
          </div>
          {selectedPlugin && (
            <ConfigForm fields={selectedPlugin.config_fields} config={config} onChange={setConfig} />
          )}
          <button
            onClick={() => void create()}
            className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 text-xs px-3 py-1.5 text-indigo-300 transition"
          >
            Add Integration
          </button>
        </div>
      )}

      <div className="space-y-2">
        {instances.map((a) => (
          <div key={a.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <p className="text-sm text-slate-200">
              {a.name} <span className="text-xs text-slate-500">({a.plugin_key})</span>
            </p>
          </div>
        ))}
        {instances.length === 0 && <p className="text-sm text-slate-500">No response-action integrations configured yet.</p>}
      </div>
    </div>
  )
}

export function IntegrationsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const canOperate = isAdmin || user?.role === 'analyst'

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-slate-100">Integrations</h1>
        <p className="text-sm text-slate-500 mt-1">
          Pluggable connectors (inbound log sources) and response actions (outbound execution targets) - see
          app/plugins/ on the backend for how to add more.
        </p>
      </div>
      <ConnectorsSection canCreate={isAdmin} canOperate={canOperate} />
      <ResponseActionsSection canCreate={isAdmin} />
      <StreamingSection canAct={canOperate} />
    </div>
  )
}
