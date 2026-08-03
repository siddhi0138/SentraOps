import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, slackAuthorizeUrl } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct, isAdminRole } from '../auth/roles'
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
      <h2 className="text-sm font-medium text-foreground">Real-Time Streaming Ingestion</h2>
      <p className="text-xs text-muted-foreground">
        High-volume log sources can publish onto a Redis Stream instead of waiting on a synchronous ingest request -
        a separate Celery worker drains it moments later (Redis Streams + a dispatched consumer standing in for a
        Kafka + Spark Streaming pipeline).
      </p>
      {status && (
        <div className="flex gap-4 panel p-3 text-sm">
          <span className="text-foreground">
            Queued: <span className="font-mono text-foreground">{status.queued}</span>
          </span>
          <span className="text-foreground">
            Awaiting processing: <span className="font-mono text-foreground">{status.pending}</span>
          </span>
        </div>
      )}
      {canAct && (
        <button
          onClick={() => void sendTestLog()}
          disabled={sending}
          className="rounded-lg border border-primary hover:bg-primary/40 disabled:opacity-50 text-xs px-3 py-1.5 text-primary transition"
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
  if (fields.length === 0) return <p className="text-xs text-muted-foreground">No configuration needed.</p>
  return (
    <div className="space-y-2">
      {fields.map((field) => (
        <input
          key={field}
          placeholder={field}
          value={config[field] ?? ''}
          onChange={(e) => onChange({ ...config, [field]: e.target.value })}
          className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
      ))}
    </div>
  )
}

const CHANNEL_ROLES: { key: string; label: string; placeholder: string }[] = [
  { key: 'critical_channel', label: 'Critical incidents also go to', placeholder: 'critical-incidents' },
  { key: 'soc_team_channel', label: 'Investigation progress & approvals go to', placeholder: 'soc-team' },
  { key: 'executive_channel', label: 'Daily summary goes to', placeholder: 'executive-security' },
  { key: 'compliance_channel', label: 'Compliance reports go to', placeholder: 'compliance' },
]

function ChannelField({ connector, onSaved, roleKey, label, placeholder }: {
  connector: ConnectorInstance
  onSaved: () => void
  roleKey: string
  label: string
  placeholder: string
}) {
  const [value, setValue] = useState(connector.config[roleKey] ?? '')
  const [saving, setSaving] = useState(false)

  async function save() {
    setSaving(true)
    try {
      await api.updateConnectorConfig(connector.id, { [roleKey]: value.trim() })
      await onSaved()
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-muted-foreground shrink-0 w-64">{label}:</span>
      <input
        placeholder={placeholder}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="w-40 rounded-lg border border-border bg-card px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground"
      />
      <button
        onClick={() => void save()}
        disabled={saving}
        className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-xs px-2.5 py-1 text-foreground transition"
      >
        {saving ? 'Saving...' : 'Save'}
      </button>
      {connector.config[roleKey] && <span className="text-xs text-muted-foreground">currently: #{connector.config[roleKey]}</span>}
    </div>
  )
}

function ChannelRoutingEditor({ connector, onSaved }: { connector: ConnectorInstance; onSaved: () => void }) {
  return (
    <div className="mt-3 space-y-2 border-t border-border pt-3">
      <p className="text-xs text-muted-foreground">
        Optional - everything already goes to your default channel. Point specific message types at additional
        channels too, matching how a real SOC team splits alerts/investigation-noise/executive summaries/compliance
        into separate channels. Leave any of these blank to keep using just the default channel.
      </p>
      {CHANNEL_ROLES.map((role) => (
        <ChannelField key={role.key} connector={connector} onSaved={onSaved} roleKey={role.key} label={role.label} placeholder={role.placeholder} />
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

  // Slack's OAuth callback redirects the browser back here with
  // ?slack=connected|error - a one-time toast, then scrub the param so a
  // refresh doesn't keep re-showing it.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const slackResult = params.get('slack')
    if (!slackResult) return
    setMessage(slackResult === 'connected' ? 'Slack connected successfully.' : 'Failed to connect Slack - please try again.')
    void load()
    params.delete('slack')
    const query = params.toString()
    window.history.replaceState({}, '', window.location.pathname + (query ? `?${query}` : ''))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

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
      <h2 className="text-sm font-medium text-foreground">Connectors</h2>
      <p className="text-xs text-muted-foreground">
        Real integrations: keyless log sources that pull data into the platform through the same ingestion pipeline
        as file uploads, plus OAuth-installed apps like Slack that post incident alerts and take approve/reject
        actions from inside the workspace.
      </p>

      {message && <p className="text-xs text-muted-foreground bg-card/60 border border-secondary rounded-lg px-3 py-2">{message}</p>}

      {canCreate && (
        <div className="panel p-4 space-y-3">
          <div className="flex gap-2">
            <select
              value={pluginKey}
              onChange={(e) => {
                setPluginKey(e.target.value)
                setConfig({})
              }}
              className="rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground"
            >
              {plugins.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.display_name}
                </option>
              ))}
            </select>
            {selectedPlugin?.auth_type !== 'oauth' && (
              <input
                placeholder="Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
              />
            )}
          </div>
          {selectedPlugin?.auth_type === 'oauth' ? (
            <>
              <p className="text-xs text-muted-foreground">
                Installs SentraOps as a Slack app in your workspace - no config to type in, Slack handles the
                connection.
              </p>
              <a
                href={slackAuthorizeUrl()}
                className="inline-block rounded-lg border border-primary hover:bg-primary/40 text-xs px-3 py-1.5 text-primary transition"
              >
                Connect to {selectedPlugin.display_name}
              </a>
            </>
          ) : (
            <>
              {selectedPlugin && (
                <ConfigForm fields={selectedPlugin.config_fields} config={config} onChange={setConfig} />
              )}
              <button
                onClick={() => void create()}
                className="rounded-lg border border-primary hover:bg-primary/40 text-xs px-3 py-1.5 text-primary transition"
              >
                Add Connector
              </button>
            </>
          )}
        </div>
      )}

      <div className="space-y-2">
        {instances.map((c) => (
          <div key={c.id} className="panel p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-sm text-foreground">
                  {c.name} <span className="text-xs text-muted-foreground">({c.plugin_key})</span>
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
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
                    className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-xs px-2.5 py-1 text-foreground transition"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => void sync(c.id)}
                    disabled={busyId === c.id}
                    className="rounded-lg border border-severity-low hover:bg-severity-low/40 disabled:opacity-50 text-xs px-2.5 py-1 text-severity-low transition"
                  >
                    {busyId === c.id ? 'Syncing...' : 'Sync Now'}
                  </button>
                </div>
              )}
            </div>
            {canOperate && c.plugin_key === 'slack' && <ChannelRoutingEditor connector={c} onSaved={load} />}
          </div>
        ))}
        {instances.length === 0 && <p className="text-sm text-muted-foreground">No connectors configured yet.</p>}
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
      <h2 className="text-sm font-medium text-foreground">Response Action Integrations</h2>
      <p className="text-xs text-muted-foreground">
        Where an <em>approved</em> proposed action actually gets executed. Nothing here ever fires automatically -
        the AI only proposes, a human approves, and a human then hits Execute on the incident page.
      </p>

      {canCreate && (
        <div className="panel p-4 space-y-3">
          <div className="flex gap-2">
            <select
              value={pluginKey}
              onChange={(e) => {
                setPluginKey(e.target.value)
                setConfig({})
              }}
              className="rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground"
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
              className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
            />
          </div>
          {selectedPlugin && (
            <ConfigForm fields={selectedPlugin.config_fields} config={config} onChange={setConfig} />
          )}
          <button
            onClick={() => void create()}
            className="rounded-lg border border-primary hover:bg-primary/40 text-xs px-3 py-1.5 text-primary transition"
          >
            Add Integration
          </button>
        </div>
      )}

      <div className="space-y-2">
        {instances.map((a) => (
          <div key={a.id} className="panel p-3">
            <p className="text-sm text-foreground">
              {a.name} <span className="text-xs text-muted-foreground">({a.plugin_key})</span>
            </p>
          </div>
        ))}
        {instances.length === 0 && <p className="text-sm text-muted-foreground">No response-action integrations configured yet.</p>}
      </div>
    </div>
  )
}

export function IntegrationsPage() {
  const { user } = useAuth()
  const isAdmin = isAdminRole(user?.role)
  const canOperate = roleCanAct(user?.role)

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Integrations</h1>
        <p className="text-sm text-muted-foreground mt-1">
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
