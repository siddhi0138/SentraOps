import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import type { AgentRunListItem, AgentRunStatus } from '../api/types'

const STATUS_STYLES: Record<AgentRunStatus, string> = {
  running: 'bg-severity-medium/80 text-severity-medium',
  completed: 'bg-severity-low/80 text-severity-low',
  failed: 'bg-destructive/80 text-destructive',
}

function RunStatusBadge({ status }: { status: AgentRunStatus }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide ${STATUS_STYLES[status]}`}>
      {status === 'running' && <span className="h-1.5 w-1.5 rounded-full bg-severity-medium animate-pulse" />}
      {status}
    </span>
  )
}

const STAGE_LABELS: Record<string, string> = {
  detection: 'Detection',
  investigation: 'Investigation',
  threat_intel: 'Threat Intel',
  risk: 'Risk',
  response: 'Response',
  report: 'Report',
  done: 'Done',
  starting: 'Starting',
}

export function AITeamPage() {
  const [runs, setRuns] = useState<AgentRunListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const res = await api.listAllAgentRuns({ limit: 30 })
      setRuns(res.runs)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load agent runs')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Cross-incident dashboard, so polling (not a WebSocket per run) is the
  // simpler choice here - the per-incident panel already gives live
  // per-agent progress for the one investigation someone is actively
  // watching; this view just needs to notice when any investigation
  // anywhere starts or finishes.
  useEffect(() => {
    const hasRunning = runs.some((r) => r.status === "running")
    if (!hasRunning) return
    const interval = setInterval(() => void load(), 3000)
    return () => clearInterval(interval)
  }, [runs, load])

  const runningCount = runs.filter((r) => r.status === 'running').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">AI Team</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {runningCount > 0
            ? `${runningCount} investigation${runningCount === 1 ? '' : 's'} in progress across the platform`
            : 'Recent and active multi-agent investigations across every incident'}
        </p>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}
      {loading && <p className="text-muted-foreground text-sm">Loading...</p>}

      {!loading && runs.length === 0 && !error && (
        <p className="text-sm text-muted-foreground">
          No investigations have been run yet. Open an incident and run the AI Security Team to see it here.
        </p>
      )}

      <div className="space-y-2">
        {runs.map((run) => (
          <Link
            key={run.id}
            to={`/incidents/${run.incident_id}`}
            className="flex items-center justify-between gap-4 panel p-4 hover:border-agent transition"
          >
            <div className="min-w-0">
              <p className="text-sm text-foreground truncate">{run.incident_title ?? `Incident #${run.incident_id}`}</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Run #{run.id} &middot; started {run.started_at}
                {run.triggered_by_email && ` by ${run.triggered_by_email}`}
              </p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              {run.stage && (
                <span className="text-xs text-muted-foreground">{STAGE_LABELS[run.stage] ?? run.stage}</span>
              )}
              <RunStatusBadge status={run.status} />
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}
