import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { SeverityBadge } from '../components/Badge'
import { StatCard } from '../components/StatCard'
import type { AgentRunListItem, CommandCenterQueue, ShiftNote } from '../api/types'

export function SOCCommandCenterPage() {
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [queue, setQueue] = useState<CommandCenterQueue | null>(null)
  const [runningRuns, setRunningRuns] = useState<AgentRunListItem[]>([])
  const [notes, setNotes] = useState<ShiftNote[]>([])
  const [noteBody, setNoteBody] = useState('')
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [queueRes, runsRes, notesRes] = await Promise.all([
        api.getCommandCenterQueue(),
        api.listAllAgentRuns({ status: 'running', limit: 10 }),
        api.listShiftNotes(10),
      ])
      setQueue(queueRes)
      setRunningRuns(runsRes.runs)
      setNotes(notesRes.notes)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load command center')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  // Poll while anything is actively running - the same reasoning as
  // AITeamPage: a listing view needs to notice progress, not stream every
  // investigation live (the per-incident panel already does that).
  useEffect(() => {
    if (runningRuns.length === 0) return
    const interval = setInterval(() => void load(), 5000)
    return () => clearInterval(interval)
  }, [runningRuns.length, load])

  async function claimIncident(incidentId: number) {
    if (!user) return
    setBusyId(incidentId)
    try {
      await api.updateIncident(incidentId, { assignee_id: user.id })
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to claim incident')
    } finally {
      setBusyId(null)
    }
  }

  async function reviewAction(actionId: number, status: 'approved' | 'rejected') {
    setBusyId(actionId)
    try {
      await api.reviewProposedAction(actionId, status)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to review action')
    } finally {
      setBusyId(null)
    }
  }

  async function postNote() {
    if (!noteBody.trim()) return
    try {
      await api.createShiftNote(noteBody.trim())
      setNoteBody('')
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to post shift note')
    }
  }

  if (loading || !queue) {
    return <div className="text-muted-foreground">Loading command center...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">SOC Command Center</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Everything that needs an analyst's attention right now, in one place - open incidents, actions awaiting
          approval, and investigations in progress.
        </p>
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Open Incidents" value={queue.open_incidents.length} />
        <StatCard
          label="Unassigned"
          value={queue.unassigned_open_incidents}
          accent={queue.unassigned_open_incidents > 0 ? 'text-severity-medium' : undefined}
        />
        <StatCard label="Actions Awaiting Approval" value={queue.pending_actions.length} />
        <StatCard label="Investigations Running" value={runningRuns.length} />
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="panel p-4">
          <h2 className="text-sm font-medium text-foreground mb-3">Open Incidents (by risk)</h2>
          {queue.open_incidents.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing open.</p>
          ) : (
            <div className="divide-y divide-secondary">
              {queue.open_incidents.map((incident) => (
                <div key={incident.id} className="flex items-center justify-between gap-3 py-2.5">
                  <Link to={`/incidents/${incident.id}`} className="min-w-0 hover:text-agent transition">
                    <p className="text-sm text-foreground truncate">{incident.title}</p>
                    <p className="text-xs text-muted-foreground">
                      {incident.assignee_email ?? 'Unassigned'} &middot; risk {incident.risk_score}/100
                    </p>
                  </Link>
                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityBadge severity={incident.risk_level} />
                    {canAct && !incident.assignee_id && (
                      <button
                        onClick={() => void claimIncident(incident.id)}
                        disabled={busyId === incident.id}
                        className="rounded-lg border border-agent hover:bg-agent/40 disabled:opacity-50 text-xs px-2.5 py-1 text-agent transition"
                      >
                        Claim
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel p-4">
          <h2 className="text-sm font-medium text-foreground mb-3">Actions Awaiting Approval</h2>
          {queue.pending_actions.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing pending.</p>
          ) : (
            <div className="divide-y divide-secondary">
              {queue.pending_actions.map((action) => (
                <div key={action.id} className="py-2.5 space-y-1.5">
                  <Link to={`/incidents/${action.incident_id}`} className="block hover:text-agent transition">
                    <p className="text-sm text-foreground">{action.description}</p>
                    <p className="text-xs text-muted-foreground">
                      {action.incident_title} &middot; {action.category}
                    </p>
                  </Link>
                  {canAct && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => void reviewAction(action.id, 'approved')}
                        disabled={busyId === action.id}
                        className="rounded-lg border border-severity-low hover:bg-severity-low/40 disabled:opacity-50 text-xs px-2.5 py-1 text-severity-low transition"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => void reviewAction(action.id, 'rejected')}
                        disabled={busyId === action.id}
                        className="rounded-lg border border-destructive hover:bg-destructive/40 disabled:opacity-50 text-xs px-2.5 py-1 text-destructive transition"
                      >
                        Reject
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {runningRuns.length > 0 && (
        <div className="rounded-xl border border-severity-medium/60 bg-severity-medium/10 p-4">
          <h2 className="text-sm font-medium text-severity-medium mb-3">Investigations In Progress</h2>
          <div className="space-y-1.5">
            {runningRuns.map((run) => (
              <Link
                key={run.id}
                to={`/incidents/${run.incident_id}`}
                className="flex items-center justify-between text-sm hover:text-severity-medium transition"
              >
                <span className="text-foreground">{run.incident_title ?? `Incident #${run.incident_id}`}</span>
                <span className="text-xs text-severity-medium">started {run.started_at}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div className="panel p-4">
        <h2 className="text-sm font-medium text-foreground mb-3">Shift Notes</h2>
        {canAct && (
          <div className="flex gap-2 mb-3">
            <input
              value={noteBody}
              onChange={(e) => setNoteBody(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && postNote()}
              placeholder="Leave a note for the next shift..."
              className="flex-1 rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
            />
            <button
              onClick={() => void postNote()}
              className="rounded-lg border border-primary hover:bg-primary/40 text-xs px-3 py-1.5 text-primary transition"
            >
              Post
            </button>
          </div>
        )}
        {notes.length === 0 ? (
          <p className="text-sm text-muted-foreground">No shift notes yet.</p>
        ) : (
          <ul className="space-y-2">
            {notes.map((note) => (
              <li key={note.id} className="text-sm">
                <span className="text-foreground">{note.body}</span>
                <span className="text-xs text-muted-foreground ml-2">
                  {note.author_email} &middot; {note.created_at}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
