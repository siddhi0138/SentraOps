import { useCallback, useEffect, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AgentInvestigationPanel } from '../components/AgentInvestigationPanel'
import { AttackGraphView } from '../components/AttackGraphView'
import { AttackReplayPanel } from '../components/AttackReplayPanel'
import { SeverityBadge, StatusBadge } from '../components/Badge'
import type { GraphData, IncidentDetail, IncidentExplanation, Severity, SimilarIncident, User } from '../api/types'

const PRIORITIES: Severity[] = ['low', 'medium', 'high', 'critical']

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [updating, setUpdating] = useState(false)
  const [showReport, setShowReport] = useState(false)
  const [commentBody, setCommentBody] = useState('')
  const [postingComment, setPostingComment] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [explanation, setExplanation] = useState<IncidentExplanation | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [explainError, setExplainError] = useState<string | null>(null)
  const [audience, setAudience] = useState<'analyst' | 'executive'>('analyst')
  const [similar, setSimilar] = useState<SimilarIncident[]>([])
  const [graph, setGraph] = useState<GraphData | null>(null)

  const load = useCallback(async () => {
    if (!id) return
    setLoading(true)
    setError(null)
    try {
      setIncident(await api.getIncident(Number(id)))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load incident')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    // Free (local embedding search, no LLM call), so safe to auto-fetch
    // unlike the AI explanation which costs a real Groq call.
    if (!id) return
    api
      .similarIncidents(Number(id))
      .then((res) => setSimilar(res.matches))
      .catch(() => setSimilar([]))
  }, [id])

  useEffect(() => {
    // 503s if /graph/sync has never been run - fail silently and just hide
    // the section rather than surfacing an error for an optional view.
    if (!id) return
    api
      .getIncidentGraph(Number(id))
      .then(setGraph)
      .catch(() => setGraph(null))
  }, [id])

  useEffect(() => {
    if (canAct) void api.listUsers().then(setUsers)
  }, [canAct])

  async function toggleStatus() {
    if (!incident) return
    setUpdating(true)
    setActionError(null)
    try {
      const next = incident.status === 'open' ? 'closed' : 'open'
      setIncident(await api.updateIncident(incident.id, { status: next }))
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Failed to update status')
    } finally {
      setUpdating(false)
    }
  }

  async function handlePriorityChange(priority: Severity) {
    if (!incident) return
    setActionError(null)
    try {
      setIncident(await api.updateIncident(incident.id, { priority }))
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Failed to update priority')
    }
  }

  async function handleAssigneeChange(assigneeIdRaw: string) {
    if (!incident) return
    const assignee_id = assigneeIdRaw === '' ? null : Number(assigneeIdRaw)
    setActionError(null)
    try {
      setIncident(await api.updateIncident(incident.id, { assignee_id }))
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Failed to update assignee')
    }
  }

  async function handleAddComment() {
    if (!incident || !commentBody.trim()) return
    setPostingComment(true)
    setActionError(null)
    try {
      await api.addComment(incident.id, commentBody.trim())
      setCommentBody('')
      await load()
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Failed to post comment')
    } finally {
      setPostingComment(false)
    }
  }

  async function handleDownloadReport() {
    if (!incident) return
    setActionError(null)
    try {
      await api.downloadIncidentReport(incident.id)
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Failed to download report')
    }
  }

  async function handleExplain(nextAudience?: 'analyst' | 'executive') {
    if (!incident) return
    const target = nextAudience ?? audience
    setAudience(target)
    setExplaining(true)
    setExplainError(null)
    try {
      setExplanation(await api.explainIncident(incident.id, target))
    } catch (err) {
      setExplainError(err instanceof ApiError ? err.message : 'Failed to generate AI explanation')
    } finally {
      setExplaining(false)
    }
  }

  if (loading) return <div className="text-slate-400">Loading incident...</div>
  if (error) return <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>
  if (!incident) return null

  const alerts = incident.timeline.filter((e) => e.severity !== 'low')

  return (
    <div className="space-y-6">
      <Link to="/incidents" className="text-sm text-slate-400 hover:text-slate-200">
        &larr; Back to incidents
      </Link>

      {actionError && (
        <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{actionError}</p>
      )}

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-semibold text-slate-100">{incident.title}</h1>
            <p className="text-sm text-slate-500 mt-1">
              Created {incident.created_at} &middot; {incident.event_count} events
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={handleDownloadReport}
              className="rounded-lg border border-slate-700 hover:bg-slate-800 text-sm px-3 py-1.5 transition"
            >
              Download report
            </button>
            {canAct && (
              <button
                onClick={toggleStatus}
                disabled={updating}
                className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-sm px-3 py-1.5 transition"
              >
                {incident.status === 'open' ? 'Close incident' : 'Reopen incident'}
              </button>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={incident.risk_level} />
          <StatusBadge status={incident.status} />
          <span className="text-sm text-slate-400">Confidence: {incident.confidence}%</span>
          <span className="text-sm text-slate-400">Risk score: {incident.risk_score}/100</span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2 text-sm">
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected hosts</p>
            <p className="text-slate-200">{incident.affected_hosts.join(', ') || '-'}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected users</p>
            <p className="text-slate-200">{incident.affected_users.join(', ') || '-'}</p>
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Priority</p>
            {canAct ? (
              <select
                value={incident.priority}
                onChange={(e) => handlePriorityChange(e.target.value as Severity)}
                className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100"
              >
                {PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            ) : (
              <SeverityBadge severity={incident.priority} />
            )}
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Assignee</p>
            {canAct ? (
              <select
                value={incident.assignee_id ?? ''}
                onChange={(e) => handleAssigneeChange(e.target.value)}
                className="rounded bg-slate-800 border border-slate-700 px-2 py-1 text-xs text-slate-100 max-w-full"
              >
                <option value="">Unassigned</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email}
                  </option>
                ))}
              </select>
            ) : (
              <p className="text-slate-200">{incident.assignee_email ?? 'Unassigned'}</p>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-indigo-900/60 bg-indigo-950/20 p-5">
        <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
          <h2 className="text-sm font-medium text-indigo-300">AI Analysis</h2>
          <div className="flex items-center gap-2">
            {explanation && (
              <div className="flex rounded-lg border border-indigo-800 overflow-hidden text-xs">
                {(['analyst', 'executive'] as const).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => void handleExplain(mode)}
                    disabled={explaining}
                    className={`px-2.5 py-1 capitalize transition ${
                      audience === mode ? 'bg-indigo-700 text-white' : 'text-indigo-300 hover:bg-indigo-900/40'
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            )}
            <button
              onClick={() => void handleExplain()}
              disabled={explaining}
              className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 disabled:opacity-50 text-xs px-3 py-1.5 transition text-indigo-300"
            >
              {explaining ? 'Analyzing...' : explanation ? 'Regenerate' : 'Explain with AI'}
            </button>
          </div>
        </div>

        {explainError && (
          <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2 mb-3">{explainError}</p>
        )}

        {!explanation && !explaining && !explainError && (
          <p className="text-sm text-slate-500">
            Generate a plain-language explanation of why this incident matters, a narrated timeline, and a
            structured summary - grounded in this incident's own report, not a generic description.
          </p>
        )}

        {explanation && (
          <div className="space-y-4">
            <div className="prose prose-invert prose-sm max-w-none prose-p:my-1.5">
              <ReactMarkdown>{explanation.explanation}</ReactMarkdown>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Timeline narrative</p>
              <p className="text-sm text-slate-300">{explanation.timeline_narrative}</p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-1 text-sm">
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Attack type</p>
                <p className="text-slate-200">{explanation.attack_type}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected user</p>
                <p className="text-slate-200">{explanation.affected_user}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Affected assets</p>
                <p className="text-slate-200">{explanation.affected_assets}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Confidence</p>
                <p className="text-slate-200">{explanation.confidence}%</p>
              </div>
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Impact</p>
              <p className="text-sm text-slate-300">{explanation.impact}</p>
            </div>
          </div>
        )}
      </div>

      <AgentInvestigationPanel incidentId={incident.id} canAct={canAct} />

      <AttackReplayPanel incidentId={incident.id} timeline={incident.timeline} />

      {graph && graph.nodes.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-slate-300">Attack Graph</h2>
            <Link to="/attack-graph" className="text-xs text-slate-500 hover:text-slate-300 transition">
              Explore full graph &rarr;
            </Link>
          </div>
          <AttackGraphView data={graph} />
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Timeline</h2>
          <ol className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {incident.timeline.map((event) => (
              <li key={event.id} className="text-sm border-l-2 border-slate-800 pl-3">
                <p className="text-xs font-mono text-slate-500">{event.timestamp}</p>
                <p className="text-slate-200">
                  [{event.host}] {event.username ?? 'unknown'}: {event.message}
                </p>
                <div className="mt-1">
                  <SeverityBadge severity={event.severity} />
                </div>
              </li>
            ))}
          </ol>
        </div>

        <div className="space-y-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Alerts ({alerts.length})</h2>
            <ul className="space-y-1.5 text-sm">
              {alerts.map((event) => (
                <li key={event.id} className="flex items-start gap-2">
                  <SeverityBadge severity={event.severity} />
                  <span className="text-slate-300">{event.message}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-1">Why This Risk Level</h2>
            <p className="text-xs text-slate-500 mb-3">
              Computed by the correlation engine's own scoring rules, not an AI guess.
            </p>
            <ul className="space-y-1.5 text-sm">
              {incident.risk_factors.map((factor) => (
                <li key={factor} className="flex items-start gap-2 text-slate-300">
                  <span className="text-emerald-400 mt-0.5">&#10003;</span>
                  <span>{factor}</span>
                </li>
              ))}
            </ul>
          </div>

          {incident.threat_intel.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-medium text-slate-300 mb-3">Threat Intelligence</h2>
              <ul className="space-y-2 text-sm">
                {incident.threat_intel.map((ti) => (
                  <li key={ti.indicator}>
                    <p className="font-mono text-slate-200">{ti.indicator}</p>
                    <p className="text-slate-400">
                      {ti.verdict} &middot; {ti.confidence}% confidence &middot; {ti.source}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-sm font-medium text-slate-300 mb-3">Recommended Actions</h2>
            <ul className="space-y-1.5 text-sm text-slate-300 list-disc list-inside">
              {incident.recommended_actions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </div>

          {similar.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="text-sm font-medium text-slate-300 mb-3">Similar Incidents</h2>
              <div className="space-y-2">
                {similar.map((match) => (
                  <Link
                    key={match.id}
                    to={`/incidents/${match.id}`}
                    className="flex items-center justify-between py-1.5 hover:bg-slate-800/40 -mx-2 px-2 rounded transition"
                  >
                    <div className="min-w-0">
                      <p className="text-sm text-slate-200 truncate">{match.title}</p>
                      <p className="text-xs text-slate-500">{match.affected_hosts.join(', ')}</p>
                    </div>
                    {match.similarity !== null && (
                      <span className="text-xs text-slate-400 shrink-0 ml-2">{Math.round(match.similarity * 100)}% similar</span>
                    )}
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="text-sm font-medium text-slate-300 mb-3">Comments ({incident.comments.length})</h2>
        <div className="space-y-3 mb-4">
          {incident.comments.map((comment) => (
            <div key={comment.id} className="text-sm border-l-2 border-slate-800 pl-3">
              <p className="text-xs text-slate-500">
                {comment.author_email} &middot; {comment.created_at}
              </p>
              <p className="text-slate-200">{comment.body}</p>
            </div>
          ))}
          {incident.comments.length === 0 && <p className="text-sm text-slate-500">No comments yet.</p>}
        </div>
        {canAct && (
          <div className="flex gap-2">
            <input
              value={commentBody}
              onChange={(e) => setCommentBody(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
              placeholder="Add a comment..."
              className="flex-1 rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <button
              onClick={handleAddComment}
              disabled={postingComment || !commentBody.trim()}
              className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-1.5 transition"
            >
              Post
            </button>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <button
          onClick={() => setShowReport((v) => !v)}
          className="text-sm font-medium text-slate-300 hover:text-white transition"
        >
          {showReport ? 'Hide' : 'Show'} full report
        </button>
        {showReport && (
          <pre className="mt-3 text-xs text-slate-300 whitespace-pre-wrap font-mono bg-slate-950 rounded-lg p-4 overflow-x-auto">
            {incident.report}
          </pre>
        )}
      </div>
    </div>
  )
}
